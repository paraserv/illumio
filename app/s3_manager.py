#!/usr/bin/env python3
"""
Manages interactions with AWS S3, including fetching and downloading log files.
"""

# Standard library imports
import gzip
import shutil
import os
import time
import json
import threading
from datetime import datetime, timedelta
from pathlib import Path
import configparser
import tempfile

# Third-party imports
import boto3
import pytz
from botocore.config import Config as BotoConfig

# Local application imports
from logger_config import get_logger

# Typing imports
from typing import List, Dict, Any

logger = get_logger(__name__)

class S3Manager:
    def __init__(
        self,
        aws_access_key_id,
        aws_secret_access_key,
        s3_bucket_name,
        minutes,
        max_files_per_folder,
        health_reporter,
        max_pool_connections,
        state_file,
        downloaded_files_folder,
        config
    ):
        self.s3_bucket_name = s3_bucket_name
        self.minutes = minutes
        self.max_files_per_folder = max_files_per_folder
        self.health_reporter = health_reporter
        self.state_file = state_file
        self.processed_keys = self.load_state(state_file)

        boto_config = BotoConfig(
            max_pool_connections=max_pool_connections,
            retries={'max_attempts': 10, 'mode': 'adaptive'}
        )
        
        self.session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
        self.s3 = self.session.client('s3', config=boto_config)

        self.queue_size_threshold = config.QUEUE_SIZE_THRESHOLD
        self.downloaded_files_folder = Path(downloaded_files_folder)
        self.downloaded_files_folder.mkdir(parents=True, exist_ok=True)

        # Load settings from settings.ini
        settings_config = configparser.ConfigParser()
        script_dir = Path(__file__).parent
        settings_file = script_dir / 'settings.ini'
        settings_config.read(settings_file)

        self.baseline_period = settings_config.getfloat('S3', 'BASELINE_PERIOD', fallback=300.0)
        self.MIN_TIMEFRAME = settings_config.getfloat('Processing', 'MIN_TIMEFRAME', fallback=0.25)
        self.MAX_TIMEFRAME = settings_config.getfloat('Processing', 'MAX_TIMEFRAME', fallback=24.0)
        self.log_timeframe = config.LOG_TIMEFRAME

        self.config = config  # Store the config object
        self.time_window_hours = config.TIME_WINDOW_HOURS

        self.last_ingestion_check = datetime.now(pytz.UTC)
        self.last_ingestion_count = 0
        self.total_log_entries = 0
        self.baseline_start_time = datetime.now(pytz.UTC)
        self.baseline_data = []
        self.app_logger = get_logger('s3_manager')
        self.last_log_time = time.time()
        self.log_interval = 60  # Log at most once per minute

        # Log the paths being used
        logger.info(f"S3Manager will save state to: {self.state_file}")
        logger.info(f"S3Manager will download files to: {self.downloaded_files_folder}")

        self.current_download = None
        self.download_complete = threading.Event()

        self.last_ingestion_time = time.time()
        self.last_ingestion_count = 0
        self.current_ingestion_rate = 0.0

        self.s3_stats = {
            'files_discovered': 0,
            'files_downloaded': 0,
            'files_processed': 0,
            'logs_extracted': 0
        }
        self.last_stats_update = time.time()

    def update_ingestion_rate(self, new_logs_count):
        current_time = time.time()
        time_diff = current_time - self.last_ingestion_time
        if time_diff > 0:
            self.current_ingestion_rate = (new_logs_count - self.last_ingestion_count) / time_diff
            self.last_ingestion_time = current_time
            self.last_ingestion_count = new_logs_count
        return self.current_ingestion_rate

    def get_new_s3_objects(self, log_type, time_window_start, time_window_end, batch_size, current_queue_size):
        if current_queue_size >= self.queue_size_threshold:
            logger.info(f"Pausing downloads. Current queue size: {current_queue_size}")
            return []

        folder = f"illumio/{log_type}/"
        new_objects = []

        try:
            # Use the TIME_WINDOW_HOURS setting to determine the start time
            time_window_start = datetime.now(pytz.UTC) - timedelta(hours=self.config.TIME_WINDOW_HOURS)
            time_window_end = datetime.now(pytz.UTC)

            logger.info(f"Scanning S3 for {log_type} from {time_window_start} to {time_window_end}")

            if log_type == 'summaries':
                # Use date-based prefixes for summaries
                date_list = [time_window_start.date() + timedelta(days=x) for x in range((time_window_end.date() - time_window_start.date()).days + 1)]
                prefixes = [f"{folder}{date.strftime('%Y%m%d')}" for date in date_list]
                logger.info(f"Scanning prefixes for summaries: {prefixes}")
                for prefix in prefixes:
                    self._scan_prefix(prefix, time_window_start, time_window_end, new_objects, batch_size, log_type)
                    if len(new_objects) >= batch_size:
                        break
            else:
                self._scan_prefix(folder, time_window_start, time_window_end, new_objects, batch_size, log_type)

            logger.info(f"Found {len(new_objects)} new objects for {log_type}. Time window: {time_window_start} to {time_window_end}")

            self.s3_stats['files_discovered'] += len(new_objects)
            self.update_s3_stats()

            return new_objects[:batch_size]  # Return up to batch_size number of objects
        except Exception as e:
            logger.error(f"Error listing objects: {e}")
            logger.exception("Detailed error information:")
        
        return []

    def _scan_prefix(self, prefix, time_window_start, time_window_end, new_objects, batch_size, log_type):
        paginator = self.s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=self.s3_bucket_name, Prefix=prefix):
            if 'Contents' in page:
                for obj in page['Contents']:
                    if obj['Key'].endswith('.gz'):
                        obj_last_modified = obj['LastModified'].replace(tzinfo=pytz.UTC)
                        if (obj['Key'] not in self.processed_keys[log_type] and
                            time_window_start <= obj_last_modified <= time_window_end):
                            new_objects.append(obj)
                            logger.debug(f"Found new object: {obj['Key']}, Last Modified: {obj_last_modified}")
                        else:
                            logger.debug(f"Skipped object: {obj['Key']}, Last Modified: {obj_last_modified}, Already Processed: {obj['Key'] in self.processed_keys[log_type]}")
                        if len(new_objects) >= batch_size:
                            return
            else:
                logger.info(f"No contents found for prefix: {prefix}")

    def save_state(self):
        if not self.state_file:
            logger.error("State file path is not set.")
            return

        logger.info(f"Saving state to: {self.state_file}")
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.processed_keys, f)
            logger.info(
                f"Saved state: Summaries: {len(self.processed_keys['summaries'])}, "
                f"Auditable Events: {len(self.processed_keys['auditable_events'])}"
            )
        except Exception as e:
            logger.error(f"Failed to save state file {self.state_file}: {e}")

    def estimate_log_entries(self, objects):
        # This is a rough estimate. For accuracy, we'd need to download and count entries in each file.
        return sum(obj['Size'] for obj in objects) / 100  # Assuming average compressed log size of 100 bytes

    def adjust_log_timeframe(self, processed_count, processing_time, ingestion_mps):
        if (datetime.now(pytz.UTC) - self.baseline_start_time).total_seconds() < self.baseline_period:
            self.app_logger.info("S3 Manager: Still in baseline period. Not adjusting log timeframe.")
            return

        if processing_time > 0:
            processing_mps = float(processed_count) / processing_time
            ideal_timeframe = max(60.0, (ingestion_mps / processing_mps) * 3600 * 1.2)
            old_timeframe = self.log_timeframe * 3600
            self.log_timeframe = max(min(ideal_timeframe, self.MAX_TIMEFRAME * 3600), self.MIN_TIMEFRAME * 3600) / 3600
            
            message = (f"S3 Manager: Log timeframe adjusted: {old_timeframe/60:.2f} min -> {self.log_timeframe*60:.2f} min. "
                       f"Processing rate: {processing_mps:.2f} MB/s, "
                       f"Ingestion rate: {ingestion_mps:.2f} MB/s, "
                       f"Ideal timeframe: {ideal_timeframe/60:.2f} min. "
                       f"This adjustment aims to optimize log processing based on current ingestion and processing rates.")
            
            self.app_logger.info(message)
            self.health_reporter.log_message(message)

    def extract_timestamp_from_filename(self, key):
        try:
            # Extract just the filename from the full S3 key
            filename = key.split('/')[-1]
            # Assuming filename format: YYYYMMDDHHMMSS_XXXXX.gz
            timestamp_str = filename[:14]
            return datetime.strptime(timestamp_str, "%Y%m%d%H%M%S").replace(tzinfo=pytz.UTC)
        except ValueError:
            logger.warning(f"Unable to extract timestamp from filename: {filename}")
            return None

    def download_and_extract(self, key, stop_event):
        if stop_event.is_set():
            logger.info(f"Stopping extraction of {key} due to shutdown signal.")
            return None, 0

        try:
            s3_object = self.s3.get_object(Bucket=self.s3_bucket_name, Key=key)
            file_content = s3_object['Body'].read()

            with tempfile.NamedTemporaryFile(delete=False, suffix='.gz') as temp_file:
                temp_filename = Path(temp_file.name)
                temp_file.write(file_content)

            dest_path = self.downloaded_files_folder / Path(key).name.replace('.gz', '')
            logger.debug(f"Extracting to: {dest_path}")
            
            logs_extracted = 0
            with gzip.open(temp_filename, 'rb') as f_in:
                with open(dest_path, 'wb') as f_out:
                    for line in f_in:
                        f_out.write(line)
                        logs_extracted += 1

            logger.debug(f"Extracted {key} to {dest_path}")
            logger.debug(f"  Compressed size: {s3_object['ContentLength']} bytes")
            logger.debug(f"  Uncompressed size: {dest_path.stat().st_size} bytes")
            logger.debug(f"  Logs extracted: {logs_extracted}")

            self.s3_stats['files_downloaded'] += 1
            self.s3_stats['files_processed'] += 1
            self.s3_stats['logs_extracted'] += logs_extracted
            self.update_s3_stats()
            return str(dest_path), logs_extracted
        except Exception as e:
            logger.error(f"Error downloading or extracting {key}: {e}")
            logger.exception("Detailed error information:")
            return None, 0
        finally:
            if 'temp_filename' in locals():
                temp_filename.unlink(missing_ok=True)

    def update_and_save_state(self, log_type, s3_object):
        self.processed_keys[log_type][s3_object['Key']] = datetime.now(pytz.UTC).isoformat()
        self.save_state()

    def load_state(self, state_file):
        if os.path.exists(state_file):
            with open(state_file, 'r') as f:
                state = json.load(f)
            logger.info(f"Loaded state from {state_file}: Summaries: {len(state['summaries'])}, Auditable Events: {len(state['auditable_events'])}")
            return state
        logger.info(f"No existing state file found at {state_file}. Starting fresh.")
        return {'summaries': {}, 'auditable_events': {}}

    def update_s3_stats(self):
        current_time = time.time()
        elapsed_time = current_time - self.last_stats_update
        if elapsed_time >= 60:  # Update stats every minute
            stats_message = (
                f"S3 Stats: Discovered: {self.s3_stats['files_discovered']}, "
                f"Downloaded: {self.s3_stats['files_downloaded']}, "
                f"Processed: {self.s3_stats['files_processed']}, "
                f"Logs extracted: {self.s3_stats['logs_extracted']}"
            )
            try:
                self.health_reporter.log_s3_stats(stats_message)
            except Exception as e:
                logger.error(f"Failed to log S3 stats: {e}")
            self.last_stats_update = current_time
        return self.s3_stats.copy()