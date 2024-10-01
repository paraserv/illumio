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
        boto_config=None,
        state_file=None,
        downloaded_files_folder=None
    ):
        self.session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )
        if boto_config is None:
            boto_config = BotoConfig(
                max_pool_connections=max_pool_connections,
                retries={'max_attempts': 10, 'mode': 'adaptive'}
            )
        self.s3_client = self.session.client('s3', config=boto_config)
        self.s3_bucket_name = s3_bucket_name
        self.minutes = minutes
        self.max_files_per_folder = max_files_per_folder
        self.health_reporter = health_reporter
        self.last_check_time = datetime.now(pytz.UTC)
        self.last_check_count = 0
        self.last_ingestion_check = datetime.now(pytz.UTC)
        self.last_ingestion_count = 0
        self.total_log_entries = 0

        # Load settings
        config = configparser.ConfigParser()
        script_dir = Path(__file__).parent
        settings_file = script_dir / 'settings.ini'
        config.read(settings_file)

        self.baseline_period = config.getfloat('S3', 'BASELINE_PERIOD', fallback=300.0)
        self.MIN_TIMEFRAME = config.getfloat('Processing', 'MIN_TIMEFRAME', fallback=0.25)
        self.MAX_TIMEFRAME = config.getfloat('Processing', 'MAX_TIMEFRAME', fallback=24.0)

        self.last_ingestion_check = datetime.now(pytz.UTC)
        self.last_ingestion_count = 0
        self.total_log_entries = 0
        self.baseline_start_time = datetime.now(pytz.UTC)
        self.baseline_data = []
        self.app_logger = get_logger('s3_manager')
        self.last_log_time = time.time()
        self.log_interval = 60  # Log at most once per minute

        # Set the state_file path
        self.state_file = Path(state_file).resolve() if state_file else None

        # Set the downloaded_files_folder path
        self.downloaded_files_folder = Path(downloaded_files_folder).resolve() if downloaded_files_folder else None

        # Log the paths being used
        logger.info(f"S3Manager will save state to: {self.state_file}")
        logger.info(f"S3Manager will download files to: {self.downloaded_files_folder}")

    def get_new_s3_objects(self, log_type, processed_keys, time_window_start, time_window_end, batch_size):
        folder = f"illumio/{log_type}/"
        new_objects = []

        try:
            if log_type == 'summaries':
                # Use date-based prefixes for summaries
                date_list = [time_window_start + timedelta(days=x) for x in range((time_window_end - time_window_start).days + 1)]
                prefixes = [f"{folder}{date.strftime('%Y%m%d')}" for date in date_list]
                logger.info(f"Scanning prefixes for summaries: {prefixes}")
                for prefix in prefixes:
                    self._list_objects(prefix, new_objects, processed_keys, time_window_start, time_window_end, batch_size)
                    if len(new_objects) >= batch_size:
                        break
            else:
                # Scan entire folder for auditable_events
                logger.info(f"Scanning folder for auditable_events: {folder}")
                self._list_objects(folder, new_objects, processed_keys, time_window_start, time_window_end, batch_size)

        except Exception as e:
            logger.error(f"Error in get_new_s3_objects for {log_type}: {e}")

        logger.info(f"Found {len(new_objects)} new {log_type} objects")
        return new_objects

    def _list_objects(self, prefix, new_objects, processed_keys, time_window_start, time_window_end, batch_size):
        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=self.s3_bucket_name, Prefix=prefix)

            for page in page_iterator:
                if 'Contents' in page:
                    for obj in page['Contents']:
                        obj_last_modified = obj['LastModified'].replace(tzinfo=pytz.UTC)
                        if (obj['Key'] not in processed_keys and
                            time_window_start <= obj_last_modified <= time_window_end):
                            new_objects.append(obj)
                            if len(new_objects) >= batch_size:
                                return
        except Exception as e:
            logger.error(f"Error listing objects for prefix {prefix}: {e}")

    def save_state(self, processed_keys):
        state_data = {
            'summaries': {},
            'auditable_events': {}
        }
        for log_type in ['summaries', 'auditable_events']:
            for key, timestamp in processed_keys[log_type].items():
                if isinstance(timestamp, datetime):
                    state_data[log_type][key] = timestamp.isoformat()
                else:
                    state_data[log_type][key] = timestamp  # Assume it's already a string

        if not self.state_file:
            logger.error("State file path is not set.")
            return

        logger.info(f"Saving state to: {self.state_file}")
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state_data, f)
            logger.info(
                f"Saved state: Summaries: {len(state_data['summaries'])}, "
                f"Auditable Events: {len(state_data['auditable_events'])}"
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

    def download_and_extract(self, s3_object, stop_event: threading.Event):
        key = s3_object['Key']

        if stop_event.is_set():
            logger.info(f"Stopping download of {key} due to shutdown signal.")
            return None

        try:
            logger.info(f"Downloading {key}")
            temp_filename = self.downloaded_files_folder / os.path.basename(key)
            logger.debug(f"Temporary file path: {temp_filename}")
            
            # Ensure the parent directory exists
            temp_filename.parent.mkdir(parents=True, exist_ok=True)
            
            try:
                self.s3_client.download_file(self.s3_bucket_name, key, str(temp_filename))
                logger.debug(f"Download completed: {temp_filename}")
            except Exception as e:
                logger.error(f"Failed to download {key} from S3: {e}")
                return None

            if stop_event.is_set():
                logger.info(f"Stopping extraction of {key} due to shutdown signal.")
                return None

            # Extract the file
            dest_path = temp_filename.with_suffix('')
            logger.debug(f"Extracting to: {dest_path}")
            with gzip.open(temp_filename, 'rb') as f_in:
                with open(dest_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            logger.debug(f"Extracted {key} to {dest_path}")
            logger.debug(f"  Compressed size: {s3_object['Size']} bytes")
            logger.debug(f"  Uncompressed size: {dest_path.stat().st_size} bytes")

            return dest_path
        except Exception as e:
            logger.error(f"Error downloading or extracting {key}: {e}")
            logger.exception("Detailed error information:")
            return None
        finally:
            if 'temp_filename' in locals() and temp_filename.exists():
                temp_filename.unlink()

    def update_and_save_state(self, processed_keys, log_type, s3_key):
        processed_keys[log_type][s3_key] = datetime.now(pytz.UTC)
        self.save_state(processed_keys)

    def load_state(self, state_file):
        if os.path.exists(state_file):
            with open(state_file, 'r') as f:
                return json.load(f)
        return {'summaries': {}, 'auditable_events': {}}