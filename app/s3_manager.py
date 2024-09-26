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
        bucket_name,
        log_timeframe,
        base_paths,
        enable_dynamic_timeframe,
        health_reporter,
        max_pool_connections,
        boto_config=None,
        state_file=None,
        checkpoint_file=None
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
        self.bucket_name = bucket_name
        self.log_timeframe = log_timeframe
        self.base_paths = base_paths
        self.enable_dynamic_timeframe = enable_dynamic_timeframe
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

        self.state_file = state_file
        self.checkpoint_file = checkpoint_file

    def get_new_s3_objects(self, log_type, processed_keys, time_window_start, time_window_end, batch_size):
        folder = f"illumio/{log_type}/"
        new_objects = []

        if log_type == 'summaries':
            # Use date-based prefixes for summaries
            date_list = [time_window_start + timedelta(days=x) for x in range((time_window_end - time_window_start).days + 1)]
            prefixes = [f"{folder}{date.strftime('%Y%m%d')}" for date in date_list]
            logger.info(f"Scanning prefixes for summaries: {prefixes}")
            try:
                for prefix in prefixes:
                    paginator = self.s3_client.get_paginator('list_objects_v2')
                    page_iterator = paginator.paginate(
                        Bucket=self.bucket_name,
                        Prefix=prefix
                    )

                    for page in page_iterator:
                        if 'Contents' in page:
                            for obj in page['Contents']:
                                # Filter objects by time window and whether they have been processed
                                obj_last_modified = obj['LastModified'].replace(tzinfo=pytz.UTC)
                                if obj['Key'] not in processed_keys[log_type] and \
                                   time_window_start <= obj_last_modified <= time_window_end:
                                    new_objects.append(obj)
                                    if len(new_objects) >= batch_size:
                                        break
                            if len(new_objects) >= batch_size:
                                break
            except Exception as e:
                logger.error(f"Error listing objects for prefix {prefix}: {e}")
                return []
        else:
            # Scan entire folder for auditable_events
            logger.info(f"Scanning folder for auditable_events: {folder}")
            try:
                paginator = self.s3_client.get_paginator('list_objects_v2')
                page_iterator = paginator.paginate(
                    Bucket=self.bucket_name,
                    Prefix=folder
                )

                for page in page_iterator:
                    if 'Contents' in page:
                        for obj in page['Contents']:
                            # Filter by time window and processed keys
                            obj_last_modified = obj['LastModified'].replace(tzinfo=pytz.UTC)
                            if obj['Key'] not in processed_keys[log_type] and \
                               time_window_start <= obj_last_modified <= time_window_end:
                                new_objects.append(obj)
                                if len(new_objects) >= batch_size:
                                    break
                        if len(new_objects) >= batch_size:
                            break
            except Exception as e:
                logger.error(f"Error listing objects in folder {folder}: {e}")
                return []

        return new_objects

    def save_state(self, processed_keys):
        state_data = {
            'summaries': {},
            'auditable_events': {}
        }
        for log_type in ['summaries', 'auditable_events']:
            for key, timestamp in processed_keys[log_type].items():
                state_data[log_type][key] = timestamp.isoformat()
        
        with open(self.state_file, 'w') as f:
            json.dump(state_data, f)
        logger.info(f"Saved state: Summaries: {len(state_data['summaries'])}, Auditable Events: {len(state_data['auditable_events'])}")

    def save_checkpoint(self, processed_files):
        checkpoint_data = {
            'summaries': [f for f in processed_files if 'summaries' in f],
            'auditable_events': [f for f in processed_files if 'auditable_events' in f]
        }
        with open(self.checkpoint_file, 'w') as f:
            json.dump(checkpoint_data, f)
        logger.info(f"Saved checkpoint: {len(checkpoint_data['summaries'])} summary files, {len(checkpoint_data['auditable_events'])} auditable event files")

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

    def download_and_extract(self, s3_object, download_folder, stop_event: threading.Event):
        key = s3_object['Key']

        if stop_event.is_set():
            logger.info(f"Stopping download of {key} due to shutdown signal.")
            return None

        try:
            logger.info(f"Downloading {key}")
            temp_filename = os.path.join(download_folder, os.path.basename(key))
            self.s3_client.download_file(self.bucket_name, key, temp_filename)

            if stop_event.is_set():
                logger.info(f"Stopping extraction of {key} due to shutdown signal.")
                return None

            # Extract the file
            dest_path = temp_filename.rstrip('.gz')
            with gzip.open(temp_filename, 'rb') as f_in:
                with open(dest_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # Convert dest_path to a Path object
            dest_path = Path(dest_path)

            logger.debug(f"Extracted {key} to {dest_path}")
            logger.debug(f"  Compressed size: {s3_object['Size']} bytes")
            logger.debug(f"  Uncompressed size: {dest_path.stat().st_size} bytes")

            return dest_path
        except Exception as e:
            logger.error(f"Error downloading or extracting {key}: {e}")
            return None
        finally:
            if os.path.exists(temp_filename):
                os.remove(temp_filename)