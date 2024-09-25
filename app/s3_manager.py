# app/s3_manager.py

import boto3
import gzip
import shutil
import os
import tempfile
from pathlib import Path
from logger_config import get_logger
from datetime import datetime, timedelta
import pytz
from tenacity import retry, stop_after_attempt, wait_exponential
import time
import json
from configparser import ConfigParser
from botocore.config import Config as BotoConfig

logger = get_logger(__name__)

class S3Manager:
    def __init__(self, aws_access_key_id, aws_secret_access_key, bucket_name, log_timeframe, base_paths, enable_dynamic_timeframe, health_reporter, max_pool_connections, boto_config=None, state_file=None, checkpoint_file=None):
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
        config = ConfigParser()
        config.read('settings.ini')
        
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

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    def get_new_log_objects(self, processed_keys):
        try:
            start_time = datetime.now(pytz.UTC)
            end_date = datetime.now(pytz.UTC)
            start_date = end_date - timedelta(hours=self.log_timeframe)
            
            logger.info(f"Scanning for unprocessed logs from {start_date} to {end_date}")

            unprocessed_objects = {'summaries': [], 'auditable_events': []}
            total_size = {'summaries': 0, 'auditable_events': 0}

            current_date = end_date.strftime('%Y%m%d')

            for base_path in self.base_paths:
                logger.info(f"Scanning folder: {base_path}")
                
                date_prefix = f"{base_path}{current_date}"
                
                paginator = self.s3_client.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=self.bucket_name, Prefix=date_prefix):
                    if 'Contents' in page:
                        for obj in page['Contents']:
                            log_type = 'auditable_events' if 'auditable_events' in obj['Key'] else 'summaries'
                            
                            if start_date <= obj['LastModified'] <= end_date:
                                if obj['Key'] not in processed_keys:
                                    unprocessed_objects[log_type].append(obj)
                                    total_size[log_type] += obj['Size']

            logger.info(f"Found {len(unprocessed_objects['summaries'])} summary logs and {len(unprocessed_objects['auditable_events'])} auditable event logs")
            logger.info(f"Total size: Summaries: {total_size['summaries'] / (1024 * 1024):.2f} MB, Auditable Events: {total_size['auditable_events'] / (1024 * 1024):.2f} MB")
            logger.info(f"Time range: {start_date} to {end_date}")

            # Save state
            self.save_state(processed_keys)

            return unprocessed_objects['summaries'] + unprocessed_objects['auditable_events']
        except Exception as e:
            error_message = f"S3 Manager: Error scanning for unprocessed log objects: {e}"
            self.app_logger.error(error_message)
            self.health_reporter.report_error(error_message)
            raise

    def save_state(self, processed_keys):
        state_data = {
            'summaries': {},
            'auditable_events': {}
        }
        for key, timestamp in processed_keys.items():
            log_type = 'auditable_events' if 'auditable_events' in key else 'summaries'
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

    def download_and_extract(self, s3_object, download_folder):
        key = s3_object['Key']
        relative_path = os.path.dirname(key)
        filename = os.path.basename(key).replace('.gz', '')

        # Remove the 'illumio/' prefix from the relative path if it exists
        if relative_path.startswith('illumio/'):
            relative_path = relative_path[len('illumio/'):]

        # Create the destination path, preserving the folder structure
        dest_folder = Path(download_folder) / relative_path
        dest_folder.mkdir(parents=True, exist_ok=True)
        dest_path = dest_folder / filename

        try:
            logger.info(f"Downloading {key}")
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_filename = temp_file.name

            self.s3_client.download_file(self.bucket_name, key, temp_filename)
            
            # Extract the gz file
            with gzip.open(temp_filename, 'rb') as f_in:
                with open(dest_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

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