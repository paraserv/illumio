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
from contextlib import contextmanager
import logging
import traceback

# Third-party imports
import boto3
import pytz
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, ConnectionError, NoCredentialsError, EndpointConnectionError
from tenacity import retry, stop_after_attempt, wait_exponential

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
        max_files_per_folder,
        health_reporter,
        max_pool_connections,
        state_file,
        config,
        stop_event
    ):
        self.config = config  # Store the config object as an instance attribute
        self.s3_bucket_name = s3_bucket_name
        self.max_files_per_folder = max_files_per_folder
        self.health_reporter = health_reporter
        self.state_file = Path(state_file)
        self.processed_keys = {log_type: {} for log_type in config.LOG_TYPES}
        self.load_state()

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
        self.downloaded_files_folder = config.DOWNLOADS_DIR
        self.downloaded_files_folder.mkdir(parents=True, exist_ok=True)

        self.time_window_hours = config.TIME_WINDOW_HOURS
        logger.info(f"S3Manager initialized with TIME_WINDOW_HOURS: {self.time_window_hours}")

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

        self.MAX_FILES_PER_FOLDER = max_files_per_folder
        self.stop_event = stop_event

        logger.info(f"Processing S3 logs with settings: TIME_WINDOW_HOURS={self.time_window_hours}, MAX_FILES_PER_FOLDER={self.MAX_FILES_PER_FOLDER}")

        self.current_operation = None
        self.shutdown_event = threading.Event()

    @contextmanager
    def s3_operation(self, operation_name):
        self.current_operation = operation_name
        start_time = time.time()
        try:
            yield
        finally:
            duration = time.time() - start_time
            logger.info(f"S3 operation '{operation_name}' completed in {duration:.2f} seconds")
            self.current_operation = None
            self.shutdown_event.set()  # Signal that the operation is complete

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    def _s3_operation_with_retry(self, operation, *args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except (ClientError, ConnectionError) as e:
            logger.warning(f"S3 operation failed: {e}. Retrying...")
            raise

    def update_ingestion_rate(self, new_logs_count):
        current_time = time.time()
        time_diff = current_time - self.last_ingestion_time
        if time_diff > 0:
            self.current_ingestion_rate = (new_logs_count - self.last_ingestion_count) / time_diff
            self.last_ingestion_time = current_time
            self.last_ingestion_count = new_logs_count
        return self.current_ingestion_rate

    def get_new_s3_objects(
        self,
        log_type: str,
        time_window_start: datetime,
        time_window_end: datetime,
        batch_size: int,
        current_queue_size: int
    ):
        new_objects = []
        total_size = 0
        skipped_objects = 0

        # Check if the current queue size exceeds the threshold
        if current_queue_size >= self.queue_size_threshold:
            logger.info(
                f"Current queue size ({current_queue_size}) exceeds threshold ({self.queue_size_threshold}). "
                f"Pausing S3 object retrieval for {log_type}."
            )
            return new_objects  # Return empty list to pause retrieval

        try:
            paginator = self.s3.get_paginator('list_objects_v2')
            prefix = f"illumio/{log_type}/"
            logger.info(f"Searching for {log_type} objects with prefix: {prefix}")

            # Generate date-based prefixes for the time window
            date_range = (time_window_end.date() - time_window_start.date()).days
            date_prefixes = [
                f"{prefix}{(time_window_start + timedelta(days=i)).strftime('%Y%m%d')}"
                for i in range(date_range + 1)
            ]

            skipped_files = 0
            for date_prefix in date_prefixes:
                if self.stop_event.is_set():
                    logger.info("Stop event set. Interrupting S3 object listing.")
                    break

                for page in paginator.paginate(Bucket=self.s3_bucket_name, Prefix=date_prefix):
                    if 'Contents' in page:
                        for obj in page['Contents']:
                            if self.stop_event.is_set():
                                logger.info("Stop event set. Interrupting S3 object listing.")
                                break

                            if obj['Key'].endswith('.gz'):
                                self.s3_stats['files_discovered'] += 1
                                obj_last_modified = obj['LastModified'].replace(tzinfo=pytz.UTC)
                                if obj['Key'] in self.processed_keys[log_type]:
                                    logger.debug(f"Skipping already processed object: {obj['Key']}")
                                    skipped_objects += 1
                                    skipped_files += 1
                                elif time_window_start <= obj_last_modified <= time_window_end:
                                    new_objects.append(obj)
                                    total_size += obj['Size']
                                    logger.debug(f"Adding new object: {obj['Key']}, Size: {obj['Size']} bytes")

                                    if len(new_objects) >= batch_size:
                                        logger.info(f"Reached batch size limit of {batch_size} for {log_type}")
                                        break
                                else:
                                    logger.debug(f"Skipping object outside time window: {obj['Key']}, Last Modified: {obj_last_modified}")
                                    skipped_objects += 1
                    else:
                        logger.debug(f"No contents found for prefix {date_prefix}")

                    if len(new_objects) >= batch_size:
                        break

                if len(new_objects) >= batch_size:
                    break

            logger.info(
                f"Found {len(new_objects)} new objects for {log_type}. "
                f"Total size: {total_size / 1024:.2f} KB. "
                f"Skipped {skipped_files} S3 files as previously processed."
            )

        except NoCredentialsError:
            logger.error("AWS credentials not found. Please configure your AWS credentials.")
            self.stop_event.set()
        except ClientError as e:
            logger.error(f"An AWS client error occurred: {e}")
            self.stop_event.set()
        except EndpointConnectionError as e:
            logger.error(f"Endpoint connection error occurred: {e}")
            self.stop_event.set()
        except Exception as e:
            logger.error(f"An unexpected error occurred while listing S3 objects: {e}")
            logger.debug(traceback.format_exc())
            self.stop_event.set()
        return new_objects

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
            old_timeframe = self.time_window_hours * 3600  # Use time_window_hours instead of log_timeframe
            self.time_window_hours = max(min(ideal_timeframe, self.MAX_TIMEFRAME * 3600), self.MIN_TIMEFRAME * 3600) / 3600
            
            message = (f"S3 Manager: Log timeframe adjusted: {old_timeframe/60:.2f} min -> {self.time_window_hours*60:.2f} min. "
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

    def download_and_extract(self, key: str, stop_event: threading.Event):
        try:
            if stop_event.is_set():
                logger.info(f"Stop event set. Skipping download of {key}")
                return None, 0

            s3_object = self.s3.get_object(Bucket=self.s3_bucket_name, Key=key)
            log_type = 'summaries' if 'summaries' in key else 'auditable_events'

            # Save files in the existing 'state/downloads' directory without changing the structure
            local_dir = self.downloaded_files_folder / log_type
            local_dir.mkdir(parents=True, exist_ok=True)
            local_file_path = local_dir / Path(key).name.replace('.gz', '')

            with open(local_file_path, 'wb') as f_out:
                with gzip.GzipFile(fileobj=s3_object['Body']) as gz:
                    shutil.copyfileobj(gz, f_out)

            total_lines = 0
            valid_json_lines = 0
            with open(local_file_path, 'r') as f:
                for line in f:
                    total_lines += 1
                    try:
                        json.loads(line)
                        valid_json_lines += 1
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON in file {key} at line {total_lines}")

            if self.config.RETAIN_DOWNLOADED_LOGS:
                logger.info(f"Extracted file saved at: {local_file_path}")
            else:
                logger.info(f"Extracted file temporarily saved at: {local_file_path}")

            logger.info(
                f"Downloaded and extracted {key}. Size: {s3_object['ContentLength']} bytes, "
                f"Total lines: {total_lines}, Valid JSON lines: {valid_json_lines}"
            )

            self.s3_stats['files_downloaded'] += 1
            self.s3_stats['logs_extracted'] += valid_json_lines

            return str(local_file_path), valid_json_lines

        except ClientError as e:
            logger.error(f"AWS Error downloading {key}: {e}")
            return None, 0
        except Exception as e:
            logger.error(f"Error downloading or extracting {key}: {e}")
            logger.debug(traceback.format_exc())
            return None, 0

    def update_and_save_state(self, log_type: str, s3_object):
        self.processed_keys[log_type][s3_object['Key']] = datetime.now(pytz.UTC).isoformat()
        self.s3_stats['files_processed'] += 1
        self.save_state()

    def load_state(self):
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    self.processed_keys = json.load(f)
                logger.info(
                    f"Loaded state from {self.state_file}: "
                    f"Auditable Events: {len(self.processed_keys.get('auditable_events', {}))}, "
                    f"Summaries: {len(self.processed_keys.get('summaries', {}))}"
                )
            except Exception as e:
                logger.error(f"Failed to load state file {self.state_file}: {e}")
                self.processed_keys = {log_type: {} for log_type in self.config.LOG_TYPES}
        else:
            logger.info(f"No existing state file found at {self.state_file}. Starting fresh.")
            self.processed_keys = {log_type: {} for log_type in self.config.LOG_TYPES}

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
            self.last_stats_update = current_time
        return self.s3_stats.copy()

    def stop(self):
        logger.info("Stopping S3 Manager...")
        self.stop_event.set()
        if hasattr(self.s3, 'close'):
            self.s3.close()
        logger.info("S3 Manager stopped.")

    def cleanup_downloaded_file(self, file_path):
        if not self.config.RETAIN_DOWNLOADED_LOGS:
            try:
                os.remove(file_path)
                logger.info(f"Cleaned up downloaded file: {file_path}")
            except Exception as e:
                logger.error(f"Failed to clean up file {file_path}: {e}")