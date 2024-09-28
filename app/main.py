#!/usr/bin/env python3
"""
Main entry point for processing Illumio S3 logs and sending them to the SIEM.
"""

# Standard library imports
import os
import sys
import threading
import json
import time
import signal
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from datetime import datetime, timedelta

# Third-party imports
import psutil
import pytz
from botocore.config import Config as BotoCoreConfig
from tenacity import retry, wait_exponential, stop_after_attempt

# Local application imports
from s3_manager import S3Manager
from log_processor import LogProcessor
from logger_config import setup_logging, get_logger
from health_reporter import HealthReporter
from config import Config

# Set up logging
setup_logging()

# Get the logger for this module with a more descriptive name
logger = get_logger('illumio_s3_processor')

# Global variables
executor = None
processed_keys = {'summaries': {}, 'auditable_events': {}}
state_file = None
config = None
already_processed_files = set()
stop_event = threading.Event()
log_processor = None  # Declare log_processor globally
health_reporter = None  # Declare health_reporter globally

def signal_handler(signum, frame):
    logger.info("Received termination signal. Finishing current tasks...")
    stop_event.set()
    # Wait for a short period to allow current processing to complete
    time.sleep(5)
    shutdown(processed_keys)
    sys.exit(0)

def shutdown(processed_keys):
    global executor, state_file, log_processor, health_reporter
    logger.info("Initiating shutdown...")

    try:
        if executor:
            logger.info("Shutting down ThreadPoolExecutor...")
            executor.shutdown(wait=False, cancel_futures=True)
            logger.info("ThreadPoolExecutor shutdown initiated.")

        if log_processor:
            logger.info("Closing syslog connection...")
            log_processor.close()
            logger.info("Syslog connection closed.")

        # Update counts in health_reporter
        if health_reporter:
            health_reporter.state_summaries_count = len(processed_keys['summaries'])
            health_reporter.state_auditable_events_count = len(processed_keys['auditable_events'])

            # Now stop the health_reporter
            if health_reporter.running:
                health_reporter.stop()

        logger.info("Shutdown complete.")
    except Exception as e:
        logger.error(f"Exception during shutdown: {e}")

def load_state(state_file):
    processed_keys = {'summaries': {}, 'auditable_events': {}}
    if state_file.exists():
        with open(state_file, 'r') as f:
            state_data = json.load(f)
        for log_type in ['summaries', 'auditable_events']:
            for k, v in state_data.get(log_type, {}).items():
                try:
                    processed_keys[log_type][k] = datetime.fromisoformat(v)
                except (TypeError, ValueError):
                    logger.warning(f"Invalid datetime format for key {k}: {v}. Skipping this entry.")
        summaries_count = len(processed_keys['summaries'])
        auditable_events_count = len(processed_keys['auditable_events'])
        logger.info(f"Loaded state: Summaries: {summaries_count}, Auditable Events: {auditable_events_count}")
    else:
        logger.info("No state file found. Starting from scratch.")
    return processed_keys

def handle_log_file_with_retry(
    s3_object, s3_manager, log_processor, processed_keys,
    processed_keys_lock, health_reporter, log_type, stop_event
):
    @retry(wait=wait_exponential(min=1, max=10), stop=stop_after_attempt(5))
    def process():
        if stop_event.is_set():
            return False
        # Download and extract the log file
        local_file = s3_manager.download_and_extract(s3_object, stop_event)
        if not local_file:
            raise Exception(f"Failed to download and extract {s3_object['Key']}")
        # Process the log file
        success, log_count = log_processor.process_log_file(local_file, log_type, stop_event)
        if not success:
            raise Exception(f"Failed to process log file {local_file}")
        # Report processed counts to health_reporter
        health_reporter.report_gz_file_processed(log_type)
        return True

    try:
        return process()
    except Exception as e:
        logger.error(f"Error processing {s3_object['Key']}: {e}")
        health_reporter.report_error(str(e), log_type)
        return False

def adjust_batch_size(current_batch_size, processing_time, min_batch_size, max_batch_size):
    # Simple logic to adjust batch size based on processing time
    desired_processing_time_per_batch = 60  # seconds
    if processing_time > desired_processing_time_per_batch:
        new_batch_size = max(min_batch_size, current_batch_size // 2)
    else:
        new_batch_size = min(max_batch_size, current_batch_size + 10)
    return new_batch_size

def adjust_max_workers(current_workers, min_workers, max_workers):
    # Simple logic to adjust the number of workers
    cpu_utilization = psutil.cpu_percent()
    if cpu_utilization > 80:
        new_workers = max(min_workers, current_workers - 1)
    elif cpu_utilization < 50:
        new_workers = min(max_workers, current_workers + 1)
    else:
        new_workers = current_workers
    return new_workers

def cleanup_downloaded_files(download_folder):
    # Remove files older than a certain age
    file_retention_time = timedelta(hours=1)
    now = datetime.now()
    for file in download_folder.glob('*'):
        if file.is_file():
            file_modified_time = datetime.fromtimestamp(file.stat().st_mtime)
            if now - file_modified_time > file_retention_time:
                file.unlink()
                logger.info(f"Deleted old file: {file}")

def main():
    global executor, processed_keys, state_file, config, log_processor, health_reporter
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    health_reporter = None  # Initialize health_reporter
    try:
        config = Config()

        # Use the STATE_FILE path directly from config
        state_file = config.STATE_FILE

        # Initialize HealthReporter
        health_reporter = HealthReporter(
            config.HEARTBEAT_INTERVAL,
            config.SUMMARY_INTERVAL,
            log_folder=config.LOG_FOLDER  # Pass the log folder
        )
        health_reporter.start()

        # Load state from the state file if it exists
        processed_keys = load_state(state_file)

        # Initialize LogProcessor
        log_processor = LogProcessor(
            config.SMA_HOST,
            config.SMA_PORT,
            config.MAX_MESSAGES_PER_SECOND,
            config.MIN_MESSAGES_PER_SECOND,
            config.ENABLE_DYNAMIC_SYSLOG_RATE,
            config.BEATNAME,
            config.USE_TCP,
            config.MAX_MESSAGE_LENGTH,
            health_reporter
        )

        executor = ThreadPoolExecutor(max_workers=config.MAX_WORKERS)

        if not config.AWS_ACCESS_KEY_ID or not config.AWS_SECRET_ACCESS_KEY or not config.S3_BUCKET_NAME:
            logger.error("AWS credentials or S3 bucket name are not set.")
            sys.exit(1)

        # Ensure directories exist
        config.DOWNLOADED_FILES_FOLDER.mkdir(parents=True, exist_ok=True)
        config.LOG_FOLDER.mkdir(parents=True, exist_ok=True)

        # Initialize S3Manager
        boto_config = BotoCoreConfig(
            max_pool_connections=config.MAX_POOL_CONNECTIONS,
            retries={'max_attempts': 3, 'mode': 'standard'}
        )
        s3_manager = S3Manager(
            aws_access_key_id=config.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
            bucket_name=config.S3_BUCKET_NAME,
            log_timeframe=config.LOG_TIMEFRAME,
            base_paths=config.BASE_PATHS,
            enable_dynamic_timeframe=config.ENABLE_DYNAMIC_TIMEFRAME,
            health_reporter=health_reporter,
            max_pool_connections=config.MAX_POOL_CONNECTIONS,
            boto_config=boto_config,
            state_file=config.STATE_FILE,  # Pass the correct state_file path
            downloaded_files_folder=config.DOWNLOADED_FILES_FOLDER  # Pass the downloaded files folder
        )

        processed_keys_lock = threading.Lock()

        ADJUSTMENT_INTERVAL = 60  # seconds
        last_adjustment_time = time.time()

        baseline_period = config.BASELINE_PERIOD  # Fetch baseline period from config
        baseline_start_time = time.time()

        while not stop_event.is_set():
            try:
                current_time = time.time()
                if current_time - baseline_start_time < baseline_period:
                    logger.info(f"In baseline period. {baseline_period - (current_time - baseline_start_time):.0f} seconds remaining.")
                else:
                    if not globals().get('baseline_ended', False):
                        logger.info("Baseline period ended. Starting normal operation with adjustments.")
                        globals()['baseline_ended'] = True

                start_time = time.time()
                total_processed = 0

                # Before starting new tasks
                if stop_event.is_set():
                    break

                # Process log types
                for log_type in ['auditable_events', 'summaries']:
                    logger.info(f"Checking for new {log_type} logs...")
                    new_objects = s3_manager.get_new_s3_objects(
                        log_type,
                        processed_keys,
                        datetime.now(pytz.UTC) - timedelta(hours=config.TIME_WINDOW_HOURS),
                        datetime.now(pytz.UTC),
                        config.BATCH_SIZE
                    )

                    if new_objects:
                        logger.info(f"Found {len(new_objects)} new {log_type} log files.")
                        processed_count = 0
                        futures = []

                        for s3_object in new_objects:
                            if stop_event.is_set():
                                break  # Exit if stop_event is set
                            future = executor.submit(
                                handle_log_file_with_retry,
                                s3_object, s3_manager, log_processor, processed_keys,
                                processed_keys_lock, health_reporter, log_type, stop_event
                            )
                            futures.append((future, s3_object, log_type))

                        # Wait for all futures to complete or stop if stop_event is set
                        for future, s3_object, log_type in futures:
                            if stop_event.is_set():
                                break
                            try:
                                result = future.result()
                                if result:
                                    with processed_keys_lock:
                                        processed_keys[log_type][s3_object['Key']] = datetime.now(pytz.UTC)
                                    processed_count += 1
                                    logger.info(f"Successfully processed: {s3_object['Key']}, Type: {log_type}")
                                else:
                                    logger.error(f"Failed to process: {s3_object['Key']}, Type: {log_type}")
                            except Exception as e:
                                logger.error(f"Error processing {s3_object['Key']}: {str(e)}")
                                health_reporter.report_error(f"Error processing {s3_object['Key']}: {str(e)}", log_type)

                        # After processing each log type, save the state
                        s3_manager.save_state(processed_keys)

                        logger.info(f"Processed {processed_count} {log_type} log files.")
                        total_processed += processed_count
                    else:
                        logger.info(f"No new {log_type} logs found.")

                processing_time = time.time() - start_time
                if total_processed > 0 and processing_time > 0:
                    processing_rate = total_processed / processing_time * 3600  # logs per hour
                else:
                    processing_rate = 0

                if current_time - baseline_start_time >= baseline_period and total_processed > 0:
                    # Only perform adjustments after the baseline period
                    if config.ENABLE_DYNAMIC_BATCH_SIZE:
                        new_batch_size = adjust_batch_size(config.BATCH_SIZE, processing_time, config.MIN_BATCH_SIZE, config.MAX_BATCH_SIZE)
                        if new_batch_size != config.BATCH_SIZE:
                            message = f"Batch size adjusted: {config.BATCH_SIZE} -> {new_batch_size}"
                            logger.info(message)
                            health_reporter.log_adjustment(message)
                            config.BATCH_SIZE = new_batch_size

                    if config.ENABLE_DYNAMIC_WORKERS:
                        new_max_workers = adjust_max_workers(executor._max_workers, config.MIN_WORKERS, config.MAX_WORKERS)
                        if new_max_workers != executor._max_workers:
                            message = f"Max workers adjusted: {executor._max_workers} -> {new_max_workers}"
                            logger.info(message)
                            health_reporter.log_adjustment(message)
                            executor._max_workers = new_max_workers

                    logger.info(f"Processed {total_processed} log files at a rate of {processing_rate:.2f} logs/hour.")
                    health_reporter.log_message(f"Processing rate: {processing_rate:.2f} logs/hour")
                    
                    last_adjustment_time = current_time

                if stop_event.is_set():
                    break

                # Responsive sleep
                sleep_time = config.POLL_INTERVAL
                sleep_increment = 1  # Check every 1 second
                while sleep_time > 0 and not stop_event.is_set():
                    time.sleep(min(sleep_increment, sleep_time))
                    sleep_time -= sleep_increment

                cleanup_downloaded_files(config.DOWNLOADED_FILES_FOLDER)

            except Exception as e:
                logger.exception(f"Unhandled exception in main loop: {e}")
                health_reporter.report_error(str(e), 'general')
                stop_event.set()  # Exit the loop on exception

    except Exception as e:
        logger.exception(f"Unhandled exception in main: {e}")
        if health_reporter:
            health_reporter.report_error(str(e), 'general')
    finally:
        shutdown(processed_keys)
        logger.info("Script has been terminated.")

if __name__ == '__main__':
    main()