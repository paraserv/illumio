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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from datetime import datetime, timedelta
import logging
import concurrent.futures

# Third-party imports
import pytz
from tenacity import retry, wait_exponential, stop_after_attempt

# Local application imports
from s3_manager import S3Manager
from log_processor import LogProcessor
from logger_config import setup_logging, get_logger
from health_reporter import HealthReporter
from config import Config

# Set up logging
setup_logging()
logger = get_logger('illumio_s3_processor')

# Global variables
executor = None
stop_event = threading.Event()

def signal_handler(signum, frame):
    logger.info("Received termination signal. Initiating shutdown...")
    stop_event.set()

def shutdown(s3_manager, log_processor, health_reporter):
    logger.info("Initiating shutdown...")
    
    if log_processor:
        logger.info("Stopping log queue processing...")
        log_processor.stop_processing()
        logger.info("Log queue processing stopped.")

    if health_reporter:
        health_reporter.stop()
        logger.info("Health reporter stopped.")

    if s3_manager:
        s3_manager.save_state()
        logger.info("S3 Manager state saved.")

    logger.info("Shutdown complete.")

def handle_log_file(s3_object, s3_manager, log_processor, log_type, stop_event, health_reporter):
    local_file, logs_extracted = s3_manager.download_and_extract(s3_object['Key'], stop_event)
    if local_file is None:
        logger.warning(f"Failed to download or extract {s3_object['Key']}")
        return False, 0

    result, logs_processed = log_processor.process_log_file(local_file, log_type, stop_event)
    
    try:
        os.remove(local_file)
    except Exception as e:
        logger.error(f"Error removing temporary file {local_file}: {e}")

    if result:
        health_reporter.report_gz_file_processed(log_type)
        health_reporter.report_logs_extracted(logs_extracted, log_type)

    return result, logs_processed

def monitor_queue(log_processor, config, stop_event):
    while not stop_event.is_set():
        current_queue_size = log_processor.get_queue_size()
        if current_queue_size >= config.QUEUE_SIZE_THRESHOLD:
            logger.warning(f"Queue size ({current_queue_size}) exceeded threshold ({config.QUEUE_SIZE_THRESHOLD})")
        time.sleep(config.QUEUE_MONITOR_INTERVAL)

def update_health_reporter_s3_stats(s3_manager, health_reporter, stop_event):
    while not stop_event.is_set():
        stats = s3_manager.update_s3_stats()
        health_reporter.update_s3_stats(stats)
        time.sleep(60)  # Update every minute

def main():
    global executor

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Load configuration
    config = Config()

    script_dir = Path(__file__).parent
    state_file = script_dir / config.STATE_FILE

    # Ensure the downloaded files folder exists
    download_folder = script_dir / config.DOWNLOADED_FILES_FOLDER
    download_folder.mkdir(parents=True, exist_ok=True)
    logger.info(f"Ensuring download folder exists: {download_folder}")

    # Ensure the log folder exists
    log_folder = Path(config.LOG_FOLDER)
    log_folder.mkdir(parents=True, exist_ok=True)
    logger.info(f"Ensuring log folder exists: {log_folder}")

    # Ensure the health report log file directory exists
    health_report_log_dir = os.path.dirname(config.HEALTH_REPORT_LOG_FILE)
    os.makedirs(health_report_log_dir, exist_ok=True)

    # Initialize HealthReporter
    health_reporter = HealthReporter(config)
    health_reporter.start()

    # Initialize LogProcessor
    log_processor = LogProcessor(config, health_reporter)

    # Initialize S3Manager
    s3_manager = S3Manager(
        aws_access_key_id=config.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
        s3_bucket_name=config.S3_BUCKET_NAME,
        minutes=config.MINUTES,
        max_files_per_folder=config.MAX_FILES_PER_FOLDER,
        health_reporter=health_reporter,
        max_pool_connections=config.MAX_POOL_CONNECTIONS,
        state_file=state_file,
        downloaded_files_folder=download_folder,
        config=config
    )

    # Initialize ThreadPoolExecutor
    executor = ThreadPoolExecutor(max_workers=config.MAX_WORKERS)

    queue_monitor_thread = threading.Thread(target=monitor_queue, args=(log_processor, config, stop_event))
    queue_monitor_thread.start()

    s3_stats_thread = threading.Thread(target=update_health_reporter_s3_stats, args=(s3_manager, health_reporter, stop_event))
    s3_stats_thread.start()

    last_stats_log = time.time()
    last_detailed_report_time = time.time()
    last_mps_log_time = time.time()

    try:
        while not stop_event.is_set():
            current_queue_size = log_processor.get_queue_size()
            if current_queue_size >= config.QUEUE_SIZE_THRESHOLD:
                logger.warning(f"Queue size ({current_queue_size}) exceeded threshold ({config.QUEUE_SIZE_THRESHOLD}). Pausing download and extraction.")
                time.sleep(config.POLL_INTERVAL)
                log_processor._process_queue()  # Changed from process_queue to _process_queue
                continue

            for log_type in ['auditable_events', 'summaries']:
                if stop_event.is_set():
                    break

                time_window_start = datetime.now(pytz.UTC) - timedelta(hours=config.TIME_WINDOW_HOURS)
                time_window_end = datetime.now(pytz.UTC)

                logger.info(f"Fetching new S3 objects for {log_type} from {time_window_start} to {time_window_end}")
                new_s3_objects = s3_manager.get_new_s3_objects(
                    log_type, time_window_start, time_window_end, config.BATCH_SIZE, current_queue_size
                )

                if not new_s3_objects:
                    logger.info(f"No new {log_type} objects to process or queue is full. Skipping.")
                    continue

                logger.info(f"Processing {len(new_s3_objects)} new {log_type} objects")
                for s3_object in new_s3_objects:
                    logger.info(f"Processing S3 object: {s3_object['Key']}")
                    result, logs_extracted = handle_log_file(s3_object, s3_manager, log_processor, log_type, stop_event, health_reporter)
                    if result:
                        s3_manager.update_and_save_state(log_type, s3_object)
                        logger.info(f"Successfully processed: {s3_object['Key']}, Type: {log_type}, Logs extracted: {logs_extracted}, Current MPS: {log_processor.current_mps:.2f}")
                    else:
                        logger.warning(f"Failed to process: {s3_object['Key']}, Type: {log_type}, Logs extracted: {logs_extracted}")

                # Process the queue after each batch to maintain balance
                log_processor._process_queue()  # Changed from process_queue to _process_queue

            # Log queue stats every 60 seconds
            if time.time() - last_stats_log > 60:
                log_processor.log_queue_stats()
                last_stats_log = time.time()

            # Generate detailed report periodically
            if time.time() - last_detailed_report_time > config.DETAILED_REPORT_INTERVAL:
                health_reporter.generate_detailed_report()
                last_detailed_report_time = time.time()

            # Log MPS every 5 minutes
            if time.time() - last_mps_log_time > 300:
                logger.info(f"[MPS_SUMMARY] Current MPS: {log_processor.current_mps:.2f}, Max MPS: {log_processor.max_messages_per_second}, Min MPS: {log_processor.min_messages_per_second}")
                last_mps_log_time = time.time()

            # Sleep for a short interval to prevent tight looping
            time.sleep(1)

    except Exception as e:
        logger.exception(f"Unhandled exception in main loop: {e}")
    finally:
        shutdown(s3_manager, log_processor, health_reporter)
        logger.info("Application has been terminated.")

if __name__ == '__main__':
    main()