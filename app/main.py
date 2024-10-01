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
from datetime import datetime, timedelta, timezone
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
processed_keys = {'summaries': {}, 'auditable_events': {}}
stop_event = threading.Event()  # Shared stop_event across modules

def signal_handler(signum, frame):
    logger.info("Received termination signal. Setting stop event.")
    stop_event.set()

def shutdown():
    global executor, log_processor, health_reporter
    logger.info("Initiating shutdown...")

    if executor:
        logger.info("Shutting down ThreadPoolExecutor...")
        executor.shutdown(wait=False)
        for _ in range(5):  # Wait up to 5 seconds for threads to terminate
            if all(not thread.is_alive() for thread in executor._threads):
                break
            time.sleep(1)
        executor._threads.clear()
        logger.info("ThreadPoolExecutor shutdown complete.")

    if log_processor:
        logger.info("Draining log queue...")
        log_processor.drain_queue(stop_event, timeout=5)
        logger.info("Log queue drain attempt completed.")

        logger.info("Closing syslog connection...")
        log_processor.close()
        logger.info("Syslog connection closed.")

    if health_reporter and health_reporter.running:
        health_reporter.stop()
        logger.info("Health reporter stopped.")

    logger.info("Shutdown complete.")

def main():
    global executor, processed_keys, stop_event, log_processor, health_reporter

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

    # Initialize HealthReporter
    health_reporter = HealthReporter(
        heartbeat_interval=config.HEARTBEAT_INTERVAL,
        summary_interval=config.SUMMARY_INTERVAL,
        log_folder=script_dir / config.LOG_FOLDER
    )
    health_reporter.start()

    # Initialize LogProcessor
    log_processor = LogProcessor(
        sma_host=config.SMA_HOST,
        sma_port=config.SMA_PORT,
        max_messages_per_second=config.MAX_MESSAGES_PER_SECOND,
        min_messages_per_second=config.MIN_MESSAGES_PER_SECOND,
        enable_dynamic_syslog_rate=config.ENABLE_DYNAMIC_SYSLOG_RATE,
        beatname=config.BEATNAME,
        use_tcp=config.USE_TCP,
        max_message_length=config.MAX_MESSAGE_LENGTH,
        health_reporter=health_reporter
    )

    # Set log_processor in health_reporter
    health_reporter.set_log_processor(log_processor)

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
        downloaded_files_folder=download_folder
    )

    # Load the previous state
    processed_keys = s3_manager.load_state(state_file)

    # Initialize ThreadPoolExecutor
    executor = ThreadPoolExecutor(max_workers=config.MAX_WORKERS)

    try:
        while not stop_event.is_set():
            logger.debug("Main loop iteration started.")
            try:
                # Check for new logs and process them
                for log_type in ['auditable_events', 'summaries']:
                    if stop_event.is_set():
                        break

                    time_window_start = datetime.now(pytz.UTC) - timedelta(minutes=config.MINUTES)
                    time_window_end = datetime.now(pytz.UTC)

                    new_s3_objects = s3_manager.get_new_s3_objects(
                        log_type, processed_keys[log_type], time_window_start, time_window_end, config.BATCH_SIZE
                    )

                    futures = []
                    for s3_object in new_s3_objects:
                        if stop_event.is_set():
                            break
                        future = executor.submit(
                            handle_log_file_with_retry,
                            s3_object,
                            s3_manager,
                            log_processor,
                            processed_keys,
                            log_type,
                            stop_event
                        )
                        futures.append((future, s3_object, log_type))

                    for future, s3_object, log_type in futures:
                        if stop_event.is_set():
                            future.cancel()
                            continue
                        try:
                            result = future.result(timeout=60)
                            if result:
                                s3_manager.update_and_save_state(processed_keys, log_type, s3_object['Key'])
                                logger.info(f"Successfully processed: {s3_object['Key']}, Type: {log_type}")
                            else:
                                logger.error(f"Failed to process: {s3_object['Key']}, Type: {log_type}")
                        except concurrent.futures.TimeoutError:
                            logger.warning(f"Timeout while processing: {s3_object['Key']}, Type: {log_type}")
                            future.cancel()
                        except Exception as e:
                            logger.exception(f"Exception processing {s3_object['Key']}: {e}")
                            health_reporter.report_error(str(e), log_type)

                if stop_event.is_set():
                    break

            except Exception as e:
                logger.exception(f"Unhandled exception in main loop: {e}")
                health_reporter.report_error(str(e), 'general')
            finally:
                logger.debug("Main loop iteration ended.")
                if not stop_event.is_set():
                    stop_event.wait(timeout=config.POLL_INTERVAL)

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Exiting.")
    finally:
        stop_event.set()
        shutdown()
        logger.info("Application has been terminated.")

def handle_log_file_with_retry(
    s3_object, s3_manager, log_processor,
    processed_keys, log_type, stop_event
):
    if stop_event.is_set():
        return False

    local_file = s3_manager.download_and_extract(s3_object, stop_event)
    if local_file is None:
        return False

    @retry(wait=wait_exponential(min=1, max=5), stop=stop_after_attempt(3))
    def process():
        if stop_event.is_set():
            return False
        logger.debug(f"Starting processing of {s3_object['Key']} for {log_type}")
        start_time = time.time()
        success, logs_extracted = log_processor.process_log_file(local_file, log_type, stop_event)
        end_time = time.time()
        if success:
            processing_duration = end_time - start_time
            logger.info(f"Processed {local_file} in {processing_duration:.2f} seconds")
            health_reporter.report_gz_file_processed(log_type)
            logger.debug(f"Finished processing of {s3_object['Key']} for {log_type}")
            return True
        else:
            raise Exception(f"Failed to process log file {local_file}")

    try:
        return process()
    except Exception as e:
        if not stop_event.is_set():
            logger.error(f"Error processing {s3_object['Key']}: {e}")
            health_reporter.report_error(str(e), log_type)
        return False

if __name__ == '__main__':
    main()