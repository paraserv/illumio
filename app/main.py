# app/main.py

import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from dotenv import load_dotenv
import configparser
import json
import time
from datetime import datetime, timedelta
import signal
from tenacity import retry, stop_after_attempt, wait_exponential
import shutil
import psutil
from botocore.exceptions import ClientError
from botocore.config import Config as BotoCoreConfig
import concurrent.futures
import pytz

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
BATCH_SIZE = None
checkpoint_file = None
already_processed_files = set()
stop_event = threading.Event()
log_processor = None  # Declare log_processor globally
health_reporter = None  # Declare health_reporter globally

def signal_handler(signum, frame):
    logger.info("Received termination signal. Cleaning up...")
    if health_reporter:
        health_reporter.log_termination_signal_received()
    stop_event.set()  # Signal to stop

def shutdown(processed_keys, already_processed_files):
    global executor, state_file, checkpoint_file, log_processor, health_reporter
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

        # Initialize counts
        summaries_state_count = len(processed_keys['summaries'])
        auditable_events_state_count = len(processed_keys['auditable_events'])
        summaries_checkpoint_count = len([f for f in already_processed_files if 'summaries' in f])
        auditable_events_checkpoint_count = len([f for f in already_processed_files if 'auditable_events' in f])

        # Update counts in health_reporter
        if health_reporter:
            health_reporter.state_summaries_count = summaries_state_count
            health_reporter.state_auditable_events_count = auditable_events_state_count
            health_reporter.checkpoint_summaries_count = summaries_checkpoint_count
            health_reporter.checkpoint_auditable_events_count = auditable_events_checkpoint_count

            # Now stop the health_reporter
            if health_reporter.running:
                health_reporter.stop()

        logger.info("Shutdown complete.")
    except Exception as e:
        logger.error(f"Exception during shutdown: {e}")

def save_state(processed_keys, state_file):
    state_data = {
        'summaries': {},
        'auditable_events': {}
    }
    for log_type in ['summaries', 'auditable_events']:
        for key, timestamp in processed_keys[log_type].items():
            state_data[log_type][key] = timestamp.isoformat()

    with open(state_file, 'w') as f:
        json.dump(state_data, f)
    summaries_count = len(state_data['summaries'])
    auditable_events_count = len(state_data['auditable_events'])
    logger.info(f"Saved state: Summaries: {summaries_count}, Auditable Events: {auditable_events_count}")
    # Removed the call to health_reporter.log_saved_state() with arguments
    # if health_reporter:
    #     health_reporter.log_saved_state(summaries_count, auditable_events_count)

def save_checkpoint(already_processed_files, checkpoint_file):
    checkpoint_data = {
        'summaries': [f for f in already_processed_files if 'summaries' in f],
        'auditable_events': [f for f in already_processed_files if 'auditable_events' in f]
    }
    with open(checkpoint_file, 'w') as f:
        json.dump(checkpoint_data, f)
    summaries_count = len(checkpoint_data['summaries'])
    auditable_events_count = len(checkpoint_data['auditable_events'])
    logger.info(f"Saved checkpoint: {summaries_count} summary files, {auditable_events_count} auditable event files")
    # Removed the call to health_reporter.log_saved_checkpoint() with arguments
    # if health_reporter:
    #     health_reporter.log_saved_checkpoint(summaries_count, auditable_events_count)

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

def load_checkpoint(checkpoint_file):
    if checkpoint_file.exists():
        with open(checkpoint_file, 'r') as f:
            checkpoint_data = json.load(f)
        summary_files = set(checkpoint_data.get('summaries', []))
        auditable_files = set(checkpoint_data.get('auditable_events', []))
        logger.info(f"Loaded checkpoint: {len(summary_files)} summary files, {len(auditable_files)} auditable event files")
        return summary_files.union(auditable_files)
    logger.info("No checkpoint file found.")
    return set()

def get_files_for_batch(batch_id):
    global new_objects, BATCH_SIZE
    if BATCH_SIZE is None:
        logger.error("BATCH_SIZE is not initialized")
        return set()
    start_index = batch_id * BATCH_SIZE
    end_index = start_index + BATCH_SIZE
    batch_files = new_objects[start_index:end_index] if start_index < len(new_objects) else []
    return set(obj['Key'] for obj in batch_files)

def recover_from_unexpected_stop(downloaded_files_folder, checkpoint_file, state_file):
    global processed_keys
    logger.info("Starting recovery process from last stop...")
    
    cleanup_downloaded_files(downloaded_files_folder, max_age_hours=1)
    
    already_processed_files = load_checkpoint(checkpoint_file)
    
    if state_file.exists():
        with open(state_file, 'r') as f:
            state_data = json.load(f)
        processed_keys = {k: datetime.fromisoformat(v) for k, v in state_data.items()}
        logger.info(f"Loaded {len(processed_keys)} processed keys from state file")
    else:
        processed_keys = {}
        logger.info("No state file found. Starting from scratch.")

    return already_processed_files

def read_state_file(state_file):
    if state_file.exists():
        with open(state_file, 'r') as f:
            state_data = json.load(f)
        summaries_count = len(state_data.get('summaries', {}))
        auditable_events_count = len(state_data.get('auditable_events', {}))
        return summaries_count, auditable_events_count
    else:
        return 0, 0

def read_checkpoint_file(checkpoint_file):
    if checkpoint_file.exists():
        with open(checkpoint_file, 'r') as f:
            checkpoint_data = json.load(f)
        summaries_count = len(checkpoint_data.get('summaries', []))
        auditable_events_count = len(checkpoint_data.get('auditable_events', []))
        return summaries_count, auditable_events_count
    else:
        return 0, 0

def main():
    global executor, processed_keys, state_file, config, BATCH_SIZE, checkpoint_file, already_processed_files, log_processor, health_reporter
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    health_reporter = None  # Initialize health_reporter
    try:
        config = Config()

        # Initialize state_file and checkpoint_file paths only once
        state_file = config.BASE_FOLDER / config.STATE_FILE
        checkpoint_file = config.BASE_FOLDER / config.CHECKPOINT_FILE

        # Initialize HealthReporter
        health_reporter = HealthReporter(config.HEARTBEAT_INTERVAL, config.SUMMARY_INTERVAL)
        health_reporter.start()

        # Read counts from state.json and checkpoint.json
        state_summaries_count, state_auditable_events_count = read_state_file(state_file)
        checkpoint_summaries_count, checkpoint_auditable_events_count = read_checkpoint_file(checkpoint_file)

        # Log recovered state to health report
        health_reporter.log_recovered_state(
            state_summaries_count, state_auditable_events_count,
            checkpoint_summaries_count, checkpoint_auditable_events_count
        )

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

        # Initialize processed_keys for both summaries and auditable_events
        processed_keys = {'summaries': {}, 'auditable_events': {}}
        already_processed_files = set()

        # Explicitly create state and checkpoint files if they don't exist
        if not state_file.exists():
            save_state(processed_keys, state_file)  # Pass initialized processed_keys
            logger.info(f"Created new state file: {state_file}")
        if not checkpoint_file.exists():
            save_checkpoint(already_processed_files, checkpoint_file)
            logger.info(f"Created new checkpoint file: {checkpoint_file}")

        # Load state from the state file
        processed_keys = load_state(state_file)

        # Load checkpoint from the checkpoint file
        already_processed_files = load_checkpoint(checkpoint_file)

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
            state_file=state_file,
            checkpoint_file=checkpoint_file
        )

        processed_keys_lock = threading.Lock()

        ADJUSTMENT_INTERVAL = 60  # seconds
        last_adjustment_time = time.time()

        baseline_period = 300  # 5 minutes
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
                                s3_object, s3_manager, log_processor, config.DOWNLOADED_FILES_FOLDER,
                                processed_keys, processed_keys_lock, health_reporter, log_type, already_processed_files, stop_event
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
                                    # Add the processed file to the already_processed_files set
                                    with processed_keys_lock:
                                        already_processed_files.add(s3_object['Key'])
                                else:
                                    logger.error(f"Failed to process: {s3_object['Key']}, Type: {log_type}")
                            except Exception as e:
                                logger.error(f"Error processing {s3_object['Key']}: {str(e)}")
                                health_reporter.report_error(f"Error processing {s3_object['Key']}: {str(e)}", log_type)

                        # Save state and checkpoint after processing each log type
                        s3_manager.save_state(processed_keys)
                        save_checkpoint(already_processed_files, checkpoint_file)

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
        shutdown(processed_keys, already_processed_files)
        logger.info("Script has been terminated.")

def handle_log_file_with_retry(s3_object, s3_manager, log_processor, downloaded_files_folder,
                               processed_keys, processed_keys_lock, health_reporter, log_type,
                               already_processed_files, stop_event):
    logger.info(f"Handling log file: {s3_object['Key']}, Type: {log_type}")
    if s3_object['Key'] in processed_keys[log_type]:
        logger.info(f"Skipping already processed file: {s3_object['Key']}")
        return True

    try:
        # Check stop_event before processing
        if stop_event.is_set():
            logger.info(f"Stopping processing of {s3_object['Key']} due to shutdown signal.")
            return False

        dest_path = s3_manager.download_and_extract(s3_object, downloaded_files_folder, stop_event)
        if dest_path:
            logger.info(f"Successfully downloaded and extracted: {dest_path}")
            health_reporter.report_gz_file_processed(log_type)
            success, logs_count = log_processor.process_log_file(dest_path, log_type, stop_event)
            if success:
                dest_path.unlink()
                logger.info(f"Successfully processed and deleted: {dest_path}")
                with processed_keys_lock:
                    processed_keys[log_type][s3_object['Key']] = datetime.now(pytz.UTC)
                    already_processed_files.add(s3_object['Key'])
                logger.info(f"Added {s3_object['Key']} to processed keys")
                health_reporter.report_logs_extracted(logs_count, log_type)
                health_reporter.report_syslog_sent(logs_count, log_type)
                return True
            else:
                logger.error(f"Failed to process log file: {dest_path}")
        else:
            logger.error(f"Failed to download or extract: {s3_object['Key']}")
    except Exception as e:
        logger.error(f"Error handling log file {s3_object['Key']}: {e}")
        health_reporter.report_error(f"Error processing {s3_object['Key']}: {str(e)}", log_type)
    
    return False

def adjust_batch_size(current_batch_size, processing_time, min_batch_size, max_batch_size, target_time=30):
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    
    if processing_time < target_time and cpu_usage < 70 and memory_usage < 80:
        return min(current_batch_size * 1.5, max_batch_size)
    elif processing_time > target_time or cpu_usage > 90 or memory_usage > 90:
        return max(current_batch_size * 0.75, min_batch_size)
    return current_batch_size

def adjust_max_workers(current_workers, min_workers, max_workers):
    cpu_count = psutil.cpu_count()
    memory_available = psutil.virtual_memory().available / (1024 * 1024 * 1024)
    
    if memory_available > 4 and cpu_count > current_workers:
        return min(current_workers + 1, max_workers)
    elif memory_available < 2 or psutil.cpu_percent() > 80:
        return max(current_workers - 1, min_workers)
    return current_workers

def cleanup_downloaded_files(folder: Path, max_age_hours: int = 24):
    current_time = datetime.now()
    for file in folder.glob('**/*'):
        if file.is_file():
            file_age = current_time - datetime.fromtimestamp(file.stat().st_mtime)
            if file_age > timedelta(hours=max_age_hours):
                try:
                    file.unlink()
                    logger.info(f"Deleted old file: {file}")
                except Exception as e:
                    logger.error(f"Failed to delete file {file}: {e}")

    for dir_path in folder.glob('**/*'):
        if dir_path.is_dir():
            try:
                dir_path.rmdir()
                logger.info(f"Removed empty directory: {dir_path}")
            except OSError:
                pass

if __name__ == '__main__':
    main()