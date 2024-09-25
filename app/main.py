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
running = True
executor = None
processed_keys = {}
state_file = None
config = None
BATCH_SIZE = None
new_objects = []
already_processed_files = set()

def force_exit(signum, frame):
    logger.info("Forced exit. Terminating immediately.")
    os._exit(1)

def shutdown(processed_keys, already_processed_files):
    global running, executor, state_file, checkpoint_file
    logger.info("Initiating shutdown...")
    running = False
    if executor:
        logger.info("Shutting down ThreadPoolExecutor...")
        executor.shutdown(wait=True)
    if processed_keys is not None and state_file is not None:
        save_state(processed_keys, state_file)
    if already_processed_files is not None and checkpoint_file is not None:
        save_checkpoint(already_processed_files, checkpoint_file)
    logger.info("Shutdown complete.")
    sys.exit(0)

def signal_handler(signum, frame):
    global already_processed_files
    logger.info("Received termination signal. Cleaning up...")
    threading.Thread(target=shutdown, args=(processed_keys, already_processed_files)).start()
    signal.signal(signal.SIGALRM, force_exit)
    signal.alarm(10)

def save_state(processed_keys, state_file):
    state_data = {
        'summaries': {},
        'auditable_events': {}
    }
    for key, timestamp in processed_keys.items():
        log_type = 'auditable_events' if 'auditable_events' in key else 'summaries'
        state_data[log_type][key] = timestamp.isoformat()
    
    with open(state_file, 'w') as f:
        json.dump(state_data, f)
    logger.info(f"Saved state: Summaries: {len(state_data['summaries'])}, Auditable Events: {len(state_data['auditable_events'])}")

def load_state(state_file):
    if os.path.exists(state_file):
        with open(state_file, 'r') as f:
            state_data = json.load(f)
        processed_keys = {}
        for log_type in ['summaries', 'auditable_events']:
            for k, v in state_data.get(log_type, {}).items():
                try:
                    processed_keys[k] = datetime.fromisoformat(v)
                except (TypeError, ValueError):
                    logger.warning(f"Invalid datetime format for key {k}: {v}. Skipping this entry.")
        logger.info(f"Loaded state: Summaries: {len(state_data.get('summaries', {}))}, Auditable Events: {len(state_data.get('auditable_events', {}))}")
        return processed_keys
    return {}

def load_checkpoint(checkpoint_file):
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, 'r') as f:
            checkpoint_data = json.load(f)
        summary_files = set(checkpoint_data.get('summaries', []))
        auditable_files = set(checkpoint_data.get('auditable_events', []))
        logger.info(f"Loaded checkpoint: {len(summary_files)} summary files, {len(auditable_files)} auditable event files")
        return summary_files.union(auditable_files)
    logger.info("No checkpoint file found.")
    return set()

def save_checkpoint(processed_files, checkpoint_file):
    checkpoint_data = {
        'summaries': [f for f in processed_files if 'summaries' in f],
        'auditable_events': [f for f in processed_files if 'auditable_events' in f]
    }
    with open(checkpoint_file, 'w') as f:
        json.dump(checkpoint_data, f)
    logger.info(f"Saved checkpoint: {len(checkpoint_data['summaries'])} summary files, {len(checkpoint_data['auditable_events'])} auditable event files")

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

def main():
    global running, executor, processed_keys, state_file, config, new_objects, BATCH_SIZE, checkpoint_file, already_processed_files
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        config = Config()
        
        executor = ThreadPoolExecutor(max_workers=config.MAX_WORKERS)

        if not config.AWS_ACCESS_KEY_ID or not config.AWS_SECRET_ACCESS_KEY or not config.S3_BUCKET_NAME:
            logger.error("AWS credentials or S3 bucket name are not set.")
            sys.exit(1)

        config.DOWNLOADED_FILES_FOLDER.mkdir(parents=True, exist_ok=True)
        config.LOG_FOLDER.mkdir(parents=True, exist_ok=True)

        script_dir = Path(__file__).parent
        state_file = script_dir / config.STATE_FILE
        checkpoint_file = script_dir / 'checkpoint.json'

        health_reporter = HealthReporter(
            heartbeat_interval=60.0,
            summary_interval=3600.0
        )
        health_reporter.start()

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

        log_processor = LogProcessor(
            sma_host=config.SMA_HOST,
            sma_port=config.SMA_PORT,
            min_messages_per_second=config.MIN_MESSAGES_PER_SECOND,
            max_messages_per_second=config.MAX_MESSAGES_PER_SECOND,
            enable_dynamic_syslog_rate=config.ENABLE_DYNAMIC_SYSLOG_RATE,
            beatname=config.BEATNAME,
            use_tcp=config.USE_TCP,
            max_message_length=config.MAX_MESSAGE_LENGTH,
            health_reporter=health_reporter
        )

        processed_keys_lock = threading.Lock()

        # Explicitly create state and checkpoint files if they don't exist
        if not state_file.exists():
            save_state({}, state_file)
            logger.info(f"Created new state file: {state_file}")
        if not checkpoint_file.exists():
            save_checkpoint(set(), checkpoint_file)
            logger.info(f"Created new checkpoint file: {checkpoint_file}")

        processed_keys = load_state(state_file)
        already_processed_files = load_checkpoint(checkpoint_file)

        ADJUSTMENT_INTERVAL = 60  # seconds
        last_adjustment_time = time.time()

        baseline_period = 300  # 5 minutes
        baseline_start_time = time.time()

        while running:
            try:
                current_time = time.time()
                if current_time - baseline_start_time < baseline_period:
                    logger.info(f"In baseline period. {baseline_period - (current_time - baseline_start_time):.0f} seconds remaining.")
                else:
                    if not globals().get('baseline_ended', False):
                        logger.info("Baseline period ended. Starting normal operation with adjustments.")
                        globals()['baseline_ended'] = True

                logger.info("Checking for new logs...")
                try:
                    new_objects = s3_manager.get_new_log_objects(processed_keys)
                    logger.info(f"Found {len(new_objects)} new log files out of {len(processed_keys)} processed keys")
                except Exception as e:
                    logger.error(f"Error fetching new log objects: {e}")
                    continue

                if new_objects:
                    logger.info(f"Processing {len(new_objects)} new log files.")
                    start_time = time.time()
                    processed_count = {'summaries': 0, 'auditable_events': 0}
                    
                    futures = []

                    for s3_object in new_objects:
                        log_type = 'auditable_events' if 'auditable_events' in s3_object['Key'] else 'summaries'
                        if s3_object['Key'] not in already_processed_files:
                            future = executor.submit(
                                handle_log_file_with_retry,
                                s3_object, s3_manager, log_processor, config.DOWNLOADED_FILES_FOLDER,
                                processed_keys, processed_keys_lock, health_reporter, log_type
                            )
                            futures.append((future, s3_object, log_type))

                    for future, s3_object, log_type in futures:
                        try:
                            result = future.result()
                            if result:
                                already_processed_files.add(s3_object['Key'])
                                processed_count[log_type] += 1
                                logger.info(f"Successfully processed: {s3_object['Key']}, Type: {log_type}")
                            else:
                                logger.error(f"Failed to process: {s3_object['Key']}, Type: {log_type}")
                        except Exception as e:
                            logger.error(f"Error processing {s3_object['Key']}: {str(e)}")
                            health_reporter.report_error(f"Error processing {s3_object['Key']}: {str(e)}", log_type)

                    # Save checkpoint after processing batch
                    s3_manager.save_checkpoint(already_processed_files)

                    processing_time = time.time() - start_time
                    total_processed = sum(processed_count.values())
                    processing_rate = total_processed / processing_time * 3600  # logs per hour

                    if current_time - baseline_start_time >= baseline_period:
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

                        logger.info(f"Processed {total_processed} log files (Summaries: {processed_count['summaries']}, Auditable Events: {processed_count['auditable_events']}) at a rate of {processing_rate:.2f} logs/hour.")
                        health_reporter.log_message(f"Processing rate: {processing_rate:.2f} logs/hour")
                        
                        last_adjustment_time = current_time

                else:
                    logger.info("No new log files found.")

                if running:
                    logger.info(f"Sleeping for {config.POLL_INTERVAL} seconds before next check...")
                    time.sleep(config.POLL_INTERVAL)

                cleanup_downloaded_files(config.DOWNLOADED_FILES_FOLDER)

            except KeyboardInterrupt:
                logger.info("Keyboard interrupt received. Initiating shutdown...")
                running = False

    except Exception as e:
        logger.exception(f"Unhandled exception in main: {e}")
        health_reporter.report_error(str(e), 'general')
    finally:
        if 'health_reporter' in locals():
            health_reporter.stop()
        shutdown(processed_keys, already_processed_files)
        logger.info("Script has been terminated.")

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def handle_log_file_with_retry(s3_object, s3_manager, log_processor, downloaded_files_folder, processed_keys, processed_keys_lock, health_reporter, log_type):
    logger.info(f"Handling log file: {s3_object['Key']}, Type: {log_type}")
    if s3_object['Key'] in processed_keys:
        logger.info(f"Skipping already processed file: {s3_object['Key']}")
        return True

    try:
        dest_path = s3_manager.download_and_extract(s3_object, downloaded_files_folder)
        if dest_path:
            logger.info(f"Successfully downloaded and extracted: {dest_path}")
            health_reporter.report_gz_file_processed(log_type)
            success, logs_count = log_processor.process_log_file(Path(dest_path), log_type)
            if success:
                Path(dest_path).unlink()
                logger.info(f"Successfully processed and deleted: {dest_path}")
                with processed_keys_lock:
                    processed_keys[s3_object['Key']] = datetime.now()
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