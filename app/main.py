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
import atexit
import psutil
import traceback
import socket
import sqlite3
import configparser
import shutil  # Add this import at the top of the file

# Third-party imports
import pytz
from tenacity import retry, wait_exponential, stop_after_attempt

# Local application imports
from s3_manager import S3Manager
from log_processor import LogProcessor
from logger_config import setup_logging, get_logger
from health_reporter import HealthReporter
from config import Config
from s3_ntp_check import check_time_sync

# Set up logging
logger = setup_logging()

# After initializing the Config object
config = Config()

# Set the log level
logger.setLevel(logging.getLevelName(config.LOG_LEVEL))

logger.critical(f"Application starting with log level: {logging.getLevelName(logger.level)}")

# Global variables
executor = None
stop_event = threading.Event()
s3_manager = None
log_processor = None
health_reporter = None

shutdown_initiated = False

def signal_handler(signum, frame):
    logger.info("Received termination signal.")
    stop_event.set()

def shutdown_with_timeout(timeout=120):  # Increased timeout to 120 seconds
    global shutdown_initiated
    if shutdown_initiated:
        return
    shutdown_initiated = True

    shutdown_event = threading.Event()
    
    def shutdown_process():
        global s3_manager, log_processor, health_reporter
        logger.info("Starting shutdown process in separate thread")
        shutdown(s3_manager, log_processor, health_reporter)
        shutdown_event.set()
        logger.info("Shutdown process in separate thread completed")

    shutdown_thread = threading.Thread(target=shutdown_process)
    shutdown_thread.start()
    
    logger.info(f"Waiting for shutdown process to complete (timeout: {timeout} seconds)")
    shutdown_thread.join(timeout)
    if shutdown_thread.is_alive():
        logger.warning(f"Shutdown process did not complete within {timeout} seconds.")
        logger.info("Current thread states:")
        for thread in threading.enumerate():
            if thread.name.startswith('pydevd'):
                logger.warning(f"Debugger thread {thread.name} is still alive.")
            else:
                logger.info(f"Thread {thread.name}: {'Alive' if thread.is_alive() else 'Not Alive'}")
            if thread.is_alive():
                frame = sys._current_frames().get(thread.ident)
                if frame:
                    stack = traceback.extract_stack(frame)
                    logger.warning(f"Stack trace for thread {thread.name}:")
                    for filename, lineno, name, line in stack:
                        logger.warning(f"  File: {filename}, line {lineno}, in {name}")
                        if line:
                            logger.warning(f"    {line.strip()}")
    else:
        logger.info("Shutdown process completed successfully.")

    cleanup()
    
    # Check if network connections are open before waiting
    process = psutil.Process(os.getpid())
    connections = process.net_connections()
    if connections:
        network_timeout = 10
        logger.info(f"Open network connections detected. Allowing {network_timeout} seconds for them to close...")
        time.sleep(network_timeout)
        
        # Check again after waiting
        connections = process.net_connections()
        if connections:
            logger.warning("Some network connections are still open:")
            for conn in connections:
                logger.warning(f"  {conn}")
                report_network_connection(conn)
        else:
            logger.info("All network connections closed successfully.")
    else:
        logger.info("No open network connections detected. Proceeding with immediate shutdown.")

    logger.info("Application has been terminated. Final exit.")
    os._exit(0)  # Force exit

def shutdown(s3_manager, log_processor, health_reporter):
    global shutdown_initiated
    if shutdown_initiated:
        logger.debug("Shutdown already initiated, skipping")
        return
    shutdown_initiated = True
    
    logger.info("Initiating shutdown process...")
    start_time = time.time()

    if s3_manager:
        s3_manager.stop()
    
    if log_processor:
        log_processor.stop_processing()
    
    if health_reporter:
        health_reporter.stop()

    # Wait for all threads to finish
    for thread in threading.enumerate():
        if thread != threading.current_thread():
            thread.join(timeout=5)
            if thread.is_alive():
                logger.warning(f"Thread {thread.name} did not finish in time")

    logger.critical(f"Application stopped. Total shutdown time: {time.time() - start_time:.2f} seconds")

def cleanup():
    logger.info("Performing final cleanup...")
    
    global executor
    if executor:
        logger.info("Shutting down ThreadPoolExecutor...")
        start_time = time.time()
        executor.shutdown(wait=False)
        shutdown_time = time.time() - start_time
        logger.info(f"ThreadPoolExecutor shutdown completed in {shutdown_time:.2f} seconds")
    
    # Log information about the current process
    process = psutil.Process(os.getpid())
    logger.info(f"Current process memory usage: {process.memory_info().rss / 1024 / 1024:.2f} MB")
    logger.info(f"Current process CPU usage: {process.cpu_percent(interval=1)}%")
    
    # Check for any open file descriptors
    open_files = process.open_files()
    if open_files:
        logger.info(f"Open files: {open_files}")
    
    # Check for any active network connections
    try:
        if hasattr(process, 'connections'):
            connections = process.connections()
        else:
            logger.warning("Unable to retrieve network connections: method not available")
            connections = []

        if connections:
            logger.info("Active network connections:")
            for conn in connections:
                logger.info(f"  {conn}")
                if hasattr(conn, 'status') and conn.status == 'CLOSE_WAIT':
                    logger.warning(f"Connection in CLOSE_WAIT state: {conn}")
                    report_network_connection(conn)
    except psutil.AccessDenied:
        logger.warning("Unable to retrieve network connections due to access denied.")
    except Exception as e:
        logger.error(f"Error retrieving network connections: {e}")

    logger.info("Cleanup completed.")

def handle_log_file(s3_object, s3_manager, log_processor, log_type, stop_event, health_reporter):
    local_file, logs_extracted = s3_manager.download_and_extract(s3_object['Key'], stop_event)
    if local_file is None:
        logger.warning(f"Failed to download or extract {s3_object['Key']}")
        return False, 0

    result, logs_processed = log_processor.process_log_file(local_file, log_type, stop_event)
    
    if result:
        health_reporter.report_gz_file_processed(log_type)
        health_reporter.report_logs_extracted(logs_extracted, log_type)
        s3_manager.cleanup_downloaded_file(local_file)  # Add this line
    else:
        logger.warning(f"Failed to process {local_file}. File will be retained for inspection.")

    return result, logs_processed

def monitor_queue(log_processor, config, stop_event):
    while not stop_event.is_set():
        current_queue_size = log_processor.get_queue_size()
        if current_queue_size >= config.QUEUE_SIZE_THRESHOLD:
            logger.warning(f"Queue size ({current_queue_size}) exceeded threshold ({config.QUEUE_SIZE_THRESHOLD})")
        if stop_event.wait(config.QUEUE_MONITOR_INTERVAL):
            break  # Exit if stop_event is set

def update_health_reporter_s3_stats(s3_manager, health_reporter, stop_event):
    while not stop_event.is_set():
        stats = s3_manager.update_s3_stats()
        health_reporter.update_s3_stats(stats)
        # Use wait instead of sleep to allow for faster response to stop_event
        stop_event.wait(60)  # Wait for 60 seconds or until stop_event is set

def report_network_connection(conn):
    try:
        # Get process name
        process = psutil.Process(os.getpid())
        process_name = process.name()
        
        # Get connection details
        local_address = f"{conn.laddr.ip}:{conn.laddr.port}"
        remote_address = f"{conn.raddr.ip}:{conn.raddr.port}"
        
        # Try to get hostname of remote IP
        try:
            remote_host = socket.gethostbyaddr(conn.raddr.ip)[0]
        except socket.herror:
            remote_host = "Unknown"
        
        # Get open files for this process
        open_files = process.open_files()
        
        logger.warning(f"Detailed network connection report:")
        logger.warning(f"  Process: {process_name}")
        logger.warning(f"  Local Address: {local_address}")
        logger.warning(f"  Remote Address: {remote_address}")
        logger.warning(f"  Remote Hostname: {remote_host}")
        logger.warning(f"  Connection Status: {conn.status}")
        logger.warning(f"  Open Files: {open_files}")
        
        # Try to get more info about the connection
        for thread in threading.enumerate():
            if "network" in thread.name.lower() or "connection" in thread.name.lower():
                logger.warning(f"  Possibly related thread: {thread.name}")
                
    except Exception as e:
        logger.error(f"Error while reporting network connection: {e}")

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def main_loop_iteration(s3_manager, log_processor, health_reporter, config):
    try:
        # Check NTP and AWS time synchronization
        if not check_time_sync(config_path='app/settings.ini', health_reporter=health_reporter):
            logger.warning("Time sync check failed, but continuing operations.")

        for log_type in config.LOG_TYPES:
            if stop_event.is_set():
                break
            logger.info(f"Processing log type: {log_type}")
            processed = process_log_type(s3_manager, log_processor, health_reporter, config, log_type)
            if processed:
                logger.info(f"Processed {log_type} logs")
            else:
                logger.info(f"No {log_type} logs to process at this time")

        logger.debug("Finished processing all log types")

    except Exception as e:
        logger.error(f"An error occurred in the main loop: {str(e)}")
        logger.info("Retrying main loop iteration...")
        raise  # This will trigger the retry

def main():
    logger.critical("Application starting up...")
    global executor, s3_manager, log_processor, health_reporter

    # Load configuration
    config = Config()

    # Use log types from config
    log_types = config.LOG_TYPES

    try:
        # Initialize queue database
        queue_db_path = config.QUEUE_DB_FILE
        logger.info(f"Initializing queue database at: {queue_db_path}")
        conn = sqlite3.connect(queue_db_path)

        # Initialize components
        health_reporter = HealthReporter(config, stop_event)
        health_reporter.start()

        log_processor = LogProcessor(config, health_reporter, stop_event)
        log_processor.start_processing()

        s3_manager = S3Manager(
            aws_access_key_id=config.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
            s3_bucket_name=config.S3_BUCKET_NAME,
            max_files_per_folder=config.MAX_FILES_PER_FOLDER,
            health_reporter=health_reporter,
            max_pool_connections=config.MAX_POOL_CONNECTIONS,
            state_file=config.STATE_FILE,
            config=config,
            stop_event=stop_event
        )
        logger.info(f"S3Manager initialized. Will look back {config.TIME_WINDOW_HOURS} hours for S3 files.")

        executor = ThreadPoolExecutor(max_workers=config.MAX_WORKERS)

        queue_monitor_thread = threading.Thread(target=monitor_queue, args=(log_processor, config, stop_event))
        queue_monitor_thread.start()

        s3_stats_thread = threading.Thread(target=update_health_reporter_s3_stats, args=(s3_manager, health_reporter, stop_event))
        s3_stats_thread.start()

        maintenance_thread = threading.Thread(target=perform_maintenance, args=(config, stop_event))
        maintenance_thread.start()

        logger.critical("Application started and ready for processing.")

        # Main processing loop
        while not stop_event.is_set():
            try:
                main_loop_iteration(s3_manager, log_processor, health_reporter, config)
            except Exception as e:
                logger.error(f"Main loop iteration failed after retries: {str(e)}")
                logger.info("Waiting for 5 minutes before next attempt...")
                time.sleep(300)  # Wait for 5 minutes before trying again

            if stop_event.is_set():
                break

            logger.info(f"S3 file monitoring will wait for {config.POLL_INTERVAL} seconds before looking for new files")
            
            # Use wait instead of sleep to allow for immediate termination
            if stop_event.wait(config.POLL_INTERVAL):
                break

    except Exception as e:
        logger.exception(f"Unhandled exception in main loop: {e}")
    finally:
        logger.critical("Application shutting down...")
        shutdown(s3_manager, log_processor, health_reporter)

def process_log_type(s3_manager, log_processor, health_reporter, config, log_type):
    logger.info(f"Starting to process log type: {log_type}")
    time_window_end = datetime.now(pytz.UTC)
    time_window_start = time_window_end - timedelta(hours=config.TIME_WINDOW_HOURS)

    logger.info(f"Time window for {log_type}: {time_window_start} to {time_window_end}")
    new_s3_objects = s3_manager.get_new_s3_objects(
        log_type, time_window_start, time_window_end, config.BATCH_SIZE, log_processor.get_queue_size()
    )

    if not new_s3_objects:
        logger.info(f"No new {log_type} objects to process. Will check again in the next iteration.")
        return False

    logger.info(f"Processing {len(new_s3_objects)} new {log_type} objects")
    for s3_object in new_s3_objects:
        if stop_event.is_set():
            logger.info(f"Stop event set. Interrupting processing of {log_type}.")
            return False
        process_s3_object(s3_manager, log_processor, health_reporter, s3_object, log_type)

    logger.info(f"Finished processing {log_type} objects")
    return True

def process_s3_object(s3_manager, log_processor, health_reporter, s3_object, log_type):
    logger.info(f"Processing S3 object: {s3_object['Key']}")
    result, logs_extracted = handle_log_file(s3_object, s3_manager, log_processor, log_type, stop_event, health_reporter)
    if result:
        s3_manager.update_and_save_state(log_type, s3_object)
        logger.info(f"Successfully processed: {s3_object['Key']}, Type: {log_type}, Logs extracted: {logs_extracted}")
    else:
        logger.warning(f"Failed to process: {s3_object['Key']}, Type: {log_type}, Logs extracted: {logs_extracted}")

def perform_maintenance(config, stop_event):
    while not stop_event.is_set():
        try:
            # Clean up old log files
            cleanup_old_logs(config.LOG_DIR, max_age_days=30)

            # Optimize database
            optimize_database(config.LOG_QUEUE_DB)

            # Remove old processed entries
            cleanup_old_entries(config.LOG_QUEUE_DB, max_age_days=30)

        except Exception as e:
            logger.error(f"Error during maintenance: {e}")

        # Sleep for 24 hours before next maintenance
        stop_event.wait(86400)

def cleanup_old_logs(log_dir, max_age_days):
    current_time = time.time()
    for log_file in Path(log_dir).glob('*.log*'):
        if (current_time - os.path.getmtime(log_file)) > (max_age_days * 86400):
            os.remove(log_file)
            logger.info(f"Removed old log file: {log_file}")

def backup_state_file(state_file):
    if not os.path.exists(state_file):
        logger.warning(f"State file {state_file} does not exist. Skipping backup.")
        return
    backup_file = f"{state_file}.bak"
    shutil.copy2(state_file, backup_file)
    logger.info(f"Backed up state file to {backup_file}")

def optimize_database(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("VACUUM")
    conn.close()
    logger.info("Optimized database")

def cleanup_old_entries(db_path, max_age_days):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cutoff_time = int(time.time()) - (max_age_days * 86400)
    cursor.execute("DELETE FROM log_queue WHERE id < ?", (cutoff_time,))
    conn.commit()
    conn.close()
    logger.info(f"Removed {cursor.rowcount} old entries from database")

if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Load configuration
    config = Config()

    # Initialize components
    s3_manager = None
    log_processor = None
    health_reporter = None

    try:
        main()
    except KeyboardInterrupt:
        logger.critical("KeyboardInterrupt received. Initiating shutdown...")
    except Exception as e:
        logger.exception(f"Unhandled exception: {e}")
    finally:
        stop_event.set()
        shutdown_with_timeout(timeout=config.SHUTDOWN_TIMEOUT)