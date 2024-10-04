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
    
    logger.info("Initiating shutdown...")
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

    logger.info(f"Shutdown complete. Total time taken: {time.time() - start_time:.2f} seconds")

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
        connections = process.net_connections()
        if connections:
            logger.info("Active network connections:")
            for conn in connections:
                logger.info(f"  {conn}")
                if conn.status == 'CLOSE_WAIT':
                    logger.warning(f"Connection in CLOSE_WAIT state: {conn}")
                    report_network_connection(conn)
    except psutil.AccessDenied:
        logger.warning("Unable to retrieve network connections due to access denied.")

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

def main():
    global executor, s3_manager, log_processor, health_reporter

    # Load configuration
    config = Config()

    # Use the paths from the config, ensuring they are Path objects
    state_file = Path(config.STATE_FILE)
    download_folder = Path(config.STATE_DIR) / 'downloads'
    log_folder = Path(config.LOG_FOLDER)
    health_report_log_file = Path(config.HEALTH_REPORT_LOG_FILE)

    # Ensure directories exist
    download_folder.mkdir(parents=True, exist_ok=True)
    log_folder.mkdir(parents=True, exist_ok=True)
    health_report_log_file.parent.mkdir(parents=True, exist_ok=True)

    # Ensure the state directory exists
    config.STATE_DIR.mkdir(parents=True, exist_ok=True)

    logger.info(f"Ensuring download folder exists: {download_folder}")
    logger.info(f"Ensuring log folder exists: {log_folder}")
    logger.info(f"Health report log file: {health_report_log_file}")

    # List of log types to process
    log_types = ['auditable_events', 'summaries']

    try:
        # Initialize components
        health_reporter = HealthReporter(config, stop_event)
        health_reporter.start()

        log_processor = LogProcessor(config, health_reporter, stop_event)
        log_processor.start_processing()

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
            config=config,
            stop_event=stop_event
        )

        executor = ThreadPoolExecutor(max_workers=config.MAX_WORKERS)

        queue_monitor_thread = threading.Thread(target=monitor_queue, args=(log_processor, config, stop_event))
        queue_monitor_thread.start()

        s3_stats_thread = threading.Thread(target=update_health_reporter_s3_stats, args=(s3_manager, health_reporter, stop_event))
        s3_stats_thread.start()

        # Main processing loop
        while not stop_event.is_set():
            logger.debug("Starting new iteration of main processing loop")
            
            for log_type in log_types:
                if stop_event.is_set():
                    break
                logger.info(f"Processing log type: {log_type}")
                processed = process_log_type(s3_manager, log_processor, health_reporter, config, log_type)
                if processed:
                    logger.info(f"Processed {log_type} logs")
                else:
                    logger.info(f"No {log_type} logs to process at this time")

            if stop_event.is_set():
                break

            logger.debug("Finished processing all log types")
            logger.info(f"S3 file monitoring will wait for {config.POLL_INTERVAL} seconds before looking for new files")
            
            # Use wait instead of sleep to allow for immediate termination
            if stop_event.wait(config.POLL_INTERVAL):
                break

    except Exception as e:
        logger.exception(f"Unhandled exception in main loop: {e}")
    finally:
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
        logger.info("KeyboardInterrupt received. Initiating shutdown...")
    except Exception as e:
        logger.exception(f"Unhandled exception: {e}")
    finally:
        stop_event.set()
        shutdown_with_timeout(timeout=config.SHUTDOWN_TIMEOUT)