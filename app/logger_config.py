#!/usr/bin/env python3
"""
Logger configuration for the application.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import configparser

def setup_logging():
    # Get the directory where the script is located
    script_dir = Path(__file__).parent

    # Load settings
    config = configparser.ConfigParser(interpolation=None)  # Disable interpolation
    config.read(script_dir / 'settings.ini')

    # Get logging settings
    log_level = config.get('Logging', 'LOG_LEVEL', fallback='INFO').upper()
    max_log_size = config.getint('Logging', 'MAX_LOG_SIZE', fallback=10485760)
    backup_count = config.getint('Logging', 'BACKUP_COUNT', fallback=5)
    file_log_format = config.get('Logging', 'FILE_LOG_FORMAT', fallback='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_log_format = config.get('Logging', 'CONSOLE_LOG_FORMAT', fallback='%(asctime)s - %(levelname)s - %(message)s')

    # Set up the root logger with the specified log level
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.getLevelName(log_level))

    # Remove all existing handlers to avoid duplication
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create formatters
    file_formatter = logging.Formatter(file_log_format)
    console_formatter = logging.Formatter(console_log_format)

    # Define the log folder
    log_folder = script_dir / config.get('Paths', 'LOG_FOLDER', fallback='logs')
    log_folder.mkdir(parents=True, exist_ok=True)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.getLevelName(log_level))  # Set console handler level
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # Create file handler for app.log
    app_log_file = log_folder / 'app.log'
    file_handler = RotatingFileHandler(app_log_file, maxBytes=max_log_size, backupCount=backup_count)
    file_handler.setLevel(logging.getLevelName(log_level))  # Set file handler level
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    # Suppress debug logs from botocore and other noisy libraries
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

def get_logger(name):
    return logging.getLogger(name)