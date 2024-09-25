# app/logger_config.py

import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import configparser

def setup_logging():
    # Load settings
    config = configparser.ConfigParser(interpolation=None)  # Disable interpolation
    script_dir = Path(__file__).parent
    config.read(script_dir / 'settings.ini')

    # Get logging settings
    log_level = config.get('Logging', 'LOG_LEVEL', fallback='INFO')
    max_log_size = config.getint('Logging', 'MAX_LOG_SIZE', fallback=10485760)
    backup_count = config.getint('Logging', 'BACKUP_COUNT', fallback=5)
    file_log_format = config.get('Logging', 'FILE_LOG_FORMAT', fallback='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_log_format = config.get('Logging', 'CONSOLE_LOG_FORMAT', fallback='%(asctime)s - %(levelname)s - %(message)s')

    # Set up the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.getLevelName(log_level))

    # Remove all existing handlers to avoid duplication
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create formatters
    file_formatter = logging.Formatter(file_log_format)
    console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # Create file handler for app.log
    log_folder = Path(script_dir.parent) / config.get('Paths', 'LOG_FOLDER', fallback='logs')
    log_folder.mkdir(parents=True, exist_ok=True)
    app_log_file = log_folder / 'app.log'
    file_handler = RotatingFileHandler(app_log_file, maxBytes=max_log_size, backupCount=backup_count)
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

def get_logger(name):
    return logging.getLogger(name)