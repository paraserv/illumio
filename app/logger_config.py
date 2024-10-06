#!/usr/bin/env python3
"""
Logger configuration for the application.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import configparser
import json
import os

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            'timestamp': self.formatTime(record, self.datefmt),
            'name': record.name,
            'level': record.levelname,
            'message': record.getMessage(),
        }
        if record.exc_info:
            log_record['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(log_record)

_logging_setup_done = False
_root_logger = None

def setup_logging():
    global _logging_setup_done, _root_logger
    if _logging_setup_done:
        return _root_logger

    # Get the directory where the script is located
    script_dir = Path(__file__).parent

    # Load settings
    config = configparser.ConfigParser(interpolation=None)  # Disable interpolation
    config.read(script_dir / 'settings.ini')

    # Get logging settings
    log_level = config.get('Logging', 'LOG_LEVEL', fallback='INFO').upper()
    max_log_size = config.getint('Logging', 'MAX_LOG_SIZE', fallback=10485760)
    backup_count = config.getint('Logging', 'BACKUP_COUNT', fallback=5)

    # Set up the root logger with the specified log level
    _root_logger = logging.getLogger()
    _root_logger.setLevel(logging.getLevelName(log_level))

    # Remove all existing handlers to avoid duplication
    for handler in _root_logger.handlers[:]:
        _root_logger.removeHandler(handler)

    # Create JSON formatter
    json_formatter = JSONFormatter()

    # Use the LOG_DIR environment variable or fall back to the default
    log_folder = Path(os.environ.get('LOG_DIR', script_dir.parent / config.get('Paths', 'LOG_FOLDER', fallback='logs')))
    log_folder.mkdir(parents=True, exist_ok=True)

    # Set up JSON file handler
    json_log_file = log_folder / 'app.json'
    json_file_handler = RotatingFileHandler(
        json_log_file,
        maxBytes=max_log_size,
        backupCount=backup_count
    )
    json_file_handler.setFormatter(json_formatter)
    _root_logger.addHandler(json_file_handler)

    # Set up console handler with JSON formatting
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(json_formatter)
    _root_logger.addHandler(console_handler)

    # Log the current log level
    _root_logger.critical(f"Logging initialized. Current log level: {logging.getLevelName(_root_logger.level)}")

    # Log folder and JSON log file paths using the JSON formatter
    _root_logger.info(f"Log folder path: {log_folder}")
    _root_logger.info(f"JSON log file path: {json_log_file}")

    _logging_setup_done = True
    return _root_logger

def get_logger(name):
    global _root_logger
    if not _logging_setup_done:
        _root_logger = setup_logging()
    return _root_logger.getChild(name)