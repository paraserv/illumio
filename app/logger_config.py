import logging
import os
from logging.handlers import RotatingFileHandler
import configparser
from pathlib import Path
import glob
import sys

def cleanup_old_logs(log_file: Path, backup_count: int):
    """Remove old log files exceeding the backup count."""
    base_name = log_file.stem  # Get the filename without extension
    log_files = glob.glob(str(log_file.parent / f"{base_name}*.log*"))
    log_files.sort(key=os.path.getmtime, reverse=True)
    
    # Keep the current log file and up to backup_count rotated files
    files_to_keep = backup_count + 1

    if len(log_files) > files_to_keep:
        for old_log in log_files[files_to_keep:]:
            try:
                os.remove(old_log)
            except Exception as e:
                print(f"Failed to remove old log file {old_log}: {e}")

def setup_logger(script_name):
    # Load configuration with interpolation disabled
    script_dir = Path(__file__).parent
    settings_file = script_dir / 'settings.ini'
    config = configparser.ConfigParser(interpolation=None)
    config.read(settings_file)

    # Use current working directory as default base folder
    BASE_FOLDER = (script_dir / config.get('Paths', 'BASE_FOLDER', fallback='..')).resolve()
    LOG_FOLDER = BASE_FOLDER / config.get('Paths', 'LOG_FOLDER', fallback='logs')
    LOG_FILE = LOG_FOLDER / f'{script_name}.log'
    LOG_LEVEL = config.get('Logging', 'LOG_LEVEL', fallback='INFO')
    MAX_LOG_SIZE = config.getint('Logging', 'MAX_LOG_SIZE', fallback=10485760)
    BACKUP_COUNT = config.getint('Logging', 'BACKUP_COUNT', fallback=5)
    FILE_LOG_FORMAT = config.get('Logging', 'FILE_LOG_FORMAT', fallback='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    CONSOLE_LOG_FORMAT = config.get('Logging', 'CONSOLE_LOG_FORMAT', fallback='%(asctime)s - %(levelname)s - %(message)s')

    # Ensure log directory exists
    LOG_FOLDER.mkdir(parents=True, exist_ok=True)

    # Clean up old log files before setting up the new logger
    cleanup_old_logs(LOG_FILE, BACKUP_COUNT)

    # Create logger
    logger = logging.getLogger(script_name)
    logger.setLevel(getattr(logging, LOG_LEVEL.upper()))

    # Create handlers
    handlers = []

    # File handler
    try:
        file_handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT)
        file_formatter = logging.Formatter(FILE_LOG_FORMAT)
        file_handler.setFormatter(file_formatter)
        handlers.append(file_handler)
    except Exception as e:
        print(f"Error setting up file handler: {e}")
        raise

    # Console handler (logs to stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter(CONSOLE_LOG_FORMAT)
    console_handler.setFormatter(console_formatter)
    handlers.append(console_handler)

    # Add handlers to the logger
    for handler in handlers:
        if not logger.hasHandlers():
            logger.addHandler(handler)
        else:
            logger.addHandler(handler)

    return logger