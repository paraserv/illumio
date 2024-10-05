#!/usr/bin/env python3
# app/config.py
"""
Configuration loader for the application.
"""

# Standard library imports
import os
from pathlib import Path
import configparser

# Third-party imports
from dotenv import load_dotenv

# Typing imports
from typing import List

class Config:
    def __init__(self):
        # Load .env file
        load_dotenv()

        # Load settings.ini
        self._config = configparser.ConfigParser()
        script_dir = Path(__file__).parent
        settings_file = script_dir / 'settings.ini'
        self._config.read(settings_file)

        # Load configuration from environment variables or settings.ini
        self.AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
        self.AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
        
        # S3 settings
        self.MAX_FILES_PER_FOLDER = self._config.getint('S3', 'MAX_FILES_PER_FOLDER', fallback=5)
        self.BASE_PATHS = self._config.get('S3', 'BASE_PATHS', fallback='').split(',')
        self.MAX_POOL_CONNECTIONS = self._config.getint('S3', 'MAX_POOL_CONNECTIONS', fallback=10)
        self.POLL_INTERVAL = self._config.getint('S3', 'POLL_INTERVAL', fallback=10)
        self.TIME_WINDOW_HOURS = self._config.getfloat('S3', 'TIME_WINDOW_HOURS', fallback=12.0)
        
        # Determine if we're running in a container
        self.IN_CONTAINER = os.environ.get('IN_CONTAINER', 'false').lower() == 'true'

        # Set base directories
        if self.IN_CONTAINER:
            self.BASE_DIR = Path('/')
            self.APP_DIR = Path('/app')
        else:
            self.BASE_DIR = Path(__file__).parent.parent  # Go up one level from the script directory
            self.APP_DIR = Path(__file__).parent  # The directory containing this script

        # Set STATE_DIR and LOG_DIR
        if self.IN_CONTAINER:
            self.STATE_DIR = Path(os.getenv('STATE_DIR', '/state'))
            self.LOG_DIR = Path(os.getenv('LOG_DIR', '/logs'))
        else:
            self.STATE_DIR = self.APP_DIR / 'state'
            self.LOG_DIR = self.APP_DIR / 'logs'

        # Ensure directories exist
        self.STATE_DIR.mkdir(parents=True, exist_ok=True)
        self.LOG_DIR.mkdir(parents=True, exist_ok=True)

        # Update paths
        self.STATE_FILE = self.STATE_DIR / self._config.get('Paths', 'STATE_FILE', fallback='state.json')
        self.APP_LOG_FILE = self.LOG_DIR / self._config.get('Logging', 'APP_LOG_FILE', fallback='app.json')
        self.HEALTH_REPORT_LOG_FILE = self.LOG_DIR / self._config.get('Logging', 'HEALTH_REPORT_LOG_FILE', fallback='health_report.json')
        self.LOG_QUEUE_DB = self.STATE_DIR / 'log_queue.db'

        # Add this line to maintain compatibility with existing code
        self.LOG_FOLDER = self.LOG_DIR

        # Health Reporting
        self.HEARTBEAT_INTERVAL = self._config.getfloat('HealthReporting', 'HEARTBEAT_INTERVAL', fallback=15.0)
        self.SUMMARY_INTERVAL = self._config.getfloat('HealthReporting', 'SUMMARY_INTERVAL', fallback=20.0)
        self.ENABLE_HEALTH_REPORTER = self._config.getboolean('HealthReporting', 'ENABLE_HEALTH_REPORTER', fallback=True)
        
        # Syslog settings
        self.SMA_HOST = self._config.get('Syslog', 'SMA_HOST')
        self.SMA_PORT = self._config.getint('Syslog', 'SMA_PORT', fallback=514)
        self.MAX_MESSAGES_PER_SECOND = self._config.getint('Syslog', 'MAX_MESSAGES_PER_SECOND', fallback=1000)
        self.MIN_MESSAGES_PER_SECOND = self._config.getint('Syslog', 'MIN_MESSAGES_PER_SECOND', fallback=5)
        self.ENABLE_DYNAMIC_SYSLOG_RATE = self._config.getboolean('Syslog', 'ENABLE_DYNAMIC_SYSLOG_RATE', fallback=True)
        self.USE_TCP = self._config.getboolean('Syslog', 'USE_TCP', fallback=False)
        self.MAX_MESSAGE_LENGTH = self._config.getint('Syslog', 'MAX_MESSAGE_LENGTH', fallback=2048)
        self.BASELINE_PERIOD = self._config.getfloat('Syslog', 'BASELINE_PERIOD', fallback=300.0)
        
        # General settings
        self.BEATNAME = self._config.get('General', 'BEATNAME', fallback='IllumioS3')
        
        # Processing settings
        self.MAX_WORKERS = self._config.getint('Processing', 'MAX_WORKERS', fallback=4)
        self.MIN_WORKERS = self._config.getint('Processing', 'MIN_WORKERS', fallback=1)
        self.BATCH_SIZE = self._config.getint('Processing', 'BATCH_SIZE', fallback=100)
        self.ADJUSTMENT_INTERVAL = self._config.getint('Processing', 'ADJUSTMENT_INTERVAL', fallback=60)
        self.QUEUE_SIZE_THRESHOLD = self._config.getint('Processing', 'QUEUE_SIZE_THRESHOLD', fallback=10000)
        self.MAX_QUEUE_SIZE = self._config.getint('Processing', 'MAX_QUEUE_SIZE', fallback=100000)
        self.QUEUE_EMPTY_SLEEP_TIME = float(self._config.get('Processing', 'QUEUE_EMPTY_SLEEP_TIME', fallback='0.1'))
        self.RATE_LIMIT_SLEEP_TIME = float(self._config.get('Processing', 'RATE_LIMIT_SLEEP_TIME', fallback='0.01'))
        
        # Logging settings
        self.LOG_LEVEL = self._config.get('Logging', 'LOG_LEVEL', fallback='WARNING').upper()
        self.ENABLE_SAMPLE_LOGGING = self._config.getboolean('Logging', 'ENABLE_SAMPLE_LOGGING', fallback=False)
        self.SAMPLE_LOG_INTERVAL = self._config.getint('Logging', 'SAMPLE_LOG_INTERVAL', fallback=60)
        self.SAMPLE_LOG_LENGTH = self._config.getint('Logging', 'SAMPLE_LOG_LENGTH', fallback=1000)

        # Queue Monitoring settings
        self.QUEUE_MONITOR_INTERVAL = self._config.getfloat('QueueMonitoring', 'MONITOR_INTERVAL', fallback=5.0)

        # Detailed Reporting settings
        self.DETAILED_REPORT_INTERVAL = self._config.getint('DetailedReporting', 'REPORT_INTERVAL', fallback=300)

        # Shutdown settings
        self.SHUTDOWN_TIMEOUT = self._config.getint('Shutdown', 'SHUTDOWN_TIMEOUT', fallback=30)

        if not self.SMA_HOST:
            raise ValueError("SMA_HOST is not set in settings.ini")

        # Add this line
        self.LOG_QUEUE_DB = self.STATE_DIR / 'log_queue.db'

    @property
    def RETAIN_DOWNLOADED_LOGS(self):
        return self._config.getboolean('Processing', 'RETAIN_DOWNLOADED_LOGS', fallback=False)