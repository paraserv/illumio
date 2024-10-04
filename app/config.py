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
        self.MINUTES = self._config.getint('S3', 'MINUTES', fallback=30)
        self.MAX_FILES_PER_FOLDER = self._config.getint('S3', 'MAX_FILES_PER_FOLDER', fallback=5)
        self.LOG_TIMEFRAME = self._config.getfloat('S3', 'LOG_TIMEFRAME', fallback=2.0)
        self.BASE_PATHS = self._config.get('S3', 'BASE_PATHS', fallback='').split(',')
        self.ENABLE_DYNAMIC_TIMEFRAME = self._config.getboolean('S3', 'ENABLE_DYNAMIC_TIMEFRAME', fallback=True)
        self.MAX_POOL_CONNECTIONS = self._config.getint('S3', 'MAX_POOL_CONNECTIONS', fallback=10)
        
        # Paths
        self.APP_DIR = Path(__file__).parent
        self.STATE_DIR = self.APP_DIR / 'state'
        self.STATE_DIR.mkdir(parents=True, exist_ok=True)  # Ensure STATE_DIR exists
        self.STATE_FILE = self.STATE_DIR / 'state.json'
        self.LOG_QUEUE_DB = self.STATE_DIR / 'log_queue.db'
        self.DOWNLOADED_FILES_FOLDER = self.APP_DIR / self._config.get('Paths', 'DOWNLOADED_FILES_FOLDER', fallback='illumio')
        self.LOG_FOLDER = self.APP_DIR / self._config.get('Paths', 'LOG_FOLDER', fallback='logs')
        self.HEALTH_REPORT_LOG_FILE = self.LOG_FOLDER / 'health_report.log'
        
        # Health Reporting
        self.HEARTBEAT_INTERVAL = self._config.getfloat('HealthReporting', 'HEARTBEAT_INTERVAL', fallback=15.0)
        self.SUMMARY_INTERVAL = self._config.getfloat('HealthReporting', 'SUMMARY_INTERVAL', fallback=20.0)
        
        # Syslog settings
        self.SMA_HOST = self._config.get('Syslog', 'SMA_HOST')
        self.SMA_PORT = self._config.getint('Syslog', 'SMA_PORT', fallback=514)
        self.MAX_MESSAGES_PER_SECOND = self._config.getint('Syslog', 'MAX_MESSAGES_PER_SECOND', fallback=1000)
        self.MIN_MESSAGES_PER_SECOND = self._config.getint('Syslog', 'MIN_MESSAGES_PER_SECOND', fallback=5)
        self.ENABLE_DYNAMIC_SYSLOG_RATE = self._config.getboolean('Syslog', 'ENABLE_DYNAMIC_SYSLOG_RATE', fallback=True)
        self.USE_TCP = self._config.getboolean('Syslog', 'USE_TCP', fallback=False)
        self.MAX_MESSAGE_LENGTH = self._config.getint('Syslog', 'MAX_MESSAGE_LENGTH', fallback=2048)
        
        # General settings
        self.BEATNAME = self._config.get('General', 'BEATNAME', fallback='IllumioS3')
        
        # Processing settings
        self.MAX_WORKERS = self._config.getint('Processing', 'MAX_WORKERS', fallback=4)
        self.BATCH_SIZE = self._config.getint('Processing', 'BATCH_SIZE', fallback=100)
        self.POLL_INTERVAL = self._config.getint('S3', 'POLL_INTERVAL', fallback=10)
        self.QUEUE_SIZE_THRESHOLD = self._config.getint('Processing', 'QUEUE_SIZE_THRESHOLD', fallback=10000)
        self.QUEUE_MONITOR_INTERVAL = self._config.getfloat('Processing', 'QUEUE_MONITOR_INTERVAL', fallback=5.0)
        self.MAX_QUEUE_SIZE = self._config.getint('Processing', 'MAX_QUEUE_SIZE', fallback=100000)

        # New settings for sample logging
        self.ENABLE_SAMPLE_LOGGING = self._config.getboolean('Logging', 'ENABLE_SAMPLE_LOGGING', fallback=False)
        self.SAMPLE_LOG_INTERVAL = self._config.getint('Logging', 'SAMPLE_LOG_INTERVAL', fallback=60)
        self.SAMPLE_LOG_LENGTH = self._config.getint('Logging', 'SAMPLE_LOG_LENGTH', fallback=1000)

        # Processing settings
        self.ADJUSTMENT_INTERVAL = self._config.getint('Processing', 'ADJUSTMENT_INTERVAL', fallback=60)

        # Health Reporting settings
        self.DROP_THRESHOLD = self._config.getint('HealthReporting', 'DROP_THRESHOLD', fallback=100)

        # Queue Monitoring settings
        self.QUEUE_MONITOR_INTERVAL = self._config.getfloat('QueueMonitoring', 'MONITOR_INTERVAL', fallback=5.0)

        # Detailed Reporting settings
        self.DETAILED_REPORT_INTERVAL = self._config.getint('DetailedReporting', 'REPORT_INTERVAL', fallback=300)

        # Add these lines
        self.ENABLE_HEALTH_REPORTER = self._config.getboolean('HealthReporting', 'enable_health_reporter', fallback=True)
        
        # Add this line
        self.HEALTH_REPORT_LOG_FILE = os.path.join(self.LOG_FOLDER, 'health_report.log')

        # Add this line
        self.TIME_WINDOW_HOURS = self._config.getfloat('Processing', 'TIME_WINDOW_HOURS', fallback=8.0)

        if not self.SMA_HOST:
            raise ValueError("SMA_HOST is not set in settings.ini")

        # Add this line towards the end of the method
        self.SHUTDOWN_TIMEOUT = self._config.getint('Processing', 'SHUTDOWN_TIMEOUT', fallback=30)

        # Add this line for queue size threshold
        self.QUEUE_SIZE_THRESHOLD = int(os.getenv('QUEUE_SIZE_THRESHOLD', 1000))  # Default to 1000 if not set