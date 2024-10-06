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

        # Initialize the configparser
        self._config = configparser.ConfigParser()

        # Load settings.ini
        script_dir = Path(__file__).parent
        settings_file = script_dir.parent / 'settings.ini'  # Look for settings.ini in the project root
        self._config.read(settings_file)
        
        if not self._config.sections():
            raise FileNotFoundError(f"Settings file not found or empty: {settings_file}")
        
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

        # Set base directories
        self.BASE_DIR = Path(__file__).parent.parent  # This is the project root
        self.APP_DIR = self.BASE_DIR / 'app'
        self.STATE_DIR = self.BASE_DIR / 'state'
        self.LOG_DIR = self.BASE_DIR / 'logs'

        # Ensure directories exist
        self.STATE_DIR.mkdir(parents=True, exist_ok=True)
        self.LOG_DIR.mkdir(parents=True, exist_ok=True)

        # Update paths
        self.STATE_FILE = self.STATE_DIR / 'state.json'
        self.APP_LOG_FILE = self.LOG_DIR / 'app.json'
        self.HEALTH_REPORT_LOG_FILE = self.LOG_DIR / 'health_report.json'
        self.LOG_QUEUE_DB = self.STATE_DIR / 'log_queue.db'
        self.DOWNLOADS_DIR = self.STATE_DIR / 'downloads'
        self.QUEUE_DB_FILE = self.LOG_QUEUE_DB

        # Ensure downloads directory exists
        self.DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

        # Add this line to create the QUEUE_DB_FILE attribute
        self.QUEUE_DB_FILE = self.LOG_QUEUE_DB

        # Add this line to maintain compatibility with existing code
        self.LOG_FOLDER = self.LOG_DIR

        # Health Reporting
        self.HEARTBEAT_INTERVAL = self._config.getfloat('HealthReporting', 'HEARTBEAT_INTERVAL', fallback=15.0)
        self.SUMMARY_INTERVAL = self._config.getfloat('HealthReporting', 'SUMMARY_INTERVAL', fallback=20.0)
        self.ENABLE_HEALTH_REPORTER = self._config.getboolean('HealthReporting', 'ENABLE_HEALTH_REPORTER', fallback=True)
        
        # Syslog settings
        if 'Syslog' not in self._config.sections():
            raise ValueError("Syslog section missing from settings.ini")
        
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
        self.LOG_TYPES = self._config.get('General', 'LOG_TYPES', fallback='auditable_events,summaries').split(',')

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

        # Maintenance settings
        self.ENABLE_MAINTENANCE = self._config.getboolean('Maintenance', 'ENABLE_MAINTENANCE', fallback=True)
        self.MAINTENANCE_INTERVAL = self._config.getint('Maintenance', 'MAINTENANCE_INTERVAL', fallback=86400)
        self.LOG_CLEANUP_AGE = self._config.getint('Maintenance', 'LOG_CLEANUP_AGE', fallback=30)
        self.STATE_FILE_BACKUP_INTERVAL = self._config.getint('Maintenance', 'STATE_FILE_BACKUP_INTERVAL', fallback=86400)
        self.DB_VACUUM_INTERVAL = self._config.getint('Maintenance', 'DB_VACUUM_INTERVAL', fallback=604800)
        self.DB_CLEANUP_AGE = self._config.getint('Maintenance', 'DB_CLEANUP_AGE', fallback=30)

    @property
    def RETAIN_DOWNLOADED_LOGS(self):
        return self._config.getboolean('Processing', 'RETAIN_DOWNLOADED_LOGS', fallback=False)