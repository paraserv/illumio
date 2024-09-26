#!/usr/bin/env python3
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
        script_dir = Path(__file__).parent
        env_path = script_dir.parent / '.env'
        load_dotenv(dotenv_path=env_path)

        settings_file = script_dir / 'settings.ini'
        config = configparser.ConfigParser(interpolation=None)
        config.read(settings_file)

        # AWS Credentials
        self.AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
        self.AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')

        # Paths
        self.BASE_FOLDER = (script_dir / config.get('Paths', 'BASE_FOLDER', fallback='..')).resolve()
        self.DOWNLOADED_FILES_FOLDER = self.BASE_FOLDER / config.get('Paths', 'DOWNLOADED_FILES_FOLDER', fallback='illumio')
        self.LOG_FOLDER = self.BASE_FOLDER / config.get('Paths', 'LOG_FOLDER', fallback='logs')
        self.STATE_FILE = config.get('Paths', 'STATE_FILE', fallback='state.json')
        self.CHECKPOINT_FILE = config.get('Paths', 'CHECKPOINT_FILE', fallback='checkpoint.json')

        # S3 Settings
        self.POLL_INTERVAL = config.getfloat('S3', 'POLL_INTERVAL', fallback=60.0)
        self.LOG_TIMEFRAME = config.getfloat('S3', 'LOG_TIMEFRAME', fallback=1.0)
        self.BASE_PATHS = config.get('S3', 'BASE_PATHS', fallback='illumio/summaries/,illumio/auditable_events/').split(',')
        self.MAX_POOL_CONNECTIONS = config.getint('S3', 'MAX_POOL_CONNECTIONS', fallback=10)
        self.ENABLE_DYNAMIC_TIMEFRAME = config.getboolean('Processing', 'ENABLE_DYNAMIC_TIMEFRAME', fallback=True)
        self.TIME_WINDOW_HOURS = config.getfloat('Processing', 'TIME_WINDOW_HOURS', fallback=1.0)

        # Syslog Settings
        self.SMA_HOST = config.get('Syslog', 'SMA_HOST')
        self.SMA_PORT = config.getint('Syslog', 'SMA_PORT')
        self.USE_TCP = config.getboolean('Syslog', 'USE_TCP', fallback=False)
        self.MAX_MESSAGE_LENGTH = config.getint('Syslog', 'MAX_MESSAGE_LENGTH', fallback=1024)
        self.MIN_MESSAGES_PER_SECOND = config.getint('Syslog', 'MIN_MESSAGES_PER_SECOND', fallback=5)
        self.MAX_MESSAGES_PER_SECOND = config.getint('Syslog', 'MAX_MESSAGES_PER_SECOND', fallback=250)
        self.ENABLE_DYNAMIC_SYSLOG_RATE = config.getboolean('Syslog', 'ENABLE_DYNAMIC_SYSLOG_RATE', fallback=True)

        # General Settings
        self.BEATNAME = config.get('General', 'BEATNAME', fallback='IllumioS3')

        # Processing Settings
        self.BATCH_SIZE = config.getint('Processing', 'BATCH_SIZE', fallback=100)
        self.MIN_BATCH_SIZE = config.getint('Processing', 'MIN_BATCH_SIZE', fallback=10)
        self.MAX_BATCH_SIZE = config.getint('Processing', 'MAX_BATCH_SIZE', fallback=1000)
        self.MIN_WORKERS = config.getint('Processing', 'MIN_WORKERS', fallback=1)
        self.MAX_WORKERS = config.getint('Processing', 'MAX_WORKERS', fallback=4)
        self.ENABLE_DYNAMIC_BATCH_SIZE = config.getboolean('Processing', 'ENABLE_DYNAMIC_BATCH_SIZE', fallback=True)
        self.ENABLE_DYNAMIC_WORKERS = config.getboolean('Processing', 'ENABLE_DYNAMIC_WORKERS', fallback=True)

        # Health Reporting Settings
        self.HEARTBEAT_INTERVAL = config.getfloat('HealthReporting', 'HEARTBEAT_INTERVAL', fallback=60.0)
        self.SUMMARY_INTERVAL = config.getfloat('HealthReporting', 'SUMMARY_INTERVAL', fallback=3600.0)

        # Additional Settings
        self.BASELINE_PERIOD = config.getfloat('S3', 'BASELINE_PERIOD', fallback=300.0)
        self.ADJUSTMENT_INTERVAL = config.getfloat('Processing', 'ADJUSTMENT_INTERVAL', fallback=60.0)