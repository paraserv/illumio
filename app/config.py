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
        config = configparser.ConfigParser()
        script_dir = Path(__file__).parent
        settings_file = script_dir / 'settings.ini'
        config.read(settings_file)

        # Load configuration from environment variables or settings.ini
        self.AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
        self.AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
        
        # S3 settings
        self.MINUTES = config.getint('S3', 'MINUTES', fallback=30)
        self.MAX_FILES_PER_FOLDER = config.getint('S3', 'MAX_FILES_PER_FOLDER', fallback=5)
        self.LOG_TIMEFRAME = config.getfloat('S3', 'LOG_TIMEFRAME', fallback=2.0)
        self.BASE_PATHS = config.get('S3', 'BASE_PATHS', fallback='').split(',')
        self.ENABLE_DYNAMIC_TIMEFRAME = config.getboolean('S3', 'ENABLE_DYNAMIC_TIMEFRAME', fallback=True)
        self.MAX_POOL_CONNECTIONS = config.getint('S3', 'MAX_POOL_CONNECTIONS', fallback=10)
        
        # Paths
        self.STATE_FILE = config.get('Paths', 'STATE_FILE', fallback='state.json')
        self.DOWNLOADED_FILES_FOLDER = config.get('Paths', 'DOWNLOADED_FILES_FOLDER', fallback='illumio')
        self.LOG_FOLDER = config.get('Paths', 'LOG_FOLDER', fallback='logs')
        
        # Health Reporting
        self.HEARTBEAT_INTERVAL = config.getfloat('HealthReporting', 'HEARTBEAT_INTERVAL', fallback=15.0)
        self.SUMMARY_INTERVAL = config.getfloat('HealthReporting', 'SUMMARY_INTERVAL', fallback=20.0)
        
        # Syslog settings
        self.SMA_HOST = config.get('Syslog', 'SMA_HOST')
        self.SMA_PORT = config.getint('Syslog', 'SMA_PORT', fallback=514)
        self.MAX_MESSAGES_PER_SECOND = config.getint('Syslog', 'MAX_MESSAGES_PER_SECOND', fallback=1000)
        self.MIN_MESSAGES_PER_SECOND = config.getint('Syslog', 'MIN_MESSAGES_PER_SECOND', fallback=5)
        self.ENABLE_DYNAMIC_SYSLOG_RATE = config.getboolean('Syslog', 'ENABLE_DYNAMIC_SYSLOG_RATE', fallback=True)
        self.USE_TCP = config.getboolean('Syslog', 'USE_TCP', fallback=False)
        self.MAX_MESSAGE_LENGTH = config.getint('Syslog', 'MAX_MESSAGE_LENGTH', fallback=2048)
        
        # General settings
        self.BEATNAME = config.get('General', 'BEATNAME', fallback='IllumioS3')
        
        # Processing settings
        self.MAX_WORKERS = config.getint('Processing', 'MAX_WORKERS', fallback=4)
        self.BATCH_SIZE = config.getint('Processing', 'BATCH_SIZE', fallback=100)
        self.POLL_INTERVAL = config.getint('S3', 'POLL_INTERVAL', fallback=10)

        if not self.SMA_HOST:
            raise ValueError("SMA_HOST is not set in settings.ini")