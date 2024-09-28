#!/usr/bin/env python3
"""
Initializer module for setting up the application environment.
"""

# Standard library imports
from pathlib import Path
import logging

# Local application imports
from config import Config

def initialize_directories():
    config = Config()
    directories = [
        config.LOG_FOLDER,
        config.DOWNLOADED_FILES_FOLDER,
        # Add any other directories your application needs
    ]
    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            logging.info(f"Directory created or already exists: {directory}")
        except Exception as e:
            logging.error(f"Failed to create directory {directory}: {e}")
            raise