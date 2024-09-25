import os
from pathlib import Path
from dotenv import load_dotenv
import configparser

class Config:
    def __init__(self):
        script_dir = Path(__file__).parent
        env_path = script_dir.parent / '.env'
        load_dotenv(dotenv_path=env_path)

        settings_file = script_dir / 'settings.ini'
        config = configparser.ConfigParser(interpolation=None)
        config.read(settings_file)

        self.AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
        self.AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
        self.S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')

        self.BASE_FOLDER = (script_dir / config.get('Paths', 'BASE_FOLDER', fallback='..')).resolve()
        self.DOWNLOADED_FILES_FOLDER = self.BASE_FOLDER / config.get('Paths', 'DOWNLOADED_FILES_FOLDER', fallback='illumio')
        self.LOG_FOLDER = self.BASE_FOLDER / config.get('Paths', 'LOG_FOLDER', fallback='logs')

        self.POLL_INTERVAL = config.getfloat('S3', 'POLL_INTERVAL')
        self.LOG_TIMEFRAME = config.getfloat('S3', 'LOG_TIMEFRAME')
        self.BASE_PATHS = config.get('S3', 'BASE_PATHS').split(',')
        self.STATE_FILE = config.get('S3', 'STATE_FILE', fallback='state.json')  # Add this line

        self.SMA_HOST = config.get('Syslog', 'SMA_HOST')
        self.SMA_PORT = config.getint('Syslog', 'SMA_PORT')
        self.USE_TCP = config.getboolean('Syslog', 'USE_TCP')
        self.MAX_MESSAGE_LENGTH = config.getint('Syslog', 'MAX_MESSAGE_LENGTH')
        self.MIN_MESSAGES_PER_SECOND = config.getfloat('Syslog', 'MIN_MESSAGES_PER_SECOND', fallback=5.0)
        self.MAX_MESSAGES_PER_SECOND = config.getfloat('Syslog', 'MAX_MESSAGES_PER_SECOND', fallback=100.0)
        self.ENABLE_DYNAMIC_SYSLOG_RATE = config.getboolean('Syslog', 'ENABLE_DYNAMIC_SYSLOG_RATE', fallback=True)

        self.BEATNAME = config.get('General', 'BEATNAME')

        self.BATCH_SIZE = config.getint('Processing', 'BATCH_SIZE', fallback=25)
        self.MIN_BATCH_SIZE = config.getint('Processing', 'MIN_BATCH_SIZE', fallback=10)
        self.MAX_BATCH_SIZE = config.getint('Processing', 'MAX_BATCH_SIZE', fallback=100)
        self.MIN_WORKERS = config.getint('Processing', 'MIN_WORKERS', fallback=2)
        self.MAX_WORKERS = config.getint('Processing', 'MAX_WORKERS', fallback=8)
        self.ENABLE_DYNAMIC_BATCH_SIZE = config.getboolean('Processing', 'ENABLE_DYNAMIC_BATCH_SIZE', fallback=True)
        self.ENABLE_DYNAMIC_WORKERS = config.getboolean('Processing', 'ENABLE_DYNAMIC_WORKERS', fallback=True)
        self.ENABLE_DYNAMIC_TIMEFRAME = config.getboolean('Processing', 'ENABLE_DYNAMIC_TIMEFRAME', fallback=True)

        # Increase the default value for MAX_POOL_CONNECTIONS
        self.MAX_POOL_CONNECTIONS = config.getint('S3', 'MAX_POOL_CONNECTIONS', fallback=10)