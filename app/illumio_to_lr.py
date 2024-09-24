#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Illumio to LogRhythm Log Processor

This script processes Illumio Cloud log files and forwards them to the LogRhythm SIEM
via syslog. It handles both auditable events and summaries, transforming the
logs into a format compatible with LogRhythm's parsing requirements, which matches
the Syslog - Open Collector base MPE regex rule.

Features:
- Configurable via settings.ini file
- Supports both UDP and TCP syslog transmission
- Implements log rotation to manage file sizes
- Uses multi-threading for improved performance

Author: Nathan Church
Company: Exabeam (formerly LogRhythm)
Created: September 2024

Usage:
    python illumio_to_lr.py

Requirements:
    Python 3.12.6 or higher
    See requirements.txt for additional dependencies
"""

import json
import socket
import logging
import time
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import configparser
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Dict, Any

from logger_config import setup_logger

# Set up logging immediately after imports
logger = setup_logger('illumio_to_lr')

# Get the directory where the script is located
script_dir = Path(__file__).parent

# Construct the path to settings.ini and .env
settings_file = script_dir / 'settings.ini'
env_path = script_dir.parent / '.env'

# Log the paths for debugging
logger.debug(f"Script directory: {script_dir}")
logger.debug(f"Loading .env from: {env_path}")
logger.debug(f"Loading settings.ini from: {settings_file}")

# Load environment variables from the .env file
load_dotenv(dotenv_path=env_path)

# Load configuration with interpolation disabled
config = configparser.ConfigParser(interpolation=None)
config.read(settings_file)

# Debugging: Log the sections loaded from settings.ini
logger.debug(f"Config sections: {config.sections()}")

# Constants
BASE_FOLDER = (script_dir / config.get('Paths', 'BASE_FOLDER', fallback='..')).resolve()
DOWNLOADED_FILES_FOLDER = BASE_FOLDER / config.get('Paths', 'DOWNLOADED_FILES_FOLDER', fallback='illumio')
LOG_FOLDER = BASE_FOLDER / config.get('Paths', 'LOG_FOLDER', fallback='logs')
BEATNAME = config.get('General', 'BEATNAME', fallback='IllumioCustomBeat')
LOG_FILE = LOG_FOLDER / config.get('Logging', 'LOG_FILE', fallback='app.log')
BACKUP_COUNT = config.getint('Logging', 'BACKUP_COUNT', fallback=2)

# Retrieve SIEM configuration from environment variables or settings.ini
sma_host_from_env = os.getenv('SMA_HOST')
sma_host_from_config = config.get('Syslog', 'SMA_HOST', fallback=None)
SMA_HOST = sma_host_from_env or sma_host_from_config

SMA_PORT = int(os.getenv('SMA_PORT', config.get('Syslog', 'SMA_PORT', fallback='514')))
USE_TCP = os.getenv('USE_TCP', config.get('Syslog', 'USE_TCP', fallback='False')).lower() == 'true'
MAX_MESSAGE_LENGTH = int(os.getenv('MAX_MESSAGE_LENGTH', config.get('Syslog', 'MAX_MESSAGE_LENGTH', fallback='2048')))
MAX_WORKERS = int(os.getenv('MAX_WORKERS', config.get('Processing', 'MAX_WORKERS', fallback='10')))

# Log the initial configuration
logger.info(f"Script started with configuration:")
logger.info(f"  BEATNAME={BEATNAME}")
logger.info(f"  BASE_FOLDER={BASE_FOLDER}")
logger.info(f"  DOWNLOADED_FILES_FOLDER={DOWNLOADED_FILES_FOLDER}")
logger.info(f"  LOG_FOLDER={LOG_FOLDER}")
logger.info(f"  SMA_HOST={SMA_HOST}")
logger.info(f"  SMA_PORT={SMA_PORT}")
logger.info(f"  USE_TCP={USE_TCP}")
logger.info(f"  MAX_MESSAGE_LENGTH={MAX_MESSAGE_LENGTH}")
logger.info(f"  MAX_WORKERS={MAX_WORKERS}")

# Check if SMA_HOST is set
if not SMA_HOST:
    logger.error("SMA_HOST is not set in environment variables or settings.ini")
    sys.exit(1)
if not SMA_PORT:
    logger.error("SMA_PORT is not set; defaulting to 514")
    SMA_PORT = 514

# Function to clean up old log files
def cleanup_old_logs(log_file: Path, backup_count: int):
    """Remove old log files exceeding the backup count."""
    base_name = log_file.stem
    log_files = list(log_file.parent.glob(f"{base_name}*.log*"))
    logger.info(f"Found {len(log_files)} log files matching {base_name}*.log*")
    log_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

    # Keep the current log file and up to backup_count rotated files
    files_to_keep = backup_count + 1

    if len(log_files) > files_to_keep:
        for old_log in log_files[files_to_keep:]:
            try:
                old_log.unlink()
                logger.info(f"Removed old log file: {old_log}")
            except Exception as e:
                logger.error(f"Failed to remove old log file {old_log}: {e}")
    else:
        logger.info(f"No log files to remove. Current count ({len(log_files)}) does not exceed limit ({files_to_keep})")

    # Verify cleanup
    remaining_files = list(log_file.parent.glob(f"{base_name}*.log*"))
    logger.info(f"After cleanup: {len(remaining_files)} log files remaining")

# Clean up old log files
cleanup_old_logs(LOG_FILE, BACKUP_COUNT)
cleanup_old_logs(LOG_FOLDER / 'illumio_log_sender.log', BACKUP_COUNT)

# Function to check if port is open
def is_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except (socket.timeout, socket.error) as e:
        logger.error(f"Port {port} on host {host} is not open: {e}")
        return False

# Check if the syslog server port is open
if not is_port_open(SMA_HOST, SMA_PORT):
    logger.error(f"Cannot connect to {SMA_HOST}:{SMA_PORT}. Please check the network connection and syslog server.")
    sys.exit(1)

def transform_log_based_on_policy(log_entry: Dict[str, Any], folder_type: str) -> Dict[str, Any]:
    device_type = 'IllumioAudit' if folder_type == 'auditable_events' else 'IllumioSummary'
    
    result = {
        'beatname': BEATNAME,
        'device_type': device_type,
        'fullyqualifiedbeatname': BEATNAME,
    }

    # Define the order of fields as per the given list
    field_order = [
        'time', 'object', 'objectname', 'objecttype', 'hash', 'policy', 'result', 'url', 'useragent',
        'responsecode', 'subject', 'version', 'command', 'reason', 'action', 'status', 'sessiontype',
        'process', 'processid', 'parentprocessid', 'parentprocessname', 'parentprocesspath', 'quantity',
        'amount', 'size', 'rate', 'minutes', 'seconds', 'milliseconds', 'session', 'kilobytesin',
        'kilobytesout', 'kilobytes', 'packetsin', 'packetsout', 'severity', 'vmid', 'vendorinfo',
        'threatname', 'threatid', 'cve', 'smac', 'dmac', 'sinterface', 'dinterface', 'sip', 'dip',
        'snatip', 'dnatip', 'sname', 'dname', 'serialnumber', 'login', 'account', 'sender', 'recipient',
        'group', 'domainimpacted', 'domainorigin', 'protnum', 'protname', 'sport', 'dport', 'snatport',
        'dnatport', 'augmented', 'tag1', 'tag2', 'tag3', 'tag4', 'tag5', 'tag6', 'tag7', 'tag8', 'tag9', 'tag10'
    ]

    def safe_get(dictionary, key):
        value = dictionary.get(key)
        if value is None:
            return None
        if isinstance(value, str):
            return value.strip() or None
        return value

    if folder_type == 'auditable_events':
        audit_fields = {
            'time': safe_get(log_entry, 'timestamp'),
            'objectname': safe_get(log_entry, 'pce_fqdn'),
            'url': safe_get(log_entry, 'href'),
            'version': str(safe_get(log_entry, 'version') or ''),
            'result': safe_get(log_entry, 'status'),
            'severity': safe_get(log_entry, 'severity'),
            'action': safe_get(log_entry, 'action'),
            'vendorinfo': safe_get(log_entry, 'event_type'),
        }
        if log_entry.get('notifications'):
            notification = log_entry['notifications'][0]
            info = notification.get('info', {})
            audit_fields.update({
                'sip': safe_get(info, 'src_ip'),
                'command': safe_get(info, 'api_method'),
                'tag1': safe_get(notification, 'notification_type'),
                'tag2': safe_get(info, 'api_endpoint'),
                'tag3': safe_get(info, 'api_method'),
            })
        result.update({k: v for k, v in audit_fields.items() if v is not None})
    else:  # summaries
        summary_fields = {
            'time': safe_get(log_entry, 'timestamp'),
            'object': safe_get(log_entry, 'sn'),
            'objecttype': safe_get(log_entry, 'class'),
            'policy': safe_get(log_entry, 'pd_qualifier'),
            'result': safe_get(log_entry, 'pd'),
            'url': safe_get(log_entry, 'src_href'),
            'subject': safe_get(log_entry, 'dst_href'),
            'version': str(safe_get(log_entry, 'version') or ''),
            'status': safe_get(log_entry, 'state'),
            'process': safe_get(log_entry, 'pn'),
            'quantity': str(safe_get(log_entry, 'count') or ''),
            'seconds': str(safe_get(log_entry, 'interval_sec') or ''),
            'kilobytesin': safe_get(log_entry, 'tdms'),
            'kilobytesout': safe_get(log_entry, 'ddms'),
            'sip': safe_get(log_entry, 'src_ip'),
            'dip': safe_get(log_entry, 'dst_ip'),
            'sname': safe_get(log_entry, 'src_hostname'),
            'dname': safe_get(log_entry, 'dst_hostname'),
            'login': safe_get(log_entry, 'un'),
            'protnum': str(safe_get(log_entry, 'proto') or ''),
            'dport': str(safe_get(log_entry, 'dst_port') or ''),
            'tag4': safe_get(log_entry, 'dir'),
            'tag5': safe_get(log_entry, 'pce_fqdn'),
        }
        
        proto = safe_get(log_entry, 'proto')
        if proto is not None:
            summary_fields['protname'] = 'TCP' if proto == 6 else 'UDP'
        
        src_labels = log_entry.get('src_labels', {})
        dst_labels = log_entry.get('dst_labels', {})
        src_info = ', '.join(f'{k}={v}' for k, v in src_labels.items() if v)
        dst_info = ', '.join(f'{k}={v}' for k, v in dst_labels.items() if v)
        if src_info:
            summary_fields['tag2'] = f'Source: {src_info}'
        if dst_info:
            summary_fields['tag3'] = f'Destination: {dst_info}'
        
        result.update({k: v for k, v in summary_fields.items() if v is not None})

    # Create the final ordered result, ensuring required fields are first
    ordered_result = {
        'beatname': BEATNAME,
        'device_type': result['device_type'],
        'fullyqualifiedbeatname': BEATNAME
    }
    for field in field_order:
        if field in result and result[field] is not None:
            ordered_result[field] = result[field]
    ordered_result['original_message'] = ''

    return ordered_result

def format_log_for_siem(transformed_log: Dict[str, Any], original_log: Dict[str, Any]) -> str:
    formatted_fields = []
    for k, v in transformed_log.items():
        if v is not None and v != '':  # Only include non-empty fields
            v = str(v).replace('|', '_')
            formatted_fields.append(f"{k}={v}")
    
    formatted_log = '|'.join(formatted_fields)
    
    original_json = json.dumps(original_log)
    escaped_json = original_json.replace('|', '_')
    
    # Truncate the original message if it's too long
    max_original_length = MAX_MESSAGE_LENGTH - len(formatted_log) - len("|original_message=")
    if len(escaped_json) > max_original_length:
        escaped_json = escaped_json[:max_original_length-3] + "..."
    
    return f"{formatted_log}|original_message={escaped_json}"

def send_logs(logs: List[Tuple[Dict[str, Any], Dict[str, Any]]], host: str, port: int):
    logger.info(f"Attempting to send {len(logs)} logs to {host}:{port} via {'TCP' if USE_TCP else 'UDP'}")
    try:
        sock_type = socket.SOCK_STREAM if USE_TCP else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, sock_type) as sock:
            if USE_TCP:
                sock.connect((host, port))
            for transformed_log, original_log in logs:
                formatted_log = format_log_for_siem(transformed_log, original_log)
                current_time = time.strftime("%b %d %Y %H:%M:%S", time.localtime())
                syslog_ip = socket.gethostbyname(socket.gethostname())
                syslog_message = f"{current_time} {syslog_ip} <USER:NOTE> {formatted_log}"
                if USE_TCP:
                    sock.sendall(syslog_message.encode() + b'\n')
                else:
                    sock.sendto(syslog_message.encode(), (host, port))
                logger.debug(f"Sent syslog message: {syslog_message}")
        logger.info(f"Successfully sent all {len(logs)} log entries")
    except Exception as e:
        logger.error(f"Failed to send logs to {host}:{port}: {e}")
        raise

def process_log_file(file_path, sma_host, sma_port, folder_type):
    """Process a single log file and send its contents as syslog messages."""
    try:
        logger.info(f"Processing file: {file_path}")
        with open(file_path, 'r') as f:
            logs = [json.loads(line.strip()) for line in f if line.strip()]
        if logs:
            transformed_logs = [(transform_log_based_on_policy(log, folder_type), log) for log in logs]
            send_logs(transformed_logs, sma_host, sma_port)
            logger.info(f"Log processing completed successfully for {file_path}")
        else:
            logger.warning(f"No valid log entries found in {file_path}")
        
        # After processing, delete the file
        os.remove(file_path)
        logger.info(f"Processed and deleted file: {file_path}")
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON in file {file_path}")
    except Exception as e:
        logger.error(f"Error processing file {file_path}: {e}")

def main():
    try:
        logger.info("Starting Illumio log processing")
        if not DOWNLOADED_FILES_FOLDER.exists():
            logger.error(f"Downloaded files folder does not exist: {DOWNLOADED_FILES_FOLDER}")
            return

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for folder_type in ['auditable_events', 'summaries']:
                folder_path = DOWNLOADED_FILES_FOLDER / folder_type
                if not folder_path.exists():
                    logger.warning(f"Folder does not exist: {folder_path}")
                    continue

                logger.info(f"Processing folder: {folder_path}")
                log_files = list(folder_path.glob('*'))
                log_files = [f for f in log_files if f.is_file()]
                logger.info(f"Found {len(log_files)} log files in {folder_path}")
                
                for file_path in log_files:
                    logger.info(f"Submitting file for processing: {file_path}")
                    executor.submit(process_log_file, file_path, SMA_HOST, SMA_PORT, folder_type)
        
        logger.info("Illumio log processing completed")
    except Exception as e:
        logger.exception("An error occurred during script execution")

if __name__ == "__main__":
    main()