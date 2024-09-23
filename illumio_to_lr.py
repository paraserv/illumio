#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Illumio to LogRhythm Log Processor

This script processes Illumio Cloud log files and forwards them to the LogRhythm SIEM
via syslog. It handles both auditable events and summaries, transforming the
logs into a format compatible with LogRhythm's parsing requirements, which happens to
match the Syslog - Open Collector base MPE regex rule.

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
import logging
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, Any, List, Tuple
import configparser
import glob

# Script version
__version__ = "1.0.0"

# Load configuration
config = configparser.ConfigParser()
config.read('settings.ini')

LOG_FILE = config.get('Logging', 'LOG_FILE', fallback='illumio_to_lr.log')
LOG_LEVEL = config.get('Logging', 'LOG_LEVEL', fallback='INFO')
MAX_LOG_SIZE = config.getint('Logging', 'MAX_LOG_SIZE', fallback=10*1024*1024)  # Default 10 MB
BACKUP_COUNT = config.getint('Logging', 'BACKUP_COUNT', fallback=5)
BEATNAME = config.get('General', 'BEATNAME', fallback='IllumioS3')
DOWNLOADED_FILES_FOLDER = Path(config.get('Paths', 'DOWNLOADED_FILES_FOLDER'))
SMA_HOST = config.get('Syslog', 'SMA_HOST')
SMA_PORT = config.getint('Syslog', 'SMA_PORT')
USE_TCP = config.getboolean('Syslog', 'USE_TCP', fallback=False)
MAX_MESSAGE_LENGTH = config.getint('Syslog', 'MAX_MESSAGE_LENGTH', fallback=1024)
MAX_WORKERS = config.getint('Processing', 'MAX_WORKERS', fallback=5)

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(getattr(logging, LOG_LEVEL.upper()))
handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Now we can use logger
logger.info(f"BACKUP_COUNT set to: {BACKUP_COUNT}")

def cleanup_old_logs(log_file: str, backup_count: int):
    """Remove old log files exceeding the backup count."""
    base_name = log_file.replace('.log', '')
    log_files = glob.glob(f"{base_name}*.log*")
    logger.info(f"Found {len(log_files)} log files matching {base_name}*.log*")
    log_files.sort(key=os.path.getmtime, reverse=True)
    
    # Keep the current log file and up to backup_count rotated files
    files_to_keep = backup_count + 1
    
    if len(log_files) > files_to_keep:
        for old_log in log_files[files_to_keep:]:
            try:
                os.remove(old_log)
                logger.info(f"Removed old log file: {old_log}")
            except Exception as e:
                logger.error(f"Failed to remove old log file {old_log}: {e}")
    else:
        logger.info(f"No log files to remove. Current count ({len(log_files)}) does not exceed limit ({files_to_keep})")

    # Verify cleanup
    remaining_files = glob.glob(f"{base_name}*.log*")
    logger.info(f"After cleanup: {len(remaining_files)} log files remaining")

# Clean up old log files
cleanup_old_logs(LOG_FILE, BACKUP_COUNT)
cleanup_old_logs('illumio_log_sender.log', BACKUP_COUNT)

def is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        result = s.connect_ex((host, port))
        return result == 0

def transform_log_based_on_policy(log_entry: Dict[str, Any], folder_type: str) -> Dict[str, Any]:
    device_type = 'IllumioAudit' if folder_type == 'auditable_events' else 'IllumioSummary'
    
    result = {
        'beatname': BEATNAME,
        'device_type': device_type,
        'fullyqualifiedbeatname': BEATNAME,
    }

    # Define the order of fields as per the provided list
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
        'beatname': result['beatname'],
        'device_type': result['device_type'],
        'fullyqualifiedbeatname': result['fullyqualifiedbeatname']
    }
    for field in field_order:
        if field in result and result[field] is not None:
            ordered_result[field] = result[field]

    # Add original_message as the last field
    ordered_result['original_message'] = ''

    return ordered_result

def format_log_for_siem(transformed_log: Dict[str, Any], original_log: Dict[str, Any]) -> str:
    formatted_fields = []
    for k, v in transformed_log.items():
        if v:
            v = str(v).replace('|', '_')
            formatted_fields.append(f"{k}={v}")
    
    original_json = json.dumps(original_log)
    escaped_json = original_json.replace('|', '_')
    
    # Truncate the original message if it's too long
    max_original_length = MAX_MESSAGE_LENGTH - len('|'.join(formatted_fields)) - len("original_message=")
    if len(escaped_json) > max_original_length:
        escaped_json = escaped_json[:max_original_length-3] + "..."
    
    return '|'.join(formatted_fields) + f"|original_message={escaped_json}"

def send_logs(logs: List[Tuple[Dict[str, Any], Dict[str, Any]]], host: str, port: int):
    if not is_port_open(host, port):
        logger.error(f"Port {port} is not open on host {host}. Unable to send logs.")
        return

    logger.info(f"Attempting to send {len(logs)} logs to {host}:{port} via {'TCP' if USE_TCP else 'UDP'}")
    try:
        sock_type = socket.SOCK_STREAM if USE_TCP else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, sock_type) as sock:
            if USE_TCP:
                sock.connect((host, port))
            for transformed_log, original_log in logs:
                formatted_log = format_log_for_siem(transformed_log, original_log)
                syslog_message = f"<{transformed_log['device_type']}> {formatted_log}"
                if USE_TCP:
                    sock.sendall(syslog_message.encode() + b'\n')
                else:
                    sock.sendto(syslog_message.encode(), (host, port))
                logger.debug(f"Sent syslog message: {syslog_message}")
        logger.info(f"Successfully sent all {len(logs)} log entries")
    except Exception as e:
        logger.error(f"Failed to send logs to {host}:{port}: {e}")
        raise

def process_log_file(log_file: Path, sma_host: str, sma_port: int, folder_type: str):
    try:
        logger.info(f"Processing file: {log_file}")
        with log_file.open('r') as f:
            logs = [json.loads(line.strip()) for line in f if line.strip()]
        if logs:
            transformed_logs = [(transform_log_based_on_policy(log, folder_type), log) for log in logs]
            send_logs(transformed_logs, sma_host, sma_port)
            logger.info(f"Log processing completed successfully for {log_file}")
        else:
            logger.warning(f"No valid log entries found in {log_file}")
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON in file {log_file}")
    except Exception as e:
        logger.error(f"Error during log processing for {log_file}: {e}")

def main():
    try:
        logger.info("Starting Illumio log processing")
        logger.info("Cleaning up old log files...")
        cleanup_old_logs(LOG_FILE, BACKUP_COUNT)
        cleanup_old_logs('illumio_log_sender.log', BACKUP_COUNT)
        
        illumio_folder = DOWNLOADED_FILES_FOLDER / 'illumio'
        if not illumio_folder.exists():
            logger.error(f"Illumio folder does not exist: {illumio_folder}")
            return

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for folder_type in ['auditable_events', 'summaries']:
                folder_path = illumio_folder / folder_type
                if not folder_path.exists():
                    logger.warning(f"Folder does not exist: {folder_path}")
                    continue

                logger.info(f"Processing folder: {folder_path}")
                log_files = list(folder_path.glob('*'))  # This will find all files
                log_files = [f for f in log_files if f.is_file()]  # Ensure we only process files, not directories
                logger.info(f"Found {len(log_files)} log files in {folder_path}")
                
                for file_path in log_files:
                    logger.info(f"Submitting file for processing: {file_path}")
                    executor.submit(process_log_file, file_path, SMA_HOST, SMA_PORT, folder_type)
        
        logger.info("Illumio log processing completed")
    except Exception as e:
        logger.exception("An error occurred during script execution")

if __name__ == "__main__":
    main()