#!/usr/bin/env python3
"""
Processes logs and sends them to the SIEM via syslog.
"""

# Standard library imports
import json
import os
import time
import math
import threading
from pathlib import Path
import configparser
import sqlite3
import logging

# Third-party imports
import socket

# Local application imports
from logger_config import get_logger
from health_reporter import HealthReporter

# Typing imports
from typing import Dict, Any, List, Tuple

logger = get_logger(__name__)

class LogProcessor:
    def __init__(
        self,
        sma_host,
        sma_port,
        max_messages_per_second,
        min_messages_per_second,
        enable_dynamic_syslog_rate,
        beatname,
        use_tcp,
        max_message_length,
        health_reporter: HealthReporter
    ):
        # Load settings
        config = configparser.ConfigParser()
        config.read('settings.ini')

        self.sma_host = sma_host
        self.sma_port = sma_port
        self.max_messages_per_second = max_messages_per_second
        self.min_messages_per_second = min_messages_per_second
        self.enable_dynamic_syslog_rate = enable_dynamic_syslog_rate
        self.BEATNAME = beatname
        self.USE_TCP = use_tcp
        self.MAX_MESSAGE_LENGTH = max_message_length
        self.syslog = self._setup_syslog()
        if self.syslog is None:
            logger.error(f"Failed to set up syslog connection to {self.sma_host}:{self.sma_port}")
            # You might want to raise an exception here or implement a retry mechanism
        self.message_count = 0
        self.last_send_time = time.time()
        self.health_reporter = health_reporter
        self.baseline_period = config.getfloat('Syslog', 'BASELINE_PERIOD', fallback=300)
        self.baseline_start_time = time.time()
        self.baseline_data = []
        self.last_adjustment_time = time.time()
        self.adjustment_interval = config.getfloat('Syslog', 'ADJUSTMENT_INTERVAL', fallback=60)
        self.app_logger = get_logger(__name__)
        self.last_log_time = time.time()
        self.log_interval = 60  # Log at most once per minute
        self.dropped_logs = {'summaries': 0, 'auditable_events': 0}
        self.queue_lock = threading.Lock()
        self.tokens = self.max_messages_per_second
        self.last_refill = time.time()
        self.token_lock = threading.Lock()
        self._setup_persistent_queue()

    def _setup_syslog(self):
        try:
            sock_type = socket.SOCK_STREAM if self.USE_TCP else socket.SOCK_DGRAM
            syslog = socket.socket(socket.AF_INET, sock_type)
            if self.USE_TCP:
                syslog.connect((self.sma_host, self.sma_port))
            logger.info(f"Syslog connection established to {self.sma_host}:{self.sma_port}")
            return syslog
        except Exception as e:
            logger.error(f"Error setting up syslog connection: {e}")
            return None

    def _setup_persistent_queue(self):
        self.db_connection = sqlite3.connect('log_queue.db', check_same_thread=False)
        self.db_cursor = self.db_connection.cursor()
        self.db_cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_message TEXT,
                log_type TEXT
            )
        ''')
        self.db_connection.commit()

    def enqueue_log(self, formatted_log, log_type):
        with self.queue_lock:
            self.db_cursor.execute('''
                INSERT INTO log_queue (log_message, log_type) VALUES (?, ?)
            ''', (formatted_log, log_type))
            self.db_connection.commit()

    def dequeue_log(self):
        with self.queue_lock:
            self.db_cursor.execute('SELECT id, log_message, log_type FROM log_queue ORDER BY id ASC LIMIT 1')
            record = self.db_cursor.fetchone()
            if record:
                self.db_cursor.execute('DELETE FROM log_queue WHERE id = ?', (record[0],))
                self.db_connection.commit()
                return record[1], record[2]
            else:
                return None, None

    def drain_queue(self, stop_event):
        while not stop_event.is_set():
            with self.queue_lock:
                self.db_cursor.execute(
                    'SELECT id, log_message, log_type FROM log_queue ORDER BY id ASC LIMIT 100'
                )
                records = self.db_cursor.fetchall()
                if records:
                    ids_to_delete = []
                    for record in records:
                        if stop_event.is_set():
                            logger.info("Stopping drain_queue due to shutdown signal.")
                            break
                        log_id, log_message, log_type = record
                        sent = self._send_log(log_message, log_type)
                        if not sent:
                            logger.error(f"Failed to send log: {log_message[:100]}...")
                            break  # Stop processing if send fails
                        else:
                            ids_to_delete.append((log_id,))
                            self.health_reporter.report_syslog_sent(1, log_type)
                    if ids_to_delete:
                        self.db_cursor.executemany('DELETE FROM log_queue WHERE id = ?', ids_to_delete)
                        self.db_connection.commit()
                else:
                    break

    def process_log_file(
        self,
        file_path: Path,
        log_type: str,
        stop_event: threading.Event
    ) -> Tuple[bool, int]:
        try:
            self.app_logger.info(f"Processing file: {file_path}, Type: {log_type}")
            
            logs_to_send = []
            with open(file_path, 'r') as f:
                logs = f.readlines()
                total_logs = len(logs)
                logger.info(f"Extracted {total_logs} logs from {file_path}")
                for log_entry in logs:
                    if stop_event.is_set():
                        logger.info(f"Stopping log processing for {file_path} due to shutdown signal.")
                        return False, 0
                    try:
                        log_entry = json.loads(log_entry.strip())
                        transformed_log = self.transform_log_based_on_policy(log_entry, log_type)
                        if transformed_log is not None:
                            logs_to_send.append((transformed_log, log_entry))
                            self.health_reporter.report_logs_extracted(1, log_type)
                        else:
                            logger.warning(f"Skipping log entry due to transformation failure: {log_entry}")
                    except Exception as e:
                        logger.error(f"Error processing log entry: {e}")
                        self.health_reporter.report_error(f"Error processing log entry: {e}", log_type)
                        self.dropped_logs[log_type] += 1
        
            self.app_logger.info(f"Extracted {len(logs_to_send)} logs from {file_path}")
            self.send_logs(logs_to_send, log_type, stop_event)
            
            self.app_logger.info(f"Log processing completed successfully for {file_path}")
            return True, len(logs_to_send)
        except Exception as e:
            self.app_logger.error(f"Error processing log file {file_path}: {e}")
            return False, 0

    def transform_log_based_on_policy(self, log_entry: Dict[str, Any], folder_type: str) -> Dict[str, Any]:
        device_type = 'IllumioAudit' if folder_type == 'auditable_events' else 'IllumioSummary'
        
        result = {
            'beatname': self.BEATNAME,
            'device_type': device_type,
            'fullyqualifiedbeatname': self.BEATNAME,
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

        # Add tag1 with the same value as device_type
        result['tag1'] = device_type

        # Create the final ordered result, ensuring required fields are first
        ordered_result = {
            'beatname': self.BEATNAME,
            'device_type': result['device_type'],
            'fullyqualifiedbeatname': self.BEATNAME
        }
        for field in field_order:
            if field in result and result[field] is not None:
                ordered_result[field] = result[field]
        ordered_result['original_message'] = ''

        return ordered_result

    def format_log_for_siem(self, transformed_log: Dict[str, Any], original_log: Dict[str, Any]) -> str:
        formatted_fields = []
        for k, v in transformed_log.items():
            if v is not None and v != '':  # Only include non-empty fields
                v = str(v).replace('|', '_')
                formatted_fields.append(f"{k}={v}")
        
        formatted_log = '|'.join(formatted_fields)
        
        original_json = json.dumps(original_log)
        escaped_json = original_json.replace('|', '_')
        
        # Truncate the original message if it's too long
        max_original_length = self.MAX_MESSAGE_LENGTH - len(formatted_log) - len("|original_message=")
        if len(escaped_json) > max_original_length:
            escaped_json = escaped_json[:max_original_length-3] + "..."
        
        return f"{formatted_log}|original_message={escaped_json}"

    def send_logs(self, logs, log_type, stop_event: threading.Event, batch_size=100):
        for i in range(0, len(logs), batch_size):
            batch = logs[i:i + batch_size]
            if stop_event.is_set():
                logger.info("Stopping send_logs due to shutdown signal.")
                break
            for transformed_log, original_log in batch:
                if stop_event.is_set():
                    logger.info("Stopping send_logs due to shutdown signal.")
                    break
                formatted_log = self.format_log_for_siem(transformed_log, original_log)
                self.enqueue_log(formatted_log, log_type)
            self.drain_queue(stop_event)
            if stop_event.is_set():
                logger.info("Stopping send_logs due to shutdown signal.")
                break

    def _send_log(self, log_line, log_type):
        max_retries = 5
        retry_delay = 1  # in seconds

        for attempt in range(max_retries):
            try:
                if self.send_to_siem(log_line):
                    self.health_reporter.report_syslog_sent(1, log_type)
                    return True
                else:
                    logger.error(f"Attempt {attempt + 1}: Failed to send log.")
            except Exception as e:
                logger.error(f"Exception in _send_log: {e}")
                self.health_reporter.report_error(f"Exception in _send_log: {e}", log_type)
            time.sleep(retry_delay)
            retry_delay *= 2  # Exponential backoff

        # After max retries, log the error and continue
        self.health_reporter.report_error("Max retries reached. Log dropped.", log_type)
        return False

    def _refill_tokens(self):
        current_time = time.time()
        elapsed = current_time - self.last_refill
        refill_amount = elapsed * self.max_messages_per_second
        with self.token_lock:
            self.tokens = min(self.max_messages_per_second, self.tokens + refill_amount)
            self.last_refill = current_time

    def send_to_siem(self, log_line):
        if self.syslog is None:
            logger.error("Syslog connection is not available")
            return False

        self._refill_tokens()
        with self.token_lock:
            if self.tokens >= 1:
                self.tokens -= 1
                try:
                    if self.USE_TCP:
                        self.syslog.sendall(log_line.encode() + b'\n')
                    else:
                        self.syslog.sendto(log_line.encode(), (self.sma_host, self.sma_port))
                    return True
                except Exception as e:
                    logger.error(f"Error sending log to SIEM: {e}")
                    # Try to re-establish the connection
                    self.syslog = self._setup_syslog()
                    return False
            else:
                # Tokens exhausted, wait and retry
                time.sleep(1 / self.max_messages_per_second)
                return self.send_to_siem(log_line)

    def adjust_syslog_rate(self, logs_sent, start_time):
        current_time = time.time()
        if current_time - self.last_adjustment_time < self.adjustment_interval:
            return  # Don't adjust if less than a minute has passed since the last adjustment

        if current_time - self.baseline_start_time < self.baseline_period:
            self.app_logger.info("Log Processor: Still in baseline period. Not adjusting syslog rate.")
            return

        elapsed_time = current_time - start_time
        current_rate = logs_sent / elapsed_time

        if current_rate < self.max_messages_per_second * 0.8:  # If we're sending at less than 80% capacity
            new_rate = min(self.max_messages_per_second, self.max_messages_per_second * 1.1)  # Increase by 10%
        elif current_rate > self.max_messages_per_second:
            new_rate = max(self.min_messages_per_second, self.max_messages_per_second * 0.9)  # Decrease by 10%
        else:
            return  # No adjustment needed

        if new_rate != self.max_messages_per_second:
            self.max_messages_per_second = round(new_rate)
            message = f"Log Processor: Adjusted syslog sending rate: {self.max_messages_per_second} messages/s. This adjustment aims to optimize log sending based on current processing capabilities and system load."
            self.app_logger.info(message)
            self.health_reporter.log_message(message)
        
        self.last_adjustment_time = current_time

    def close(self):
        if self.syslog:
            try:
                self.syslog.close()
                logger.info("Syslog socket closed.")
            except Exception as e:
                logger.error(f"Error closing syslog socket: {e}")