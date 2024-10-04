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
import queue
from datetime import datetime, timedelta
import traceback

# Third-party imports
import socket

# Local application imports
from logger_config import get_logger
from health_reporter import HealthReporter

# Typing imports
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

class TokenBucket:
    def __init__(self, rate, capacity=None):
        self.rate = rate
        self.capacity = capacity or rate
        self.tokens = self.capacity
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def consume(self):
        with self.lock:
            now = time.time()
            time_passed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + time_passed * self.rate)
            self.last_refill = now

            if self.tokens < 1:
                return False
            self.tokens -= 1
            return True

class LogProcessor:
    def __init__(
        self,
        config,
        health_reporter: HealthReporter,
        stop_event: threading.Event
    ):
        self.config = config
        self.sma_host = config.SMA_HOST
        self.sma_port = config.SMA_PORT
        self.max_messages_per_second = config.MAX_MESSAGES_PER_SECOND
        self.token_bucket = TokenBucket(self.max_messages_per_second)
        self.min_messages_per_second = config.MIN_MESSAGES_PER_SECOND
        self.enable_dynamic_syslog_rate = config.ENABLE_DYNAMIC_SYSLOG_RATE
        self.BEATNAME = config.BEATNAME
        self.USE_TCP = config.USE_TCP
        self.MAX_MESSAGE_LENGTH = config.MAX_MESSAGE_LENGTH
        self.health_reporter = health_reporter
        self.stop_event = stop_event

        self.syslog = None
        self.message_count = 0
        self.last_send_time = time.time()
        self.baseline_start_time = time.time()
        self.baseline_data = []
        self.last_adjustment_time = time.time()
        self.app_logger = get_logger(__name__)
        self.last_log_time = time.time()
        self.dropped_logs = {'summaries': 0, 'auditable_events': 0}
        self.queue_lock = threading.Lock()
        self.tokens = self.max_messages_per_second
        self.last_refill = time.time()
        self.token_lock = threading.Lock()
        self.logs_extracted = 0
        self.logs_sent = 0
        self.logs_dropped = 0
        self.current_log_type = None
        self.max_queue_size = config.MAX_QUEUE_SIZE
        self.queue_size_threshold = config.QUEUE_SIZE_THRESHOLD
        self.adjustment_interval = config.ADJUSTMENT_INTERVAL
        self.log_queue_db = Path(config.LOG_QUEUE_DB)
        self._setup_persistent_queue()
        self.log_queue = queue.Queue()  # Remove maxsize to allow unlimited queueing
        self.processing_thread = threading.Thread(target=self.process_queue, daemon=True)
        self.processing_thread.start()
        self.stats = {
            'logs_queued': 0,
            'logs_sent': 0,
            'logs_failed': 0,
            'current_queue_size': 0
        }
        self.stats_lock = threading.Lock()
        self.token_bucket = TokenBucket(self.max_messages_per_second)
        self.ENABLE_SAMPLE_LOGGING = config.ENABLE_SAMPLE_LOGGING
        self.SAMPLE_LOG_INTERVAL = config.SAMPLE_LOG_INTERVAL
        self.SAMPLE_LOG_LENGTH = config.SAMPLE_LOG_LENGTH
        self.last_sample_log_time = 0
        self.last_mps_check = time.time()
        self.messages_sent_since_last_check = 0
        self.current_mps = self.min_messages_per_second  # Start with the minimum rate
        self.messages_sent_since_last_report = 0
        self.last_report_time = time.time()
        self.report_interval = 60  # Report every 60 seconds

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
        # Ensure the directory exists
        self.log_queue_db.parent.mkdir(parents=True, exist_ok=True)
        
        self.db_connection = sqlite3.connect(str(self.log_queue_db), check_same_thread=False)
        self.db_cursor = self.db_connection.cursor()
        self.db_cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_message TEXT,
                log_type TEXT
            )
        ''')
        self.db_connection.commit()

    def enqueue_log(self, log_line, log_type):
        with self.queue_lock:
            self.db_cursor.execute('INSERT INTO log_queue (log_message, log_type) VALUES (?, ?)', (log_line, log_type))
            self.db_connection.commit()
        with self.stats_lock:
            self.stats['logs_queued'] += 1
            self.stats['current_queue_size'] = self.get_queue_size()
        
        if self.stats['current_queue_size'] > self.queue_size_threshold:
            logger.warning(f"Queue size ({self.stats['current_queue_size']}) has exceeded the threshold ({self.queue_size_threshold})")

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

    def get_queue_size(self):
        with self.queue_lock:
            self.db_cursor.execute('SELECT COUNT(*) FROM log_queue')
            return self.db_cursor.fetchone()[0]

    def process_queue(self):
        while not self.stop_event.is_set():
            if self.token_bucket.consume():
                log_line, log_type = self.dequeue_log()
                if log_line:
                    success = self._send_log(log_line, log_type)
                    with self.stats_lock:
                        if success:
                            self.stats['logs_sent'] += 1
                        else:
                            self.stats['logs_failed'] += 1
                            self.enqueue_log(log_line, log_type)  # Re-queue failed logs
                else:
                    time.sleep(self.config.QUEUE_EMPTY_SLEEP_TIME)
            else:
                time.sleep(self.config.RATE_LIMIT_SLEEP_TIME)

    def _send_log(self, log_line, log_type):
        max_retries = 5
        retry_delay = 1  # in seconds

        for attempt in range(max_retries):
            try:
                if self.send_to_siem(log_line, log_type):
                    return True
                else:
                    logger.error(f"Attempt {attempt + 1}: Failed to send log.")
            except Exception as e:
                logger.error(f"Exception in _send_log: {e}")
                self.health_reporter.report_error(f"Exception in _send_log: {e}", log_type)
            
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff

        logger.warning(f"Max retries reached for log. Re-queueing.")
        return False

    def send_to_siem(self, log_line, log_type):
        try:
            if self.syslog is None:
                self.syslog = self._setup_syslog()
                if self.syslog is None:
                    return False

            if isinstance(log_line, str):
                log_line_str = log_line
            else:
                log_line_str = log_line.decode('utf-8')

            current_time_str = time.strftime("%b %d %Y %H:%M:%S", time.localtime())
            syslog_ip = socket.gethostbyname(socket.gethostname())
            syslog_message = f"{current_time_str} {syslog_ip} <USER:NOTE> {log_line_str}"

            if self.USE_TCP:
                self.syslog.sendall(syslog_message.encode('utf-8') + b'\n')
            else:
                self.syslog.sendto(syslog_message.encode('utf-8'), (self.sma_host, self.sma_port))

            self.messages_sent_since_last_report += 1
            self.health_reporter.report_syslog_sent(1, log_type)

            current_time = time.time()
            if current_time - self.last_report_time >= self.report_interval:
                self._report_stats()

            return True
        except Exception as e:
            logger.error(f"[ERROR] Sending log to SIEM ({self.sma_host}:{self.sma_port}): {str(e)}")
            if self.syslog:
                self.syslog.close()
                self.syslog = None
            return False

    def _report_stats(self):
        current_time = time.time()
        elapsed_time = current_time - self.last_report_time
        mps = self.messages_sent_since_last_report / elapsed_time if elapsed_time > 0 else 0
        
        logger.info(f"[SYSLOG] Sent {self.messages_sent_since_last_report} logs to SIEM in the last {elapsed_time:.2f} seconds. Current MPS: {mps:.2f}")
        
        self.health_reporter.log_message(f"LogProcessor: Sent {self.messages_sent_since_last_report} logs, MPS: {mps:.2f}")
        
        self.messages_sent_since_last_report = 0
        self.last_report_time = current_time

    def start_processing(self):
        if not self.processing_thread.is_alive():
            self.processing_thread = threading.Thread(target=self.process_queue, daemon=True)
            self.processing_thread.start()

    def stop_processing(self):
        logger.info("Stopping Log Processor...")
        start_time = time.time()
        self.stop_event.set()
        if self.processing_thread.is_alive():
            self.processing_thread.join(timeout=5)
        self.drain_queue(self.stop_event, timeout=self.config.SHUTDOWN_TIMEOUT)
        logger.info(f"Log Processor stopped. Time taken: {time.time() - start_time:.2f} seconds")

    def drain_queue(self, stop_event, timeout=None):
        start_time = time.time()
        while not stop_event.is_set():
            log_line, log_type = self.dequeue_log()
            if log_line:
                success = self._send_log(log_line, log_type)
                if not success:
                    self.enqueue_log(log_line, log_type)  # Re-queue failed logs
            else:
                break  # Queue is empty
            if timeout and (time.time() - start_time) > timeout:
                logger.warning("Drain queue timeout reached.")
                break

    def get_stats(self):
        with self.stats_lock:
            stats = self.stats.copy()
        stats['current_queue_size'] = self.get_queue_size()
        return stats

    def log_queue_stats(self):
        stats = self.get_stats()
        logger.info(f"[QUEUE_STATS] Size: {stats['current_queue_size']}, Queued: {stats['logs_queued']}, Sent: {stats['logs_sent']}, Failed: {stats['logs_failed']}")

    def process_log_file(self, file_path: Path, log_type: str, stop_event: threading.Event) -> Tuple[bool, int]:
        logger.info(f"[FILE_PROCESSING] Starting: {file_path}, Type: {log_type}")
        
        try:
            logs_extracted = 0
            logs_enqueued = 0
            total_lines = 0
            with open(file_path, 'r') as f:
                for line in f:
                    total_lines += 1
                    if stop_event.is_set():
                        logger.info(f"[FILE_PROCESSING] Stopped: {file_path} due to shutdown signal.")
                        return False, logs_extracted

                    logs_extracted += 1
                    
                    try:
                        log_entry_dict = json.loads(line)
                        transformed_log = self.transform_log_based_on_policy(log_entry_dict, log_type)
                        formatted_log = self.format_log_for_siem(transformed_log, log_entry_dict)
                        
                        # Enqueue the log instead of sending directly
                        self.enqueue_log(formatted_log, log_type)
                        logs_enqueued += 1
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON in file {file_path} at line {total_lines}: {line[:100]}...")
                    except Exception as e:
                        logger.error(f"Error processing line {total_lines} in file {file_path}: {str(e)}")
                    
                    if logs_extracted % 100 == 0:
                        logger.info(f"[PROGRESS] {file_path}: {logs_extracted}/{total_lines} logs processed, {logs_enqueued} enqueued.")

            logger.info(f"[FILE_PROCESSING] Completed: {file_path}. Total lines: {total_lines}, Logs extracted: {logs_extracted}, Logs enqueued: {logs_enqueued}")
            return True, logs_extracted
        except Exception as e:
            logger.error(f"[ERROR] Processing file {file_path}: {e}")
            logger.error(f"Full exception: {traceback.format_exc()}")
            return False, logs_extracted

    def transform_log_based_on_policy(self, log_entry: Dict[str, Any], log_type: str) -> Dict[str, Any]:
        logger.debug(f"Starting transformation for log entry: {str(log_entry)[:100]}...")
        device_type = 'IllumioAudit' if log_type == 'auditable_events' else 'IllumioSummary'
        
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

        if log_type == 'auditable_events':
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
        elif log_type == 'summaries':
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

        logger.debug(f"Transformed log entry: {str(result)[:100]}...")
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

    def send_logs(self, logs_to_send, log_type, stop_event):
        for transformed_log, original_log in logs_to_send:
            if stop_event.is_set():
                break
            formatted_log = self.format_log_for_siem(transformed_log, original_log)
            if self.send_to_siem(formatted_log, log_type):
                self.logs_sent += 1
            else:
                self.logs_dropped += 1

    def _refill_tokens(self):
        current_time = time.time()
        elapsed = current_time - self.last_refill
        refill_amount = elapsed * self.max_messages_per_second
        with self.token_lock:
            self.tokens = min(self.max_messages_per_second, self.tokens + refill_amount)
            self.last_refill = current_time

    def adjust_syslog_rate(self, logs_sent, elapsed_time):
        if not self.enable_dynamic_syslog_rate:
            return

        current_time = time.time()
        if current_time - self.last_adjustment_time < self.adjustment_interval:
            return  # Don't adjust if less than the adjustment interval has passed

        if elapsed_time > 0:
            current_rate = logs_sent / elapsed_time
        else:
            current_rate = self.current_mps

        if current_rate < self.max_messages_per_second * 0.8:  # If we're sending at less than 80% capacity
            new_rate = min(current_rate * 1.1, self.max_messages_per_second)
        elif current_rate > self.max_messages_per_second:
            new_rate = max(current_rate * 0.9, self.min_messages_per_second)
        else:
            new_rate = current_rate

        self.current_mps = max(new_rate, self.min_messages_per_second)  # Ensure we never go below the minimum
        logger.info(f"[ADJUSTMENT] Syslog sending rate adjusted to: {self.current_mps:.2f} messages/s. Current actual MPS: {current_rate:.2f}")
        
        self.last_adjustment_time = current_time

    def close(self):
        logger.info("Closing LogProcessor resources...")
        start_time = time.time()
        if self.syslog:
            self.syslog.close()
        if self.db_connection:
            self.db_connection.close()
        logger.info(f"LogProcessor resources closed. Time taken: {time.time() - start_time:.2f} seconds")