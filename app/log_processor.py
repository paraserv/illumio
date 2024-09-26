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

    def _setup_syslog(self):
        try:
            sock_type = socket.SOCK_STREAM if self.USE_TCP else socket.SOCK_DGRAM
            syslog = socket.socket(socket.AF_INET, sock_type)
            if self.USE_TCP:
                syslog.connect((self.sma_host, self.sma_port))
            return syslog
        except Exception as e:
            logger.error(f"Error setting up syslog connection: {e}")
            return None

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
                        logs_to_send.append((transformed_log, log_entry))
                        self.health_reporter.report_logs_extracted(1, log_type)
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

    def send_logs(self, logs: List[Tuple[Dict[str, Any], Dict[str, Any]]], log_type: str, stop_event: threading.Event):
        total_logs = len(logs)
        self.app_logger.info(f"Log Processor: Attempting to send {total_logs} logs to {self.sma_host}:{self.sma_port} via {'TCP' if self.USE_TCP else 'UDP'}")
        
        estimated_time = math.ceil(total_logs / self.max_messages_per_second)
        self.app_logger.info(f"Log Processor: Estimated time to send all logs: {estimated_time} seconds")

        try:
            start_time = time.time()
            last_baseline_log_time = start_time
            for index, (transformed_log, original_log) in enumerate(logs, 1):
                if stop_event.is_set():
                    self.app_logger.info(f"Stopping log sending due to shutdown signal.")
                    break  # Exit the loop if stop_event is set

                formatted_log = self.format_log_for_siem(transformed_log, original_log)
                current_time = time.strftime("%b %d %Y %H:%M:%S", time.localtime())
                syslog_ip = socket.gethostbyname(socket.gethostname())
                syslog_message = f"{current_time} {syslog_ip} <USER:NOTE> {formatted_log}"
                
                self.send_to_siem(syslog_message)
                self.health_reporter.report_syslog_sent(1, log_type)
                
                if index % 100 == 0:  # Check every 100 logs
                    current_time = time.time()
                    if current_time - self.baseline_start_time < self.baseline_period:
                        # We're still in the baseline period
                        self.baseline_data.append((index, current_time))
                        if current_time - last_baseline_log_time >= 60:  # Log at most once per minute
                            remaining_time = self.baseline_period - (current_time - self.baseline_start_time)
                            message = f"Log Processor: In syslog sending baseline period. {remaining_time:.0f} seconds remaining. This period is used to establish initial performance metrics."
                            self.app_logger.info(message)
                            self.health_reporter._log_health_message(message)
                            last_baseline_log_time = current_time
                    elif current_time - self.last_adjustment_time >= self.adjustment_interval:
                        # Baseline period is over and it's time for an adjustment
                        self.adjust_syslog_rate(index, start_time)
                        self.last_adjustment_time = current_time

            total_time = time.time() - start_time
            actual_mps = round(total_logs / total_time)
            self.app_logger.info(f"Log Processor: Successfully sent all {total_logs} log entries in {total_time:.2f} seconds")
            
            current_time = time.time()
            if current_time - self.last_log_time >= self.log_interval:
                message = f"Log Processor: Log processing and sending rate: {actual_mps} messages/s. This represents the rate at which logs are being processed and sent to the SIEM."
                self.health_reporter.log_message(message)
                
                s3_ingestion_rate = self.health_reporter.get_last_s3_ingestion_rate()
                if s3_ingestion_rate is not None:
                    delta_mps = actual_mps - s3_ingestion_rate
                    message = f"Log Processor: Delta between processing and S3 ingestion rates: {delta_mps:.2f} messages/s. A positive value indicates processing is faster than ingestion, negative means ingestion is outpacing processing."
                    self.health_reporter.log_message(message)
                self.last_log_time = current_time
        except Exception as e:
            error_message = f"Log Processor: Failed to send logs to {self.sma_host}:{self.sma_port}: {e}"
            self.app_logger.error(error_message)
            self.health_reporter.report_error(error_message)
            raise

    def send_to_siem(self, log_line):
        if self.syslog:
            try:
                current_time = time.time()
                if current_time - self.last_send_time >= 1:
                    # Reset the counter if a second has passed
                    self.message_count = 0
                    self.last_send_time = current_time

                if self.message_count < self.max_messages_per_second:
                    if self.USE_TCP:
                        self.syslog.sendall(log_line.encode() + b'\n')
                    else:
                        self.syslog.sendto(log_line.encode(), (self.sma_host, self.sma_port))
                    self.message_count += 1
                else:
                    # Sleep for the remainder of the second if we've hit the limit
                    sleep_time = 1 - (current_time - self.last_send_time)
                    if sleep_time > 0:
                        time.sleep(sleep_time)
                    # Reset for the next second
                    self.message_count = 1
                    self.last_send_time = time.time()
                    if self.USE_TCP:
                        self.syslog.sendall(log_line.encode() + b'\n')
                    else:
                        self.syslog.sendto(log_line.encode(), (self.sma_host, self.sma_port))
            except Exception as e:
                logger.error(f"Error sending log to SIEM: {e}")
        else:
            logger.error("Syslog connection not available")

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