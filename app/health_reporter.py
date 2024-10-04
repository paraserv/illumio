#!/usr/bin/env python3
"""
HealthReporter module for monitoring application health and logging statistics.
"""

# Standard library imports
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
import configparser
import json
import os

# Local application imports
from logger_config import get_logger

logger = get_logger(__name__)

class HealthReporter:
    def __init__(self, config, stop_event):
        self.config = config
        self.stop_event = stop_event
        self.heartbeat_interval = config.HEARTBEAT_INTERVAL
        self.summary_interval = config.SUMMARY_INTERVAL
        self.health_log_file = Path(config.HEALTH_REPORT_LOG_FILE)
        self.state_file = Path(config.STATE_FILE)
        self._ensure_log_directory()
        self.last_summary_time = datetime.now()
        self.start_time = datetime.now()
        self.gz_files_processed = {'summaries': 0, 'auditable_events': 0}
        self.logs_extracted = {'summaries': 0, 'auditable_events': 0}
        self.syslog_messages_sent = {'summaries': 0, 'auditable_events': 0}
        self.running = False
        self.lock = threading.Lock()
        self.last_s3_ingestion_rate = 0.0
        self.last_log_time = time.time()
        self.log_interval = 60  # Log at most once per minute
        self.termination_signal_time = None
        self.shutdown_time = None
        self.state_summaries_count = 0
        self.state_auditable_events_count = 0
        self.enable_health_reporter = config.ENABLE_HEALTH_REPORTER
        self.dropped_logs = {'summaries': 0, 'auditable_events': 0}
        self.drop_threshold = config.DROP_THRESHOLD
        self.log_processor = None
        self.last_report = {
            'gz_files_processed': {'summaries': 0, 'auditable_events': 0},
            'logs_extracted': {'summaries': 0, 'auditable_events': 0},
            'syslog_messages_sent': {'summaries': 0, 'auditable_events': 0}
        }
        self.summary_logs_sent_since_last_report = 0
        self.audit_logs_sent_since_last_report = 0
        self.s3_ingestion_rate = 0.0
        self.s3_stats = {
            'files_discovered': 0,
            'files_downloaded': 0,
            'files_processed': 0,
            'logs_extracted': 0
        }

    def start(self):
        if not self.running:
            self.running = True
            self.stop_event.clear()
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
            self.heartbeat_thread.start()
            self.log_info("*** Application Started ***")  # Adjusted for clarity

    def stop(self):
        logger.info("Stopping Health Reporter...")
        start_time = time.time()
        self.running = False
        self.stop_event.set()
        if self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=5)
        logger.info(f"Health Reporter stopped. Time taken: {time.time() - start_time:.2f} seconds")

    def _heartbeat_loop(self):
        while not self.stop_event.is_set():
            self._send_heartbeat()
            self.stop_event.wait(self.heartbeat_interval)

    def _send_heartbeat(self):
        with self.lock:
            uptime = datetime.now() - self.start_time
            self.log_info(f"Heartbeat: Uptime: {self._format_duration(uptime)}")
            self.log_statistics()
        if datetime.now() - self.last_summary_time >= timedelta(seconds=self.summary_interval):
            self.log_summary()

    def log_statistics(self):
        current_stats = {
            'gz_files_processed': self.gz_files_processed.copy(),
            'logs_extracted': self.logs_extracted.copy(),
            'syslog_messages_sent': self.syslog_messages_sent.copy()
        }

        diff_stats = {
            'gz_files_processed': {k: current_stats['gz_files_processed'][k] - self.last_report['gz_files_processed'][k] for k in current_stats['gz_files_processed']},
            'logs_extracted': {k: current_stats['logs_extracted'][k] - self.last_report['logs_extracted'][k] for k in current_stats['logs_extracted']},
            'syslog_messages_sent': {k: current_stats['syslog_messages_sent'][k] - self.last_report['syslog_messages_sent'][k] for k in current_stats['syslog_messages_sent']}
        }

        summary_stats = (
            f"Summary Logs: GZ Files Processed: {self.gz_files_processed['summaries']} (+{diff_stats['gz_files_processed']['summaries']}), "
            f"Logs Extracted: {self.logs_extracted['summaries']} (+{diff_stats['logs_extracted']['summaries']}), "
            f"Syslog Messages Sent: {self.syslog_messages_sent['summaries']} (Total), +{self.summary_logs_sent_since_last_report} (Since Last Report)"
        )
        audit_stats = (
            f"Audit Logs: GZ Files Processed: {self.gz_files_processed['auditable_events']} (+{diff_stats['gz_files_processed']['auditable_events']}), "
            f"Logs Extracted: {self.logs_extracted['auditable_events']} (+{diff_stats['logs_extracted']['auditable_events']}), "
            f"Syslog Messages Sent: {self.syslog_messages_sent['auditable_events']} (Total), +{self.audit_logs_sent_since_last_report} (Since Last Report)"
        )
        self.log_info(summary_stats)
        self.log_info(audit_stats)

        self.last_report = current_stats

    def log_summary(self, final=False):
        self.generate_detailed_report()
        if final:
            logger.info("[SUMMARY] Final report generated in health_report.log")
        else:
            logger.info("[SUMMARY] Periodic report generated in health_report.log")

    def report_gz_file_processed(self, log_type):
        with self.lock:
            self.gz_files_processed[log_type] += 1

    def report_logs_extracted(self, count, log_type):
        with self.lock:
            self.logs_extracted[log_type] += count

    def report_syslog_sent(self, count, log_type):
        with self.lock:
            if log_type == 'summaries':
                self.syslog_messages_sent[log_type] += count
                self.summary_logs_sent_since_last_report += count
            elif log_type == 'auditable_events':
                self.syslog_messages_sent[log_type] += count
                self.audit_logs_sent_since_last_report += count

    def log_info(self, message):
        if not self.enable_health_reporter:
            return
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - INFO - {message}"
        os.makedirs(os.path.dirname(self.health_log_file), exist_ok=True)
        with open(self.health_log_file, 'a') as f:
            f.write(f"{log_message}\n")
        logger.info(f"Health Report: {message}")

    def log_error(self, message):
        if not self.enable_health_reporter:
            return
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - ERROR - {message}"
        os.makedirs(os.path.dirname(self.health_log_file), exist_ok=True)
        with open(self.health_log_file, 'a') as f:
            f.write(f"{log_message}\n")
        logger.error(f"Health Report: {message}")

    @staticmethod
    def _format_duration(delta):
        days = delta.days
        hours, rem = divmod(delta.seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{days}d {hours}h {minutes}m {seconds}s"

    def log_adjustment(self, message):
        with self.lock:
            self.log_info(f"Adjustment: {message}")
            if "S3 log ingestion rate:" in message:
                try:
                    rate_str = message.split(":")[-1].strip().split()[0]
                    self.last_s3_ingestion_rate = float(rate_str)
                except ValueError:
                    logger.error(f"Health Reporter: Failed to parse S3 ingestion rate from message: {message}")

    def get_last_s3_ingestion_rate(self):
        with self.lock:
            return self.last_s3_ingestion_rate

    def log_message(self, message):
        with self.lock:
            current_time = time.time()
            if current_time - self.last_log_time >= self.log_interval:
                self.log_info(message)
                self.last_log_time = current_time
            if "S3 Manager: Current S3 log ingestion rate:" in message:
                try:
                    rate_str = message.split(":")[-2].strip().split()[0]
                    self.last_s3_ingestion_rate = float(rate_str)
                except ValueError:
                    logger.error(f"Health Reporter: Failed to parse S3 ingestion rate from message: {message}")

    def log_recovered_state(self, state_summaries_count, state_auditable_events_count):
        self.log_info(f"Recovered State - Summaries: {state_summaries_count}, Auditable Events: {state_auditable_events_count}")

    def log_termination_signal_received(self):
        with self.lock:
            self.termination_signal_time = datetime.now()
            self.log_info("Termination signal received")

    def log_saved_state(self):
        self.log_info(
            f"Saved state to {self.state_file} - Summaries: {self.state_summaries_count}, "
            f"Auditable Events: {self.state_auditable_events_count}"
        )

    def report_error(self, message, log_type='general'):
        with self.lock:
            self.log_error(f"{log_type} Error: {message}")
            if 'Log dropped' in message:
                self.dropped_logs[log_type] += 1
                if self.dropped_logs[log_type] > self.drop_threshold:
                    self.alert_on_dropped_logs(log_type)

    def alert_on_dropped_logs(self, log_type):
        alert_message = f"Alert: Dropped logs for {log_type} exceeded threshold of {self.drop_threshold}."
        self.log_error(alert_message)
        # Optionally, integrate with an alerting system here

    def report_heartbeat(self):
        with self.lock:
            uptime = datetime.now() - self.start_time
            self.log_info(f"Heartbeat: Uptime: {self._format_duration(uptime)}")
            self.log_statistics()
            if self.log_processor:
                log_processor_stats = self.log_processor.get_stats()
                logger.info(f"Health Report: Log Processor Stats: {log_processor_stats}")

    def report_summary(self):
        with self.lock:
            uptime = datetime.now() - self.start_time
            self.log_info(f"Summary: Uptime: {self._format_duration(uptime)}")
            self.log_statistics()
            self.last_summary_time = datetime.now()
            if self.log_processor:
                log_processor_stats = self.log_processor.get_stats()
                logger.info(f"Health Report: Log Processor Stats: {log_processor_stats}")

    def set_log_processor(self, log_processor):
        self.log_processor = log_processor

    def report_queue_stats(self, stats):
        with self.lock:
            self.log_info(f"Queue Stats: {stats}")

    def log_processor(self, log_processor):
        self.log_processor = log_processor

    def generate_report(self):
        with self.lock:
            report = (
                f"Health Report: Heartbeat: {self.get_uptime()}\n"
                f"Health Report: Summary Logs: GZ Files Processed: {self.gz_files_processed['summaries']} (+{self.gz_files_processed['summaries'] - self.last_report['gz_files_processed']['summaries']}), "
                f"Logs Extracted: {self.logs_extracted['summaries']} (+{self.logs_extracted['summaries'] - self.last_report['logs_extracted']['summaries']}), "
                f"Syslog Messages Sent: {self.syslog_messages_sent['summaries']} (Total), +{self.summary_logs_sent_since_last_report} (Since Last Report)\n"
                f"Health Report: Audit Logs: GZ Files Processed: {self.gz_files_processed['auditable_events']} (+{self.gz_files_processed['auditable_events'] - self.last_report['gz_files_processed']['auditable_events']}), "
                f"Logs Extracted: {self.logs_extracted['auditable_events']} (+{self.logs_extracted['auditable_events'] - self.last_report['logs_extracted']['auditable_events']}), "
                f"Syslog Messages Sent: {self.syslog_messages_sent['auditable_events']} (Total), +{self.audit_logs_sent_since_last_report} (Since Last Report)"
            )
            
            # Update last report values
            self.last_report = {
                'gz_files_processed': self.gz_files_processed.copy(),
                'logs_extracted': self.logs_extracted.copy(),
                'syslog_messages_sent': self.syslog_messages_sent.copy()
            }
            
            # Reset the "since last report" counters
            self.summary_logs_sent_since_last_report = 0
            self.audit_logs_sent_since_last_report = 0

            return report

    def generate_detailed_report(self):
        with self.lock:
            report = {
                "timestamp": datetime.now().isoformat(),
                "uptime": str(datetime.now() - self.start_time),
                "summary_logs": {
                    "gz_files_processed": self.gz_files_processed['summaries'],
                    "logs_extracted": self.logs_extracted['summaries'],
                    "syslog_messages_sent": self.syslog_messages_sent['summaries']
                },
                "audit_logs": {
                    "gz_files_processed": self.gz_files_processed['auditable_events'],
                    "logs_extracted": self.logs_extracted['auditable_events'],
                    "syslog_messages_sent": self.syslog_messages_sent['auditable_events']
                },
                "s3_operations": self.s3_stats,
                "s3_ingestion_rate": self.s3_ingestion_rate
            }
            self._write_to_health_log(json.dumps(report, indent=2))

    def _write_to_health_log(self, message):
        with open(self.health_log_file, 'a') as f:
            f.write(f"{datetime.now().isoformat()} - {message}\n")

    def _ensure_log_directory(self):
        self.health_log_file.parent.mkdir(parents=True, exist_ok=True)

    def update_s3_ingestion_rate(self, rate):
        with self.lock:
            self.s3_ingestion_rate = rate

    def log_s3_stats(self, stats_message):
        self.log_info(f"S3 Operations: {stats_message}")

    def update_s3_stats(self, stats):
        with self.lock:
            self.s3_stats = stats