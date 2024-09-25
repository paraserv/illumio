import time
import threading
from datetime import datetime, timedelta
from logger_config import get_logger
from pathlib import Path
import configparser

logger = get_logger(__name__)

class HealthReporter:
    def __init__(self, heartbeat_interval, summary_interval):
        self.heartbeat_interval = heartbeat_interval
        self.summary_interval = summary_interval
        self.health_log_file = self._get_health_log_file()
        self.last_summary_time = datetime.now()
        self.start_time = datetime.now()
        self.gz_files_processed = {'summaries': 0, 'auditable_events': 0}
        self.logs_extracted = {'summaries': 0, 'auditable_events': 0}
        self.syslog_messages_sent = {'summaries': 0, 'auditable_events': 0}
        self.errors_count = {'summaries': 0, 'auditable_events': 0, 'general': 0}
        self.running = False
        self.lock = threading.Lock()
        self.last_s3_ingestion_rate = 0.0
        self.last_log_time = time.time()
        self.log_interval = 60  # Log at most once per minute

    def _get_health_log_file(self):
        script_dir = Path(__file__).parent
        settings_file = script_dir / 'settings.ini'
        config = configparser.ConfigParser(interpolation=None)
        config.read(settings_file)
        base_folder = Path(script_dir).parent
        log_folder = base_folder / config.get('Paths', 'LOG_FOLDER', fallback='logs')
        return log_folder / 'health_report.log'

    def start(self):
        self.running = True
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
        self.heartbeat_thread.start()
        self._log_health_message(f"Application started at {self.start_time}")

    def stop(self):
        self.running = False
        if self.heartbeat_thread:
            self.heartbeat_thread.join()
        self._log_health_message("Application stopped")

    def _heartbeat_loop(self):
        time.sleep(self.heartbeat_interval)  # Wait for the first interval before sending the first heartbeat
        while self.running:
            self._send_heartbeat()
            time.sleep(self.heartbeat_interval)

    def _send_heartbeat(self):
        with self.lock:
            uptime = datetime.now() - self.start_time
            self._log_health_message(f"Heartbeat: Uptime: {self._format_uptime(uptime)}")
            self._log_health_message(f"Summary logs: GZ files: {self.gz_files_processed['summaries']}, Logs extracted: {self.logs_extracted['summaries']}, Syslog messages sent: {self.syslog_messages_sent['summaries']}, Errors: {self.errors_count['summaries']}")
            self._log_health_message(f"Audit logs: GZ files: {self.gz_files_processed['auditable_events']}, Logs extracted: {self.logs_extracted['auditable_events']}, Syslog messages sent: {self.syslog_messages_sent['auditable_events']}, Errors: {self.errors_count['auditable_events']}")

        if datetime.now() - self.last_summary_time >= timedelta(seconds=self.summary_interval):
            self._send_summary()

    def _send_summary(self):
        with self.lock:
            uptime = datetime.now() - self.start_time
            self._log_health_message(f"Summary: Uptime: {self._format_uptime(uptime)}")
            self._log_health_message(f"Total Summary logs: GZ files: {self.gz_files_processed['summaries']}, Logs extracted: {self.logs_extracted['summaries']}, Syslog messages sent: {self.syslog_messages_sent['summaries']}, Errors: {self.errors_count['summaries']}")
            self._log_health_message(f"Total Audit logs: GZ files: {self.gz_files_processed['auditable_events']}, Logs extracted: {self.logs_extracted['auditable_events']}, Syslog messages sent: {self.syslog_messages_sent['auditable_events']}, Errors: {self.errors_count['auditable_events']}")
            self.last_summary_time = datetime.now()

    def report_gz_file_processed(self, log_type):
        with self.lock:
            self.gz_files_processed[log_type] += 1

    def report_logs_extracted(self, count, log_type):
        with self.lock:
            self.logs_extracted[log_type] += count

    def report_syslog_sent(self, count, log_type):
        with self.lock:
            self.syslog_messages_sent[log_type] += count

    def report_error(self, error_message, log_type):
        with self.lock:
            if log_type not in self.errors_count:
                log_type = 'general'
            self.errors_count[log_type] += 1
            self._log_health_message(f"Error ({log_type}): {error_message}")

    def _log_health_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.health_log_file, 'a') as f:
            f.write(f"{timestamp} - {message}\n")
        logger.info(f"Health Report: {message}")

    @staticmethod
    def _format_uptime(delta):
        days = delta.days
        hours, rem = divmod(delta.seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{days}d {hours}h {minutes}m {seconds}s"

    def log_adjustment(self, message):
        with self.lock:
            self._log_health_message(f"Adjustment: {message}")
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
                self._log_health_message(message)
                self.last_log_time = current_time
            if "S3 Manager: Current S3 log ingestion rate:" in message:
                try:
                    rate_str = message.split(":")[-2].strip().split()[0]
                    self.last_s3_ingestion_rate = float(rate_str)
                except ValueError:
                    logger.error(f"Health Reporter: Failed to parse S3 ingestion rate from message: {message}")