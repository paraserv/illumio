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
        self.termination_signal_time = None
        self.shutdown_time = None

        # Initialize variables to store final counts
        self.state_summaries_count = 0
        self.state_auditable_events_count = 0
        self.checkpoint_summaries_count = 0
        self.checkpoint_auditable_events_count = 0

    def _get_health_log_file(self):
        script_dir = Path(__file__).parent
        settings_file = script_dir / 'settings.ini'
        config = configparser.ConfigParser(interpolation=None)
        config.read(settings_file)
        base_folder = Path(script_dir).parent
        log_folder = base_folder / config.get('Paths', 'LOG_FOLDER', fallback='logs')
        return log_folder / 'health_report.log'

    def start(self):
        if not self.running:
            self.running = True
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
            self.heartbeat_thread.start()
            self.log_info("*** Application Started ***")  # Added asterisks for clarity

    def stop(self):
        self.running = False
        if self.heartbeat_thread:
            self.heartbeat_thread.join()
        self.shutdown_time = datetime.now()

        if self.termination_signal_time:
            shutdown_duration = self.shutdown_time - self.termination_signal_time
            self.log_info(
                f"Shutdown completed in {self._format_duration(shutdown_duration)} after termination signal was received."
            )

        self.log_summary(final=True)
        self.log_saved_state()
        self.log_saved_checkpoint()
        self.log_info("*** Application Stopped ***")  # Added asterisks for clarity

    def _heartbeat_loop(self):
        time.sleep(self.heartbeat_interval)  # Wait for the first interval before sending the first heartbeat
        while self.running:
            self._send_heartbeat()
            time.sleep(self.heartbeat_interval)

    def _send_heartbeat(self):
        with self.lock:
            uptime = datetime.now() - self.start_time
            self.log_info(f"Heartbeat: Uptime: {self._format_duration(uptime)}")
            self.log_statistics()
        if datetime.now() - self.last_summary_time >= timedelta(seconds=self.summary_interval):
            self.log_summary()

    def log_statistics(self):
        # Log current statistics
        summary_stats = (
            f"Summary Logs: GZ Files Processed: {self.gz_files_processed['summaries']}, "
            f"Logs Extracted: {self.logs_extracted['summaries']}, "
            f"Syslog Messages Sent: {self.syslog_messages_sent['summaries']}, "
            f"Errors: {self.errors_count['summaries']}"
        )
        audit_stats = (
            f"Audit Logs: GZ Files Processed: {self.gz_files_processed['auditable_events']}, "
            f"Logs Extracted: {self.logs_extracted['auditable_events']}, "
            f"Syslog Messages Sent: {self.syslog_messages_sent['auditable_events']}, "
            f"Errors: {self.errors_count['auditable_events']}"
        )
        self.log_info(summary_stats)
        self.log_info(audit_stats)

    def log_summary(self, final=False):
        with self.lock:
            uptime = datetime.now() - self.start_time
            summary_type = "Final Summary" if final else "Summary"
            self.log_info(f"{summary_type}: Uptime: {self._format_duration(uptime)}")
            self.log_statistics()
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
            self.log_error(f"Error ({log_type}): {error_message}")

    def log_info(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - INFO - {message}"
        with open(self.health_log_file, 'a') as f:
            f.write(f"{log_message}\n")
        logger.info(f"Health Report: {message}")

    def log_error(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - ERROR - {message}"
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

    def log_recovered_state(self, state_summaries_count, state_auditable_events_count,
                            checkpoint_summaries_count, checkpoint_auditable_events_count):
        self.log_info(f"Recovered State - Summaries: {state_summaries_count}, Auditable Events: {state_auditable_events_count}")
        self.log_info(f"Recovered Checkpoint - Summaries: {checkpoint_summaries_count}, Auditable Events: {checkpoint_auditable_events_count}")

    def log_termination_signal_received(self):
        with self.lock:
            self.termination_signal_time = datetime.now()
            self.log_info("Termination signal received")

    def log_saved_state(self):
        self.log_info(f"Saved state - Summaries: {self.state_summaries_count}, Auditable Events: {self.state_auditable_events_count}")

    def log_saved_checkpoint(self):
        self.log_info(f"Saved checkpoint - Summaries: {self.checkpoint_summaries_count}, Auditable Events: {self.checkpoint_auditable_events_count}")