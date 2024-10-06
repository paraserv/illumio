#!/usr/bin/env python3
"""
Integrated NTP and AWS time check for the main application and the AWS S3 infrastructure.
"""

import os
import datetime
import statistics
import boto3
from botocore.exceptions import ClientError
import ntplib
import time
import logging
import configparser

logger = logging.getLogger(__name__)

def get_local_time():
    return datetime.datetime.now(datetime.timezone.utc)

def get_s3_time():
    s3 = boto3.client('s3')
    bucket_name = os.environ.get('S3_BUCKET_NAME')
    
    try:
        # Use head_bucket instead of list_buckets
        response = s3.head_bucket(Bucket=bucket_name)
        s3_time_str = response['ResponseMetadata']['HTTPHeaders']['date']
        return datetime.datetime.strptime(s3_time_str, '%a, %d %b %Y %H:%M:%S %Z').replace(tzinfo=datetime.timezone.utc)
    except ClientError as e:
        logger.error(f"Error accessing S3: {e}")
    
    return None

def get_ntp_time(ntp_server):
    ntp_client = ntplib.NTPClient()
    try:
        response = ntp_client.request(ntp_server, version=3)
        return datetime.datetime.fromtimestamp(response.tx_time, datetime.timezone.utc)
    except Exception as e:
        logger.error(f"Error getting NTP time: {e}")
        return None

def format_time_difference(diff):
    total_seconds = abs(diff.total_seconds())
    sign = '-' if diff.total_seconds() < 0 else '+'
    hours, remainder = divmod(int(total_seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{sign}{hours:02d}:{minutes:02d}:{seconds:02d}.{int(total_seconds % 1 * 1e6):06d}"

def check_time_sync(config_path='app/settings.ini', health_reporter=None):
    config = configparser.ConfigParser()
    config.read(config_path)

    enable_ntp_checks = config.getboolean('ntp', 'enable_ntp_checks', fallback=True)
    if not enable_ntp_checks:
        logger.info("NTP checks are disabled in settings.")
        return True

    ntp_server = config.get('ntp', 'server', fallback='pool.ntp.org')
    max_retries = config.getint('ntp', 'max_retries', fallback=3)
    base_delay = config.getint('ntp', 'base_delay', fallback=1)
    max_time_diff = config.getint('ntp', 'max_time_diff', fallback=5)

    for attempt in range(max_retries):
        try:
            local_time = get_local_time()
            ntp_time = get_ntp_time(ntp_server)
            s3_time = get_s3_time()

            time_sync_info = {
                "local_time": local_time.isoformat(),
                "ntp_server": ntp_server,
            }

            simplified_output = "Time Sync Check: "

            if ntp_time:
                ntp_diff = local_time - ntp_time
                time_sync_info["ntp_time"] = ntp_time.isoformat()
                time_sync_info["ntp_diff"] = format_time_difference(ntp_diff)
                time_sync_info["ntp_diff_seconds"] = ntp_diff.total_seconds()
                ntp_diff_ms = abs(ntp_diff.total_seconds() * 1000)
                simplified_output += f"NTP diff: {ntp_diff_ms:.2f}ms "
                if ntp_diff_ms > max_time_diff * 1000:
                    simplified_output += "(WARNING) "
                else:
                    simplified_output += "(OK) "

            if s3_time:
                s3_diff = local_time - s3_time
                time_sync_info["s3_time"] = s3_time.isoformat()
                time_sync_info["s3_diff"] = format_time_difference(s3_diff)
                time_sync_info["s3_diff_seconds"] = s3_diff.total_seconds()
                s3_diff_ms = abs(s3_diff.total_seconds() * 1000)
                simplified_output += f"S3 diff: {s3_diff_ms:.2f}ms "
                if s3_diff_ms > max_time_diff * 1000:
                    simplified_output += "(WARNING)"
                else:
                    simplified_output += "(OK)"

            logger.info(simplified_output)

            if health_reporter:
                health_reporter.report_time_sync(time_sync_info)

            return True
        except Exception as e:
            delay = base_delay * (2 ** attempt)
            logger.error(f"Failed to check time sync: {str(e)}. Retrying in {delay} seconds.")
            time.sleep(delay)

    logger.error(f"Failed to check time synchronization after multiple attempts.")
    return False

if __name__ == "__main__":
    check_time_sync()