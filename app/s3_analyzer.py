#!/usr/bin/env python3
"""
Script to analyze S3 contents related to Illumio logs and monitor file addition rates.
"""

# Standard library imports
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
import gzip
import io
import configparser
import time
from collections import defaultdict
import argparse
import signal

# Third-party imports
import pytz
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

# Get the directory where the script is located
script_dir = Path(__file__).parent

# Construct the full path to the .env file in the parent directory
env_path = script_dir.parent / '.env'

# Load environment variables from the .env file located in the parent directory
load_dotenv(dotenv_path=env_path)

# Retrieve AWS credentials from environment variables
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')

# Construct the path to settings.ini
settings_file = script_dir / 'settings.ini'

# Load configuration with interpolation disabled
config = configparser.ConfigParser(interpolation=None)
config.read(script_dir / 'settings.ini')

# Load settings from the [S3] section
MINUTES = config.getint('S3', 'MINUTES', fallback=10)
MAX_FILES_PER_FOLDER = config.getint('S3', 'MAX_FILES_PER_FOLDER', fallback=5)
EXTRACT_LOG_LINES = config.getint('S3', 'EXTRACT_LOG_LINES', fallback=0)

def list_s3_contents(bucket_name, minutes=10, max_files_per_folder=5, extract_lines=0, count_only=True):
    """
    List the folders and .gz filenames in the S3 bucket from the last 'minutes',
    limited to a maximum of 'max_files_per_folder' files per folder.
    Optionally extract and display the first 'extract_lines' lines from each .gz file.
    If count_only is True, only provide a count of files instead of listing them.
    """
    try:
        session = boto3.Session(
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        )
        s3 = session.client('s3')

        end_date = datetime.now(pytz.UTC)
        start_date = end_date - timedelta(minutes=minutes)

        print(f"Analyzing S3 contents from {start_date} to {end_date} in bucket '{bucket_name}'...")

        base_paths = ["illumio/summaries/", "illumio/auditable_events/"]

        for base_path in base_paths:
            print(f"\nFolder: {base_path}")

            prefixes = [f"{base_path}{(start_date + timedelta(days=i)).strftime('%Y%m%d')}" 
                        for i in range((end_date - start_date).days + 1)]

            total_files = 0
            for prefix in prefixes:
                file_count = 0
                print(f"  Subfolder: {prefix}")
                paginator = s3.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
                    if 'Contents' in page:
                        for obj in page['Contents']:
                            if obj['Key'].endswith('.gz'):
                                last_modified = obj['LastModified'].replace(tzinfo=pytz.UTC)
                                if start_date <= last_modified <= end_date:
                                    file_count += 1
                                    total_files += 1
                                    if not count_only:
                                        filename = os.path.basename(obj['Key'])
                                        print(f"    {filename}")
                                    
                                    if extract_lines > 0 and not count_only:
                                        try:
                                            response = s3.get_object(Bucket=bucket_name, Key=obj['Key'])
                                            with gzip.GzipFile(fileobj=io.BytesIO(response['Body'].read())) as gzipfile:
                                                print(f"      Log contents (first {extract_lines} line(s)):")
                                                for i, line in enumerate(gzipfile):
                                                    if i < extract_lines:
                                                        print(f"        {line.decode('utf-8').strip()}")
                                                    else:
                                                        break
                                        except Exception as e:
                                            print(f"      Error extracting log contents: {e}")
                                    
                                    if file_count >= max_files_per_folder:
                                        break
                    if file_count >= max_files_per_folder:
                        break
                
                if count_only:
                    print(f"    Files in this subfolder: {file_count}")
            
            print(f"  Total files in {base_path}: {total_files}")

    except NoCredentialsError:
        print("Error: AWS credentials not found. Please configure your AWS credentials.")
        sys.exit(1)
    except ClientError as e:
        print(f"An AWS client error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

def get_recent_files(s3, bucket_name, prefix, start_date, end_date):
    """
    Get the count and list of recent files within the specified date range.
    """
    paginator = s3.get_paginator('list_objects_v2')
    file_count = 0
    recent_files = []

    for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
        if 'Contents' in page:
            for obj in page['Contents']:
                if obj['Key'].endswith('.gz'):
                    last_modified = obj['LastModified'].replace(tzinfo=pytz.UTC)
                    if start_date <= last_modified <= end_date:
                        file_count += 1
                        recent_files.append(obj['Key'])

    return file_count, recent_files

def get_file_stats(s3, bucket_name, file_key, verbose=False):
    """
    Get file size and row count for a given S3 file.
    """
    response = s3.get_object(Bucket=bucket_name, Key=file_key)
    file_size = response['ContentLength']
    last_modified = response['LastModified']
    row_count = 0
    
    with gzip.GzipFile(fileobj=io.BytesIO(response['Body'].read())) as gzipfile:
        row_count = sum(1 for _ in gzipfile)
    
    if verbose:
        print(f"  File: {file_key}")
        print(f"    Last modified: {last_modified}")
        print(f"    Size: {file_size / 1024:.2f} KB")
        print(f"    Rows: {row_count}")
    
    return file_size, row_count, last_modified

def monitor_file_addition_rate(bucket_name, interval_minutes=0.5, duration_minutes=None, verbose=False):
    """
    Monitor the rate of file additions in the S3 bucket over a specified duration or indefinitely.
    """
    session = boto3.Session(
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    s3 = session.client('s3')

    base_paths = ["illumio/summaries/", "illumio/auditable_events/"]

    print(f"Monitoring file addition rate every {interval_minutes} minutes{'.' if duration_minutes is None else f' for {duration_minutes} minutes.'}")

    start_time = datetime.now(pytz.UTC)
    end_time = start_time + timedelta(minutes=duration_minutes) if duration_minutes else None

    cumulative_files = 0
    cumulative_size = 0
    cumulative_rows = 0
    baseline_established = False
    baseline_time = None

    interrupted = False

    def signal_handler(signum, frame):
        nonlocal interrupted
        interrupted = True
        print("\nMonitoring interrupted. Generating summary...")

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while not interrupted and (end_time is None or datetime.now(pytz.UTC) < end_time):
            loop_start = datetime.now(pytz.UTC)
            end_date = loop_start
            start_date = end_date - timedelta(minutes=interval_minutes)

            new_files = 0
            new_size = 0
            new_rows = 0
            files_per_prefix = defaultdict(int)
            file_details = []

            for base_path in base_paths:
                prefix = f"{base_path}{end_date.strftime('%Y%m%d')}"
                file_count, recent_files = get_recent_files(s3, bucket_name, prefix, start_date, end_date)
                new_files += file_count
                files_per_prefix[base_path] = file_count

                for file_key in recent_files:
                    file_size, row_count, last_modified = get_file_stats(s3, bucket_name, file_key, verbose)
                    new_size += file_size
                    new_rows += row_count
                    file_details.append((file_key, file_size, row_count, last_modified))

            if not baseline_established:
                baseline_established = True
                baseline_time = loop_start
                print("Baseline established. Starting to monitor for new files...")
                cumulative_files = new_files
                cumulative_size = new_size
                cumulative_rows = new_rows
                continue

            cumulative_files += new_files
            cumulative_size += new_size
            cumulative_rows += new_rows

            # Calculate MPS for the current interval
            interval_seconds = interval_minutes * 60
            interval_mps = new_rows / interval_seconds if interval_seconds > 0 else 0

            # Calculate cumulative MPS
            cumulative_seconds = (end_date - baseline_time).total_seconds()
            cumulative_mps = (cumulative_rows - new_rows) / cumulative_seconds if cumulative_seconds > 0 else 0

            print(f"\nTime window: {start_date} to {end_date}")
            print(f"Interval statistics:")
            print(f"  New files: {new_files:,}")
            for base_path, count in files_per_prefix.items():
                print(f"    {base_path}: {count:,} new files")
            print(f"  New data size: {new_size / 1024 / 1024:.2f} MB")
            print(f"  New rows: {new_rows:,}")
            print(f"  ***Current MPS: {interval_mps:.2f}***")
            
            interval_file_rate = new_files / interval_minutes
            interval_row_rate = new_rows / interval_minutes
            print(f"  Interval average rates:")
            print(f"    Files: {interval_file_rate:.2f} per minute")
            print(f"    Rows: {interval_row_rate:.2f} per minute")

            if verbose:
                print("\n  Detailed file information:")
                for file_key, file_size, row_count, last_modified in file_details:
                    print(f"    File: {file_key}")
                    print(f"      Last modified: {last_modified}")
                    print(f"      Size: {file_size / 1024:.2f} KB")
                    print(f"      Rows: {row_count}")
                    print(f"      Rows per KB: {row_count / (file_size / 1024):.2f}")

            print(f"\nCumulative statistics (since baseline):")
            print(f"  Total new files: {cumulative_files - new_files:,}")
            print(f"  Total new data size: {(cumulative_size - new_size) / 1024 / 1024:.2f} MB")
            print(f"  Total new rows: {cumulative_rows - new_rows:,}")
            print(f"  ***Average MPS: {cumulative_mps:.2f}***")

            cumulative_duration = cumulative_seconds / 60
            cumulative_file_rate = (cumulative_files - new_files) / cumulative_duration if cumulative_duration > 0 else 0
            cumulative_row_rate = (cumulative_rows - new_rows) / cumulative_duration if cumulative_duration > 0 else 0
            print(f"  Cumulative average rates:")
            print(f"    Files: {cumulative_file_rate:.2f} per minute")
            print(f"    Rows: {cumulative_row_rate:.2f} per minute")

            if verbose:
                print(f"\n  Verbose cumulative statistics:")
                print(f"    Cumulative duration: {cumulative_duration:.2f} minutes")
                print(f"    Cumulative seconds: {cumulative_seconds:.2f}")
                print(f"    Average file size: {(cumulative_size - new_size) / (cumulative_files - new_files) / 1024:.2f} KB")
                print(f"    Average rows per file: {(cumulative_rows - new_rows) / (cumulative_files - new_files):.2f}")
                print(f"    Rows per MB: {(cumulative_rows - new_rows) / ((cumulative_size - new_size) / 1024 / 1024):.2f}")

            loop_duration = (datetime.now(pytz.UTC) - loop_start).total_seconds()
            sleep_time = max(0, interval_minutes * 60 - loop_duration)
            if sleep_time > 0 and not interrupted and (end_time is None or datetime.now(pytz.UTC) + timedelta(seconds=sleep_time) < end_time):
                time.sleep(sleep_time)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if not interrupted:
            print("\nMonitoring completed. Generating summary...")
        print_summary(baseline_time, datetime.now(pytz.UTC), cumulative_files, cumulative_size, cumulative_rows, verbose)

def print_summary(start_time, end_time, total_files, total_size, total_rows, verbose=False):
    duration = (end_time - start_time).total_seconds() / 60
    total_seconds = (end_time - start_time).total_seconds()
    average_mps = total_rows / total_seconds if total_seconds > 0 else 0

    print(f"\nSummary:")
    print(f"Monitoring duration: {duration:.2f} minutes")
    print(f"Total new files processed: {total_files:,}")
    print(f"Total new data size: {total_size / 1024 / 1024:.2f} MB")
    print(f"Total new rows: {total_rows:,}")
    print(f"***Average MPS: {average_mps:.2f}***")
    if total_files > 0:
        print(f"Average file size: {(total_size / total_files) / 1024:.2f} KB")
        print(f"Average rows per file: {total_rows / total_files:.2f}")
    else:
        print("Average file size: N/A")
        print("Average rows per file: N/A")
    print(f"Average file rate: {total_files / duration:.2f} files per minute")
    print(f"Average row rate: {total_rows / duration:.2f} rows per minute")

    if verbose:
        print("\nVerbose summary:")
        print(f"  Start time: {start_time}")
        print(f"  End time: {end_time}")
        print(f"  Total seconds: {total_seconds:.2f}")
        print(f"  Average file size: {(total_size / total_files) / 1024:.2f} KB")
        print(f"  Rows per MB: {total_rows / (total_size / 1024 / 1024):.2f}")
        print(f"  Files per minute: {total_files / duration:.2f}")
        print(f"  Rows per second: {total_rows / total_seconds:.2f}")

def main():
    print("Starting S3 analysis process")
    if not S3_BUCKET_NAME:
        print("Error: S3_BUCKET_NAME is not set in environment variables (.env file).")
        print("Please set it in the .env file.")
        sys.exit(1)

    if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
        print("AWS credentials are not set in environment variables (.env file). Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="S3 Analyzer for Illumio logs")
    parser.add_argument("-i", "--interval", type=float, default=0.5, help="Interval in minutes for monitoring mode (default: 0.5, can be fractional)")
    parser.add_argument("-d", "--duration", type=float, help="Duration in minutes for monitoring mode (default: run indefinitely)")
    parser.add_argument("-f", "--forever", action="store_true", help="Run indefinitely (overrides -d/--duration)")
    parser.add_argument("-o", "--one-time", action="store_true", help="Run one-time analysis")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if args.one_time:
        print("Running one-time analysis")
        list_s3_contents(S3_BUCKET_NAME, minutes=MINUTES, max_files_per_folder=MAX_FILES_PER_FOLDER, extract_lines=EXTRACT_LOG_LINES, count_only=not args.verbose)
    else:
        duration = None if args.forever else args.duration
        print(f"Running in monitoring mode{' indefinitely' if duration is None else f' for {duration} minutes'} with {args.interval}-minute intervals")
        monitor_file_addition_rate(S3_BUCKET_NAME, interval_minutes=args.interval, duration_minutes=duration, verbose=args.verbose)

    print("S3 analysis process completed")

if __name__ == "__main__":
    main()