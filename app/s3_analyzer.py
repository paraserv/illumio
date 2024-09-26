# s3_analyzer.py
import os
import sys
from datetime import datetime, timedelta
import pytz
from dotenv import load_dotenv
import configparser
from pathlib import Path
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import gzip
import io

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
config.read(settings_file)

# Constants
MINUTES = config.getint('S3', 'MINUTES', fallback=30)
MAX_FILES_PER_FOLDER = config.getint('S3', 'MAX_FILES_PER_FOLDER', fallback=5)

# New configurable option
# Set this to 0 to disable log extraction, or to a positive integer to extract that many log lines from each .gz file
EXTRACT_LOG_LINES = 1  # Change this value to extract log lines (e.g., set to 1 to extract the first line of each log)

def list_s3_contents(bucket_name, minutes=30, max_files_per_folder=5, extract_lines=0):
    """
    List the folders and .gz filenames in the S3 bucket from the last 'minutes',
    limited to a maximum of 'max_files_per_folder' files per folder.
    Optionally extract and display the first 'extract_lines' lines from each .gz file.
    """
    try:
        session = boto3.Session(
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        )
        s3 = session.client('s3')

        end_date = datetime.now(pytz.UTC)
        start_date = end_date - timedelta(minutes=minutes)

        print(f"Listing folders and .gz files from {start_date} to {end_date} in bucket '{bucket_name}'...")

        base_paths = ["illumio/summaries/", "illumio/auditable_events/"]

        for base_path in base_paths:
            print(f"\nFolder: {base_path}")

            prefixes = [f"{base_path}{(start_date + timedelta(days=i)).strftime('%Y%m%d')}" 
                        for i in range((end_date - start_date).days + 1)]

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
                                    filename = os.path.basename(obj['Key'])
                                    print(f"    {filename}")
                                    
                                    if extract_lines > 0:
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
                                    
                                    file_count += 1
                                    if file_count >= max_files_per_folder:
                                        break
                    if file_count >= max_files_per_folder:
                        break
                if file_count >= max_files_per_folder:
                    break

    except NoCredentialsError:
        print("Error: AWS credentials not found. Please configure your AWS credentials.")
        sys.exit(1)
    except ClientError as e:
        print(f"An AWS client error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

def main():
    print("Starting S3 listing process")
    if not S3_BUCKET_NAME:
        print("Error: S3_BUCKET_NAME is not set in environment variables (.env file).")
        print("Please set it in the .env file.")
        sys.exit(1)

    if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
        print("AWS credentials are not set in environment variables (.env file). Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.")
        sys.exit(1)

    list_s3_contents(S3_BUCKET_NAME, minutes=MINUTES, max_files_per_folder=MAX_FILES_PER_FOLDER, extract_lines=EXTRACT_LOG_LINES)
    print("S3 listing process completed")

if __name__ == "__main__":
    main()