import boto3
import os
import sys
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timedelta
import gzip
import pytz
import tempfile
from tqdm import tqdm
from dotenv import load_dotenv
import configparser

# Load environment variables
load_dotenv()

# Load configuration
config = configparser.ConfigParser()
config.read('settings.ini')

# Constants
LOG_FOLDER = config.get('Paths', 'LOG_FOLDER')
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')
MINUTES = config.getint('S3', 'MINUTES')
MAX_FILES_PER_FOLDER = config.getint('S3', 'MAX_FILES_PER_FOLDER')

def generate_prefixes(start_date, end_date):
    """Generate a list of prefixes to search based on the date range."""
    prefixes = []
    base_paths = ["illumio/summaries/", "illumio/auditable_events/"]
    current_date = start_date
    while current_date <= end_date:
        for base_path in base_paths:
            prefixes.append(f"{base_path}{current_date.strftime('%Y%m%d')}")
        current_date += timedelta(days=1)
    return prefixes

def list_recent_logs(bucket_name, minutes=30, max_files_per_folder=5):
    """
    List and analyze the most recent logs in the S3 bucket from the last 30 minutes,
    limited to a maximum of 5 files per folder.
    """
    try:
        s3 = boto3.client('s3')
        
        end_date = datetime.now(pytz.UTC)
        start_date = end_date - timedelta(minutes=minutes)
        
        print(f"Analyzing logs from {start_date} to {end_date} in bucket '{bucket_name}'...")
        
        base_paths = ["illumio/summaries/", "illumio/auditable_events/"]
        
        all_log_files = []
        total_size = 0

        for base_path in base_paths:
            log_files = []
            print(f"\nScanning folder: {base_path}")
            
            prefixes = [f"{base_path}{(start_date + timedelta(days=i)).strftime('%Y%m%d')}" 
                        for i in range((end_date - start_date).days + 1)]
            
            for prefix in prefixes:
                paginator = s3.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
                    if 'Contents' in page:
                        for obj in page['Contents']:
                            if obj['Key'].endswith('.gz'):
                                last_modified = obj['LastModified'].replace(tzinfo=pytz.UTC)
                                if start_date <= last_modified <= end_date:
                                    log_files.append(obj)
                                    total_size += obj['Size']
                                    if len(log_files) >= max_files_per_folder:
                                        break
                    if len(log_files) >= max_files_per_folder:
                        break
                if len(log_files) >= max_files_per_folder:
                    break
            
            log_files.sort(key=lambda x: x['LastModified'], reverse=True)
            log_files = log_files[:max_files_per_folder]
            all_log_files.extend(log_files)
            
            print(f"Found {len(log_files)} log files in {base_path}")

        print(f"\nTotal log files found: {len(all_log_files)}")
        print(f"Total compressed size: {total_size / (1024*1024):.2f} MB")

        print(f"\nAnalyzing and downloading log files:")
        total_uncompressed_size = 0
        for log in tqdm(all_log_files, desc="Processing logs", unit="file"):
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_filename = temp_file.name
            
            try:
                s3.download_file(bucket_name, log['Key'], temp_filename)
                
                with gzip.open(temp_filename, 'rb') as f:
                    f.seek(0, 2)
                    uncompressed_size = f.tell()
                
                total_uncompressed_size += uncompressed_size
                
                # Extract the relative path from the S3 key
                relative_path = os.path.dirname(log['Key'])
                filename = os.path.basename(log['Key']).replace('.gz', '')
                
                # Create the destination path, preserving the folder structure
                dest_folder = os.path.join(LOG_FOLDER, relative_path)
                os.makedirs(dest_folder, exist_ok=True)
                dest_path = os.path.join(dest_folder, filename)
                
                # Decompress and save the file
                with gzip.open(temp_filename, 'rb') as f_in:
                    with open(dest_path, 'wb') as f_out:
                        f_out.write(f_in.read())
                
                print(f"\n- {log['Key']}")
                print(f"  Last modified: {log['LastModified']}")
                print(f"  Compressed size: {log['Size']} bytes")
                print(f"  Uncompressed size: {uncompressed_size} bytes")
                print(f"  Saved to: {dest_path}")
            
            except ClientError as e:
                print(f"\nError downloading {log['Key']}: {e}")
            except gzip.BadGzipFile:
                print(f"\nError: {log['Key']} is not a valid gzip file")
            except Exception as e:
                print(f"\nUnexpected error processing {log['Key']}: {e}")
            finally:
                if os.path.exists(temp_filename):
                    os.remove(temp_filename)

        print(f"\nSummary:")
        print(f"Total log files: {len(all_log_files)}")
        print(f"Total compressed size: {total_size / (1024*1024):.2f} MB")
        print(f"Total uncompressed size: {total_uncompressed_size / (1024*1024):.2f} MB")
        print(f"Files saved to: {LOG_FOLDER}")

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
    if not S3_BUCKET_NAME:
        print("Error: S3_BUCKET_NAME is not set in settings.ini.")
        print("Please set it in the [S3] section of settings.ini")
        sys.exit(1)

    # Ensure the LOG_FOLDER exists
    os.makedirs(LOG_FOLDER, exist_ok=True)

    list_recent_logs(S3_BUCKET_NAME, minutes=MINUTES, max_files_per_folder=MAX_FILES_PER_FOLDER)

if __name__ == "__main__":
    main()