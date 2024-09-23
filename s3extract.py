import boto3
import os
import sys
from botocore.exceptions import ClientError, NoCredentialsError
from datetime import datetime, timedelta
import gzip
import pytz
from tqdm import tqdm

def generate_prefixes(start_date, end_date):
    """Generate a list of prefixes to search based on the date range."""
    prefixes = []
    current_date = start_date
    while current_date <= end_date:
        prefixes.append(f"illumio/summaries/{current_date.strftime('%Y%m%d')}")
        current_date += timedelta(days=1)
    return prefixes

def download_and_extract_logs(bucket_name, output_folder, minutes=10):
    """
    Download and extract the most recent logs from the S3 bucket from the last 10 minutes.
    """
    try:
        s3 = boto3.client('s3')
        
        end_date = datetime.now(pytz.UTC)
        start_date = end_date - timedelta(minutes=minutes)
        
        print(f"Downloading logs from {start_date} to {end_date} in bucket '{bucket_name}'...")
        
        prefixes = generate_prefixes(start_date, end_date)
        
        log_files = []

        print("Fetching log file details...")
        for prefix in prefixes:
            print(f"Scanning prefix: {prefix}")
            paginator = s3.get_paginator('list_objects_v2')
            for page in tqdm(paginator.paginate(Bucket=bucket_name, Prefix=prefix), desc="Scanning", unit="page"):
                if 'Contents' in page:
                    for obj in page['Contents']:
                        if obj['Key'].endswith('.gz'):
                            last_modified = obj['LastModified'].replace(tzinfo=pytz.UTC)
                            if start_date <= last_modified <= end_date:
                                log_files.append(obj)

        log_files.sort(key=lambda x: x['LastModified'], reverse=True)

        print(f"\nFound {len(log_files)} log files to download and extract.")

        # Create output folder if it doesn't exist
        os.makedirs(output_folder, exist_ok=True)

        print(f"\nDownloading and extracting log files to {output_folder}:")
        for log in tqdm(log_files, desc="Processing logs", unit="file"):
            output_filename = os.path.join(output_folder, os.path.basename(log['Key']).rstrip('.gz'))
            
            try:
                # Download the .gz file
                with open(output_filename + '.gz', 'wb') as f:
                    s3.download_fileobj(bucket_name, log['Key'], f)
                
                # Extract the .gz file
                with gzip.open(output_filename + '.gz', 'rb') as f_in:
                    with open(output_filename, 'wb') as f_out:
                        f_out.write(f_in.read())
                
                # Remove the .gz file
                os.remove(output_filename + '.gz')
                
                print(f"\nExtracted: {output_filename}")
                print(f"  Last modified: {log['LastModified']}")
                print(f"  Size: {os.path.getsize(output_filename)} bytes")
            
            except ClientError as e:
                print(f"\nError downloading {log['Key']}: {e}")
            except gzip.BadGzipFile:
                print(f"\nError: {log['Key']} is not a valid gzip file")
            except Exception as e:
                print(f"\nUnexpected error processing {log['Key']}: {e}")

        print(f"\nSummary:")
        print(f"Total log files downloaded and extracted: {len(log_files)}")
        print(f"Output folder: {output_folder}")

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
    bucket_name = os.environ.get('S3_BUCKET_NAME')
    if not bucket_name:
        print("Error: S3_BUCKET_NAME environment variable is not set.")
        print("Please set it using: export S3_BUCKET_NAME='your-bucket-name'")
        sys.exit(1)

    output_folder = os.path.join(os.getcwd(), 'downloaded_logs')
    download_and_extract_logs(bucket_name, output_folder)

if __name__ == "__main__":
    main()