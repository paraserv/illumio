#!/usr/bin/env python3
"""
Standalone script to validate the time difference between local time and S3 time.
"""

import os
import datetime
import statistics
import boto3
from botocore.exceptions import ClientError

def get_local_time():
    return datetime.datetime.now(datetime.timezone.utc)

def get_s3_time():
    s3 = boto3.client('s3')
    bucket_name = os.environ.get('S3_BUCKET_NAME')
    
    try:
        response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        if 'ResponseMetadata' in response and 'HTTPHeaders' in response['ResponseMetadata']:
            s3_time_str = response['ResponseMetadata']['HTTPHeaders']['date']
            return datetime.datetime.strptime(s3_time_str, '%a, %d %b %Y %H:%M:%S %Z').replace(tzinfo=datetime.timezone.utc)
    except ClientError as e:
        print(f"Error accessing S3: {e}")
    
    return None

def format_time_difference(diff):
    total_seconds = abs(diff.total_seconds())
    sign = '-' if diff.total_seconds() < 0 else '+'
    hours, remainder = divmod(int(total_seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{sign}{hours:02d}:{minutes:02d}:{seconds:02d}.{int(total_seconds % 1 * 1e6):06d}"

def check_time_difference():
    local_time = get_local_time()
    s3_time = get_s3_time()
    
    if s3_time:
        time_diff = local_time - s3_time
        return time_diff.total_seconds()
    return None

def main():
    num_checks = 10
    differences = []

    print(f"Running {num_checks} time checks...")
    for i in range(num_checks):
        diff = check_time_difference()
        if diff is not None:
            differences.append(diff)
            print(f"Check {i+1}: Time difference: {format_time_difference(datetime.timedelta(seconds=diff))}")
        else:
            print(f"Check {i+1}: Failed to retrieve AWS S3 time.")

    if differences:
        abs_differences = [abs(d) for d in differences]
        avg_diff = statistics.mean(differences)
        max_diff = max(differences)
        min_diff = min(differences)
        
        print("\nSummary:")
        print(f"Number of successful checks: {len(differences)}")
        print(f"Average difference:  {format_time_difference(datetime.timedelta(seconds=avg_diff))}")
        print(f"Largest difference:  {format_time_difference(datetime.timedelta(seconds=max_diff))}")
        print(f"Smallest difference: {format_time_difference(datetime.timedelta(seconds=min_diff))}")
        print(f"Standard deviation:  {format_time_difference(datetime.timedelta(seconds=statistics.stdev(differences)))}")
        print(f"\nAbsolute average difference: {statistics.mean(abs_differences):.6f} seconds")
        print(f"Absolute largest difference:  {max(abs_differences):.6f} seconds")
        print(f"Absolute smallest difference: {min(abs_differences):.6f} seconds")
    else:
        print("No successful time checks were performed.")

if __name__ == "__main__":
    main()