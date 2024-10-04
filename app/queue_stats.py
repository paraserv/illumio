#!/usr/bin/env python3
"""
Script to query the log_queue.db and provide statistics about the logs.
"""

import sqlite3
import argparse
from pathlib import Path
import time
from datetime import datetime, timedelta
import os

def connect_to_db(db_path):
    """Connect to the SQLite database."""
    return sqlite3.connect(db_path)

def get_log_count(cursor):
    """Get the total number of logs in the queue."""
    cursor.execute("SELECT COUNT(*) FROM log_queue")
    return cursor.fetchone()[0]

def get_log_types(cursor):
    """Get the count of each log type."""
    cursor.execute("SELECT log_type, COUNT(*) FROM log_queue GROUP BY log_type")
    return cursor.fetchall()

def get_oldest_log(cursor):
    """Get the age of the oldest log in the queue."""
    cursor.execute("SELECT MIN(id) FROM log_queue")
    oldest_id = cursor.fetchone()[0]
    if oldest_id is not None:
        return oldest_id
    return None

def get_newest_log(cursor):
    """Get the age of the newest log in the queue."""
    cursor.execute("SELECT MAX(id) FROM log_queue")
    newest_id = cursor.fetchone()[0]
    if newest_id is not None:
        return newest_id
    return None

def get_queue_growth(cursor, time_period):
    """Get the growth of the queue over the specified time period."""
    current_time = int(time.time())
    past_time = current_time - time_period
    
    cursor.execute("SELECT COUNT(*) FROM log_queue WHERE id > ?", (past_time,))
    new_logs = cursor.fetchone()[0]
    
    return new_logs

def get_table_names(cursor):
    """Get all table names in the database."""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    return [table[0] for table in cursor.fetchall()]

def get_table_info(cursor, table_name):
    """Get information about table structure."""
    cursor.execute(f"PRAGMA table_info({table_name})")
    return cursor.fetchall()

def get_sample_data(cursor, table_name, limit=5):
    """Get sample data from the table."""
    cursor.execute(f"SELECT * FROM {table_name} LIMIT {limit}")
    return cursor.fetchall()

def main():
    parser = argparse.ArgumentParser(description="Query log_queue.db for statistics.")
    parser.add_argument("--db_path", type=str, help="Path to the log_queue.db file")
    args = parser.parse_args()

    if args.db_path:
        db_path = Path(args.db_path).resolve()
    else:
        # Determine the path to log_queue.db based on the script's location
        script_dir = Path(__file__).resolve().parent
        db_path = script_dir / "state" / "log_queue.db"

    if not db_path.exists():
        print(f"Error: Database file not found at {db_path}")
        return

    conn = connect_to_db(db_path)
    cursor = conn.cursor()

    try:
        # Get total log count
        total_logs = get_log_count(cursor)
        print(f"Total logs in queue: {total_logs}")

        # Get log types
        log_types = get_log_types(cursor)
        print("\nLog types:")
        for log_type, count in log_types:
            print(f"  {log_type}: {count}")

        # Get oldest and newest log
        oldest_id = get_oldest_log(cursor)
        newest_id = get_newest_log(cursor)
        if oldest_id and newest_id:
            print(f"\nOldest log ID: {oldest_id}")
            print(f"Newest log ID: {newest_id}")
            print(f"Queue span: {newest_id - oldest_id} logs")

        # Get queue growth
        growth_1h = get_queue_growth(cursor, 3600)
        growth_24h = get_queue_growth(cursor, 86400)
        growth_7d = get_queue_growth(cursor, 604800)

        print("\nQueue growth:")
        print(f"  Last hour: {growth_1h} logs")
        print(f"  Last 24 hours: {growth_24h} logs")
        print(f"  Last 7 days: {growth_7d} logs")

        # New: Get all table names
        tables = get_table_names(cursor)
        print("\nTables in the database:")
        for table in tables:
            print(f"  {table}")

        # New: Get table structure and sample data for each table
        for table in tables:
            print(f"\nStructure of table '{table}':")
            table_info = get_table_info(cursor, table)
            for column in table_info:
                print(f"  {column[1]} ({column[2]})")
            
            print(f"\nSample data from '{table}':")
            sample_data = get_sample_data(cursor, table)
            for row in sample_data:
                print(f"  {row}")

    finally:
        conn.close()

if __name__ == "__main__":
    main()