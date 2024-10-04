#!/usr/bin/env python3
"""
Script to query the log_queue.db and provide statistics about the logs.
Can run as a one-time report or continuously monitor the queue.
"""

import sqlite3
import argparse
from pathlib import Path
import time
from datetime import datetime, timedelta
import os
import sys

# Add this as a global variable at the top of the file
queue_stats_start_time = time.time()

def connect_to_db(db_path):
    """Connect to the SQLite database."""
    return sqlite3.connect(db_path)

def get_log_count(cursor):
    """Get the total number of logs in the queue."""
    cursor.execute("SELECT COUNT(*) FROM log_queue")
    return cursor.fetchone()[0]

def get_log_types(cursor):
    """Get the count of each log type, both current and total."""
    cursor.execute("SELECT log_type, COUNT(*) FROM log_queue GROUP BY log_type")
    current_counts = dict(cursor.fetchall())
    
    cursor.execute("SELECT log_type, MAX(id) FROM log_queue GROUP BY log_type")
    max_ids = dict(cursor.fetchall())
    
    cursor.execute("SELECT log_type, COUNT(DISTINCT id) FROM log_queue GROUP BY log_type")
    total_counts = dict(cursor.fetchall())
    
    # Get historical data from a separate table
    cursor.execute("CREATE TABLE IF NOT EXISTS log_type_history (log_type TEXT PRIMARY KEY, total_processed INTEGER, highest_id INTEGER)")
    cursor.execute("SELECT log_type, total_processed, highest_id FROM log_type_history")
    history = {row[0]: (row[1], row[2]) for row in cursor.fetchall()}
    
    # Update historical data
    for log_type in set(current_counts.keys()) | set(max_ids.keys()) | set(history.keys()):
        current = current_counts.get(log_type, 0)
        total = max(total_counts.get(log_type, 0), history.get(log_type, (0, 0))[0])
        highest = max(max_ids.get(log_type, 0), history.get(log_type, (0, 0))[1])
        cursor.execute("INSERT OR REPLACE INTO log_type_history (log_type, total_processed, highest_id) VALUES (?, ?, ?)",
                       (log_type, total, highest))
    
    cursor.connection.commit()
    
    # Return data including historical data
    return {log_type: (current_counts.get(log_type, 0), total, highest) 
            for log_type in set(current_counts.keys()) | set(max_ids.keys()) | set(history.keys())}

def get_total_logs_ever_inserted(cursor):
    """Get the total number of logs ever inserted into the queue."""
    cursor.execute("SELECT seq, name FROM sqlite_sequence WHERE name='log_queue'")
    result = cursor.fetchone()
    total = result[0] if result else 0
    
    creation_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(queue_stats_start_time))
    
    return total, creation_date

def get_queue_growth(cursor, time_period):
    """Get the growth of the queue over the specified time period."""
    current_time = int(time.time())
    past_time = current_time - time_period
    
    # Get the current maximum ID
    cursor.execute("SELECT COALESCE(MAX(id), 0) FROM log_queue")
    max_id = cursor.fetchone()[0]
    
    # Count new logs
    cursor.execute("SELECT COUNT(*) FROM log_queue WHERE id > ?", (max_id - time_period,))
    new_logs = cursor.fetchone()[0]
    
    # Count total logs in the period
    cursor.execute("SELECT COUNT(*) FROM log_queue WHERE id > ?", (max_id - time_period,))
    total_logs_in_period = cursor.fetchone()[0]
    
    return new_logs, total_logs_in_period

def get_processing_rate(cursor, time_period):
    """Get the processing rate over the specified time period."""
    current_time = int(time.time())
    past_time = current_time - time_period
    
    cursor.execute("SELECT seq FROM sqlite_sequence WHERE name='log_queue'")
    total_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM log_queue WHERE id <= ?", (past_time,))
    logs_before = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM log_queue")
    current_queue_size = cursor.fetchone()[0]
    
    processed_logs = (total_logs - logs_before) - (current_queue_size - logs_before)
    
    return processed_logs, processed_logs / time_period if time_period > 0 else 0

def get_sample_log(cursor):
    """Get a sample log from the queue."""
    cursor.execute("SELECT log_message, log_type FROM log_queue ORDER BY RANDOM() LIMIT 1")
    result = cursor.fetchone()
    return result if result else ("No logs in queue", "N/A")

def print_stats(cursor, continuous=False, show_sample=False):
    """Print the current queue statistics."""
    total_logs = get_log_count(cursor)
    total_ever_inserted, creation_date = get_total_logs_ever_inserted(cursor)
    log_types = get_log_types(cursor)
    growth_1h, total_1h = get_queue_growth(cursor, 3600)
    growth_24h, total_24h = get_queue_growth(cursor, 86400)
    processed_1h, rate_1h = get_processing_rate(cursor, 3600)
    processed_24h, rate_24h = get_processing_rate(cursor, 86400)

    if continuous:
        os.system('cls' if os.name == 'nt' else 'clear')  # Clear the console

    print(f"--- Queue Statistics at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---")
    print(f"Queue stats started at: {creation_date}")
    print(f"\nProcessing statistics:")
    print(f"  Total logs currently in queue: {total_logs:,}")
    print(f"  Logs processed and removed from queue: {total_ever_inserted - total_logs:,}")
    print(f"  Total logs ever inserted: {total_ever_inserted:,}")

    print("\nLog types (current in queue / total unique processed / highest ID ever):")
    for log_type, (current, total, highest) in log_types.items():
        print(f"  {log_type:<15} {current:>7,} / {total:>7,} / {highest:>7,}")

    print("\nQueue activity:")
    print(f"  New logs in last hour: {growth_1h:,}")
    print(f"  New logs in last 24 hours: {growth_24h:,}")
    print(f"  Total logs handled in last hour: {total_1h:,}")
    print(f"  Total logs handled in last 24 hours: {total_24h:,}")
    print(f"  Logs processed in last hour: {processed_1h:,}")
    print(f"  Logs processed in last 24 hours: {processed_24h:,}")
    print(f"  Processing rate (last hour): {rate_1h:.2f} logs/second")
    print(f"  Processing rate (last 24 hours): {rate_24h:.2f} logs/second")

    if not continuous:
        print("\nDatabase tables:")
        tables = get_table_names(cursor)
        for table in tables:
            print(f"  {table}")
            print_table_info(cursor, table)
    
    if show_sample:
        sample, sample_type = get_sample_log(cursor)
        print("\nSample log:")
        print(f"  Type: {sample_type}")
        print(f"  Content: {sample[:2048]}..." if len(sample) > 2048 else f"  Content: {sample}")

def get_table_names(cursor):
    """Get all table names in the database."""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    return [table[0] for table in cursor.fetchall()]

def print_table_info(cursor, table_name):
    """Print information about table structure."""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()
    print(f"    Columns:")
    for column in columns:
        print(f"      {column[1]} ({column[2]})")

def print_usage():
    print("Usage: python queue_stats.py [OPTIONS]")
    print("Options:")
    print("  -f, --follow     Run in continuous monitoring mode")
    print("  -n SECONDS       Specify refresh interval in seconds (default: 5)")
    print("  -s, --sample     Show a sample log in the output")
    print("  --db_path PATH   Path to the log_queue.db file")
    print("  -h, --help       Show this help message and exit")

def main():
    parser = argparse.ArgumentParser(description="Query log_queue.db for statistics.", add_help=False)
    parser.add_argument("-f", "--follow", action="store_true", help="Run in continuous monitoring mode")
    parser.add_argument("-n", type=float, default=5, help="Specify refresh interval in seconds")
    parser.add_argument("-s", "--sample", action="store_true", help="Show a sample log in the output")
    parser.add_argument("--db_path", type=str, help="Path to the log_queue.db file")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")

    # Parse known args first
    args, unknown = parser.parse_known_args()

    # If help is requested or unknown args are provided, print usage and exit
    if args.help or unknown:
        print_usage()
        sys.exit(0)

    # If no arguments are provided, suggest -h for help
    if len(sys.argv) == 1:
        print("Tip: Use -h or --help to see available options.")
        print()  # Add a blank line for better readability
        args.sample = True  # Enable sample log display by default

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
        if args.follow:
            print(f"Starting continuous monitoring. Refresh every {args.n} seconds. Press Ctrl+C to stop.")
            while True:
                print_stats(cursor, continuous=True, show_sample=args.sample)
                time.sleep(args.n)
        else:
            print_stats(cursor, show_sample=args.sample)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
    finally:
        conn.close()

if __name__ == "__main__":
    main()