# Illumio S3 Log Processor

## Overview

The Illumio S3 Log Processor is a robust Python application designed to fetch, process, and forward Illumio logs stored in AWS S3 buckets to a SIEM (Security Information and Event Management) system via syslog. It's specifically written to work with LogRhythm SIEM and parse under the Open Collector log source type. Creating two virtual log source types for Illumio Cloud Summaries and Illumio Cloud Audit works well. It handles two primary types of logs: summary logs and auditable event logs.

Key Features:
- Fetches logs from AWS S3 buckets
- Processes and transforms logs based on their type
- Forwards logs to a SIEM system using syslog (TCP/UDP)
- Implements rate limiting and dynamic adjustment of processing speed
- Provides health reporting and monitoring
- Supports running as a standalone application or in a Docker container

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Running the Application](#running-the-application)
5. [Docker Support](#docker-support)
6. [Monitoring and Maintenance](#monitoring-and-maintenance)
7. [Troubleshooting](#troubleshooting)

## Requirements

- Python 3.12.7
- AWS S3 bucket with Illumio logs
- SIEM system capable of receiving syslog messages
- Docker (optional, for containerized deployment)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/paraserv/illumio.git
   cd illumio
   git checkout refactor-app-structure
   cd illumio-s3-log-processor
   ```

2. Create a virtual environment:
   ```
   python -m venv .venv
   source .venv/bin/activate  # On Windows, use `.venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Configuration

1. Copy the `settings.ini.example` file to `settings.ini`:
   ```
   cp settings.ini.example settings.ini
   ```

2. Edit `settings.ini` to configure the application settings, including:
   - S3 bucket details
   - Syslog server information
   - Log processing parameters
   - Health reporting settings

3. Create a `.env` file in the project root with the following content:
   ```
   AWS_ACCESS_KEY_ID=your_aws_access_key
   AWS_SECRET_ACCESS_KEY=your_aws_secret_key
   AWS_DEFAULT_REGION=your_aws_region (e.g. us-west-2)
   S3_BUCKET_NAME=your_s3_bucket_name
   ```

## Running the Application

To run the application locally:


```
python app/main.py
```

The application will start processing logs from the configured S3 bucket and send them to the specified SIEM system.

## Docker Support

### Building the Docker Image

To build the Docker image:

```
docker build -t illumio-s3-log-processor .
```

### Running with Docker

To run the application using Docker:

```
docker run -d \
  --name lrillumio \
  -e LOCAL_USER_ID=$(id -u) \
  -e LOCAL_GROUP_ID=$(id -g) \
  --restart unless-stopped \
  -v $(pwd)/settings.ini:/app/settings.ini:ro \
  -v $(pwd)/.env:/app/.env:ro \
  -v $(pwd)/state:/app/state \
  -v $(pwd)/logs:/app/logs \
  --env-file .env \
  --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \
  --memory 512m --cpus 0.5 \
  lrillumio:latest
```

The docker run command above, when ran with these parameters, will create a state and logs folder and utilize the currently logged in user's id and group id to run the container.

### Using Docker Compose

1. Create a `docker-compose.yml` file with the following content:

```yaml
version: '3'
services:
  illumio-log-processor:
    build: .
    env_file: .env
    volumes:
      - ./settings.ini:/app/settings.ini
      - ./logs:/app/logs
      - ./state:/app/state
    restart: unless-stopped
```

2. Run the application using Docker Compose:

```
docker-compose up -d
```

## Monitoring and Maintenance

- The application generates log files in the specified log directory.
- Health reports are periodically written to `health_report.json` in the log directory.
- Use the `db_stats.py` script to monitor the log queue and processing statistics:
  ```
  python app/db_stats.py
  ```

## Troubleshooting

- Check the application logs for error messages and warnings.
- Verify AWS credentials and S3 bucket permissions.
- Ensure the SIEM system is reachable and configured to accept syslog messages.
- Use the `s3_time_validator.py` script to check time synchronization with AWS S3:
  ```
  python app/s3_time_validator.py
  ```

For more detailed information on each component and its functionality, refer to the comments in the source code files.

## License

This project is licensed under the MIT License. The author is Nathan Church
with Exabeam, Inc., formerly LogRhythm, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Support

For support, please contact LogRhythm Professional Services.
