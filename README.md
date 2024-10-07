# LR Illumio S3 Log Processor

Version: 1.0.0

## Overview

The LR Illumio S3 Log Processor is a robust Python application designed to fetch, process, and forward Illumio logs stored in AWS S3 buckets to a SIEM (Security Information and Event Management) system via syslog. It's specifically built for LogRhythm SIEM and is optimized to parse under the Open Collector log source type. This processor can handle two primary log types: summary logs and auditable event logs, and works best with two virtual log source types for Illumio Cloud Summaries and Illumio Cloud Audit.

Key Features:

- Log Retrieval: Fetches logs from AWS S3 buckets.
- Log Processing: Transforms logs based on their type.
- SIEM Forwarding: Forwards logs to a SIEM system via syslog (TCP/UDP).
- Rate Limiting: Implements rate limiting with various options for optimal performance.
- Health Monitoring: Provides health reporting and monitoring capabilities.
- Container Support: Can run as a standalone application or within a Docker container.

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Running the Application](#running-the-application)
5. [Docker Support](#docker-support)
6. [Monitoring and Maintenance](#monitoring-and-maintenance)
7. [Troubleshooting](#troubleshooting)
8. [License](#license)
9. [Contributing](#contributing)
10. [Support](#support)
11. [Prerequisites](#prerequisites)
12. [Security Considerations](#security-considerations)
13. [Updating](#updating)
14. [Performance Tuning](#performance-tuning)

## Requirements

### Local Installation (Mac, Linux, Windows)

- Python 3.12.7
- pip (Python package manager)
- Git

### Docker Container

- Docker Engine
- Docker Compose (optional)

### Common Requirements

- AWS S3 bucket with Illumio logs
- SIEM system capable of receiving syslog messages

## Installation

1. Clone the Repository:
   ```
   git clone https://github.com/paraserv/illumio.git
   cd illumio
   ```

2. Local Installation:
   ```
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

## Configuration

1. Edit `settings.ini`:
   - Configure general settings, paths, logging levels, S3 configurations, syslog details, and optional parameters for health reporting, queue monitoring, and NTP settings.
   - Avoid inline comments to ensure compatibility.
   - If running in a Docker container, copy the settings.ini file to the root path of where you'll run the container. This is mounted as a volume and can be edited directly in the container.

2. Create an `.env` File:
   ```
   AWS_ACCESS_KEY_ID=your_aws_access_key
   AWS_SECRET_ACCESS_KEY=your_aws_secret_key
   AWS_DEFAULT_REGION=your_aws_region
   S3_BUCKET_NAME=your_s3_bucket_name
   ```

   Important: Do not add quotation marks or inline comments to any of the lines in the .env file.

## Running the Application

To run the application locally:
```
python app/main.py
```

## Docker Support

### Building the Docker Image

Navigate to the project root and run:
```
docker build -t lrillumio .
```

Note: If using Docker Desktop, you can use the --load flag to load the image into Docker Desktop:
```
docker build -t lrillumio . --load
```

Validate the image was created and is available:
```
docker images
``` 

### Running with Docker

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

Other useful Docker commands:
```
docker ps -a             #view all containers, even stopped ones
docker logs lrillumio    #view the logs of the container
docker stop lrillumio    #stop the container
docker start lrillumio   #start the container
docker rm -f lrillumio   #forcefully remove the container
docker images            #view all images
docker rmi lrillumio     #remove the image
docker inspect lrillumio #view container details
```

The above run command will utilize the current user's ID and group ID to run the container and adjust the file permissions
on the mounted volumes. Adjust the memory and CPU settings as needed.

### Using Docker Compose

1. Create a `docker-compose.yml` file:
   ```yaml
   version: '3'
   services:
     lrillumio:
       build: .
       env_file: .env
       environment:
         - LOCAL_USER_ID=${LOCAL_USER_ID:-9001}
         - LOCAL_GROUP_ID=${LOCAL_GROUP_ID:-9001}
       volumes:
         - ./settings.ini:/app/settings.ini:ro
         - ./logs:/app/logs
         - ./state:/app/state
       restart: unless-stopped
   ```

2. Set the LOCAL_USER_ID and LOCAL_GROUP_ID environment variables:
   ```
   export LOCAL_USER_ID=$(id -u)
   export LOCAL_GROUP_ID=$(id -g)
   ```

3. Run the application using Docker Compose:
   ```
   docker-compose up -d
   ```

## Monitoring and Maintenance

- Log Files: The application writes log files to the specified directory, including `app.json` for general logs and `health_report.json` for health reports if enabled.
- Container Troubleshooting: Access the container shell:
  ```
  docker exec -it lrillumio /bin/bash
  ```
Available utilities:
   ```
   python app/db_stats.py
   python app/s3_time_validator.py
   ```

Exit the container's bash shell:
   ```
   exit
   ```  

Alternatively, you can run these utilities directly without entering the container:

```
docker exec lrillumio python app/s3_time_validator.py

docker exec lrillumio python app/db_stats.py
```
`db_stats.py`
Usage: python queue_stats.py [OPTIONS]
Options:
  -f, --follow     Run in continuous monitoring mode
  -n SECONDS       Specify refresh interval in seconds (default: 5)
  -s, --sample     Show a sample log in the output
  --db_path PATH   Path to the log_queue.db file
  -h, --help       Show this help message and exit

### Log Rotation
The application uses a RotatingFileHandler for log rotation. Logs are automatically rotated when they reach a certain size, as specified in the `settings.ini` file.

### Log Levels
Adjust the log level in `settings.ini` to control the verbosity of logging:
- DEBUG: Detailed information, typically of interest only when diagnosing problems.
- INFO: Confirmation that things are working as expected.
- WARNING: An indication that something unexpected happened, or indicative of some problem in the near future.
- ERROR: Due to a more serious problem, the software has not been able to perform some function.
- CRITICAL: A serious error, indicating that the program itself may be unable to continue running.

### Interpreting Common Log Messages
- "Processing batch of X logs": Normal operation, indicates the number of logs being processed in a batch.
- "Rate limit reached": The application has hit the configured rate limit and is slowing down processing.
- "Failed to connect to SIEM": Check network connectivity and SIEM configuration.
- "S3 access denied": Verify AWS credentials and S3 bucket permissions.

## Troubleshooting

- Check logs for errors or warnings.
- Verify AWS credentials and S3 permissions.
- Ensure the SIEM system is reachable and configured for syslog.

- Issue: Container exits immediately after starting
  Solution: Check the Docker logs for error messages. Ensure all required environment variables are set and volumes are correctly mounted.

- Issue: Logs are not being sent to the SIEM
  Solution: Verify SIEM connectivity, check syslog configuration in `settings.ini`, and ensure the SIEM is listening on the specified port.

- Issue: High CPU or memory usage
  Solution: Adjust the rate limiting settings in `settings.ini`, or increase the Docker container's resource limits.

## Prerequisites

- AWS account with appropriate S3 bucket access
- SIEM system with syslog receiving capabilities
- [Any other specific prerequisites]

## Security Considerations

- Store the .env file securely and never commit it to version control
- Regularly rotate AWS access keys
- Ensure the S3 bucket has appropriate access controls

## Updating

### Local Installation
1. Pull the latest changes: `git pull origin main`
2. Update dependencies: `pip install -r requirements.txt --upgrade`
3. Restart the application

### Docker Deployment
1. Obtain the latest docker image and load it: `docker load < lrillumio_latest.tar.gz`
2. Stop the existing container: `docker stop lrillumio`
3. Remove the old container: `docker rm lrillumio`
4. Start a new container with the updated image (use the run command from the "Running with Docker" section)

## Performance Tuning

- Adjust the `batch_size` in `settings.ini` to optimize the balance between processing speed and resource usage.
- Modify the `rate_limit` setting to control the maximum number of logs processed per second.
- Adjust the `MAX_MESSAGES_PER_SECOND` setting to control the maximum number of logs sent via SYSLOG to the SIEM per second (MPS).
- For Docker deployments, adjust the `--memory` and `--cpus` flags in the `docker run` command based on available resources and processing requirements.

## License

This project is licensed under the MIT License. The author is Nathan Church
with Exabeam, Inc., formerly LogRhythm, Inc.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Support

For support, please contact Exabeam Professional Services.