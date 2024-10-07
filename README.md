# LR Illumio S3 Log Processor

Version: 1.0.0

## Overview

The **LR Illumio S3 Log Processor** is a robust and scalable Python application designed to fetch, process, and forward Illumio Cloud logs stored in AWS S3 buckets to a SIEM (Security Information and Event Management) system via syslog. Specifically tailored for LogRhythm SIEM, it is optimized to parse logs under the Open Collector log source type. The processor handles two primary log types:

- **Summary Logs**: High volume logs recording process or network activities.
- **Auditable Event Logs**: Low volume logs containing important security events, such as request.authentication_failed.

The application is ideal for environments that require efficient log ingestion and processing, leveraging rate limiting, health monitoring, and containerization for optimal performance.

## Table of Contents

1. [Requirements](#requirements)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Running the Application](#running-the-application)
6. [Docker Support](#docker-support)
    - [Building the Docker Image](#building-the-docker-image)
    - [Running with Docker](#running-with-docker)
    - [Using Docker Compose](#using-docker-compose)
7. [Monitoring and Maintenance](#monitoring-and-maintenance)
    - [Available Utilities](#available-utilities)
    - [Log Rotation](#log-rotation)
    - [Log Levels](#log-levels)
    - [Interpreting Common Log Messages](#interpreting-common-log-messages)
8. [Troubleshooting](#troubleshooting)
9. [Updating](#updating)
10. [Performance Tuning](#performance-tuning)
11. [Security Considerations](#security-considerations)
12. [License](#license)
13. [Contributing](#contributing)
14. [Support](#support)

## Requirements

### Local Installation on Linux, Mac, or WSL (Windows Subsystem for Linux)

- Python 3.12.7 or higher
- `pip` (Python package manager)
- Git

### Docker Container

- Docker Engine (version 19.03 or higher)
- Docker Compose (optional, version 1.25 or higher)

### Common Requirements

- AWS S3 bucket containing Illumio logs
- SIEM system capable of receiving syslog messages (TCP or UDP)

## Prerequisites

- **AWS Account**: With access to the S3 bucket containing Illumio logs.
- **SIEM System Access**: Ensure the SIEM is reachable from the host machine or Docker container.
- **Network Access**: Open required ports in firewalls or network ACLs for outbound traffic to AWS S3 and the SIEM system.
- **AWS Credentials**: Access Key ID and Secret Access Key with permissions to read from the S3 bucket.

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/paraserv/illumio.git
   cd illumio
   ```

2. **Local Installation**:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

## Configuration

1. **Edit `settings.ini`**:

   - Configure the following sections:
     - **General Settings**: Application behavior, paths, and logging levels.
     - **AWS S3 Configuration**: Bucket name, prefixes, and region.
     - **Syslog Settings**: SIEM IP address, port, protocol (TCP/UDP), and formatting options.
     - **Rate Limiting**: Control log processing and forwarding rates.
     - **Health Reporting**: Enable or disable health checks and reporting intervals.
     - **NTP Settings**: Configure if time sync validation is important..
   - **Important**: Avoid inline comments and ensure no extraneous whitespace.

2. **Create an `.env` File**:

   ```ini
   AWS_ACCESS_KEY_ID=your_aws_access_key
   AWS_SECRET_ACCESS_KEY=your_aws_secret_key
   AWS_DEFAULT_REGION=your_aws_region
   S3_BUCKET_NAME=your_s3_bucket_name
   ```

   - **Important**: Do not add quotation marks or inline comments.
   - **Security**: Store this file securely and exclude it from version control (`.gitignore`).

## Running the Application

To run the application locally:

```bash
python app/main.py
```

- **Logs**: Check the `logs/` directory for application logs.
- **State**: The application maintains state in the `state/` directory to track processed files.

## Docker Support

### Building the Docker Image

You can build the Docker image for either amd64 or arm64 architecture:

#### For amd64 (Intel/AMD 64-bit systems, including Rocky 9/RHEL 9):

```bash
docker buildx build --platform linux/amd64 -t lrillumio:latest . --load
```

#### For arm64 (Apple Silicon M1/M2/M3/M4, some AWS instances):

```bash
docker buildx build --platform linux/arm64 -t lrillumio:latest . --load
```

- **Flags**:
  - `--load`: Loads the image into Docker after building (optional)

```
- **Note**: Ensure Docker Buildx is installed and set up correctly if using the buildx command.

#### Option 2: Traditional Docker Build

If you don't have Buildx set up, you can use the traditional `docker build` command, which will build for the current system's architecture:

```bash
docker build -t lrillumio:latest .
```

#### Validating the Build

After building with any method, verify the image:

```bash
docker images
```

You should see `lrillumio` listed with the `latest` tag.

To inspect the architecture of the built image:
```bash
docker inspect lrillumio:latest --format '{{.Architecture}}'
```

#### Creating and Distributing Image Tarballs

On the development system:

1. Save the Docker image as a tarball and compress it:
   ```bash
   docker save lrillumio:latest | gzip > lrillumio_latest.tar.gz
   ```

   This creates a compressed file `lrillumio_latest.tar.gz` which is smaller and easier to distribute.

2. Transfer the `lrillumio_latest.tar.gz` file to the target system using your preferred method (e.g., scp, sftp).

On the target system (e.g., Rocky 9 or RHEL 9):

1. Load the compressed image into Docker:
   ```bash
   gunzip -c lrillumio_latest.tar.gz | docker load
   ```

   This command decompresses the file and loads it into Docker in one step.

2. Verify the loaded image:
   ```bash
   docker images lrillumio
   ```

   You should see the `lrillumio` image listed with its tag(s).

3. Inspect the architecture of the loaded image:
   ```bash
   docker inspect lrillumio:latest --format '{{.Architecture}}'
   ```

   This will confirm the architecture of the loaded image (e.g., `amd64` for x86_64 systems).

Note: Ensure you have sufficient disk space on both the development and target systems for the Docker image and the compressed tarball during this process.

### Running with Docker

```bash
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

- **Explanation**:
  - `--env-file .env`: Passes AWS credentials securely.
  - `-v $(pwd)/state:/app/state`: Persists application state between restarts.
  - `-v $(pwd)/logs:/app/logs`: Access logs on the host system.
  - `--memory` and `--cpus`: Resource limits for the container.
  - `--restart unless-stopped`: Ensures the container restarts automatically unless stopped manually.

### Using Docker Compose

1. **Create a `docker-compose.yml` File**:

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
       ports:
         - "514:514"  # Adjust if exposing ports is necessary
       restart: unless-stopped
       deploy:
         resources:
           limits:
             cpus: '0.5'
             memory: 512M
   ```

2. **Set Environment Variables**:

   ```bash
   export LOCAL_USER_ID=$(id -u)
   export LOCAL_GROUP_ID=$(id -g)
   ```

3. **Run with Docker Compose**:

   ```bash
   docker-compose up -d
   ```

- **Additional Commands**:

  ```bash
  docker-compose logs -f
  docker-compose down
  ```

## Monitoring and Maintenance

- **Access Container Shell**:

  ```bash
  docker exec -it lrillumio /bin/bash
  ```

### Available Utilities

- **Database Statistics**:

  ```bash
  python app/db_stats.py [OPTIONS]
  ```

  **Options**:

  - `-f`, `--follow`: Continuous monitoring.
  - `-n SECONDS`: Refresh interval (default: 5).
  - `-s`, `--sample`: Show a sample log.
  - `--db_path PATH`: Path to `log_queue.db`.
  - `-h`, `--help`: Show help message.

- **S3 Time Validator**:

  ```bash
  python app/s3_time_validator.py
  ```

  **Purpose**: Validates the time difference between the local system and AWS S3, important for authentication.

### Log Rotation

The application uses a `RotatingFileHandler` for log rotation. Logs automatically rotate based on the size configured in `settings.ini`.

### Log Levels

Adjust the log level in `settings.ini` under the `[logging]` section:

- **Levels**:
  - `DEBUG`
  - `INFO`
  - `WARNING`
  - `ERROR`
  - `CRITICAL`

### Interpreting Common Log Messages

- **"Processing batch of X logs"**: Normal operation.
- **"Rate limit reached"**: Throttling to maintain configured rate.
- **"Failed to connect to SIEM"**: Check network connectivity and SIEM status.
- **"S3 access denied"**: Verify AWS credentials and S3 permissions.

## Troubleshooting

- **Container Exits Immediately**:
  - **Solution**: Run `docker logs lrillumio` to view error messages.
  - **Common Issues**:
    - Missing or incorrect environment variables.
    - Improper volume mounts.

- **Logs Not Sent to SIEM**:
  - **Solution**: Verify SIEM network connectivity and syslog configuration in `settings.ini`.

- **High Resource Usage**:
  - **Solution**: Adjust `batch_size` and `rate_limit` in `settings.ini`. Increase container resource limits if necessary.

- **Time Synchronization Issues**:
  - **Symptom**: Authentication failures when accessing AWS S3.
  - **Solution**: Ensure system time is synchronized via NTP. Use `s3_time_validator.py` to check time differences.

## Updating

### Local Installation

1. **Pull Latest Changes**:

   ```bash
   git pull origin main
   ```

2. **Update Dependencies**:

   ```bash
   pip install -r requirements.txt --upgrade
   ```

3. **Restart Application**.

### Docker Deployment

1. **Build or Obtain Latest Image**:

   ```bash
   docker buildx build --platform linux/amd64 -t lrillumio:latest . --load
   ```

2. **Stop and Remove Existing Container**:

   ```bash
   docker stop lrillumio
   docker rm lrillumio
   ```

3. **Start New Container** (use the run command from [Running with Docker](#running-with-docker)).

## Performance Tuning

- **Batch Size**: Increase or decrease `batch_size` in `settings.ini` to control the number of logs processed per batch.
- **Rate Limits**:
  - **Log Processing Rate**: Adjust `rate_limit` settings.
  - **Syslog Sending Rate**: Modify `MAX_MESSAGES_PER_SECOND` in `settings.ini`.
- **Resource Allocation**:
  - Adjust `--memory` and `--cpus` in the Docker run command.
- **Dynamic Rate Adjustment**:
  - Enable `enable_dynamic_rate` in `settings.ini` to allow the application to adjust rates based on current performance metrics.

## Security Considerations

- **Credentials Management**:
  - Do not commit `.env` files to version control.
  - Store AWS credentials securely.
- **Access Controls**:
  - Limit network exposure of the container.
  - Ensure S3 buckets have appropriate IAM policies.
- **Encryption**:
  - Use secure channels (TLS) for syslog transmission if supported by the SIEM.

## License

This project is licensed under the MIT License. The author is Nathan Church with Exabeam, Inc., formerly LogRhythm, Inc.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Support

For support, please contact Exabeam Professional Services.