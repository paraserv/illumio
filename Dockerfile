FROM python:3.12-slim

WORKDIR /app

COPY app/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./

ENV BASE_FOLDER=/app
ENV DOWNLOADED_FILES_FOLDER=illumio
ENV LOG_FOLDER=logs
ENV PYTHONUNBUFFERED=1

# Create directories with appropriate permissions
RUN mkdir -p $DOWNLOADED_FILES_FOLDER $LOG_FOLDER && \
    chmod 755 $DOWNLOADED_FILES_FOLDER $LOG_FOLDER

# Ensure main.py is executable
RUN chmod +x main.py

# Add build arguments for user and group IDs
ARG USER_ID=1000
ARG GROUP_ID=1000

# Create a non-root user with specified UID and GID
RUN addgroup --gid $GROUP_ID appuser && \
    adduser --disabled-password --gecos '' --uid $USER_ID --gid $GROUP_ID appuser && \
    chown -R appuser:appuser /app

USER appuser

# Set the entrypoint to execute main.py
ENTRYPOINT ["./main.py"]