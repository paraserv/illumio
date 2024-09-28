FROM python:3.12-slim

WORKDIR /app

COPY app/requirements.txt .

# Install build tools required for psutil
RUN apt-get update && apt-get install -y gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

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

# **Comment out the non-root user creation and switch to root user**
# ARG USER_ID=1000
# ARG GROUP_ID=1000
# RUN group_name=$(getent group $GROUP_ID | cut -d: -f1) || group_name=appuser && \
#     if ! getent group $GROUP_ID > /dev/null; then \
#         addgroup --gid $GROUP_ID $group_name; \
#     fi && \
#     adduser --disabled-password --gecos '' --uid $USER_ID --gid $GROUP_ID appuser && \
#     chown -R appuser:$GROUP_ID /app

# **Remove the USER directive to run as root**
# USER appuser

# Set the entrypoint to execute main.py
ENTRYPOINT ["./main.py"]