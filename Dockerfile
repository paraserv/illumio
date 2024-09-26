FROM python:3.12-slim

WORKDIR /app

COPY app/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./

ENV BASE_FOLDER=/app
ENV DOWNLOADED_FILES_FOLDER=illumio
ENV LOG_FOLDER=logs
ENV PYTHONUNBUFFERED=1

RUN mkdir -p $DOWNLOADED_FILES_FOLDER $LOG_FOLDER

# Ensure main.py is executable
RUN chmod +x main.py

# Create a non-root user and switch to it
RUN adduser --disabled-password --gecos '' appuser && chown -R appuser /app
USER appuser

# Set the entrypoint to execute main.py
ENTRYPOINT ["./main.py"]