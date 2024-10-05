FROM python:3.12-slim

WORKDIR /app

COPY app/requirements.txt .

# Install build tools required for psutil
RUN apt-get update && apt-get install -y gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./

ENV IN_CONTAINER=true
ENV BASE_FOLDER=/app
ENV STATE_DIR=/state
ENV LOG_DIR=/logs
ENV PYTHONUNBUFFERED=1

# Create directories with appropriate permissions
RUN mkdir -p $STATE_DIR $LOG_DIR && \
    chmod 755 $STATE_DIR $LOG_DIR

# Ensure main.py is executable
RUN chmod +x main.py

# Add a health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD python -c "import os, sys; sys.exit(0 if os.path.exists('/state/log_queue.db') else 1)"

# Set the entrypoint to execute main.py
ENTRYPOINT ["./main.py"]

# Add a CMD instruction for default arguments (if any)
CMD []