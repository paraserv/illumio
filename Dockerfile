FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

# Install build tools required for psutil and gosu
RUN apt-get update && apt-get install -y gcc python3-dev gosu && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY settings.ini .
COPY entrypoint.sh /entrypoint.sh

ENV PYTHONUNBUFFERED=1

# Create directories
RUN mkdir -p state/downloads logs

# Ensure main.py and entrypoint.sh are executable
RUN chmod +x app/main.py /entrypoint.sh

# Add a health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD python -c "import os, sys; sys.exit(0 if os.path.exists('state/log_queue.db') and os.path.exists('logs/app.json') else 1)"

# Set the entrypoint to our script
ENTRYPOINT ["/entrypoint.sh"]

# Add a CMD instruction for default arguments (if any)
CMD []