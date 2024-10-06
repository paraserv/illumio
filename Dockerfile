FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

# Install build tools required for psutil
RUN apt-get update && apt-get install -y gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY settings.ini .
COPY .env .

ENV PYTHONUNBUFFERED=1

# Create directories with appropriate permissions
RUN mkdir -p /state/downloads /logs && \
    chmod 755 /state /logs /state/downloads

# Ensure main.py is executable
RUN chmod +x app/main.py

# Add a health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
  CMD python -c "import os, sys; sys.exit(0 if os.path.exists('/state/log_queue.db') else 1)"

# Set the entrypoint to execute main.py
ENTRYPOINT ["python", "app/main.py"]

# Add a CMD instruction for default arguments (if any)
CMD []