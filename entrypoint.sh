#!/bin/bash
set -euo pipefail

log() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*"
}

# Get the user ID and group ID from environment variables
USER_ID=${LOCAL_USER_ID:-9001}
GROUP_ID=${LOCAL_GROUP_ID:-9001}

log "Starting entrypoint script"
log "Ensuring user with UID: $USER_ID, GID: $GROUP_ID"

# Create group if it doesn't exist
if ! getent group appgroup > /dev/null 2>&1; then
    groupadd -g $GROUP_ID appgroup
else
    # If group exists but with wrong GID, update it
    if [ "$(getent group appgroup | cut -d: -f3)" != "$GROUP_ID" ]; then
        groupmod -g $GROUP_ID appgroup
    fi
fi

# Create user if it doesn't exist
if ! id -u appuser > /dev/null 2>&1; then
    useradd -u $USER_ID -g $GROUP_ID -m appuser
else
    # If user exists but with wrong UID or GID, update it
    if [ "$(id -u appuser)" != "$USER_ID" ] || [ "$(id -g appuser)" != "$GROUP_ID" ]; then
        usermod -u $USER_ID -g $GROUP_ID appuser
    fi
fi

# Set ownership of the necessary directories
chown -R appuser:appgroup /app/logs /app/state

# Perform initialization checks
if [ ! -f /app/settings.ini ]; then
  log "Error: settings.ini not found"
  exit 1
elif [ ! -s /app/settings.ini ]; then
  log "Warning: settings.ini is empty"
fi

# Handle SIGTERM
trap 'log "Caught SIGTERM signal, shutting down..."; kill -TERM $child' TERM

log "Starting main application"
# Switch to the new user and run the main application
exec gosu appuser python /app/app/main.py &
child=$!
wait $child