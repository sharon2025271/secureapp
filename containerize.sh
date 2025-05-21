#!/bin/bash

# Exit on error
set -e

# Configuration
IMAGE_NAME="flask-app"
CONTAINER_NAME="flask-app-container"
PORT=5000
LOG_DIR="./logs"

# Check if port is already in use
if lsof -i :$PORT > /dev/null; then
    echo "Error: Port $PORT is already in use. Please stop any services using this port and try again."
    exit 1
fi

# Create logs directory if it doesn't exist
mkdir -p "$LOG_DIR"

echo "Building Docker image..."
docker build -t $IMAGE_NAME .

echo "Stopping existing container if running..."
docker stop $CONTAINER_NAME 2>/dev/null || true
docker rm $CONTAINER_NAME 2>/dev/null || true

echo "Starting container..."
echo "Application will be available at http://localhost:$PORT"
echo "Logs are being written to $LOG_DIR"
echo "Press Ctrl+C to stop the container"
echo "----------------------------------------"

# Run container in foreground mode
docker run --rm \
    --name $CONTAINER_NAME \
    -p $PORT:5000 \
    -v "$LOG_DIR:/app/logs" \
    -e FLASK_APP=app.py \
    -e FLASK_ENV=production \
    $IMAGE_NAME 