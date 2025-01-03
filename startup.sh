#!/bin/bash

# Wait for the /data directory to be available
max_retries=30
count=0
while [ ! -d "/data" ] && [ $count -lt $max_retries ]; do
    echo "Waiting for /data directory to be mounted... ($count/$max_retries)"
    sleep 2
    count=$((count + 1))
done

if [ ! -d "/data" ]; then
    echo "Error: /data directory not available after waiting"
    exit 1
fi

# Create credits file if it doesn't exist
if [ ! -f "/data/user_credits.json" ]; then
    echo "{}" > /data/user_credits.json
    chmod 666 /data/user_credits.json
fi

# Ensure correct permissions
chmod 777 /data
chmod 666 /data/user_credits.json

# Start Ollama
ollama serve &

# Wait for Ollama to start
while ! curl -s http://localhost:11434/api/tags >/dev/null; do
    echo "Waiting for Ollama to start..."
    sleep 1
done

# Download test model
echo "Downloading test model..."
ollama pull nomic-embed-text:latest

# Start Flask with Gunicorn
echo "Starting Flask application..."
exec gunicorn -w 4 -b 0.0.0.0:8080 --timeout 6000 app:app
