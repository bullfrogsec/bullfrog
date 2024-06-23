#!/bin/bash

CONTAINER_NAME=nginx-6c5e1575

test() {
    local retries=10

    for ((attempt = 1; attempt <= retries; attempt++)); do
        echo "Attempt $attempt..."
        if curl --max-time 1 "http://127.0.0.1:8080" >/dev/null; then
            echo "Successfully connected to nginx container."
            exit 0
        else
            echo "Connection attempt $attempt failed."
            sleep 1
        fi
    done

    echo "Failed to connect to nginx container."
    exit 1
}

# Start nginx container in detached mode and name it 'nginx'
docker run --detach --publish 8080:80 --name $CONTAINER_NAME nginx:1.27

test
