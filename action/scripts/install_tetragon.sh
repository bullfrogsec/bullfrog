#!/bin/bash

# Immediately exit if any command has a non-zero exit status
set -e

TETRAGON_FILE="/tmp/tetragon.tar.gz"
if [ -f "$TETRAGON_FILE" ]; then
    echo "$TETRAGON_FILE exists."
else
    curl -L https://github.com/cilium/tetragon/releases/download/v1.1.0/tetragon-v1.1.0-amd64.tar.gz -o $TETRAGON_FILE
fi
tar -xvf /tmp/tetragon.tar.gz -C /tmp

sudo cp -vRf /tmp/tetragon-v1.1.0-amd64/usr/local/* /usr/local/
sudo rm -rf /tmp/tetragon-v1.1.0-amd64
sudo install -d /etc/tetragon/tetragon.conf.d/
sudo install -d /etc/tetragon/tetragon.tp.d/
sudo cp -v -n -r /usr/local/lib/tetragon/tetragon.conf.d /etc/tetragon/
sudo cp "$TETRAGON_POLICIES_DIRECTORY"/* /etc/tetragon/tetragon.tp.d
