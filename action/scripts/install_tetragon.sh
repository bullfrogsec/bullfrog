#!/bin/bash

# Immediately exit if any command has a non-zero exit status
set -e

TETRAGON_FILE="/tmp/tetragon.tar.gz"
if [ -f "$TETRAGON_FILE" ]; then
    echo "$TETRAGON_FILE exists."
else
    curl -L https://github.com/cilium/tetragon/releases/download/v1.1.0/tetragon-v1.1.0-amd64.tar.gz -o "$TETRAGON_FILE"
    echo "e00fd8050869910b8a3ddd75c333eda67ca71d891b0d5e2b1516de3052628e07 $TETRAGON_FILE" | sha256sum --check
fi
tar -xf "$TETRAGON_FILE" -C /tmp

sudo cp -vRf /tmp/tetragon-v1.1.0-amd64/usr/local/* /usr/local/
sudo rm -rf /tmp/tetragon-v1.1.0-amd64
sudo install -d /etc/tetragon/tetragon.conf.d/
sudo install -d /etc/tetragon/tetragon.tp.d/
sudo cp -v -n -r /usr/local/lib/tetragon/tetragon.conf.d /etc/tetragon/
sudo cp "$TETRAGON_POLICIES_DIRECTORY"/* /etc/tetragon/tetragon.tp.d
