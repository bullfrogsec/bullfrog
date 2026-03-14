#!/bin/bash

# Immediately exit if any command has a non-zero exit status
set -e

VERSION="v0.10.3-rc"
CHECKSUM="e89fe97136f44a52428063b86f812dacd69ba3818787905e65d6849192dc40db"
BASE_DOWNLOAD_URL="https://github.com/bullfrogsec/agent/releases/download/"

TMP_DIR="/tmp"
AGENT_FILE_PATH="${TMP_DIR}/agent"
AGENT_FILE="$AGENT_FILE_PATH.tar.gz"
FINAL_BIN_DIR="/opt/bullfrog"

echo "Downloading agent ${VERSION}"
curl -L "${BASE_DOWNLOAD_URL}${VERSION}/agent.tar.gz" -o "$AGENT_FILE"

echo "Verifying checksum"
echo "${CHECKSUM}  ${AGENT_FILE}" | sha256sum --check --strict

tar -xvf "$AGENT_FILE" -C $TMP_DIR

mkdir -p "$FINAL_BIN_DIR"
sudo mv -vf "$AGENT_FILE_PATH" "$FINAL_BIN_DIR/agent"
