#!/bin/bash

# Immediately exit if any command has a non-zero exit status
set -e

VERSION="v0.11.0"
CHECKSUM_AMD64="3a48c0120ec691199091f8001baa69180441df053f5f9bd4411d2fc5dac9d1dd"
CHECKSUM_ARM64="474caf93baac8adc47fec9fad35a4bb6691f530811a73840ab3285d07427a9ed"
BASE_DOWNLOAD_URL="https://github.com/bullfrogsec/agent/releases/download/"

TMP_DIR="/tmp"
AGENT_FILE_PATH="${TMP_DIR}/agent"
FINAL_BIN_DIR="/opt/bullfrog"

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
  x86_64)
    AGENT_ARCH="amd64"
    CHECKSUM="$CHECKSUM_AMD64"
    ;;
  aarch64|arm64)
    AGENT_ARCH="arm64"
    CHECKSUM="$CHECKSUM_ARM64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

AGENT_FILE="$AGENT_FILE_PATH-$AGENT_ARCH.tar.gz"

echo "Downloading agent ${VERSION} for ${AGENT_ARCH}"
curl -L "${BASE_DOWNLOAD_URL}${VERSION}/agent-${AGENT_ARCH}.tar.gz" -o "$AGENT_FILE"

echo "Verifying checksum"
echo "${CHECKSUM}  ${AGENT_FILE}" | sha256sum --check --strict

tar -xvf "$AGENT_FILE" -C $TMP_DIR

mkdir -p "$FINAL_BIN_DIR"
sudo mv -vf "$AGENT_FILE_PATH" "$FINAL_BIN_DIR/agent"
