#!/bin/bash

# Immediately exit if any command has a non-zero exit status
set -e

VERSION="v0.10.2"
CHECKSUM_AMD64="42798719fa6bb65f89fcf677c74b370b68246a79470355b36432f4ad6eefe81e"
CHECKSUM_ARM64="bcf1d1024d60894e4e4fe1d1cd13c4ee0b9a0c32b4dbf0d39ac9e43a16a24336"
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
