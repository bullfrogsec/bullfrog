#!/bin/bash

# Verbose
set -x

# Stop on failure
set -e

sudo pkill --signal 9 agent || true
sudo pkill --signal 9 tetragon || true

sudo nft flush ruleset || true
# TODO: disable nftables
sudo systemctl restart docker
# TODO: remove tetragon (and all other files we install)

sudo rm -f /var/run/bullfrog/agent-ready
# sudo rm -f /tmp/tetragon.tar.gz

sudo NODE_OPTIONS=--enable-source-maps node --require /vagrant/test/block.env.js /vagrant/action/dist/main.js

source /vagrant/test/make_http_requests.sh
source /vagrant/test/make_dns_requests.sh

echo "Tests passed successfully"
