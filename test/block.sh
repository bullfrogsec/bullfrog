#!/bin/bash

# Verbose
set -x

# Stop on failure
set -e

POST_WARNINGS_FILEPATH=/tmp/post.warnings

sudo pkill --signal 9 agent || true
sudo pkill --signal 9 tetragon || true

sudo nft flush ruleset || true
# TODO: disable nftables
sudo systemctl restart docker
# TODO: remove tetragon (and all other files we install)

sudo rm -f /var/run/bullfrog/agent-ready
# sudo rm -f /tmp/tetragon.tar.gz
sudo rm -f $POST_WARNINGS_FILEPATH
sudo rm -f /var/log/tetragon/tetragon.log

sudo touch /etc/sudoers.d/runner

sudo NODE_OPTIONS=--enable-source-maps node \
  --require /vagrant/test/block.env.js \
  /vagrant/action/dist/main.js

source /vagrant/test/make_http_requests.sh
source /vagrant/test/make_dns_requests.sh

NODE_OPTIONS=--enable-source-maps node \
  --require /vagrant/test/block.env.js \
  /vagrant/action/dist/post.js | grep "^::warning::" |  sed 's/%0A/\n/g' > $POST_WARNINGS_FILEPATH

grep --quiet 'Blocked DNS request to www.bing.com from unknown process' $POST_WARNINGS_FILEPATH
grep --quiet 'Blocked request to 93.184.215.14:443 from processs `/usr/bin/curl https://93.184.215.14 --output /dev/null' $POST_WARNINGS_FILEPATH
grep --quiet 'Blocked DNS request to registry-1.docker.io from unknown process' $POST_WARNINGS_FILEPATH
grep --quiet 'Blocked DNS request to www.wikipedia.org from unknown process' $POST_WARNINGS_FILEPATH
grep --quiet 'Blocked DNS request to www.google.com from unknown process' $POST_WARNINGS_FILEPATH

echo "Tests passed successfully"
