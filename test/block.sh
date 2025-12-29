#!/bin/bash

# Verbose
set -x

# Stop on failure
set -e

export GITHUB_STEP_SUMMARY="/tmp/github_step_summary"
sudo rm -f $GITHUB_STEP_SUMMARY
touch $GITHUB_STEP_SUMMARY

sudo pkill --signal 9 agent || true

sudo nft flush ruleset || true
# TODO: disable nftables
sudo systemctl restart docker
# TODO: remove all other files we install

sudo rm -f /var/run/bullfrog/agent-ready

sudo touch /etc/sudoers.d/runner

sudo NODE_OPTIONS=--enable-source-maps node \
  --require /vagrant/test/block.env.js \
  /vagrant/action/dist/main.js

source /vagrant/test/make_http_requests.sh
source /vagrant/test/make_dns_requests.sh

NODE_OPTIONS=--enable-source-maps node \
  --require /vagrant/test/block.env.js \
  /vagrant/action/dist/post.js

echo "Content of $GITHUB_STEP_SUMMARY"
echo "-------------------------------"
cat $GITHUB_STEP_SUMMARY

grep --quiet  'www.bing.com</td><td>127.0.0.53</td><td>53</td><td>DNS</td><td>Domain not allowed</td><td>🚫 Blocked' $GITHUB_STEP_SUMMARY
grep --quiet '93.184.215.14</td><td>443</td><td>TCP</td><td>IP not allowed</td><td>🚫 Blocked' $GITHUB_STEP_SUMMARY
grep --quiet  'registry-1.docker.io</td><td>127.0.0.53</td><td>53</td><td>DNS</td><td>Domain not allowed</td><td>🚫 Blocked' $GITHUB_STEP_SUMMARY
grep --quiet  'www.wikipedia.org</td><td>127.0.0.53</td><td>53</td><td>DNS</td><td>Domain not allowed</td><td>🚫 Blocked' $GITHUB_STEP_SUMMARY
grep --quiet  'tcp.example.com</td><td>127.0.0.53</td><td>53</td><td>DNS</td><td>Domain not allowed</td><td>🚫 Blocked' $GITHUB_STEP_SUMMARY
grep --quiet  'www.google.com</td><td>8.8.8.8</td><td>53</td><td>DNS</td><td>Untrusted DNS server</td><td>🚫 Blocked' $GITHUB_STEP_SUMMARY
grep -E --quiet 'www\.google\.com</td><td>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+</td><td>443</td><td>TCP</td><td>IP allowed</td><td>✅ Authorized' $GITHUB_STEP_SUMMARY

echo "Tests passed successfully"
