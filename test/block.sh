#!/bin/bash

# Verbose
set -x

# Stop on failure
set -e

# Detect environment: Vagrant vs GitHub Actions
if [ -d "/vagrant" ]; then
  # Running in Vagrant
  BASE_PATH="/vagrant"
  STEP_SUMMARY_PATH="/tmp/github_step_summary"
else
  # Running in GitHub Actions or locally
  BASE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  STEP_SUMMARY_PATH="${RUNNER_TEMP:-/tmp}/github_step_summary"
fi

echo "Running in environment with BASE_PATH: $BASE_PATH"

export GITHUB_STEP_SUMMARY="$STEP_SUMMARY_PATH"
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
  --require "$BASE_PATH/test/block.env.js" \
  "$BASE_PATH/action/dist/main.js"

source "$BASE_PATH/test/make_http_requests.sh"
source "$BASE_PATH/test/make_dns_requests.sh"
source "$BASE_PATH/test/make_docker_requests.sh"

NODE_OPTIONS=--enable-source-maps node \
  --require "$BASE_PATH/test/block.env.js" \
  "$BASE_PATH/action/dist/post.js"

echo "Content of $GITHUB_STEP_SUMMARY"
echo "-------------------------------"
cat $GITHUB_STEP_SUMMARY

# HTTP Requests - www.google.com (should succeed)
grep -E --quiet 'www\.google\.com</td><td>127\.0\.0\.53</td><td>53</td><td>DNS</td><td>Domain allowed</td><td>✅ Authorized</td><td>curl</td><td>[-]</td><td>/usr/bin/curl</td><td>curl https://www\.google\.com' $GITHUB_STEP_SUMMARY
grep -E --quiet 'www\.google\.com</td><td>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+</td><td>443</td><td>TCP</td><td>IP allowed</td><td>✅ Authorized</td><td>curl</td><td>[-]</td><td>/usr/bin/curl</td><td>curl https://www\.google\.com' $GITHUB_STEP_SUMMARY

# HTTP Requests - www.bing.com (should be blocked)
grep -E --quiet 'www\.bing\.com</td><td>127\.0\.0\.53</td><td>53</td><td>DNS</td><td>Domain not allowed</td><td>🚫 Blocked</td><td>curl</td><td>[-]</td><td>/usr/bin/curl</td><td>curl https://www\.bing\.com' $GITHUB_STEP_SUMMARY

# HTTP Requests - Direct IP (should be blocked)
grep -E --quiet '[-]</td><td>93\.184\.215\.14</td><td>443</td><td>TCP</td><td>IP not allowed</td><td>🚫 Blocked</td><td>curl</td><td>[-]</td><td>/usr/bin/curl</td><td>curl https://93\.184\.215\.14' $GITHUB_STEP_SUMMARY

# DNS Requests - example.com (should be blocked)
grep -E --quiet 'example\.com</td><td>127\.0\.0\.53</td><td>53</td><td>DNS</td><td>Domain not allowed</td><td>🚫 Blocked</td><td>dig</td><td>[-]</td><td>/usr/bin/dig</td><td>dig example\.com' $GITHUB_STEP_SUMMARY

# DNS Requests - tcp.example.com (should be blocked)
grep -E --quiet 'tcp\.example\.com</td><td>127\.0\.0\.53</td><td>53</td><td>DNS</td><td>Domain not allowed</td><td>🚫 Blocked</td><td>dig</td><td>[-]</td><td>/usr/bin/dig</td><td>dig tcp\.example\.com \+tcp' $GITHUB_STEP_SUMMARY

# DNS Requests - www.google.com (should succeed)
grep -E --quiet 'www\.google\.com</td><td>127\.0\.0\.53</td><td>53</td><td>DNS</td><td>Domain allowed</td><td>✅ Authorized</td><td>dig</td><td>[-]</td><td>/usr/bin/dig</td><td>dig www\.google\.com' $GITHUB_STEP_SUMMARY

# DNS Requests - www.wikipedia.org (should be blocked)
grep -E --quiet 'www\.wikipedia\.org</td><td>127\.0\.0\.53</td><td>53</td><td>DNS</td><td>Domain not allowed</td><td>🚫 Blocked</td><td>dig</td><td>[-]</td><td>/usr/bin/dig</td><td>dig www\.wikipedia\.org' $GITHUB_STEP_SUMMARY

# DNS Requests - www.google.com to untrusted DNS server (should be blocked)
grep -E --quiet 'www\.google\.com</td><td>8\.8\.8\.8</td><td>53</td><td>DNS</td><td>Untrusted DNS server</td><td>🚫 Blocked</td><td>dig</td><td>[-]</td><td>/usr/bin/dig</td><td>dig @8\.8\.8\.8 www\.google\.com' $GITHUB_STEP_SUMMARY

# DNS Requests - www.google.com to untrusted DNS server with TCP (should be blocked)
grep -E --quiet 'www\.google\.com</td><td>8\.8\.8\.8</td><td>53</td><td>TCP-DNS</td><td>Untrusted DNS server</td><td>🚫 Blocked</td><td>dig</td><td>[-]</td><td>/usr/bin/dig</td><td>dig @8\.8\.8\.8 www\.google\.com \+tcp' $GITHUB_STEP_SUMMARY

# DNS Requests - www.google.com to additional DNS server (should succeed)
grep -E --quiet 'www\.google\.com</td><td>1\.1\.1\.1</td><td>53</td><td>DNS</td><td>Domain allowed</td><td>✅ Authorized</td><td>dig</td><td>[-]</td><td>/usr/bin/dig</td><td>dig @1\.1\.1\.1 www\.google\.com' $GITHUB_STEP_SUMMARY

# DNS Requests - www.google.com to additional DNS server with TCP (should succeed)
grep -E --quiet 'www\.google\.com</td><td>1\.1\.1\.1</td><td>53</td><td>DNS</td><td>Domain allowed</td><td>✅ Authorized</td><td>dig</td><td>[-]</td><td>/usr/bin/dig</td><td>dig @1\.1\.1\.1 www\.google\.com \+tcp' $GITHUB_STEP_SUMMARY

# Docker Requests - www.google.com DNS from container (should succeed)
grep -E --quiet 'www\.google\.com</td><td>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+</td><td>53</td><td>DNS</td><td>Domain allowed</td><td>✅ Authorized</td><td>curl</td><td>alpine/curl:8\.7\.1:[^<]+</td><td>/usr/bin/curl</td><td>curl https://www\.google\.com' $GITHUB_STEP_SUMMARY

# Docker Requests - www.google.com TCP from container (should succeed)
grep -E --quiet 'www\.google\.com</td><td>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+</td><td>443</td><td>TCP</td><td>IP allowed</td><td>✅ Authorized</td><td>curl</td><td>alpine/curl:8\.7\.1:[^<]+</td><td>/usr/bin/curl</td><td>curl https://www\.google\.com' $GITHUB_STEP_SUMMARY

# Docker Requests - www.bing.com DNS from container (should be blocked)
grep -E --quiet 'www\.bing\.com</td><td>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+</td><td>53</td><td>DNS</td><td>Domain not allowed</td><td>🚫 Blocked</td><td>curl</td><td>alpine/curl:8\.7\.1:[^<]+</td><td>/usr/bin/curl</td><td>curl https://www\.bing\.com' $GITHUB_STEP_SUMMARY

# Docker Requests - www.msn.com DNS from 2nd container (should be blocked)
grep -E --quiet 'www\.msn\.com</td><td>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+</td><td>53</td><td>DNS</td><td>Domain not allowed</td><td>🚫 Blocked</td><td>curl</td><td>alpine/curl:8\.17\.0:[^<]+</td><td>/usr/bin/curl</td><td>curl https://www\.msn\.com' $GITHUB_STEP_SUMMARY

echo "Tests passed successfully"
