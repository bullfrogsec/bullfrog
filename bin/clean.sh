#!/bin/bash
# Clean-up process and files so we can start fresh
# Must run with sudo

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

pkill tetragon
pkill agent
pkill tail
nft flush ruleset
service docker restart

rm -rf /tmp/gha-agent/logs
rm -f /var/log/tetragon/tetragon.log
rm -rf /var/log/gha-agent
rm -f /tmp/agent.tar.gz
rm -rf /opt/bullfrog
rm -rf /var/run/bullfrog