#!/bin/bash
#
# Expected Bullfrog Configuration:
#   egress-policy: block
#
# This test verifies that Docker registry access is blocked when Docker
# domains are not in the allowed list.

if timeout 5 docker pull alpine:3.14; then
    echo "Expected docker pull to fail, but it succeeded"
    exit 1;
fi