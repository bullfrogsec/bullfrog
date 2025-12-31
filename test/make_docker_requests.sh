#!/bin/bash
#
# Expected Bullfrog Configuration:
#   egress-policy: block
#   allowed-domains: |
#     *.docker.io
#     production.cloudflare.docker.com
#     www.google.com
#
# This test verifies egress filtering for processes running inside Docker containers.
# Requests to allowed domains should succeed, while blocked domains should fail.

docker run --rm --entrypoint sh alpine/curl:8.7.1 -c "
    if ! timeout 5 curl https://www.google.com --output /dev/null; then
        echo 'Expected curl to www.google.com to succeed, but it failed';
        exit 1;
    fi;

    if timeout 5 curl https://www.bing.com --output /dev/null; then
        echo 'Expected curl to www.bing.com to fail, but it succeeded';
        exit 1;
    fi;
"