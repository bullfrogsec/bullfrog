#!/bin/bash
#
# Expected Bullfrog Configuration:
#   egress-policy: block
#   allowed-domains: *.google.com
#
# This test verifies that HTTP requests to allowed domains succeed while
# requests to blocked domains and direct IP addresses fail.

if ! timeout 5 curl https://www.google.com --output /dev/null; then
  echo 'Expected curl to www.google.com to succeed, but it failed';
  exit 1;
fi;

if timeout 5 curl https://www.bing.com --output /dev/null; then
  echo 'Expected curl to www.bing.com to fail, but it succeeded';
  exit 1;
fi;

if timeout 5 curl https://93.184.215.14 --output /dev/null; then
  echo 'Expected curl to 93.184.215.14 to fail, but it succeeded';
  exit 1;
fi;
