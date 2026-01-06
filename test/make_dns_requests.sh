#!/bin/bash
#
# Expected Bullfrog Configuration:
#   egress-policy: block
#   allowed-domains: *.google.com
#   allowed-ips: 1.1.1.1
#
# This test verifies DNS filtering behavior:
#   - DNS queries for allowed domains should succeed
#   - DNS queries for blocked domains should fail
#   - DNS queries to untrusted DNS servers should fail
#   - DNS queries to additional DNS server should succeed

if timeout 5 dig example.com; then
  echo 'Expected 'dig example.com' to fail, but it succeeded'
  exit 1
fi

if timeout 5 dig tcp.example.com +tcp; then
  echo 'Expected 'dig tcp.example.com +tcp' to fail, but it succeeded'
  exit 1
fi

if ! timeout 5 dig www.google.com; then
  echo 'Expected 'dig www.google.com' to succeed, but it failed'
  exit 1
fi

if ! timeout 5 dig www.google.com +tcp; then
  echo 'Expected 'dig www.google.com +tcp' to succeed, but it failed'
  exit 1
fi

if timeout 5 dig www.wikipedia.org; then
  echo 'Expected 'dig www.wikipedia.org' to fail, but it succeeded'
  exit 1
fi

if timeout 5 dig @8.8.8.8 www.google.com; then
  echo 'Expected 'dig @8.8.8.8 www.google.com' to fail, but it succeeded'
  exit 1
fi

if timeout 5 dig @8.8.8.8 www.google.com +tcp; then
  echo 'Expected 'dig @8.8.8.8 www.google.com +tcp' to fail, but it succeeded'
  exit 1
fi

if ! timeout 5 dig @1.1.1.1 www.google.com; then
  echo 'Expected 'dig @1.1.1.1 www.google.com' to succeed, but it failed'
  exit 1
fi

if ! timeout 5 dig @1.1.1.1 www.google.com +tcp; then
  echo 'Expected 'dig @1.1.1.1 www.google.com +tcp' to succeed, but it failed'
  exit 1
fi
