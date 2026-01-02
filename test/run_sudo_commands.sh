#!/bin/bash
#
# Expected Bullfrog Configuration:
#   egress-policy: block
#   enable-sudo: false
#
# This test verifies that sudo commands are blocked when enable-sudo is false.

if sudo ls; then
  echo 'Expected 'sudo ls' to fail, but it succeeded'
  exit 1
fi
