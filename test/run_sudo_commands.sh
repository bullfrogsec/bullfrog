#!/bin/bash

if sudo ls; then
  echo 'Expected 'sudo ls' to fail, but it succeeded'
  exit 1
fi
