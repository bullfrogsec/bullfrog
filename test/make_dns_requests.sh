#!/bin/bash

if timeout 5 dig example.com; then
  echo 'Expected 'dig example.com' to fail, but it succeeded'
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
