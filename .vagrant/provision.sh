#!/bin/bash

# prevent timezone prompts
export DEBIAN_FRONTEND=noninteractive

# update package list
apt-get update

# install curl and other dependencies
apt-get install -y curl software-properties-common apt-utils jq golang

# install Node.js 20.x
curl -sL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs