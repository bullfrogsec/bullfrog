#!/bin/bash
# This must run from within vagrant

# Get the directory of the current script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Use that directory as the base for the node command
node -r "$DIR/input.js" --trace-warnings "$DIR/../action/dist/main.js"
