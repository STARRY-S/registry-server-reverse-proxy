#!/bin/bash

# Build proxy executable binnary

cd $(dirname $0)/../

set -euo pipefail

go build -o proxy ./pkg/cmd

echo '----------------------'
ls -alh ./proxy
echo '----------------------'

echo "Build: Done"
