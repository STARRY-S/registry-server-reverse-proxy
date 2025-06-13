#!/bin/bash

# Validation tests

cd $(dirname $0)/../

set -euo pipefail

go test -v -count=1 ./...

echo "Test: Done"
