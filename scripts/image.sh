#!/bin/bash

cd $(dirname $0)/../

set -exuo pipefail

docker build \
    -f package/Dockerfile \
    --tag registry-server-reverse-proxy \
    .

echo "image: Done"
