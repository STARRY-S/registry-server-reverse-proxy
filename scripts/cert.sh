#!/bin/bash

cd $(dirname $0)/../
set -euo pipefail

mkdir -p certs/
cd certs

echo "Generating a self-signed private cert key"

openssl req -x509 \
    -newkey rsa:4096 \
    -keyout key.pem -out cert.pem \
    -sha256 -days 3650 \
    -nodes -subj "/ST=China/L=China/O=localhost/OU=localhost/CN=localhost"

echo "cert: Done"
