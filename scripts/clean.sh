#!/bin/bash
#!/bin/bash

cd $(dirname $0)/../

set -exuo pipefail

rm -r ./build/ || true
rm app-collection-proxy || true
