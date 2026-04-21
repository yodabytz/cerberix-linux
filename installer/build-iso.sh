#!/bin/bash
# ============================================================
# Cerberix Firewall — ISO Builder
# ============================================================
# Builds a bootable Cerberix Firewall ISO using Docker.
# Run: bash installer/build-iso.sh
# Output: output/cerberix-0.3.0.iso
# ============================================================

set -euo pipefail

CERBERIX_VERSION="0.3.0"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "============================================"
echo "Cerberix Firewall ISO Builder v${CERBERIX_VERSION}"
echo "============================================"

mkdir -p "${PROJECT_ROOT}/output"

# Build the ISO builder container
docker build -t cerberix-iso-builder -f "${PROJECT_ROOT}/installer/Dockerfile.iso" "${PROJECT_ROOT}"

# Run the build (privileged needed for mount/losetup)
docker run --rm \
    -v "${PROJECT_ROOT}/output:/output" \
    --privileged \
    --device /dev/loop-control:/dev/loop-control \
    cerberix-iso-builder

echo ""
echo "=== Output ==="
ls -lh "${PROJECT_ROOT}/output/"
