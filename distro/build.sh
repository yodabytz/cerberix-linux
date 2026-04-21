#!/bin/bash
# ============================================================
# Cerberix Linux — Master Build Script
# ============================================================
# Builds the Cerberix Linux ISO using Docker.
# Run: bash distro/build.sh
# Output: output/cerberix-linux-0.1.0-x86_64.iso
# ============================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DISTRO_DIR="${PROJECT_ROOT}/distro"

echo "============================================"
echo " Cerberix Linux — ISO Build"
echo "============================================"
echo ""

mkdir -p "${PROJECT_ROOT}/output"

echo "[0/3] Staging rootfs into build context..."
rm -rf "${DISTRO_DIR}/rootfs"
cp -a "${PROJECT_ROOT}/rootfs" "${DISTRO_DIR}/rootfs"
trap 'rm -rf "${DISTRO_DIR}/rootfs"' EXIT

echo "[1/3] Building ISO builder container..."
docker build -t cerberix-iso-builder -f "${DISTRO_DIR}/Dockerfile.iso" "${DISTRO_DIR}"

echo ""
echo "[2/3] Building ISO (this will take 10-20 minutes)..."
docker run --rm \
    --privileged \
    -v "${PROJECT_ROOT}/output:/output" \
    cerberix-iso-builder

echo ""
echo "[3/3] Done!"
echo ""
ls -lh "${PROJECT_ROOT}/output/cerberix-linux-"*
echo ""
echo "To test: boot the ISO in a VM"
echo "To install: boot → cerberix-install"
