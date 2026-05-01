#!/usr/bin/env bash
# Build every PKGBUILD under packaging/cerberix-extra/ inside a clean
# Arch container. Output lands in packaging/repo/cerberix-extra/x86_64/.
# Signing is a separate step (sign-repo.sh), run after this.
set -euo pipefail

PKG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_NAME="cerberix-extra"
OUT_DIR="$PKG_ROOT/repo/$REPO_NAME/x86_64"
IMG_NAME="cerberix-pkgbuild:latest"

mkdir -p "$OUT_DIR"

echo "==> Building builder image (no-op if unchanged)"
docker build -t "$IMG_NAME" -f "$PKG_ROOT/Dockerfile.build" "$PKG_ROOT"

for pkg_dir in "$PKG_ROOT/$REPO_NAME"/*/; do
  pkg="$(basename "$pkg_dir")"
  echo
  echo "==> Building $pkg"

  docker run --rm \
    -v "$pkg_dir":/build/pkg:ro \
    -v "$OUT_DIR":/build/out \
    "$IMG_NAME" \
    bash -c '
      set -euo pipefail
      # Sync pacman db before each build so makepkg --syncdeps does not
      # try to install whatever version was current when this builder
      # image was baked. Arch mirrors evict old package files quickly
      # (see e.g. libcups 2.4.18 → 2.4.19); without -Syy the install
      # 404s on fast-moving deps like Qt6.
      sudo pacman -Syyu --noconfirm
      cp -r /build/pkg /tmp/build
      cd /tmp/build
      sudo chown -R builder:builder .
      makepkg -s --noconfirm --nocheck
      cp -v ./*.pkg.tar.zst /build/out/
    '
done

echo
echo "==> Built packages:"
ls -la "$OUT_DIR"/*.pkg.tar.zst
