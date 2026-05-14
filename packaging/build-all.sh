#!/usr/bin/env bash
# Build PKGBUILDs under packaging/cerberix-extra/ inside a clean Arch
# container. With no arguments, every package is built. With one or more
# package directory names, only those packages are built. Output lands in
# packaging/repo/cerberix-extra/x86_64/.
# Signing is a separate step (sign-repo.sh), run after this.
set -euo pipefail

PKG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_NAME="cerberix-extra"
OUT_DIR="$PKG_ROOT/repo/$REPO_NAME/x86_64"
IMG_NAME="cerberix-pkgbuild:latest"

mkdir -p "$OUT_DIR"

echo "==> Building builder image (no-op if unchanged)"
docker build -t "$IMG_NAME" -f "$PKG_ROOT/Dockerfile.build" "$PKG_ROOT"

if [ "$#" -gt 0 ]; then
  pkg_dirs=()
  for pkg in "$@"; do
    pkg_dir="$PKG_ROOT/$REPO_NAME/$pkg"
    [ -d "$pkg_dir" ] || { echo "unknown package: $pkg" >&2; exit 1; }
    pkg_dirs+=("$pkg_dir/")
  done
else
  pkg_dirs=("$PKG_ROOT/$REPO_NAME"/*/)
fi

for pkg_dir in "${pkg_dirs[@]}"; do
  pkg="$(basename "${pkg_dir%/}")"
  echo
  echo "==> Building $pkg"

  docker run --rm \
    -v "$pkg_dir":/build/pkg:ro \
    -v "$PKG_ROOT/$REPO_NAME":/build/repo:ro \
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
      if [ -f /build/out/cerberix-extra.db ]; then
        printf "\n[cerberix-extra]\nSigLevel = Never\nServer = file:///build/out\n" | sudo tee -a /etc/pacman.conf >/dev/null
        sudo pacman -Sy --noconfirm
      fi
      cp -r /build/pkg /tmp/build
      cd /tmp/build
      pkgver="$(awk -F= '"'"'/^pkgver=/ { print $2; exit }'"'"' PKGBUILD)"
      src_tar="$(awk -F"\"" '"'"'/^source=/ { print $2; exit }'"'"' PKGBUILD)"
      src_tar="${src_tar//\$pkgver/$pkgver}"
      if [ -n "$src_tar" ] && [ ! -f "$src_tar" ] && [ -f "/build/repo/krellix/$src_tar" ]; then
        cp "/build/repo/krellix/$src_tar" .
      fi
      sudo chown -R builder:builder .
      makepkg -s --noconfirm --nocheck
      for built in ./*.pkg.tar.zst; do
        pkgname="$(bsdtar -xOf "$built" .PKGINFO | awk '"'"'$1 == "pkgname" { print $3; exit }'"'"')"
        pkgver="$(bsdtar -xOf "$built" .PKGINFO | awk '"'"'$1 == "pkgver" { print $3; exit }'"'"')"
        [ -n "$pkgname" ] || { echo "could not read pkgname from $built" >&2; exit 1; }
        [ -n "$pkgver" ] || { echo "could not read pkgver from $built" >&2; exit 1; }
        rm -f /build/out/"$pkgname"-"$pkgver"-*.pkg.tar.zst /build/out/"$pkgname"-"$pkgver"-*.pkg.tar.zst.sig
        cp -v "$built" /build/out/
      done
    '
done

echo
echo "==> Built packages:"
ls -la "$OUT_DIR"/*.pkg.tar.zst
