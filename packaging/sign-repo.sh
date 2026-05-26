#!/usr/bin/env bash
# Sign every built .pkg.tar.zst in repo/cerberix-extra/x86_64/, then
# run repo-add to generate the cerberix-extra.db + .files index and
# sign those too. Uses the Cerberix GPG key (hello@cerberix.org) on
# the host — not inside the build container, since the private key
# stays on this machine.
set -euo pipefail

PKG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_NAME="cerberix-extra"
OUT_DIR="$PKG_ROOT/repo/$REPO_NAME/x86_64"
KEY_ID="49840314FFF3DFE2D6E75439577040DEDD8E521E"

cd "$OUT_DIR"

echo "==> Signing individual packages"
for pkg in *.pkg.tar.zst; do
  [ -e "$pkg" ] || { echo "no packages found"; exit 1; }
  if [ -f "$pkg.sig" ] && gpg --verify "$pkg.sig" "$pkg" &>/dev/null; then
    echo "  $pkg already signed, skipping"
    continue
  fi
  rm -f "$pkg.sig"
  gpg --detach-sign --use-agent --local-user "$KEY_ID" --output "$pkg.sig" "$pkg"
  echo "  signed $pkg"
done

echo
echo "==> Generating $REPO_NAME.db from current package files"
# Rebuild from scratch so removed package files do not remain in the
# database and same-version rebuilt packages cannot leave stale sizes.
rm -f "$REPO_NAME.db" "$REPO_NAME.db.sig" \
      "$REPO_NAME.db.tar.zst" "$REPO_NAME.db.tar.zst.sig" \
      "$REPO_NAME.db.tar.zst.old" "$REPO_NAME.db.tar.zst.old.sig" \
      "$REPO_NAME.files" "$REPO_NAME.files.sig" \
      "$REPO_NAME.files.tar.zst" "$REPO_NAME.files.tar.zst.sig" \
      "$REPO_NAME.files.tar.zst.old" "$REPO_NAME.files.tar.zst.old.sig"
# repo-add needs the Arch toolchain. Use the builder image so this
# also works on non-Arch hosts like quantumbytz.
docker run --rm \
  -v "$OUT_DIR":/build/out \
  cerberix-pkgbuild:latest \
  bash -c "cd /build/out && sudo chown builder:builder . && repo-add --new $REPO_NAME.db.tar.zst \$(printf '%s\n' ./*.pkg.tar.zst | sort -V)"

echo
echo "==> Signing $REPO_NAME.db and $REPO_NAME.files"
for f in "$REPO_NAME.db.tar.zst" "$REPO_NAME.files.tar.zst"; do
  rm -f "$f.sig"
  gpg --detach-sign --use-agent --local-user "$KEY_ID" --output "$f.sig" "$f"
done

# pacman fetches <repo>.db (not <repo>.db.tar.zst) — repo-add makes a
# symlink but keep it explicit here.
ln -sf "$REPO_NAME.db.tar.zst" "$REPO_NAME.db"
ln -sf "$REPO_NAME.db.tar.zst.sig" "$REPO_NAME.db.sig"
ln -sf "$REPO_NAME.files.tar.zst" "$REPO_NAME.files"
ln -sf "$REPO_NAME.files.tar.zst.sig" "$REPO_NAME.files.sig"

echo
echo "==> Repo contents:"
ls -la
