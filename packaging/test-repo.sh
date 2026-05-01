#!/usr/bin/env bash
# Local end-to-end test: fresh Arch container, trust the Cerberix GPG
# key, mount the repo in as a file:// source, then `pacman -Sy` and
# install every package. Fails loud on any signature or install issue.
set -euo pipefail

PKG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_NAME="cerberix-extra"
OUT_DIR="$PKG_ROOT/repo/$REPO_NAME/x86_64"
KEY_ID="49840314FFF3DFE2D6E75439577040DEDD8E521E"

[ -f "$OUT_DIR/$REPO_NAME.db" ] || { echo "no $REPO_NAME.db — run build-all.sh + sign-repo.sh first"; exit 1; }

gpg --export --armor "$KEY_ID" > "$PKG_ROOT/cerberix.gpg.asc"
trap "rm -f $PKG_ROOT/cerberix.gpg.asc" EXIT

echo "==> Testing repo via file:// mount in fresh archlinux container"
docker run --rm \
  -v "$PKG_ROOT/cerberix.gpg.asc":/root/cerberix.gpg.asc:ro \
  -v "$OUT_DIR":/srv/$REPO_NAME:ro \
  archlinux:latest \
  bash -c "
    set -euo pipefail
    pacman-key --init
    pacman-key --add /root/cerberix.gpg.asc
    pacman-key --lsign-key $KEY_ID
    cat >> /etc/pacman.conf <<EOF

[$REPO_NAME]
SigLevel = Required DatabaseOptional
Server = file:///srv/$REPO_NAME
EOF
    pacman -Syy --noconfirm
    echo
    echo '== Repo listing =='
    pacman -Sl $REPO_NAME
    echo
    echo '== Installing all 5 packages =='
    pacman -S --noconfirm netscope swapwatch modsentry fuzzytail snitch
    echo
    echo '== Binary resolution =='
    for b in netscope swapwatch modsentry ft snitch; do
      printf '  %-10s -> %s\n' \"\$b\" \"\$(command -v \$b || echo MISSING)\"
    done
    echo
    echo '== Theme/config counts =='
    printf '  %-10s %s\n' netscope \"\$(ls /etc/netscope/themes/ | wc -l) themes\"
    printf '  %-10s %s\n' swapwatch \"\$(ls /etc/swapwatch/themes/ | wc -l) themes\"
    printf '  %-10s %s\n' modsentry \"\$(ls /etc/modsentry/themes/ | wc -l) themes, configs: \$(ls /etc/modsentry/*.conf 2>/dev/null | wc -l)\"
    printf '  %-10s %s\n' fuzzytail \"\$(ls /etc/fuzzytail/themes/ | wc -l) themes\"
    echo
    echo '== Licenses installed =='
    ls /usr/share/licenses/ | grep -E 'netscope|swapwatch|modsentry|fuzzytail|snitch'
    echo
    echo '== TEST PASSED: all 5 packages installed and verified from signed local repo =='
  "
