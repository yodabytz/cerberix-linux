#!/bin/bash
# Reject host runtime state in image overlays; never delete user logs.
set -euo pipefail
root=${1:?Usage: check-image-state.sh ROOTFS}
for path in var/log/journal var/lib/syslog-ng; do
    if [[ -d "$root/$path" ]] && [[ -n "$(find "$root/$path" -type f -print -quit)" ]]; then
        echo "Refusing image overlay containing runtime logging state: $path" >&2
        exit 1
    fi
done
if [[ -s "$root/etc/machine-id" ]]; then
    echo "Refusing image overlay containing a populated machine-id" >&2
    exit 1
fi
