#!/usr/bin/env bash
# Upload package repositories and Krellix downloads to the Cloudflare R2
# bucket served publicly as https://repo.cerberix.org/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$ROOT/packaging/repo"
BUCKET="${CERBERIX_R2_BUCKET:-cerberix-repo}"

put_tree() {
    local src="$1"
    local key_prefix="$2"

    [ -d "$src" ] || return 0

    while IFS= read -r -d '' file; do
        local rel="${file#"$src"/}"
        local key="${key_prefix}${rel}"
        put_object "$file" "$key"
    done < <(find "$src" \( -type f -o -type l \) -print0 | sort -z)
}

put_object() {
    local file="$1"
    local key="$2"
    local attempt

    for attempt in 1 2 3; do
        echo "==> R2 put $key (attempt $attempt)"
        if npx wrangler r2 object put "$BUCKET/$key" --file "$file" --remote; then
            return 0
        fi
        sleep "$attempt"
    done

    return 1
}

# Pacman clients fetch from the bucket root:
#   https://repo.cerberix.org/x86_64/cerberix-extra.db
# Cross-platform repositories keep their own prefixes.
put_tree "$REPO_ROOT/cerberix-extra" ""
put_tree "$REPO_ROOT/debian" "debian/"
put_tree "$REPO_ROOT/rpm" "rpm/"
put_tree "$REPO_ROOT/macos" "macos/"
