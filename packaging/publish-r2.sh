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

put_pacman_repo() {
    local arch_dir="$REPO_ROOT/cerberix-extra/x86_64"
    local db="$arch_dir/cerberix-extra.db.tar.zst"
    local meta
    local filename

    for meta in \
        cerberix-extra.db cerberix-extra.db.sig \
        cerberix-extra.db.tar.zst cerberix-extra.db.tar.zst.sig \
        cerberix-extra.files cerberix-extra.files.sig \
        cerberix-extra.files.tar.zst cerberix-extra.files.tar.zst.sig \
        index.html; do
        [ -e "$arch_dir/$meta" ] || continue
        put_object "$arch_dir/$meta" "x86_64/$meta"
    done

    while IFS= read -r filename; do
        put_object "$arch_dir/$filename" "x86_64/$filename"
        put_object "$arch_dir/$filename.sig" "x86_64/$filename.sig"
    done < <(
        tar -xOf "$db" --wildcards '*/desc' |
            awk 'previous == "%FILENAME%" { print } { previous = $0 }'
    )
}

# Pacman clients fetch from the bucket root:
#   https://repo.cerberix.org/x86_64/cerberix-extra.db
# Publish only package revisions present in the current signed database. Old
# local package files are release history, not active repo contents.
put_pacman_repo

# Cross-platform repositories keep their own prefixes.
put_tree "$REPO_ROOT/debian" "debian/"
put_tree "$REPO_ROOT/rpm" "rpm/"
put_tree "$REPO_ROOT/macos" "macos/"
