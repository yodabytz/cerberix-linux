#!/usr/bin/env bash
# Refresh the browsable pacman repo index from the signed database.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH_DIR="$ROOT/packaging/repo/cerberix-extra/x86_64"
DB="$ARCH_DIR/cerberix-extra.db.tar.zst"
INDEX="$ARCH_DIR/index.html"
TMP="$INDEX.tmp"

[ -f "$DB" ] || {
    echo "missing repo database: $DB" >&2
    exit 1
}

human_size() {
    numfmt --to=iec-i --suffix=B "$1"
}

package_rows() {
    local filename
    local size

    while IFS= read -r filename; do
        size="$(human_size "$(stat -c '%s' "$ARCH_DIR/$filename")")"
        printf '          <tr><td><a class="file" href="%s">%s</a></td><td class="size">%s</td></tr>\n' \
            "$filename" "$filename" "$size"
    done < <(
        tar -xOf "$DB" --wildcards '*/desc' |
            awk 'previous == "%FILENAME%" { print } { previous = $0 }' |
            sort
    )
}

db_size="$(human_size "$(stat -c '%s' "$ARCH_DIR/cerberix-extra.db")")"
db_sig_size="$(human_size "$(stat -c '%s' "$ARCH_DIR/cerberix-extra.db.sig")")"
files_size="$(human_size "$(stat -c '%s' "$ARCH_DIR/cerberix-extra.files")")"

cat >"$TMP" <<EOF
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>cerberix-extra x86_64 repo</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #080b12;
      --panel: #111826;
      --line: #263349;
      --text: #edf2fb;
      --muted: #9ba8bc;
      --accent: #62d6c6;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 15px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      width: min(960px, calc(100% - 32px));
      margin: 48px auto;
    }
    h1 { margin-bottom: 8px; font-size: clamp(28px, 4vw, 42px); }
    p { color: var(--muted); }
    section {
      margin-top: 24px;
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 8px;
      overflow: hidden;
    }
    pre {
      margin: 0;
      padding: 18px;
      overflow-x: auto;
      color: var(--accent);
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 12px 16px;
      border-bottom: 1px solid var(--line);
      text-align: left;
    }
    tr:last-child td { border-bottom: 0; }
    a { color: var(--accent); }
    .size {
      color: var(--muted);
      text-align: right;
      white-space: nowrap;
    }
  </style>
</head>
<body>
  <main>
    <h1>cerberix-extra / x86_64</h1>
    <p>Signed pacman packages for Cerberix extras. Pacman uses the database files directly; this page is only for browsing.</p>

    <section>
<pre><code>[cerberix-extra]
SigLevel = Required DatabaseOptional
Server = https://repo.cerberix.org/\$arch/</code></pre>
    </section>

    <section>
      <table>
        <thead>
          <tr><th>File</th><th class="size">Size</th></tr>
        </thead>
        <tbody>
          <tr><td><a href="cerberix-extra.db">cerberix-extra.db</a></td><td class="size">$db_size</td></tr>
          <tr><td><a href="cerberix-extra.db.sig">cerberix-extra.db.sig</a></td><td class="size">$db_sig_size</td></tr>
          <tr><td><a href="cerberix-extra.files">cerberix-extra.files</a></td><td class="size">$files_size</td></tr>
$(package_rows)
        </tbody>
      </table>
    </section>
  </main>
</body>
</html>
EOF

mv "$TMP" "$INDEX"
echo "Updated $INDEX"
