# Publishing the Cloudflare R2 repo

Cerberix package downloads are served from the Cloudflare R2 bucket
`cerberix-repo`.

- Public base URL: `https://repo.cerberix.org/`
- R2 bucket: `cerberix-repo`
- Pacman repo base: `https://repo.cerberix.org/$arch/`
- Pacman x86_64 objects: `x86_64/cerberix-extra.db`, packages, signatures
- Other repo prefixes: `debian/`, `rpm/`, `macos/`

The origin web server at `cerberix.org` still serves the site and a maintained
compatibility mirror at `https://cerberix.org/repo/cerberix-extra/`. Keep
package links and pacman config examples pointed at `repo.cerberix.org` so R2
remains the primary package path and the web origin is not used for normal
package bandwidth.

## Login

Wrangler must be authorized for the Cloudflare account before publishing:

```bash
npx wrangler login
npx wrangler whoami
```

Do not commit Cloudflare tokens or OAuth callback URLs.

If publishing starts failing with `403: Forbidden` or Wrangler cannot fetch
account IDs, refresh the local Wrangler OAuth login on this machine. For remote
sessions, use browserless login:

```bash
npx wrangler login --browser=false --callback-host 127.0.0.1 --callback-port 8976
```

Open the printed Cloudflare authorization URL in a browser. After approving,
the browser may fail to connect to `localhost`; copy the full
`http://localhost:8976/oauth/callback?...` URL and submit it from this machine:

```bash
curl 'http://localhost:8976/oauth/callback?...'
```

If `npx` fails with `ENOTEMPTY` while installing/updating Wrangler, clear the
broken local npx cache first. In the June 1, 2026 recovery this directory had
root-owned files:

```bash
sudo rm -rf ~/.npm/_npx/32026684e21afda6
```

## Publish packages

Build and sign the pacman repo first:

```bash
make extra-build
make extra-sign
make extra-test
make extra-publish
```

`make extra-publish` calls `packaging/publish-r2.sh`, then refreshes the
origin compatibility mirror. The R2 publisher refreshes the browsable pacman
index from the signed database before it uploads:

- `packaging/repo/cerberix-extra/` to the bucket root, so pacman sees
  `x86_64/cerberix-extra.db`
- `packaging/repo/debian/` below `debian/`
- `packaging/repo/rpm/` below `rpm/`
- `packaging/repo/macos/` below `macos/`

The uploader writes current artifacts. Pacman chooses current package versions
from the signed repo database, so old package objects may remain in R2 until
they are cleaned up deliberately. The origin mirror is replaced from the local
signed pacman repo so existing clients using the older `cerberix.org/repo/...`
server line still receive current metadata.

## Publish the site

The website still deploys to the origin:

```bash
make publish
```

The site pages should link package downloads to `repo.cerberix.org`.

## Verify

Check the public R2-backed URLs and the origin compatibility mirror after
publishing:

```bash
curl -sI https://repo.cerberix.org/x86_64/cerberix-extra.db
curl -sI https://repo.cerberix.org/x86_64/cerberix-extra.db.sig
curl -sI https://repo.cerberix.org/macos/x86_64/krellix-0.1.1-Darwin-x86_64-selfcontained.dmg
curl -sI https://cerberix.org/repo/cerberix-extra/x86_64/cerberix-extra.db
```

Pacman config for users:

```ini
[cerberix-extra]
SigLevel = Required DatabaseOptional
Server = https://repo.cerberix.org/$arch/
```

SourceForge remains an optional secondary pacman mirror via
`make extra-sync SF_USER=yodabytz`.
