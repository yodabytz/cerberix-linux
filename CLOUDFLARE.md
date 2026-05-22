# Publishing the Cloudflare R2 repo

Cerberix package downloads are served from the Cloudflare R2 bucket
`cerberix-repo`.

- Public base URL: `https://repo.cerberix.org/`
- R2 bucket: `cerberix-repo`
- Pacman repo base: `https://repo.cerberix.org/$arch/`
- Pacman x86_64 objects: `x86_64/cerberix-extra.db`, packages, signatures
- Other repo prefixes: `debian/`, `rpm/`, `macos/`

The origin web server at `cerberix.org` still serves the site. It is not the
primary package mirror. Keep package links and pacman config examples pointed
at `repo.cerberix.org` so the web origin is not used for package bandwidth.

## Login

Wrangler must be authorized for the Cloudflare account before publishing:

```bash
npx wrangler login
npx wrangler whoami
```

Do not commit Cloudflare tokens or OAuth callback URLs.

## Publish packages

Build and sign the pacman repo first:

```bash
make extra-build
make extra-sign
make extra-test
make extra-publish
```

`make extra-publish` calls `packaging/publish-r2.sh`. It uploads:

- `packaging/repo/cerberix-extra/` to the bucket root, so pacman sees
  `x86_64/cerberix-extra.db`
- `packaging/repo/debian/` below `debian/`
- `packaging/repo/rpm/` below `rpm/`
- `packaging/repo/macos/` below `macos/`

The uploader writes current artifacts. Pacman chooses current package versions
from the signed repo database, so old package objects may remain in R2 until
they are cleaned up deliberately.

## Publish the site

The website still deploys to the origin:

```bash
make publish
```

The site pages should link package downloads to `repo.cerberix.org`.

## Verify

Check the public R2-backed URLs after publishing:

```bash
curl -sI https://repo.cerberix.org/x86_64/cerberix-extra.db
curl -sI https://repo.cerberix.org/x86_64/cerberix-extra.db.sig
curl -sI https://repo.cerberix.org/macos/x86_64/krellix-0.1.1-Darwin-x86_64-selfcontained.dmg
```

Pacman config for users:

```ini
[cerberix-extra]
SigLevel = Required DatabaseOptional
Server = https://repo.cerberix.org/$arch/
```

SourceForge remains an optional secondary pacman mirror via
`make extra-sync SF_USER=yodabytz`.
