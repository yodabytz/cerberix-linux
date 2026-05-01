# Cerberix pacman repos

Two repositories ship alongside the distro, both hosted on
SourceForge and reachable over HTTPS:

- **`cerberix`** — official, distro-blessed packages (currently
  empty; reserved for `cerberix-shield`, `cerberix-connect`,
  `cerberix-install`, etc. once they're turned into proper PKGBUILDs)
- **`cerberix-extra`** — solo-maintained personal tooling
  (`netscope`, `swapwatch`, `modsentry`, `fuzzytail`, `snitch`)

Both repos are signed with the same key that signs the ISO
(`49840314FFF3DFE2D6E75439577040DEDD8E521E`, `hello@cerberix.org`).

---

## For users — adding the repo

One-time trust bootstrap:

```
sudo pacman-key --init
curl -s https://cerberix.org/gpg.asc | sudo pacman-key --add -
sudo pacman-key --lsign-key 49840314FFF3DFE2D6E75439577040DEDD8E521E
```

Add to `/etc/pacman.conf`:

```
[cerberix-extra]
SigLevel = Required DatabaseOptional
Server = https://cerberix.org/repo/cerberix-extra/$arch/
Server = https://downloads.sourceforge.net/project/cerberix-linux/cerberix/cerberix-extra/$arch/
```

The first `Server` line (cerberix.org) is the primary — we control
the bytes, no CDN propagation lag. The SF line is a secondary mirror;
pacman will fall back to it if cerberix.org is unreachable.

Then:

```
sudo pacman -Sy
sudo pacman -S netscope          # or any other cerberix-extra package
```

### One-time caveat for Cerberix 0.1.x installs

The 0.1.0 and 0.1.1 ISOs shipped these tools as manually-copied files,
not pacman-tracked packages. Because pacman refuses to overwrite
files it doesn't own, your first `pacman -S` on one of these will
conflict. One-time migration flag does it:

```
sudo pacman -S --overwrite '*' netscope swapwatch modsentry fuzzytail snitch
```

(note the single quotes around `*` — the shell will eat it otherwise).
After that first install the tools are pacman-tracked and future
updates are just `pacman -Syu`. 0.2.0 onwards ships these via the
pacman repo natively, so this caveat only bites 0.1.x users.

Cerberix Linux ships this trust and this stanza by default in the
installed system — this section is for other Arch users who want to
pull the same tools.

---

## For the maintainer — release flow

### Full pipeline

```
make extra-build     # build all packages in a clean Arch container
make extra-sign      # gpg-sign each package + the db
make extra-test      # install them all into a fresh Arch container to verify
make extra-sync SF_USER=yodabytz   # rsync to SourceForge
```

Each step depends on the previous via Make targets — `extra-test` will
trigger `extra-build` and `extra-sign` if they haven't been run.

### Layout

```
packaging/
├── Dockerfile.build              # Arch container with base-devel + rust
├── build-all.sh                  # orchestrator: PKGBUILD -> .pkg.tar.zst
├── sign-repo.sh                  # signs each package and the db
├── test-repo.sh                  # end-to-end install test in a fresh container
├── cerberix-extra/
│   ├── netscope/PKGBUILD
│   ├── swapwatch/PKGBUILD
│   ├── modsentry/PKGBUILD
│   ├── fuzzytail/PKGBUILD
│   └── snitch/PKGBUILD
└── repo/
    └── cerberix-extra/
        └── x86_64/
            ├── *.pkg.tar.zst       # built packages
            ├── *.pkg.tar.zst.sig   # detached signatures
            ├── cerberix-extra.db   # pacman database (symlink)
            ├── cerberix-extra.db.tar.zst
            ├── cerberix-extra.db.sig
            ├── cerberix-extra.files
            └── cerberix-extra.files.tar.zst
```

### Adding a new package

1. Create `cerberix-extra/<name>/PKGBUILD` — template from any
   existing one
2. Run `make extra-build` — confirm it builds clean
3. Run `make extra-test` — confirm it installs from a fresh container
4. Run `make extra-sync SF_USER=yodabytz` — push to SF

### Version bumps

1. Push a new version tag to the upstream repo (`git tag vX.Y.Z && git push --tags`)
2. Update `pkgver=` in the relevant PKGBUILD
3. Re-fetch the source tarball and update `sha256sums=`:
   ```
   curl -sL https://github.com/yodabytz/<name>/archive/refs/tags/v<new>.tar.gz | sha256sum
   ```
4. `make extra-sync SF_USER=yodabytz`

### Signing key

Uses the on-disk Cerberix GPG key (same one that signs ISOs). If
`gpg --list-secret-keys` doesn't show
`49840314FFF3DFE2D6E75439577040DEDD8E521E`, signing will fail; make
sure the agent is running and the key is loaded before invoking the
sign step.
