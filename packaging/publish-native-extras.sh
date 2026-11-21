#!/usr/bin/env bash
# Stage a signed release separately from publishing it, so it can be tested first.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/repo
mirror=/var/www/cerberix.org/repo
key=49840314FFF3DFE2D6E75439577040DEDD8E521E
operation=${1:?Usage: publish-native-extras.sh stage STAGE BUILD | publish STAGE}
stage=${2:?Staging directory required}
deb_meta=debian/dists/stable
rpm_meta=rpm/x86_64/repodata
base=https://repo.cerberix.org

sign() { gpg --batch --local-user "$key" "$@"; }
if [[ "$operation" == stage ]]; then
    build=${3:?Build directory required}
    [[ ! -e "$stage" ]]
    mkdir -p "$stage/"{"$deb_meta/main/binary-amd64",rpm}
    cp -a "$root/debian/pool" "$stage/debian/pool"
    cp -a "$root/rpm/x86_64" "$stage/rpm/x86_64"
    cp "$root/$deb_meta/InRelease" "$stage/original-InRelease"
    cp "$root/$rpm_meta/repomd.xml" "$stage/original-repomd.xml"
    : > "$stage/packages.list"
    for pkg in "$build/deb/"*.deb; do
        name=$(dpkg-deb -f "$pkg" Package)
        [[ "$name" =~ ^[a-z0-9][a-z0-9+.-]+$ ]]
        rel="debian/pool/main/${name:0:1}/$name/$(basename "$pkg")"
        [[ ! -e "$stage/$rel" ]]
        install -Dm644 "$pkg" "$stage/$rel"
        sign --detach-sign "$stage/$rel"
        printf '%s\n' "$rel" "$rel.sig" >> "$stage/packages.list"
    done
    mkdir "$stage/rpmdb"
    sign --armor --export "$key" > "$stage/public-key.asc"
    rpmkeys --dbpath "$stage/rpmdb" --import "$stage/public-key.asc"
    for pkg in "$build/rpm/"*.rpm; do
        rel="rpm/x86_64/$(basename "$pkg")"
        [[ ! -e "$stage/$rel" ]]
        install -m644 "$pkg" "$stage/$rel"
        rpmsign --define "_gpg_name $key" --define '__gpg /usr/bin/gpg' --addsign "$stage/$rel"
        rpmkeys --dbpath "$stage/rpmdb" --checksig "$stage/$rel"
        printf '%s\n' "$rel" >> "$stage/packages.list"
    done
    (
        cd "$stage/debian"
        dpkg-scanpackages --arch amd64 pool /dev/null > dists/stable/main/binary-amd64/Packages
        gzip -n -c dists/stable/main/binary-amd64/Packages > dists/stable/main/binary-amd64/Packages.gz
        cd dists/stable
        for index in main/binary-amd64/Packages{,.gz}; do
            for algo in SHA256 SHA512; do
                digest=$("${algo,,}sum" "$index" | cut -d' ' -f1)
                install -Dm644 "$index" "${index%/*}/by-hash/$algo/$digest"
            done
        done
        apt-ftparchive -o APT::FTPArchive::Release::Origin=Cerberix -o APT::FTPArchive::Release::Label=Cerberix \
            -o APT::FTPArchive::Release::Suite=stable -o APT::FTPArchive::Release::Codename=stable \
            -o APT::FTPArchive::Release::Architectures=amd64 -o APT::FTPArchive::Release::Components=main \
            -o APT::FTPArchive::Release::Acquire-By-Hash=yes \
            release . > Release.tmp
        mv Release.tmp Release
        sign --armor --detach-sign -o Release.gpg Release
        sign --clearsign -o InRelease Release
    )
    createrepo_c --update "$stage/rpm/x86_64"
    sign --armor --detach-sign -o "$stage/$rpm_meta/repomd.xml.asc.new" "$stage/$rpm_meta/repomd.xml"
    mv "$stage/$rpm_meta/repomd.xml.asc.new" "$stage/$rpm_meta/repomd.xml.asc"
    printf 'Signed staging ready: %s\n' "$stage"
    exit 0
fi

[[ "$operation" == publish && -s "$stage/packages.list" && -f "$stage/verified-install" ]]
# Do not overwrite repository changes made after staging.
curl -fsS "$base/$deb_meta/InRelease" | cmp - "$stage/original-InRelease"
curl -fsS "$base/$rpm_meta/repomd.xml" | cmp - "$stage/original-repomd.xml"
cmp "$root/$deb_meta/InRelease" "$stage/original-InRelease"
cmp "$root/$rpm_meta/repomd.xml" "$stage/original-repomd.xml"
publish_file() {
    local rel=$1 file="$stage/$1" existing attempt code tmp
    tmp=$(mktemp)
    if [[ "$rel" == *.deb || "$rel" == *.deb.sig || "$rel" == *.rpm ]]; then
        for existing in "$root/$rel" "$mirror/$rel"; do
            if [[ -e "$existing" ]]; then cmp "$file" "$existing"; fi
        done
        code=$(curl -sSI -o /dev/null -w '%{http_code}' "$base/$rel?preflight=$$")
        case "$code" in
            200) curl -fsS "$base/$rel" | cmp - "$file" ;;
            404) ;;
            *) printf 'Unexpected HTTP %s: %s\n' "$code" "$rel" >&2; return 1 ;;
        esac
    fi
    install -Dm644 "$file" "$root/$rel"
    sudo -n install -Dm644 "$file" "$mirror/$rel"
    npx wrangler r2 object put "cerberix-repo/$rel" --file "$file" --remote
    for attempt in 1 2 3; do
        if curl -fsS --retry 2 "$base/$rel?cerberix-verify=$$-$attempt" -o "$tmp" && cmp -s "$file" "$tmp"; then
            printf 'Verified %s\n' "$rel"
            rm "$tmp"
            return
        fi
        sleep "$attempt"
    done
    cmp "$file" "$tmp"
}
export -f publish_file
export stage root mirror base
while IFS= read -r rel; do printf '%s\0' "$rel"; done < "$stage/packages.list" |
    xargs -0 -r -P 4 -n 1 bash -e -o pipefail -c 'publish_file "$1"' _

# The RPM index references checksum-named files; publish these before repomd.xml.
while IFS= read -r -d '' file; do
    rel=${file#"$stage"/}
    [[ -e "$root/$rel" ]] || publish_file "$rel"
done < <(find "$stage/$rpm_meta" -type f ! -name 'repomd.xml*' -print0)
while IFS= read -r -d '' file; do
    publish_file "${file#"$stage"/}"
done < <(find "$stage/$deb_meta/main/binary-amd64/by-hash" -type f -print0)
for rel in main/binary-amd64/Packages.gz main/binary-amd64/Packages Release.gpg Release InRelease; do
    publish_file "$deb_meta/$rel"
done
publish_file "$rpm_meta/repomd.xml.asc"
publish_file "$rpm_meta/repomd.xml"
