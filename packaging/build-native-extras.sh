#!/usr/bin/env bash
# Rebuild the published Arch release sources with the target distro toolchain.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
format=${1:?Usage: build-native-extras.sh deb|rpm OUT [PACKAGE...]}
dest=${2:?Output directory required}
shift 2
case "$format" in deb|rpm) ;; *) exit 2 ;; esac
mkdir -p "$dest"
dest=$(cd "$dest" && pwd)
export CMAKE_BUILD_PARALLEL_LEVEL=${CMAKE_BUILD_PARALLEL_LEVEL:-4}
export RUSTUP_TOOLCHAIN=stable

if (($# == 0)); then
    set -- badgerclaw fuzzytail modsentry netscope snitch swapwatch
    for dir in "$root"/cerberix-extra/krellix-*/; do
        set -- "$@" "$(basename "$dir")"
    done
fi

build_one() (
    requested=$1
    case "$requested" in
        badgerclaw|fuzzytail|modsentry|netscope|snitch|swapwatch|krellix-krell*) ;;
        *) printf 'Not a portable extra: %s\n' "$requested" >&2; exit 1 ;;
    esac
    recipe="$root/cerberix-extra/$requested"
    # These checked-in recipes are also the manifest of released sources and assets.
    source "$recipe/PKGBUILD"
    [[ "$pkgname" == "$requested" ]]
    work=$(mktemp -d "$dest/.$requested.XXXXXX")
    srcdir="$work/src"
    pkgdir="$work/payload"
    mkdir -p "$srcdir" "$pkgdir"
    export CARCH=x86_64
    local native_patch=''
    case "$pkgname" in
        modsentry) native_patch=modsentry-whois.patch ;;
        snitch) native_patch=snitch-attachment.patch ;;
    esac
    if [[ -n "$native_patch" ]]; then ((++pkgrel)); fi
    printf '==> %s %s-%s (%s)\n' "$pkgname" "$pkgver" "$pkgrel" "$format"

    for i in "${!source[@]}"; do
        item=${source[i]}
        name=${item%%::*}
        file="$srcdir/$name"
        if [[ "$item" == *::* ]]; then
            curl --fail --silent --show-error --location --retry 2 --proto '=https' "${item#*::}" -o "$file"
        elif [[ -f "$recipe/$name" ]]; then
            cp "$recipe/$name" "$file"
        elif [[ "$name" == krellix-*.tar.gz && -f "$root/cerberix-extra/krellix/$name" ]]; then
            cp "$root/cerberix-extra/krellix/$name" "$file"
            if [[ "$(sha256sum "$file" | cut -d' ' -f1)" != "${sha256sums[i]}" && "${sha256sums[i]}" == 71d4fe94d15805dc328b84a5915a65b046d875f23bab16d3d58d2ef68d739f16 ]]; then
                # This snapshot is still pinned by several independent Arch plugins.
                if [[ -n "${CERBERIX_SOURCE_CACHE:-}" && -f "$CERBERIX_SOURCE_CACHE/${sha256sums[i]}" ]]; then
                    cp "$CERBERIX_SOURCE_CACHE/${sha256sums[i]}" "$file"
                else
                    git -C "$root/.." show '79b2425:packaging/cerberix-extra/krellix/krellix-0.1.2.tar.gz' > "$file"
                fi
            fi
        else
            printf 'Missing source: %s\n' "$item" >&2; exit 1
        fi
        if [[ "${sha256sums[i]}" != SKIP ]]; then
            printf '%s  %s\n' "${sha256sums[i]}" "$file" | sha256sum --check
        elif [[ ! -f "$recipe/$name" || "$item" == *::* || "$name" == *.tar.gz ]]; then
            printf 'Refusing unchecked external source: %s\n' "$item" >&2; exit 1
        fi
        if [[ "$name" == *.tar.gz ]]; then tar -xzf "$file" -C "$srcdir"; fi
    done

    if [[ -n "$native_patch" ]]; then
        (cd "$srcdir/$pkgname-$pkgver"; patch --fuzz=0 -p1 -i "$root/native-patches/$native_patch")
    fi
    if declare -F prepare >/dev/null; then (cd "$srcdir"; prepare); fi
    if declare -F build >/dev/null; then (cd "$srcdir"; build); fi
    if [[ "$pkgname" == fuzzytail ]]; then
        (cd "$srcdir/$pkgname-$pkgver"; cargo test --locked --release)
    elif declare -F check >/dev/null; then
        (cd "$srcdir"; check)
    fi
    (cd "$srcdir"; package)

    local is_plugin=false depends='' optional='' conffile plugin_elf=''
    case "$pkgname" in
        krellix-*)
            is_plugin=true
            plugin_elf="$pkgdir/usr/lib/krellix/plugins/lib${pkgname#krellix-}.so"
            cmake -P "$root/remove-native-rpath.cmake" "$plugin_elf"
            ;;
    esac
    if [[ "$format" == deb ]]; then
        mkdir -p "$pkgdir/DEBIAN"
        local deb_arch=all elf=''
        if "$is_plugin"; then
            deb_arch=amd64
            elf="$plugin_elf"
            depends='krellix (>= 0.1.2-30)'
        elif [[ "$pkgname" == fuzzytail ]]; then
            deb_arch=amd64
            elf="$pkgdir/usr/bin/ft"
        elif [[ "$pkgname" == badgerclaw ]]; then
            # The Go build is static and has no shared-library dependencies.
            deb_arch=amd64
        fi
        if [[ -n "$elf" ]]; then
            strip --strip-debug "$elf"
            mkdir -p "$work/debian"
            printf 'Source: %s\n\nPackage: %s\nArchitecture: any\n' "$pkgname" "$pkgname" > "$work/debian/control"
            local shlibs
            shlibs=$(cd "$work"; dpkg-shlibdeps -O -e "$elf")
            shlibs=${shlibs#shlibs:Depends=}
            depends="${depends:+$depends, }$shlibs"
        fi
        case "$pkgname" in
            badgerclaw) depends='ca-certificates' ;;
            modsentry) depends='python3, whois, iptables' ;;
            snitch) depends='python3, whois'; optional='fail2ban' ;;
            netscope|swapwatch) depends='python3, python3-psutil' ;;
            krellix-krelltop) depends+=', procps' ;;
            krellix-krellmail) depends='krellix (>= 0.1.2-34)' ;;
            krellix-krellkam) optional='yt-dlp, ffmpeg' ;;
            krellix-krelldacious) optional='audacious' ;;
            krellix-krellwifi) optional='network-manager' ;;
            krellix-krellspectrum) optional='pipewire-bin, pulseaudio-utils' ;;
            krellix-krellhealth) optional='smartmontools, lm-sensors' ;;
        esac
        {
            printf 'Package: %s\nVersion: %s-%s\nArchitecture: %s\n' "$pkgname" "$pkgver" "$pkgrel" "$deb_arch"
            printf 'Section: utils\nPriority: optional\nMaintainer: Cerberix Linux <hello@cerberix.org>\nHomepage: %s\n' "$url"
            [[ -z "$depends" ]] || printf 'Depends: %s\n' "$depends"
            [[ -z "$optional" ]] || printf 'Suggests: %s\n' "$optional"
            printf 'Description: %s\n' "$pkgdesc"
        } > "$pkgdir/DEBIAN/control"
        if [[ -d "$pkgdir/etc" ]]; then
            find "$pkgdir/etc" -type f -printf '/etc/%P\n' | LC_ALL=C sort > "$pkgdir/DEBIAN/conffiles"
        fi
        install -Dm644 "$pkgdir/usr/share/licenses/$pkgname/LICENSE" "$pkgdir/usr/share/doc/$pkgname/copyright"
        local artifact="$dest/${pkgname}_${pkgver}-${pkgrel}_${deb_arch}.deb"
        [[ ! -e "$artifact" ]]
        dpkg-deb --root-owner-group --build "$pkgdir" "$artifact"
    else
        local top="$work/rpmbuild" rpm_arch=x86_64
        mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
        case "$pkgname" in
            badgerclaw) depends='ca-certificates' ;;
            modsentry) rpm_arch=noarch; depends='python3, whois, iptables' ;;
            snitch) rpm_arch=noarch; depends='python3, whois'; optional='fail2ban' ;;
            netscope|swapwatch) rpm_arch=noarch; depends='python3, python3-psutil' ;;
            krellix-krelltop) depends='krellix >= 0.1.2-30, procps-ng' ;;
            krellix-krellmail) depends='krellix >= 0.1.2-34' ;;
            krellix-*) depends='krellix >= 0.1.2-30' ;;
        esac
        case "$pkgname" in
            krellix-krellkam) optional='yt-dlp, ffmpeg-free' ;;
            krellix-krelldacious) optional='audacious' ;;
            krellix-krellwifi) optional='NetworkManager' ;;
            krellix-krellspectrum) optional='pipewire-utils, pulseaudio-utils' ;;
            krellix-krellhealth) optional='smartmontools, lm_sensors' ;;
        esac
        local spec="$top/SPECS/$pkgname.spec"
        {
            printf '%%global debug_package %%{nil}\nName: %s\nVersion: %s\nRelease: %s%%{?dist}\n' "$pkgname" "$pkgver" "$pkgrel"
            printf 'Summary: %s\nLicense: %s\nURL: %s\nBuildArch: %s\n' "$pkgdesc" "${license[0]}" "$url" "$rpm_arch"
            [[ -z "$depends" ]] || printf 'Requires: %s\n' "$depends"
            [[ -z "$optional" ]] || printf 'Suggests: %s\n' "$optional"
            printf '\n%%description\n%s.\n\n%%install\nmkdir -p "%%{buildroot}"\ncp -a "%s/." "%%{buildroot}/"\n\n%%files\n' "$pkgdesc" "$pkgdir"
            while IFS= read -r conffile; do
                case "$conffile" in
                    /etc/*) printf '%%config(noreplace) %s\n' "$conffile" ;;
                    /usr/share/licenses/*) printf '%%license %s\n' "$conffile" ;;
                    /usr/share/doc/*) printf '%%doc %s\n' "$conffile" ;;
                    *) printf '%s\n' "$conffile" ;;
                esac
            done < <(find "$pkgdir" -type f -printf '/%P\n' | LC_ALL=C sort)
        } > "$spec"
        rpmbuild -bb --define "_topdir $top" --define '_build_id_links none' "$spec"
        local artifact
        for artifact in "$top/RPMS/$rpm_arch/"*.rpm; do
            [[ ! -e "$dest/$(basename "$artifact")" ]]
            cp "$artifact" "$dest/"
        done
    fi
)

for requested in "$@"; do build_one "$requested"; done
