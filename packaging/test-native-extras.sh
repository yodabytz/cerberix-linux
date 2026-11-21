#!/usr/bin/env bash
# Run in a disposable target-distro container, with this directory mounted at /tests.
set -euo pipefail
base=${1:-file:/repo}
key=${2:-/repo/public-key.asc}
packages=(fuzzytail modsentry netscope snitch swapwatch krellix krellix-server)
plugins=(krellbluetooth krelldacious krellhealth krellkam krellmail krellmoon
         krellpkg krellspectrum krellstack krellstock krelltop krellweather krellwifi krellwire)
for plugin in "${plugins[@]}"; do packages+=("krellix-$plugin"); done

source /etc/os-release
case "$ID:$VERSION_ID" in
    ubuntu:24.04)
        export DEBIAN_FRONTEND=noninteractive
        printf 'deb [arch=amd64 signed-by=%s] %s/debian stable main\n' "$key" "$base" > /etc/apt/sources.list.d/cerberix-test.list
        apt-get update
        apt-get install -y --no-install-recommends "${packages[@]}"
        for pair in krellix:30 krellix-server:29 krellix-krellbluetooth:29; do
            [[ "$(dpkg-query -W -f '${Version}' "${pair%:*}")" == "0.1.2-${pair#*:}" ]]
        done
        dpkg-query -W "${packages[@]}"
        ;;
    fedora:43|fedora:44)
        [[ "$base" != file:/repo ]] || base=file:///repo
        [[ "$key" == *://* ]] || key="file://$key"
        mkdir -p /etc/yum.repos.d
        printf '[cerberix-test]\nname=Cerberix Test\nbaseurl=%s/rpm/x86_64/\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=%s\n' "$base" "$key" > /etc/yum.repos.d/cerberix-test.repo
        dnf -y --setopt=install_weak_deps=False install "${packages[@]}"
        for pair in krellix:30 krellix-server:29 krellix-krellbluetooth:29; do
            [[ "$(rpm -q --qf '%{VERSION}-%{RELEASE}' "${pair%:*}")" == "0.1.2-${pair#*:}.fc43" ]]
        done
        rpm -q "${packages[@]}"
        ;;
    *) printf 'Unexpected test distro: %s:%s\n' "$ID" "$VERSION_ID" >&2; exit 1 ;;
esac

for bin in ft modsentry netscope swapwatch; do timeout 10s "$bin" -h >/dev/null; done
python3 -m py_compile /usr/bin/snitch
python3 /tests/test-snitch-attachment.py /usr/bin/snitch

export QT_QPA_PLATFORM=offscreen XDG_CONFIG_HOME
export QT_FORCE_STDERR_LOGGING=1
export QT_MESSAGE_PATTERN='%{category}: %{message}'
export QT_LOGGING_RULES='krellix.plugin.info=true'
XDG_CONFIG_HOME=$(mktemp -d)
log=$(mktemp)
rc=0
timeout 7s krellix >"$log" 2>&1 || rc=$?
sed -n '1,100p' "$log"
[[ "$rc" == 124 ]]
if grep -E 'krellix\.plugin:.*(failed to load|bad IID|rejecting plugin)' "$log"; then exit 1; fi
for plugin in "${plugins[@]}"; do
    grep -E "loaded plugin \"(io\.krellix\.)?$plugin\".*factory ready" "$log" >/dev/null
done
printf 'Installed %s packages; all %s plugin factories loaded on %s %s.\n' "${#packages[@]}" "${#plugins[@]}" "$ID" "$VERSION_ID"
