# ============================================================
# Cerberix Firewall 0.3.0 — Firewall & Network Gateway Appliance
# ============================================================
# Built on Alpine Linux 3.21 base, stripped and re-branded as
# an independent security-focused distribution.
# ============================================================

# ── Stage 1: Build Python dependencies ──────────────────────
# Compile wheels in a throwaway layer to keep the final image clean
FROM alpine:3.21 AS builder

RUN apk add --no-cache python3 py3-pip python3-dev gcc musl-dev \
        libffi-dev openblas-dev g++ gfortran

# Install only what we actually import — nothing else
RUN pip3 install --no-cache-dir --break-system-packages \
        --prefix=/opt/python-deps \
        numpy==2.1.3 \
        scikit-learn==1.5.2 \
        anthropic==0.86.0

# Strip .pyc bytecode caches and test dirs from installed packages
RUN find /opt/python-deps -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
    find /opt/python-deps -type d -name tests -exec rm -rf {} + 2>/dev/null; \
    find /opt/python-deps -type d -name "*.dist-info" -exec sh -c \
        'for d; do rm -f "$d"/RECORD "$d"/INSTALLER "$d"/REQUESTED; done' _ {} + 2>/dev/null; \
    true

# ── Stage 2: Final image ───────────────────────────────────
FROM alpine:3.21

LABEL maintainer="Cerberus Systems <security@cerberus.systems>"
LABEL description="Cerberix Firewall — AI-Powered Firewall/Gateway Appliance"
LABEL version="0.3.0"
LABEL vendor="Cerberus Systems"

# ── System packages (minimal — every package justified) ─────
# nftables         firewall engine (replaces iptables)
# dnsmasq          DHCP server + DNS forwarder/cache
# iproute2-minimal ip(8) routing (no tc/ss extras)
# iptables         kernel netfilter interface for Docker NAT compat
# syslog-ng        structured logging daemon
# bash             init scripts
# curl             healthchecks
# ca-certificates  TLS root CAs
# python3          AI threat engine runtime
# libstdc++        C++ stdlib needed by numpy/sklearn native modules
# openblas         linear algebra backend for numpy/sklearn
# libgfortran      Fortran runtime for scipy internals
# libgomp          OpenMP runtime for sklearn parallel
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache \
        nftables \
        dnsmasq \
        iproute2-minimal \
        iptables \
        syslog-ng \
        bash \
        curl \
        ca-certificates \
        openssl \
        wireguard-tools \
        fail2ban \
        suricata \
        python3 \
        libstdc++ \
        openblas \
        libgfortran \
        libgomp && \
    # ── Strip Alpine identity ───────────────────────────────
    rm -f /etc/alpine-release /etc/motd && \
    # ── Remove unnecessary system accounts ──────────────────
    sed -i '/^games\|^ftp\|^news\|^lp\|^uucp\|^mail/d' \
        /etc/passwd /etc/shadow /etc/group && \
    # ── Remove apk cache ────────────────────────────────────
    rm -rf /var/cache/apk/* /tmp/* && \
    # ── Harden: strip suid/sgid from everything ─────────────
    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) \
        -exec chmod u-s,g-s {} + 2>/dev/null || true && \
    # ── Harden: restrict sensitive paths ────────────────────
    chmod 700 /etc/crontabs && \
    chmod 600 /etc/shadow && \
    # ── Harden: remove shells for system accounts ───────────
    sed -i 's|:/bin/ash$|:/sbin/nologin|' /etc/passwd && \
    sed -i 's|^root:/sbin/nologin|root:/bin/bash|' /etc/passwd && \
    # ── Harden: restrict compiler/debugger access ───────────
    rm -f /usr/bin/gcc /usr/bin/g++ /usr/bin/gdb 2>/dev/null; \
    true

# ── Python AI dependencies (from builder) ──────────────────
COPY --from=builder /opt/python-deps/lib /usr/lib

# ── Cerberix OS Identity ───────────────────────────────────
COPY rootfs/etc/os-release           /etc/os-release
COPY rootfs/etc/cerberix-release     /etc/cerberix-release
COPY rootfs/etc/motd                 /etc/motd
COPY rootfs/etc/issue                /etc/issue
COPY rootfs/etc/issue.net            /etc/issue.net
COPY rootfs/etc/hostname             /etc/hostname
COPY rootfs/etc/profile.d/cerberix.sh /etc/profile.d/cerberix.sh
COPY rootfs/etc/cerberix-logo.png    /etc/cerberix/logo.png

# ── Directory structure ─────────────────────────────────────
RUN mkdir -p \
    /etc/cerberix \
    /etc/cerberix/nftables.d \
    /etc/cerberix/dnsmasq.d \
    /var/log/cerberix \
    /var/lib/cerberix \
    /var/lib/cerberix/ai \
    /var/run/cerberix \
    /opt/cerberix/ai && \
    # ── Harden: log directory permissions ───────────────────
    chmod 750 /var/log/cerberix && \
    chmod 750 /var/lib/cerberix

# ── Configuration files ────────────────────────────────────
COPY config/nftables.conf      /etc/cerberix/nftables.conf
COPY config/nftables.d/        /etc/cerberix/nftables.d/
COPY config/dnsmasq.conf       /etc/cerberix/dnsmasq.conf
COPY config/dnsmasq.d/         /etc/cerberix/dnsmasq.d/
COPY config/syslog-ng.conf     /etc/cerberix/syslog-ng.conf
COPY config/cerberix.conf      /etc/cerberix/cerberix.conf
COPY config/cerberix-ai.conf   /etc/cerberix/cerberix-ai.conf
COPY config/wireguard.conf     /etc/cerberix/wireguard.conf
COPY config/fail2ban/          /etc/fail2ban/
COPY config/suricata/          /etc/cerberix/suricata/

# ── AI Threat Engine ───────────────────────────────────────
COPY ai/ /opt/cerberix/ai/

# ── Web Control Panel ──────────────────────────────────────
# Download Chart.js (bundled — no CDN calls at runtime)
RUN curl -fsSL https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js \
        -o /opt/cerberix/web/static/vendor/chart.min.js || true

COPY web/ /opt/cerberix/web/

# Copy logo for web UI
RUN cp /etc/cerberix/logo.png /opt/cerberix/web/static/img/cerberix-logo.png 2>/dev/null || true

# ── Scripts ────────────────────────────────────────────────
COPY scripts/init.sh            /usr/local/bin/cerberix-init
COPY scripts/firewall.sh        /usr/local/bin/cerberix-firewall
COPY scripts/network.sh         /usr/local/bin/cerberix-network
COPY scripts/healthcheck.sh     /usr/local/bin/cerberix-healthcheck
COPY scripts/wireguard.sh      /usr/local/bin/cerberix-wg
COPY scripts/cerberix-ca.sh    /usr/local/bin/cerberix-ca
COPY scripts/threatfeeds.sh    /usr/local/bin/cerberix-feeds
COPY scripts/geoip.sh          /usr/local/bin/cerberix-geoip
COPY scripts/suricata.sh       /usr/local/bin/cerberix-ids

RUN chmod 755 /usr/local/bin/cerberix-* && \
    # ── AI CLI wrapper ──────────────────────────────────────
    printf '#!/bin/bash\nPYTHONPATH=/opt/cerberix python3 -m ai.cli "$@"\n' \
        > /usr/local/bin/cerberix-ai && chmod 755 /usr/local/bin/cerberix-ai && \
    # ── Version query tool ──────────────────────────────────
    printf '#!/bin/bash\ncat /etc/cerberix-release\n' \
        > /usr/local/bin/cerberix-version && chmod 755 /usr/local/bin/cerberix-version

# ── Final hardening ────────────────────────────────────────
RUN chmod 644 /etc/cerberix/*.conf && \
    chmod 644 /etc/cerberix/nftables.d/*.nft && \
    chmod 644 /etc/cerberix/dnsmasq.d/*.conf && \
    # Remove pip, setuptools, wheel — no installs at runtime
    rm -rf /usr/lib/python3*/ensurepip \
           /usr/lib/python3*/lib2to3 \
           /usr/lib/python3*/idlelib \
           /usr/lib/python3*/tkinter \
           /usr/lib/python3*/turtle* \
           /usr/lib/python3*/test \
           /usr/lib/python3*/unittest \
           /usr/lib/python3*/pydoc* \
           /usr/lib/python3*/doctest* 2>/dev/null; \
    # Clean any stale caches
    find /usr/lib/python3* -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
    rm -rf /tmp/* /root/.cache 2>/dev/null; \
    true

# ── Health check ───────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD /usr/local/bin/cerberix-healthcheck

EXPOSE 53/tcp 53/udp 67/udp 68/udp 123/udp 514/tcp 514/udp 8443/tcp 51820/udp

ENTRYPOINT ["/usr/local/bin/cerberix-init"]
