#!/bin/bash
# ============================================================
# Cerberix Firewall — Private Certificate Authority
# ============================================================
# Creates a CA, signs server certs, and exports for clients.
#
# Usage:
#   cerberix-ca init          Create the CA
#   cerberix-ca sign          Sign a server cert for Cerberix
#   cerberix-ca export-ca     Output CA cert (install on clients)
#   cerberix-ca info          Show CA and cert details
# ============================================================

set -euo pipefail

CA_DIR="/etc/cerberix/ssl/ca"
CA_KEY="${CA_DIR}/ca.key"
CA_CERT="${CA_DIR}/ca.crt"
SERVER_KEY="/etc/cerberix/ssl/key.pem"
SERVER_CERT="/etc/cerberix/ssl/cert.pem"

log() {
    echo "[cerberix-ca] $*"
}

# ── Create the CA ───────────────────────────────────────────
init_ca() {
    if [ -f "${CA_KEY}" ]; then
        log "CA already exists at ${CA_DIR}"
        log "To recreate, delete ${CA_DIR} first"
        return 1
    fi

    mkdir -p "${CA_DIR}"
    chmod 700 "${CA_DIR}"

    log "Generating Cerberix CA private key..."
    openssl ecparam -genkey -name prime256v1 -out "${CA_KEY}" 2>/dev/null
    chmod 600 "${CA_KEY}"

    log "Creating CA certificate (valid 10 years)..."
    openssl req -new -x509 \
        -key "${CA_KEY}" \
        -out "${CA_CERT}" \
        -days 3650 \
        -subj "/C=US/O=Cerberus Systems/CN=Cerberix Root CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        2>/dev/null

    chmod 644 "${CA_CERT}"

    log "============================================"
    log "CA created successfully"
    log "  CA Key:  ${CA_KEY}"
    log "  CA Cert: ${CA_CERT}"
    log ""
    log "Next step: run 'cerberix-ca sign' to create the server cert"
    log "Then: run 'cerberix-ca export-ca' to get the CA cert for your devices"
    log "============================================"
}

# ── Sign a server certificate ───────────────────────────────
sign_cert() {
    if [ ! -f "${CA_KEY}" ]; then
        log "No CA found. Run 'cerberix-ca init' first"
        return 1
    fi

    # Gather all IPs this cert should be valid for
    local SAN_IPS="IP:127.0.0.1"

    # LAN IP
    local LAN_IP="${CERBERIX_LAN_IP:-192.168.1.1}"
    SAN_IPS="${SAN_IPS},IP:${LAN_IP}"

    # WireGuard VPN IP
    local WG_IP="${CERBERIX_WG_SERVER_IP:-10.100.0.1}"
    SAN_IPS="${SAN_IPS},IP:${WG_IP}"

    # wg-easy VPN gateway (host network)
    SAN_IPS="${SAN_IPS},IP:10.8.0.1"

    # Docker WAN IP
    SAN_IPS="${SAN_IPS},IP:10.99.0.2"

    # Public IP if available
    local PUBLIC_IP
    PUBLIC_IP=$(curl -4 -s --connect-timeout 3 ifconfig.me 2>/dev/null || true)
    if [ -n "${PUBLIC_IP}" ]; then
        SAN_IPS="${SAN_IPS},IP:${PUBLIC_IP}"
    fi

    local SAN="DNS:cerberix.local,DNS:cerberix,DNS:localhost,${SAN_IPS}"

    log "Generating server private key..."
    openssl ecparam -genkey -name prime256v1 -out "${SERVER_KEY}" 2>/dev/null
    chmod 600 "${SERVER_KEY}"

    log "Creating certificate signing request..."
    local CSR="/tmp/cerberix-server.csr"
    openssl req -new \
        -key "${SERVER_KEY}" \
        -out "${CSR}" \
        -subj "/C=US/O=Cerberus Systems/CN=cerberix.local" \
        2>/dev/null

    log "Signing certificate with Cerberix CA (valid 2 years)..."
    local EXT_FILE="/tmp/cerberix-cert-ext.cnf"
    cat > "${EXT_FILE}" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=${SAN}
EOF

    openssl x509 -req \
        -in "${CSR}" \
        -CA "${CA_CERT}" \
        -CAkey "${CA_KEY}" \
        -CAcreateserial \
        -out "${SERVER_CERT}" \
        -days 730 \
        -extfile "${EXT_FILE}" \
        2>/dev/null

    chmod 644 "${SERVER_CERT}"
    rm -f "${CSR}" "${EXT_FILE}"

    log "============================================"
    log "Server certificate signed"
    log "  Key:  ${SERVER_KEY}"
    log "  Cert: ${SERVER_CERT}"
    log "  Valid for:"
    echo "${SAN}" | tr ',' '\n' | sed 's/^/    /'
    log ""
    log "Restart the web server to use the new cert."
    log "============================================"
}

# ── Export CA cert ──────────────────────────────────────────
export_ca() {
    if [ ! -f "${CA_CERT}" ]; then
        log "No CA found. Run 'cerberix-ca init' first"
        return 1
    fi

    echo ""
    echo "============================================"
    echo "Cerberix Root CA Certificate"
    echo "============================================"
    echo ""
    echo "Install this on your devices to trust Cerberix:"
    echo ""
    echo "  macOS:"
    echo "    1. Save the cert below to a file: cerberix-ca.crt"
    echo "    2. Double-click to open in Keychain Access"
    echo "    3. Find 'Cerberix Root CA' in System keychain"
    echo "    4. Double-click it → Trust → Always Trust"
    echo ""
    echo "  iOS:"
    echo "    1. AirDrop or email the .crt file to your device"
    echo "    2. Settings → Profile Downloaded → Install"
    echo "    3. Settings → General → About → Certificate Trust Settings → Enable"
    echo ""
    echo "  Windows:"
    echo "    1. Save as cerberix-ca.crt"
    echo "    2. Double-click → Install Certificate → Local Machine"
    echo "    3. Place in 'Trusted Root Certification Authorities'"
    echo ""
    echo "  Linux:"
    echo "    sudo cp cerberix-ca.crt /usr/local/share/ca-certificates/"
    echo "    sudo update-ca-certificates"
    echo ""
    echo "---- BEGIN CERTIFICATE (copy everything below including BEGIN/END lines) ----"
    echo ""
    cat "${CA_CERT}"
    echo ""
    echo "---- END ----"
    echo ""
}

# ── Show info ───────────────────────────────────────────────
show_info() {
    echo "=== Cerberix CA ==="
    if [ -f "${CA_CERT}" ]; then
        openssl x509 -in "${CA_CERT}" -noout -subject -issuer -dates 2>/dev/null
    else
        echo "  No CA found"
    fi
    echo ""
    echo "=== Server Certificate ==="
    if [ -f "${SERVER_CERT}" ]; then
        openssl x509 -in "${SERVER_CERT}" -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null
    else
        echo "  No server cert found"
    fi
}

# ── CLI dispatch ────────────────────────────────────────────
case "${1:-help}" in
    init)       init_ca ;;
    sign)       sign_cert ;;
    export-ca)  export_ca ;;
    info)       show_info ;;
    *)
        echo "Usage: cerberix-ca {init|sign|export-ca|info}"
        echo ""
        echo "  init       Create the Cerberix Certificate Authority"
        echo "  sign       Sign a server certificate for the web panel"
        echo "  export-ca  Output the CA cert to install on your devices"
        echo "  info       Show CA and certificate details"
        ;;
esac
