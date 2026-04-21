#!/bin/bash
set -euo pipefail

echo "[post-server] Starting post.quantumbytz.com (Gitea + PostgreSQL)..."

# ── Forward logs to Cerberix gateway via syslog ─────────────
cat > /etc/rsyslog.conf << 'EOF'
*.* @192.168.1.1:514
EOF
rsyslogd 2>/dev/null || true

# ── Initialize PostgreSQL ──────────────────────────────────
if [ ! -f /var/lib/postgresql/data/PG_VERSION ]; then
    echo "[post-server] Initializing PostgreSQL..."
    su - postgres -c "initdb -D /var/lib/postgresql/data" 2>/dev/null

    # Configure PostgreSQL
    cat >> /var/lib/postgresql/data/postgresql.conf << 'PGCONF'
listen_addresses = '*'
port = 5432
log_destination = 'syslog'
logging_collector = off
log_connections = on
log_disconnections = on
log_line_prefix = '%t [%p]: '
PGCONF

    # Allow connections from LAN
    cat >> /var/lib/postgresql/data/pg_hba.conf << 'PGHBA'
# Cerberix LAN access
host    all    all    192.168.1.0/24    md5
host    all    all    10.100.0.0/24     md5
host    all    all    10.8.0.0/24       md5
PGHBA
fi

echo "[post-server] Starting PostgreSQL..."
su - postgres -c "pg_ctl start -D /var/lib/postgresql/data -l /var/lib/postgresql/data/log" 2>/dev/null
sleep 2

# Create Gitea database
su - postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='gitea'\" | grep -q 1" 2>/dev/null || \
    su - postgres -c "createuser -s gitea" 2>/dev/null
su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname='gitea'\" | grep -q 1" 2>/dev/null || \
    su - postgres -c "createdb -O gitea gitea" 2>/dev/null

# Set password
su - postgres -c "psql -c \"ALTER USER gitea PASSWORD 'GiteaDB2026!';\"" 2>/dev/null

echo "[post-server] PostgreSQL ready"

# ── Configure Gitea ────────────────────────────────────────
if [ ! -f /var/lib/gitea/custom/conf/app.ini ]; then
    echo "[post-server] Configuring Gitea..."
    cat > /var/lib/gitea/custom/conf/app.ini << 'GITEACONF'
APP_NAME = Quantum Bytz Git
RUN_MODE = prod
RUN_USER = gitea

[server]
HTTP_PORT        = 3000
ROOT_URL         = https://post.quantumbytz.com/
DOMAIN           = post.quantumbytz.com
SSH_DOMAIN       = post.quantumbytz.com
SSH_PORT         = 22
DISABLE_SSH      = false
START_SSH_SERVER = true
SSH_LISTEN_PORT  = 22
LFS_START_SERVER = false

[database]
DB_TYPE  = postgres
HOST     = 127.0.0.1:5432
NAME     = gitea
USER     = gitea
PASSWD   = GiteaDB2026!
SSL_MODE = disable

[security]
INSTALL_LOCK   = true
SECRET_KEY     = $(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)
INTERNAL_TOKEN = $(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 80)

[service]
DISABLE_REGISTRATION       = false
REQUIRE_SIGNIN_VIEW        = false
ENABLE_NOTIFY_MAIL         = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true

[log]
MODE      = file
LEVEL     = info
ROOT_PATH = /var/lib/gitea/log

[session]
PROVIDER = file

[picture]
DISABLE_GRAVATAR = true

[openid]
ENABLE_OPENID_SIGNIN = false
ENABLE_OPENID_SIGNUP = false
GITEACONF

    chown -R gitea:www-data /var/lib/gitea
fi
# Ensure gitea owns its config
chown -R gitea:www-data /var/lib/gitea

# ── Start Gitea ────────────────────────────────────────────
echo "[post-server] Starting Gitea..."
su - gitea -c "gitea web -c /var/lib/gitea/custom/conf/app.ini" &
GITEA_PID=$!

sleep 3

# Create admin user if not exists
su - gitea -c "gitea admin user create \
    --username admin \
    --password 'QuantumAdmin2026!' \
    --email admin@quantumbytz.com \
    --admin \
    --must-change-password=false \
    -c /var/lib/gitea/custom/conf/app.ini" 2>/dev/null || true

echo "[post-server] ============================================"
echo "[post-server] post.quantumbytz.com is ONLINE"
echo "[post-server]   Gitea:      port 3000 (web)"
echo "[post-server]   SSH:        port 22 (git clone)"
echo "[post-server]   PostgreSQL: port 5432"
echo "[post-server]   Admin:      admin / QuantumAdmin2026!"
echo "[post-server] ============================================"

# Keep running
wait $GITEA_PID
