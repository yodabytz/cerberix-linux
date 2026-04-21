#!/bin/bash
set -euo pipefail

echo "[web-server] Starting heros.quantumbytz.com..."

# ── Forward logs to Cerberix gateway via syslog ─────────────
cat > /etc/rsyslog.conf << 'EOF'
*.* @192.168.1.1:514
EOF
rsyslogd 2>/dev/null || true

# ── Initialize MariaDB ─────────────────────────────────────
if [ ! -d /var/lib/mysql/mysql ]; then
    echo "[web-server] Initializing MariaDB..."
    mysql_install_db --user=mysql --datadir=/var/lib/mysql >/dev/null 2>&1
fi

echo "[web-server] Starting MariaDB..."
mysqld --user=mysql --datadir=/var/lib/mysql &
sleep 3

# Create database and user
mysql -u root << 'SQL'
CREATE DATABASE IF NOT EXISTS heros;
CREATE USER IF NOT EXISTS 'heros'@'localhost' IDENTIFIED BY 'HeroPass2026!';
GRANT ALL PRIVILEGES ON heros.* TO 'heros'@'localhost';
FLUSH PRIVILEGES;

USE heros;
CREATE TABLE IF NOT EXISTS heroes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    power VARCHAR(200),
    team VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO heroes (id, name, power, team) VALUES
    (1, 'Cerberus', 'Three-headed guardian of the network', 'Cerberix'),
    (2, 'Firewall', 'Blocks all unauthorized access', 'Cerberix'),
    (3, 'Sentinel', 'AI-powered threat detection', 'Cerberix'),
    (4, 'Cipher', 'Encryption and secure communications', 'Cerberix'),
    (5, 'Watchdog', 'Monitors all network traffic', 'Cerberix'),
    (6, 'Shield', 'DDoS protection and rate limiting', 'Cerberix');
SQL

echo "[web-server] Database ready"

# ── Start PHP-FPM ──────────────────────────────────────────
echo "[web-server] Starting PHP-FPM..."
php-fpm83 -F -y /etc/php83/php-fpm.conf &

# ── Start Nginx ────────────────────────────────────────────
echo "[web-server] Starting Nginx..."
echo "[web-server] heros.quantumbytz.com is ONLINE"
nginx -g 'daemon off;'
