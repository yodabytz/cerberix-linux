# ============================================================
# Cerberix Network — Web Server (heros.quantumbytz.com)
# Nginx + PHP-FPM + MariaDB
# ============================================================

FROM alpine:3.21

RUN apk add --no-cache \
    nginx \
    php83 \
    php83-fpm \
    php83-mysqli \
    php83-pdo \
    php83-pdo_mysql \
    php83-json \
    php83-mbstring \
    php83-session \
    mariadb \
    mariadb-client \
    bash \
    rsyslog \
    curl && \
    # Create directories
    mkdir -p /var/www/html /run/nginx /var/log/nginx \
             /run/mysqld /var/lib/mysql && \
    chown -R mysql:mysql /var/lib/mysql /run/mysqld

COPY nginx.conf /etc/nginx/http.d/default.conf
COPY site/ /var/www/html/
COPY init.sh /usr/local/bin/web-init
RUN chmod 755 /usr/local/bin/web-init

EXPOSE 80 443

ENTRYPOINT ["/usr/local/bin/web-init"]
