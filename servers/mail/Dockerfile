# ============================================================
# Cerberix Network — Gitea + PostgreSQL (post.quantumbytz.com)
# ============================================================

FROM alpine:3.21

RUN apk update && apk add --no-cache \
    gitea \
    postgresql16 \
    postgresql16-contrib \
    bash \
    rsyslog \
    git \
    openssh \
    curl && \
    mkdir -p /var/lib/gitea/custom/conf \
             /var/lib/gitea/data \
             /var/lib/gitea/log \
             /var/lib/postgresql/data \
             /run/postgresql && \
    chown -R gitea:www-data /var/lib/gitea && \
    chown -R postgres:postgres /var/lib/postgresql /run/postgresql

COPY init.sh /usr/local/bin/post-init
RUN chmod 755 /usr/local/bin/post-init

EXPOSE 3000 22 5432

ENTRYPOINT ["/usr/local/bin/post-init"]
