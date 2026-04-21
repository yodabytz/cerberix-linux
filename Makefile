# ============================================================
# Cerberix Firewall — Build & Test Makefile
# ============================================================

.PHONY: all build networks up down logs test clean shell status ai-status ai-threats ai-blocklist wg-add-peer wg-list wg-client ca-export ca-info iso vbox site publish

IMAGE_NAME := cerberix-linux
IMAGE_TAG  := 0.3.0
CONTAINER  := cerberix-gw

all: networks build up

# ── Build ───────────────────────────────────────────────────
build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

# ── Docker Networks ─────────────────────────────────────────
networks:
	@docker network inspect cerberix-wan >/dev/null 2>&1 || \
		docker network create --driver bridge --subnet 10.99.0.0/24 cerberix-wan
	@docker network inspect cerberix-lan >/dev/null 2>&1 || \
		docker network create --driver bridge --subnet 192.168.1.0/24 \
			--gateway 192.168.1.254 \
			-o com.docker.network.bridge.name=br-lan cerberix-lan

# ── Run ─────────────────────────────────────────────────────
up: networks
	docker compose up -d

down:
	docker compose down

# ── Logs ────────────────────────────────────────────────────
logs:
	docker compose logs -f cerberix

# ── Shell Access ────────────────────────────────────────────
shell:
	docker exec -it $(CONTAINER) /bin/bash

# ── Status ──────────────────────────────────────────────────
status:
	@echo "=== Container Status ==="
	@docker ps --filter name=$(CONTAINER) --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
	@echo ""
	@echo "=== Health ==="
	@docker exec $(CONTAINER) /usr/local/bin/cerberix-healthcheck 2>/dev/null || echo "Container not running"
	@echo ""
	@echo "=== Firewall Rules ==="
	@docker exec $(CONTAINER) nft list ruleset 2>/dev/null | head -30 || echo "Container not running"

# ── Test ────────────────────────────────────────────────────
test:
	@echo "=== Test 1: Firewall rules loaded ==="
	docker exec $(CONTAINER) nft list ruleset | grep -q "masquerade" && echo "PASS" || echo "FAIL"
	@echo ""
	@echo "=== Test 2: dnsmasq running ==="
	docker exec $(CONTAINER) pgrep -x dnsmasq >/dev/null && echo "PASS" || echo "FAIL"
	@echo ""
	@echo "=== Test 3: DNS resolution (from gateway) ==="
	docker exec $(CONTAINER) nslookup cloudflare.com 127.0.0.1 >/dev/null 2>&1 && echo "PASS" || echo "FAIL"
	@echo ""
	@echo "=== Test 4: IP forwarding enabled ==="
	docker exec $(CONTAINER) cat /proc/sys/net/ipv4/ip_forward | grep -q "1" && echo "PASS" || echo "FAIL"
	@echo ""
	@echo "=== Test 5: LAN client → DNS via gateway ==="
	docker exec cerberix-lan-client nslookup cloudflare.com 192.168.1.1 >/dev/null 2>&1 && echo "PASS" || echo "FAIL"
	@echo ""
	@echo "=== Test 6: LAN client → ping gateway ==="
	docker exec cerberix-lan-client ping -c 2 -W 2 192.168.1.1 >/dev/null 2>&1 && echo "PASS" || echo "FAIL"
	@echo ""
	@echo "=== Test 7: AI engine running ==="
	docker exec $(CONTAINER) pgrep -f "ai.engine" >/dev/null && echo "PASS" || echo "FAIL"
	@echo ""
	@echo "=== Test 8: AI nftables blocklist set exists ==="
	docker exec $(CONTAINER) nft list set inet cerberix_ai blocklist >/dev/null 2>&1 && echo "PASS" || echo "FAIL"

# ── AI Commands ─────────────────────────────────────────────
ai-status:
	docker exec $(CONTAINER) cerberix-ai status

ai-threats:
	docker exec $(CONTAINER) cerberix-ai threats

ai-blocklist:
	docker exec $(CONTAINER) cerberix-ai blocklist

# ── WireGuard Commands ──────────────────────────────────────
wg-add-peer:
	@read -p "Peer name: " name && docker exec $(CONTAINER) cerberix-wg add-peer $$name

wg-list:
	docker exec $(CONTAINER) cerberix-wg list-peers

wg-client:
	@read -p "Peer name: " name && docker exec $(CONTAINER) cerberix-wg show-client $$name

# ── Certificate Authority ───────────────────────────────────
ca-export:
	docker exec $(CONTAINER) cerberix-ca export-ca

ca-info:
	docker exec $(CONTAINER) cerberix-ca info

# ── ISO Build ───────────────────────────────────────────────
iso:
	bash installer/build-iso.sh

vbox:
	bash installer/build-vbox.sh

# ── Website / Blog ──────────────────────────────────────────
site:
	@echo "[1/1] Regenerating blog + RSS feed from site/posts/"
	python3 site/tools/build-blog.py

publish: site
	@echo "[1/1] Deploying to /var/www/cerberix.org/"
	sudo rsync -a --delete \
		--exclude='download/' \
		--exclude='posts/' \
		--exclude='tools/' \
		site/ /var/www/cerberix.org/
	sudo chown -R www-data:www-data /var/www/cerberix.org
	@echo "Published. Check: https://cerberix.org/"

# ── Mirror: SourceForge (run with: make mirror-sourceforge SF_USER=yourname) ─
SF_USER ?= yourname
SF_VERSION ?= 0.1.0
mirror-sourceforge:
	@test "$(SF_USER)" != "yourname" || (echo "set SF_USER=yourname"; exit 1)
	@echo "Uploading to sourceforge.net/projects/cerberix-linux/files/$(SF_VERSION)/"
	rsync -avP -e ssh \
		/var/www/cerberix.org/download/cerberix-linux-$(SF_VERSION)-x86_64.iso \
		/var/www/cerberix.org/download/cerberix-linux-$(SF_VERSION)-x86_64.iso.sha256 \
		/var/www/cerberix.org/download/cerberix-linux-$(SF_VERSION)-x86_64.iso.sig \
		/var/www/cerberix.org/gpg.asc \
		$(SF_USER)@frs.sourceforge.net:/home/frs/project/cerberix-linux/$(SF_VERSION)/
	@echo "Done. Available at: https://sourceforge.net/projects/cerberix-linux/files/$(SF_VERSION)/"

# ── Clean ───────────────────────────────────────────────────
clean: down
	docker rmi $(IMAGE_NAME):$(IMAGE_TAG) 2>/dev/null || true
	docker network rm cerberix-wan cerberix-lan 2>/dev/null || true
	docker volume rm cerberus_cerberix-logs cerberus_cerberix-data cerberus_cerberix-ai 2>/dev/null || true
