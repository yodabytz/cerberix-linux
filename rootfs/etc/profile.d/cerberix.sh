#!/bin/bash
# Cerberix Firewall — Shell Profile
# Loaded on interactive login

# Display MOTD on login
[ -f /etc/motd ] && cat /etc/motd

# Cerberix-specific PATH additions
export PATH="/usr/local/bin:$PATH"
export PYTHONPATH="/opt/cerberix"

# Aliases for common operations
alias fw='nft list ruleset'
alias fw-drops='grep "CERBERIX DROP" /var/log/cerberix/firewall.log 2>/dev/null | tail -20'
alias threats='cerberix-ai threats'
alias blocked='cerberix-ai blocklist'
alias leases='cat /var/lib/cerberix/dnsmasq.leases'

# Prompt: red for root, green for others
if [ "$(id -u)" = "0" ]; then
    PS1='\[\033[1;31m\]cerberix\[\033[0m\]:\w# '
else
    PS1='\[\033[1;32m\]cerberix\[\033[0m\]:\w$ '
fi
