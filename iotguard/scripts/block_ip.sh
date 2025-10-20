#!/usr/bin/env bash
set -euo pipefail
IP="${1:-}"
if [[ -z "$IP" ]]; then
  echo "usage: $0 <ip>" >&2
  exit 2
fi

# If rule already present, do nothing
if iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
  echo "exists"
  exit 0
fi

# Insert drop rule
iptables -I INPUT -s "$IP" -j DROP && echo "added" && exit 0
echo "failed" >&2
exit 1
