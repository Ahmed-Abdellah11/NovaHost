#!/bin/bash
# One container = DNS server + AI watcher + REST API (convenient as a single GNS3 node)
set -e
mkdir -p "$NOVA_DATA_DIR" /var/log /run
: > /var/log/dnsmasq.log
touch "$NOVA_DATA_DIR/blocklist.hosts"

python -m nova.watcher & W=$!
sleep 2                                   # watcher writes the initial blocklist first
dnsmasq --keep-in-foreground --conf-file=/etc/dnsmasq.conf --server="${UPSTREAM_DNS:-8.8.8.8}" & D=$!
uvicorn nova.api:app --host 0.0.0.0 --port 8000 --no-access-log & A=$!
# keep the query log from growing forever (watcher copes with truncation)
( while sleep 3600; do [ "$(stat -c%s /var/log/dnsmasq.log)" -gt 52428800 ] && : > /var/log/dnsmasq.log; done ) & R=$!

trap 'kill $W $D $A $R 2>/dev/null' TERM INT
wait -n
echo "a component exited - stopping container" >&2
kill $W $D $A $R 2>/dev/null
exit 1
