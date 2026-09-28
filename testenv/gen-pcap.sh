#!/usr/bin/env bash
# Пишет тестовый трафик (ping + HTTP) в pcaps/test.pcap через tcpdump в одноразовом контейнере
set -e
cd "$(dirname "$0")/.."
mkdir -p pcaps
docker run --rm --cap-add=NET_RAW -v "$PWD/pcaps:/pcaps" alpine sh -c '
  apk add --no-cache tcpdump >/dev/null
  tcpdump -i eth0 -s 0 -w /pcaps/test.pcap >/dev/null 2>&1 &
  TPID=$!
  sleep 1
  ping -c 4 8.8.8.8 >/dev/null 2>&1 || true
  wget -q -O /dev/null http://example.com/ >/dev/null 2>&1 || true
  sleep 1
  kill $TPID 2>/dev/null || true
  wait 2>/dev/null
  true
'
echo "OK: pcaps/test.pcap записан"
