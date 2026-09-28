#!/usr/bin/env bash
# Прогоняет pcap через Suricata в контейнере и дописывает события в logs/eve.json
set -e
cd "$(dirname "$0")/.."
[ -f pcaps/test.pcap ] || { echo "Сначала создай pcap: testenv/gen-pcap.sh"; exit 1; }
docker build -q -t suricata-test testenv
docker run --rm \
  -v "$PWD/logs:/var/log/suricata" \
  -v "$PWD/pcaps:/pcaps:ro" \
  -v "$PWD/testenv/rules:/rules:ro" \
  suricata-test \
  suricata -S /rules/test.rules -r /pcaps/test.pcap -l /var/log/suricata
echo "OK: logs/eve.json обновлён"
