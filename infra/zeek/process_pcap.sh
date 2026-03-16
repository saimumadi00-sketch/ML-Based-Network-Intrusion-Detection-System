#!/usr/bin/env bash
set -euo pipefail

PCAP=${1:-}
OUTDIR=${2:-data/zeek}

if [ -z "$PCAP" ]; then
  echo "Usage: process_pcap.sh <pcap> [outdir]" >&2
  exit 1
fi

mkdir -p "$OUTDIR"

if command -v zeek >/dev/null 2>&1; then
  zeek -r "$PCAP" local
  mv ./*.log "$OUTDIR" || true
  exit 0
fi

if command -v docker >/dev/null 2>&1; then
  PCAPDIR=$(dirname "$PCAP")
  PCAPFILE=$(basename "$PCAP")
  docker run --rm -v "$PCAPDIR:/pcap" -v "$OUTDIR:/out" zeek/zeek -r "/pcap/$PCAPFILE" local
  mv "$PCAPDIR"/*.log "$OUTDIR" || true
  exit 0
fi

echo "Zeek not found. Install Zeek or Docker." >&2
exit 1
