#!/usr/bin/env bash
set -euo pipefail

IFACE=${1:-eth0}
OUTDIR=${2:-data/pcap}
ROTATE=${3:-300}
FILTER=${4:-}

mkdir -p "$OUTDIR"

echo "Starting tcpdump on $IFACE"
if [ -n "$FILTER" ]; then
  echo "BPF filter: $FILTER"
fi

# Rotate files every ROTATE seconds, keep unlimited (-W 0)
if [ -n "$FILTER" ]; then
  sudo tcpdump -i "$IFACE" -w "$OUTDIR/capture_%Y%m%d_%H%M%S.pcap" -G "$ROTATE" -W 0 $FILTER
else
  sudo tcpdump -i "$IFACE" -w "$OUTDIR/capture_%Y%m%d_%H%M%S.pcap" -G "$ROTATE" -W 0
fi
