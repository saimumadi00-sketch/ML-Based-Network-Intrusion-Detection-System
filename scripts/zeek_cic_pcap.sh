#!/bin/bash
# Stream one CIC-IDS2017 day PCAP through Zeek and keep only conn.log (the PCAPs are 8-13 GB, so they are
# never written to disk).
#
#   scripts/zeek_cic_pcap.sh Friday-WorkingHours [out_dir]
#   days: Monday-WorkingHours Tuesday-WorkingHours Wednesday-workingHours Thursday-WorkingHours Friday-WorkingHours
#
# ZEEK_HOME defaults to /opt/zeek (the official package location). Default Zeek scripts are loaded, like a
# real sensor. -C ignores checksum errors (offloaded checksums in the capture).
set -euo pipefail
DAY=${1:?usage: $0 <Day-stem> [out_dir]}
OUT=${2:-datasets/cicids2017/zeek}
ZEEK_HOME=${ZEEK_HOME:-/opt/zeek}
URL=${CIC_PCAP_BASE:-https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/pcaps}/$DAY.pcap
if [ "$ZEEK_HOME" != /opt/zeek ]; then  # relocated install (e.g. unpacked .deb): point Zeek at its scripts
  export ZEEKPATH=$ZEEK_HOME/share/zeek:$ZEEK_HOME/share/zeek/policy:$ZEEK_HOME/share/zeek/site:$ZEEK_HOME/share/zeek/builtin-plugins
fi
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
WORK=$(mktemp -d "$OUT/work-$DAY.XXXX")
trap 'rm -r -- "$WORK"' EXIT
cd "$WORK"
start=$(date +%s)
curl -sL --fail "$URL" | "$ZEEK_HOME/bin/zeek" -C -r - 2> zeek.stderr
mv conn.log "$OUT/$DAY.conn.log"
echo "$DAY: $(grep -cv '^#' "$OUT/$DAY.conn.log") connections in $(( $(date +%s) - start ))s -> $OUT/$DAY.conn.log"
