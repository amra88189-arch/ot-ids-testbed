#!/bin/bash
# extract.sh — turn the raw recordings into the intermediate logs lab_convert.py
# reads. Runs in the VM (atop binary, tcpdump, zeek Docker image). Idempotent:
# a capture already processed is skipped. Never touches the live recorders.
#
#   ~/catf-lab/intermediate/zeek/plc_<time>/        conn.log, modbus.log, ... (JSON)
#   ~/catf-lab/intermediate/zeek/router_<time>_in/  same, from inbound copies only
#   ~/catf-lab/intermediate/atop/atop_YYYYMMDD.txt  parseable PRG/PRC/PRM/PRD
#
# The router capture listens on every router interface, so a forwarded packet is
# recorded twice (in and out). Zeek reads an inbound-only copy instead.
set -u
L=/home/catf/catf-lab
OUT=$L/intermediate
mkdir -p "$OUT/zeek" "$OUT/atop"

# Modbus command-semantics policy (register + value per write) — copied into the
# mounted intermediate so the Zeek container can load it. If absent, Zeek just
# produces the basic modbus.log and mb_reg/mb_val stay empty.
cp "$(dirname "$0")/modbus_detail.zeek" "$OUT/modbus_detail.zeek" 2>/dev/null || true
DETAIL=""
[ -f "$OUT/modbus_detail.zeek" ] && DETAIL="/data/intermediate/modbus_detail.zeek"

echo "== Zeek over pcaps =="
for f in "$L"/pcap/*.pcap; do
  [ -e "$f" ] || continue
  b=$(basename "$f" .pcap)
  case "$b" in
    router_*) name="${b}_in" ;;
    *)        name="$b" ;;
  esac
  d="$OUT/zeek/$name"
  if [ -f "$d/conn.log" ]; then echo "  skip $name (done)"; continue; fi
  mkdir -p "$d"
  echo "  $name"
  if [ "$name" != "$b" ]; then
    tmp="$OUT/tmp_${name}.pcap"
    tcpdump -r "$f" -w "$tmp" inbound 2>/dev/null
    docker run --rm -v "$L":/data -w "/data/intermediate/zeek/$name" zeek/zeek \
      zeek -C -r "/data/intermediate/$(basename "$tmp")" LogAscii::use_json=T $DETAIL 2>/dev/null || true
    rm -f "$tmp"
  else
    docker run --rm -v "$L":/data -w "/data/intermediate/zeek/$name" zeek/zeek \
      zeek -C -r "/data/pcap/$(basename "$f")" LogAscii::use_json=T $DETAIL 2>/dev/null || true
  fi
  # keep only the logs the converter reads; the rest (dns, ssl, weird, ...)
  # ballooned the intermediate to 11 GB last time
  find "$d" -maxdepth 1 -name '*.log' ! -name 'conn.log' ! -name 'modbus.log' \
       ! -name 'modbus_detail.log' -delete 2>/dev/null
done

echo "== atop parseable dump =="
for a in /var/log/atop/atop_20[0-9][0-9][0-9][0-9][0-9][0-9]; do
  [ -f "$a" ] || continue
  day=$(basename "$a")
  echo "  $day"
  atop -r "$a" -P PRG,PRC,PRM,PRD > "$OUT/atop/${day}.txt" 2>/dev/null || true
done

echo "intermediate logs in $OUT"
