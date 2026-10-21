#!/bin/bash
# run_convert.sh — extract + convert the baseline window and write a report
# Claude reads from the Desktop. Idempotent; safe to re-run.
#   bash /mnt/hgfs/CATF/lab/run_convert.sh
L=/home/catf/catf-lab
S=/mnt/hgfs/CATF/lab
REP="$S/convert_report.txt"
START=1792179017
END=1792222217

echo "running... Zeek + convert, several minutes. Watch for FINISHED below." >&2
{
  echo "=== run_convert $(date -Is) ==="

  # 1. intermediate logs: Zeek (router captures re-run on inbound copies) + atop
  echo "--- extract ---"
  bash "$S/extract.sh"
  echo "zeek plc dirs        : $(ls -d "$L"/intermediate/zeek/plc_* 2>/dev/null | wc -l)"
  echo "zeek router_in dirs  : $(ls -d "$L"/intermediate/zeek/router_*_in 2>/dev/null | wc -l)"
  echo "atop dumps           : $(ls "$L"/intermediate/atop 2>/dev/null | wc -l)"

  # 2. convert the baseline window to TON_IoT-style CSVs on the share
  echo "--- convert ($START..$END) ---"
  python3 "$S/lab_convert.py" --lab "$L" --out "$S/csv" --start "$START" --end "$END"

  # 3. report what landed
  echo "--- CSV row counts ---"
  for f in "$S"/csv/*.csv; do
    [ -e "$f" ] && echo "$(wc -l < "$f") $(basename "$f")"
  done
  echo "--- network: Modbus windows (measured bytes) ---"
  head -1 "$S/csv/Network_lab.csv"; grep ',modbus,' "$S/csv/Network_lab.csv" | head -8
  echo "--- network: other flows ---"
  grep -v ',modbus,' "$S/csv/Network_lab.csv" | sed -n '2,6p'
  echo "--- device sample (IoT_Tank) ---"
  head -3 "$S/csv/IoT_Tank.csv"
  echo "--- host per process (first rows) ---"
  head -4 "$S/csv/Host_lab.csv"
  echo "--- host per container (one sample) ---"
  head -7 "$S/csv/Host_lab_container.csv"
  echo "--- host per process: rows by container ---"
  awk -F, 'NR>1{c[$4]++} END{for(k in c) print c[k], k}' "$S/csv/Host_lab.csv" | sort -rn
  echo "=== FINISHED $(date -Is) ==="
} > "$REP" 2>&1
echo "FINISHED — type: done" >&2
