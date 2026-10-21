#!/bin/bash
# Extract + label + convert the attack session over its clean window
# (SESSION_NORMAL_START -> the end of the fault window, which excludes the
# post-fault abnormal drift). Writes a report Claude reads from the Desktop.
#   bash /mnt/hgfs/CATF/lab/run_session.sh
L=/home/catf/catf-lab
S_DIR=/mnt/hgfs/CATF/lab
REP="$S_DIR/session_report.txt"
S=$(grep SESSION_NORMAL_START "$L/sessions.log" | tail -1 | awk '{print $2}')
E=$(grep 'fault stop' "$L/events.log" | tail -1 | awk '{print $1}')

echo "running extract + labels + convert ($S..$E); several minutes. Watch for FINISHED." >&2
{
  echo "=== session convert $(date -Is) ==="
  echo "clean window: $S .. $E  ($(( (E - S) / 60 )) min)"
  echo "events.log:"; grep -E 'scan|command|hostload|fault|session' "$L/events.log"

  echo "--- extract (Zeek trimmed to conn+modbus, atop) ---"
  bash "$S_DIR/extract.sh"

  echo "--- make labels (marks + device fault fields) ---"
  python3 "$S_DIR/make_labels.py" --lab "$L" --out "$S_DIR/labels.csv" --start "$S" --end "$E"
  echo "labels.csv:"; cat "$S_DIR/labels.csv"

  echo "--- convert (labelled) ---"
  python3 "$S_DIR/lab_convert.py" --lab "$L" --out "$S_DIR/csv_session" \
      --labels "$S_DIR/labels.csv" --start "$S" --end "$E"

  echo "--- attack records per file (label=1, by type) ---"
  python3 - "$S_DIR/csv_session" <<'PY'
import csv, sys, glob, os, collections
for f in sorted(glob.glob(sys.argv[1] + '/*.csv')):
    c = collections.Counter(); tot = 0
    for r in csv.DictReader(open(f)):
        tot += 1
        if r.get('label') == '1':
            c[r.get('type', '?')] += 1
    tag = dict(c) if c else "all normal"
    print(f"  {os.path.basename(f):26s} {tot:8d} rows   attacks: {tag}")
PY
  echo "=== FINISHED $(date -Is) ==="
} > "$REP" 2>&1
echo "FINISHED — type: done" >&2
