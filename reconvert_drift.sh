#!/bin/bash
# Re-convert the DEVICE stream over the full session INCLUDING the post-fault
# drift (which the main convert excluded), so we can validate PhysEnvelope on a
# real sustained physical excursion. Device-only -> fast (reads the device JSONL,
# no Zeek/atop). Run on the VM.
#   bash /mnt/hgfs/CATF/lab/reconvert_drift.sh
set -u
L=/home/catf/catf-lab
S_DIR=/mnt/hgfs/CATF/lab
S=$(grep SESSION_NORMAL_START "$L/sessions.log" | tail -1 | awk '{print $2}')
# up to the 00:00 plant restart (end of the drift, before recovery)
E=$(grep 'session end' "$L/events.log" | tail -1 | awk '{print $1}')
[ -z "$E" ] && E=$(date +%s)
echo "re-converting device stream over $S .. $E (includes the 23:22-00:00 drift)"
python3 "$S_DIR/lab_convert.py" --lab "$L" --out "$S_DIR/csv_drift" --only device --start "$S" --end "$E"
echo "--- pressure range per 5-min, to confirm the drift is captured ---"
python3 - "$S_DIR/csv_drift/IoT_Tank.csv" <<'PY'
import csv, sys, collections
b = collections.defaultdict(lambda: [1e9, -1e9])
for r in csv.DictReader(open(sys.argv[1])):
    try: t = float(r["ts"]); p = float(r["pressure"])
    except: continue
    k = int(t // 300); b[k][0] = min(b[k][0], p); b[k][1] = max(b[k][1], p)
import time
for k in sorted(b):
    lo, hi = b[k]
    print(f"  {time.strftime('%H:%M', time.localtime(k*300))}: {lo:.0f}-{hi:.0f}")
PY
echo "done -> csv_drift/ (tell Claude; the frozen-band validation runs in the sandbox)"
