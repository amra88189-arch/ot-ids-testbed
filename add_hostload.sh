#!/bin/bash
# Fold the (redone) host-load window into the existing session dataset without a
# full re-convert: dump only today's atop, convert host-only for the host-load
# window, append its rows to csv_session/Host_lab.csv.
#   bash /mnt/hgfs/CATF/lab/add_hostload.sh
set -u
L=/home/catf/catf-lab
S_DIR=/mnt/hgfs/CATF/lab
HS=$(grep 'hostload start' "$L/events.log" | tail -1 | awk '{print $1}')
HE=$(grep 'hostload stop'  "$L/events.log" | tail -1 | awk '{print $1}')
echo "host-load window: $HS .. $HE  ($((HE - HS))s)"

day=$(date +%Y%m%d)
atop -r "/var/log/atop/atop_$day" -P PRG,PRC,PRM,PRD > "$L/intermediate/atop/atop_$day.txt" 2>/dev/null
echo "atop_$day dumped: $(wc -l < "$L/intermediate/atop/atop_$day.txt") lines"

# hide the older (huge) atop dumps so convert_host only parses today's -> fast
mkdir -p "$L/intermediate/atop_hold"
for f in "$L"/intermediate/atop/atop_*.txt; do
  [ "$(basename "$f")" = "atop_$day.txt" ] || mv "$f" "$L/intermediate/atop_hold/" 2>/dev/null
done

python3 "$S_DIR/make_labels.py" --lab "$L" --out "$S_DIR/labels_hostload.csv" --start "$HS" --end "$HE"
echo "labels_hostload.csv:"; cat "$S_DIR/labels_hostload.csv"
python3 "$S_DIR/lab_convert.py" --lab "$L" --out "$S_DIR/csv_hostload" \
    --labels "$S_DIR/labels_hostload.csv" --only host --start "$HS" --end "$HE"

# restore the older atop dumps
mv "$L"/intermediate/atop_hold/*.txt "$L/intermediate/atop/" 2>/dev/null
rmdir "$L/intermediate/atop_hold" 2>/dev/null

# append the host-load rows (attack) onto the main host CSV
if [ -s "$S_DIR/csv_hostload/Host_lab.csv" ]; then
  before=$(wc -l < "$S_DIR/csv_session/Host_lab.csv")
  tail -n +2 "$S_DIR/csv_hostload/Host_lab.csv" >> "$S_DIR/csv_session/Host_lab.csv"
  tail -n +2 "$S_DIR/csv_hostload/Host_lab_container.csv" >> "$S_DIR/csv_session/Host_lab_container.csv" 2>/dev/null
  after=$(wc -l < "$S_DIR/csv_session/Host_lab.csv")
  echo "appended $((after - before)) host rows"
else
  echo "!! no host rows produced — check the window / atop dump"
fi

echo "=== host attack rows now ==="
python3 - "$S_DIR/csv_session/Host_lab.csv" <<'PY'
import csv, sys, collections
c = collections.Counter(); tot = 0
for r in csv.DictReader(open(sys.argv[1])):
    tot += 1
    if r.get('label') == '1': c[r.get('type', '?')] += 1
print(f"{tot} rows, attacks: {dict(c) if c else 'all normal'}")
PY
