#!/bin/bash
# mark.sh <class> start|stop  — record one edge of a manual attack window.
# The label extractor pairs start/stop into [start_ts,end_ts] windows.
#   bash /mnt/hgfs/CATF/lab/mark.sh scan start
#   bash /mnt/hgfs/CATF/lab/mark.sh scan stop
L=/home/catf/catf-lab
if [ -z "$2" ]; then echo "usage: mark.sh <class> start|stop"; exit 1; fi
printf '%s %s %s %s\n' "$(date +%s)" "$(date -Is)" "$1" "$2" >> "$L/events.log"
echo "marked $1 $2 @ $(date +%H:%M:%S)"
