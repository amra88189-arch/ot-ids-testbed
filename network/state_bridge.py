#!/usr/bin/env python3
"""PLC state watcher -- mirror the plant's latest live values to the share so the console
can show a live process panel even when nothing is alerting.

Reads the newest record of the device feed ~1 Hz and writes a compact state.json to the
share. Run on the VM alongside the alert bridge:
  nohup python3 ~/catf-lab/live/state_bridge.py >/dev/null 2>&1 &
"""
import json, glob, os, time

L = os.path.expanduser("~/catf-lab")
OUT = "/mnt/hgfs/CATF/ot-ids-testbed/state.json"
SIGS = ["pressure", "liquid_level", "f1_flow", "f2_flow", "purge_flow", "product_flow",
        "A_in_purge", "C_in_purge", "f1_valve_pos", "f2_valve_pos",
        "purge_valve_pos", "product_valve_pos"]

def last_record(path):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2); size = f.tell()
            f.seek(max(0, size - 4096))
            chunk = f.read().decode(errors="ignore")
    except Exception:
        return None
    for line in reversed(chunk.splitlines()):
        line = line.strip()
        if line:
            try: return json.loads(line)
            except Exception: continue
    return None

while True:
    files = sorted(glob.glob(L + "/device/device_*.jsonl"))
    rec = last_record(files[-1]) if files else None
    if rec:
        d = rec.get("data", {}); m = dict(d.get("measured", {}), **d.get("state", {}))
        snap = {"ts": rec.get("ts"),
                "signals": {s: m.get(s) for s in SIGS if isinstance(m.get(s), (int, float))}}
        try:
            json.dump(snap, open(OUT, "w"))
        except Exception:
            pass
    time.sleep(1)
