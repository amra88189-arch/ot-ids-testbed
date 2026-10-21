#!/usr/bin/env python3
"""make_labels.py — build labels.csv for the attack session from three sources.

  manual marks   ~/catf-lab/events.log      (mark.sh: 'epoch iso class start|stop')
  benign faults  the device JSONL           (*_fault_mode / *_stuck / *_fault_severity)
  Caldera        an operation report JSON    (--caldera report.json), optional

Output rows:  start_ts,end_ts,scenario_id,type,streams   (what lab_convert.py reads)

The class name (from mark.sh, the Caldera ability, or 'fault') decides the type and
which streams the window labels, via CLASS_MAP. A guard band trims a few seconds at
each edge so records straddling a transition are not mislabeled.

  python3 make_labels.py --lab ~/catf-lab --out ~/catf-lab/labels.csv [--caldera r.json] [--guard 3]
"""
import argparse, csv, glob, json, os, re

# class keyword -> (type written to labels, streams it labels)
# streams: n network, d device, h host
CLASS_MAP = {
    "scan":     ("scanning",  "n"),
    "recon":    ("scanning",  "n"),
    # an unauthorised Modbus write the PLC accepts but which (in auto mode, like
    # coil 40 here) produces no physical effect: network-only. A write that does
    # move a valve should be marked 'command_phys' / 'devwrite' instead.
    "command":  ("injection", "n"),
    "setpoint": ("injection", "n"),
    "write":    ("injection", "n"),
    "command_phys": ("injection", "nd"),
    "mitm":     ("mitm",      "nd"),
    "dos":      ("dos",       "ndh"),
    "logic":    ("plc_logic", "nd"),
    "program":  ("plc_logic", "nd"),
    "devwrite": ("injection", "dh"),   # direct device write, bypassing the PLC
    "hostload": ("host_load", "h"),
    "load":     ("host_load", "h"),
    "fault":    ("benign_fault", "d"),
}
DEFAULT = ("attack", "nd")


def classify(name):
    n = str(name).lower()
    for key in sorted(CLASS_MAP, key=len, reverse=True):   # longest match wins
        if key in n:
            return CLASS_MAP[key]
    return DEFAULT


# ── manual marks ─────────────────────────────────────────────────────────────
def from_events(path):
    """Pair start/stop lines per class into windows."""
    if not os.path.exists(path):
        return []
    opens, wins = {}, []
    for line in open(path):
        p = line.split()
        if len(p) < 4:
            continue
        ts, cls, act = float(p[0]), p[2], p[3].lower()
        if act == "start":
            opens[cls] = ts
        elif act == "stop" and cls in opens:
            wins.append((opens.pop(cls), ts, cls))
    for cls, ts in opens.items():
        print(f"  warning: '{cls}' has a start at {ts:.0f} with no stop — ignored")
    return wins


# ── benign faults, self-labelled from the device stream ──────────────────────
FAULT_KEYS = re.compile(r"_fault_mode$|_fault_severity$|_stuck$")


def _fault_on(state):
    for k, v in state.items():
        if FAULT_KEYS.search(k):
            if v is True:
                return True
            try:
                if float(v) != 0:
                    return True
            except (TypeError, ValueError):
                pass
    return False


def from_faults(lab, t0, t1, gap=5.0):
    """Contiguous spans where any fault field is active -> benign-fault windows."""
    rows = []
    for f in sorted(glob.glob(os.path.join(lab, "device", "device_*.jsonl"))):
        for line in open(f, errors="ignore"):
            try:
                r = json.loads(line)
            except Exception:
                continue
            ts = r.get("ts")
            if ts is None or not (t0 <= ts <= t1):
                continue
            rows.append((ts, _fault_on(r.get("data", {}).get("state", {}))))
    rows.sort()
    wins, start, last = [], None, None
    for ts, on in rows:
        if on and start is None:
            start = ts
        elif not on and start is not None:
            if last is not None and ts - last <= gap:
                continue
            wins.append((start, last, "fault"))
            start = None
        last = ts
    if start is not None:
        wins.append((start, last, "fault"))
    return wins


# ── Caldera operation report ─────────────────────────────────────────────────
def from_caldera(path):
    """Best-effort: a step's start/finish timestamps and ability name, across the
    common report shapes. Times may be ISO strings or epoch seconds."""
    if not path or not os.path.exists(path):
        return []
    import datetime
    data = json.load(open(path))

    def epoch(v):
        if v is None:
            return None
        if isinstance(v, (int, float)):
            return float(v)
        s = str(v).replace("Z", "+00:00")
        for fmt in (None,):
            try:
                return datetime.datetime.fromisoformat(s).timestamp()
            except ValueError:
                pass
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.datetime.strptime(str(v)[:19], fmt).timestamp()
            except ValueError:
                pass
        return None

    ops = data if isinstance(data, list) else data.get("operations", [data])
    wins = []
    for op in ops:
        steps = op.get("chain") or op.get("steps") or op.get("links") or []
        for st in steps:
            s = epoch(st.get("collect") or st.get("started") or st.get("decide") or st.get("start"))
            e = epoch(st.get("finish") or st.get("finished") or st.get("status_time") or st.get("end"))
            name = (st.get("ability", {}) or {}).get("name") if isinstance(st.get("ability"), dict) else None
            name = name or st.get("name") or st.get("ability_id") or "caldera"
            if s and e and e >= s:
                wins.append((s, e, re.sub(r"\s+", "_", str(name))))
    return wins


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", default=os.path.expanduser("~/catf-lab"))
    ap.add_argument("--out", default=os.path.expanduser("~/catf-lab/labels.csv"))
    ap.add_argument("--caldera", default=None)
    ap.add_argument("--guard", type=float, default=3.0, help="seconds trimmed at each edge")
    ap.add_argument("--start", type=float, default=0)
    ap.add_argument("--end", type=float, default=2**40)
    a = ap.parse_args()

    wins = []
    wins += from_events(os.path.join(a.lab, "events.log"))
    wins += from_caldera(a.caldera)
    wins += from_faults(a.lab, a.start, a.end)
    wins = [w for w in wins if a.start <= w[0] <= a.end]
    wins.sort()

    rows, n = [], {}
    for s, e, name in wins:
        typ, streams = classify(name)
        s2, e2 = s + a.guard, e - a.guard
        if e2 <= s2:
            print(f"  skip {name}: window {e - s:.0f}s shorter than 2x guard")
            continue
        n[typ] = n.get(typ, 0) + 1
        rows.append({"start_ts": round(s2, 3), "end_ts": round(e2, 3),
                     "scenario_id": f"{typ}_{n[typ]}", "type": typ, "streams": streams})

    with open(a.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["start_ts", "end_ts", "scenario_id", "type", "streams"])
        w.writeheader()
        w.writerows(rows)
    print(f"labels: {len(rows)} windows -> {a.out}")
    for typ, c in sorted(n.items()):
        tot = sum(r["end_ts"] - r["start_ts"] for r in rows if r["type"] == typ)
        print(f"  {typ:14s} {c:3d} window(s)  {tot/60:6.1f} min active")


if __name__ == "__main__":
    main()
