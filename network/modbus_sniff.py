#!/usr/bin/env python3
"""Live Modbus command-vocabulary IDS -- Layer 3, streamed to the alert bus.

Passive sniffer (pure stdlib, no deps). Decodes Modbus/TCP WRITE requests off the wire,
freezes the normal (src, func, register) vocabulary from clean traffic, then flags any
out-of-vocabulary write live -- same freeze-then-alert model as the physics IDS, same
alerts.jsonl bus the console reads. Also logs EVERY write to command_writes.jsonl for the
separate long-running batch/forensic analysis.

Run inside the PLC container's network namespace, as root:
  PID=$(docker inspect -f '{{.State.Pid}}' plc)
  sudo nsenter -t $PID -n python3 modbus_sniff.py --learn 120      # freeze clean vocabulary
  sudo nsenter -t $PID -n python3 modbus_sniff.py --detect         # live detection -> bus

Options:
  --iface IFACE     bind to one interface (default: all)
  --vocab PATH      vocabulary file (default ./command_vocab_frozen.json)
  --alerts PATH     alert bus (default ~/catf-lab/alerts.jsonl)
  --writelog PATH   full write log for batch analysis (default ~/catf-lab/command_writes.jsonl)
"""
import sys, os, json, time, socket, struct, argparse

ETH_P_ALL = 0x0003
WRITE_FUNCS = {5: "WRITE_SINGLE_COIL", 6: "WRITE_SINGLE_REGISTER",
               15: "WRITE_MULTIPLE_COILS", 16: "WRITE_MULTIPLE_REGISTERS"}
READ_FUNCS = {1: "READ_COILS", 2: "READ_DISCRETE_INPUTS",
              3: "READ_HOLDING_REGISTERS", 4: "READ_INPUT_REGISTERS"}
ALL_FUNCS = {**READ_FUNCS, **WRITE_FUNCS}

def parse_frame(buf):
    """Return a dict for a Modbus WRITE request, or None. Ethernet/IPv4/TCP/Modbus, no VLAN."""
    try:
        if len(buf) < 14: return None
        if struct.unpack("!H", buf[12:14])[0] != 0x0800: return None      # IPv4 only
        ip = buf[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6: return None                                        # TCP only
        src = socket.inet_ntoa(ip[12:16]); dst = socket.inet_ntoa(ip[16:20])
        tcp = ip[ihl:]
        dport = struct.unpack("!H", tcp[2:4])[0]
        if dport != 502: return None                                      # Modbus requests
        doff = (tcp[12] >> 4) * 4
        mb = tcp[doff:]
        if len(mb) < 9: return None                                       # MBAP(7)+func(1)+...
        unit = mb[6]; func = mb[7]
        if func not in WRITE_FUNCS: return None
        reg = struct.unpack("!H", mb[8:10])[0]                            # starting address
        val = None
        if func in (5, 6) and len(mb) >= 12:
            val = struct.unpack("!H", mb[10:12])[0]
        elif func in (15, 16) and len(mb) >= 12:
            val = struct.unpack("!H", mb[10:12])[0]                       # quantity written
        return {"src": src, "dst": dst, "unit": unit, "func": WRITE_FUNCS[func],
                "register": reg, "value": val}
    except Exception:
        return None

def parse_any(buf):
    """Like parse_frame but for ANY Modbus request (read or write) -- for --stats."""
    try:
        if len(buf) < 14 or struct.unpack("!H", buf[12:14])[0] != 0x0800: return None
        ip = buf[14:]; ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6: return None
        src = socket.inet_ntoa(ip[12:16]); dst = socket.inet_ntoa(ip[16:20])
        tcp = ip[ihl:]
        if struct.unpack("!H", tcp[2:4])[0] != 502: return None
        doff = (tcp[12] >> 4) * 4; mb = tcp[doff:]
        if len(mb) < 8: return None
        func = mb[7]
        return {"src": src, "dst": dst, "func_code": func,
                "func": ALL_FUNCS.get(func, f"FUNC_{func}"), "is_write": func in WRITE_FUNCS}
    except Exception:
        return None

def stats(a):
    from collections import Counter
    s = open_sock(a.iface); c = Counter(); pkts = 0; t0 = time.time()
    print(f"sniffing {a.stats}s on {a.iface or 'all ifaces'} (counting ALL modbus by src/func)...")
    while time.time() - t0 < a.stats:
        try: buf = s.recv(65535)
        except socket.timeout: continue
        pkts += 1
        m = parse_any(buf)
        if m: c[(m["src"], m["func"])] += 1
    print(f"total frames seen: {pkts}")
    if not c: print("  NO Modbus/502 requests decoded at this vantage point."); return
    for (src, fn), n in c.most_common():
        print(f"  {src:16s} {fn:26s} {n}")

def open_sock(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    if iface: s.bind((iface, 0))
    s.settimeout(1.0)
    return s

def key(w):  # the vocabulary identity of a write
    return f'{w["src"]}|{w["func"]}|{w["register"]}'

def learn(a):
    s = open_sock(a.iface); seen = {}; t0 = time.time()
    print(f"learning clean command vocabulary for {a.learn}s on {a.iface or 'all ifaces'}...")
    while time.time() - t0 < a.learn:
        try: buf = s.recv(65535)
        except socket.timeout: continue
        w = parse_frame(buf)
        if w: seen[key(w)] = {"src": w["src"], "func": w["func"], "register": w["register"]}
    vocab = {"frozen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "authorized_writes": list(seen.values())}
    json.dump(vocab, open(a.vocab, "w"), indent=2)
    print(f"froze {len(seen)} normal write patterns -> {a.vocab}")
    for v in seen.values(): print("   ", v)

def detect(a):
    if not os.path.exists(a.vocab):
        sys.exit(f"no frozen vocabulary at {a.vocab} -- run --learn first")
    vocab = json.load(open(a.vocab))
    allow = {f'{w["src"]}|{w["func"]}|{w["register"]}' for w in vocab["authorized_writes"]}
    print(f"detecting: {len(allow)} authorized patterns frozen; flagging deviations "
          f"(dedup {a.dedup}s) -> {a.alerts}")
    s = open_sock(a.iface)
    af = open(a.alerts, "a"); wf = open(a.writelog, "a")
    seen = {}   # key -> {first, count, last_emit}

    def emit(w, ts, count, first):
        alert = dict(ts=round(ts, 2), det="command", device="plc", src=w["src"],
                     func=w["func"], register=w["register"], value=w["value"],
                     count=count, first_ts=round(first, 2), sev="high")
        af.write(json.dumps(alert) + "\n"); af.flush()
        print(f"ALERT [command] {w['src']} {w['func']} reg={w['register']} "
              f"val={w['value']} (x{count})")

    while True:
        try: buf = s.recv(65535)
        except socket.timeout: continue
        w = parse_frame(buf)
        if not w: continue
        ts = time.time()
        wf.write(json.dumps(dict(ts=ts, **w)) + "\n"); wf.flush()   # full log for batch analysis
        k = key(w)
        if k in allow:
            continue
        rec = seen.get(k)
        if rec is None:                                  # first sighting -> alert now
            seen[k] = {"first": ts, "count": 1, "last_emit": ts}
            emit(w, ts, 1, ts)
        else:                                            # repeat -> count, re-emit per dedup window
            rec["count"] += 1
            if ts - rec["last_emit"] >= a.dedup:
                emit(w, ts, rec["count"], rec["first"])
                rec["last_emit"] = ts

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--learn", type=float, metavar="SECONDS")
    ap.add_argument("--detect", action="store_true")
    ap.add_argument("--stats", type=float, metavar="SECONDS")
    ap.add_argument("--dedup", type=float, default=10.0, help="seconds to collapse repeated identical writes")
    ap.add_argument("--iface", default="")
    ap.add_argument("--vocab", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                     "command_vocab_frozen.json"))
    ap.add_argument("--alerts", default=os.path.expanduser("~/catf-lab/alerts.jsonl"))
    ap.add_argument("--writelog", default=os.path.expanduser("~/catf-lab/command_writes.jsonl"))
    a = ap.parse_args()
    if a.stats: return stats(a)
    if a.learn: return learn(a)
    if a.detect: return detect(a)
    ap.error("choose --learn SECONDS, --detect, or --stats SECONDS")

if __name__ == "__main__":
    main()
