#!/usr/bin/env python3
"""lab_convert.py — turn GRFICSv3 recordings into TON_IoT-style CSVs for CATF-IDS.

Pure standard library: runs in the VM with no installs. It reads
  - the device poller JSONL   (~/catf-lab/device/device_*.jsonl)
  - the raw packet captures   (~/catf-lab/pcap/*.pcap)       Modbus sizes
  - Zeek conn.log + modbus.log (made by extract.sh)           flows, function codes
  - atop parseable dumps       (made by extract.sh)           host
and writes CSVs whose column names match what catf_ids.py expects:

  IoT_<Device>.csv          device stream, one file per remote I/O device, 1 Hz
  Network_lab.csv           Modbus in fixed windows (bytes and packets measured
                            from the captures, read/write counts from Zeek) plus
                            every other flow from Zeek conn.log
  Host_lab.csv              host per process, TON_IoT layout; idle all-zero rows
                            (kernel threads doing nothing) are dropped
  Host_lab_container.csv    host per container per 10 s sample (simulation, plc,
                            HMI, router, and 'host' for everything outside Docker)

Each packet is counted from exactly one capture: the PLC capture for traffic with
the PLC as an endpoint, the router capture (inbound copies only) for the rest.

Ground-truth labels come from an optional labels.csv
(start_ts,end_ts,scenario_id,type,streams); without it every row is normal.

Usage:
  python3 lab_convert.py --lab ~/catf-lab --out ~/catf-lab/csv \
      [--labels labels.csv] [--start EPOCH] [--end EPOCH] [--slice 10] [--plc-ip IP]
  python3 lab_convert.py --verify-atop ~/catf-lab/intermediate/atop/atop_YYYYMMDD.txt
"""
import argparse, csv, glob, json, os, re, struct, sys, time
from collections import defaultdict

# ── device keyword -> (primary signal, secondary signal) ────────────────────
# Mirrors the entries lab_transfer.py adds to IOT_DEVICE_MAP. The keyword is
# matched against the CSV file name, exactly as the TON_IoT devices are.
LAB_DEVICE_MAP = {
    "feed1":    ("f1_flow",      "f1_valve_pos"),
    "feed2":    ("f2_flow",      "f2_valve_pos"),
    "purge":    ("purge_flow",   "purge_valve_pos"),
    "product":  ("product_flow", "product_valve_pos"),
    "tank":     ("pressure",     "liquid_level"),
    "analyzer": ("A_in_purge",   "C_in_purge"),
}
DEVICE_SECTION = {
    "f1_flow": "measured", "f2_flow": "measured", "purge_flow": "measured",
    "product_flow": "measured", "pressure": "measured", "liquid_level": "measured",
    "A_in_purge": "measured", "C_in_purge": "measured",
    "f1_valve_pos": "state", "f2_valve_pos": "state",
    "purge_valve_pos": "state", "product_valve_pos": "state",
}
PLC_IP_DEFAULT = "192.168.95.2"
MODBUS_PORT = 502


# ── labels ──────────────────────────────────────────────────────────────────
class Labels:
    """Ground-truth windows. stream in {'n','d','h'}; '*' = all streams."""
    def __init__(self, path=None):
        self.win = []
        if path and os.path.exists(path):
            for r in csv.DictReader(open(path)):
                self.win.append((float(r["start_ts"]), float(r["end_ts"]),
                                 r.get("type", "attack"), r.get("streams", "*")))

    def label(self, ts, stream):
        for s, e, typ, streams in self.win:
            if s <= ts <= e and (streams == "*" or stream in streams):
                return 1, typ
        return 0, "normal"


def _ffill(rows, cols):
    """forward-fill None values in place (for the analyzer's periodic nulls)."""
    last = {c: 0.0 for c in cols}
    for row in rows:
        for c in cols:
            v = row.get(c)
            if v is None:
                row[c] = last[c]
            else:
                last[c] = v


# ── device stream ───────────────────────────────────────────────────────────
def convert_devices(lab, out, labels, t0, t1):
    files = sorted(glob.glob(os.path.join(lab, "device", "device_*.jsonl")))
    per_dev = {k: [] for k in LAB_DEVICE_MAP}
    for f in files:
        for line in open(f, errors="ignore"):
            try:
                r = json.loads(line)
            except Exception:
                continue
            ts = r.get("ts")
            if ts is None or not (t0 <= ts <= t1):
                continue
            d = r.get("data", {})
            for dev, (p, s) in LAB_DEVICE_MAP.items():
                row = {"ts": round(ts, 3)}
                for col in (p, s):
                    row[col] = d.get(DEVICE_SECTION[col], {}).get(col)
                per_dev[dev].append(row)
    n = 0
    for dev, (p, s) in LAB_DEVICE_MAP.items():
        rows = per_dev[dev]
        if not rows:
            continue
        _ffill(rows, [p, s])
        for row in rows:
            row["label"], row["type"] = labels.label(row["ts"], "d")
        path = os.path.join(out, f"IoT_{dev.capitalize()}.csv")
        with open(path, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["ts", p, s, "label", "type"])
            w.writeheader()
            w.writerows(rows)
        n += len(rows)
        print(f"  device {dev:9s} {len(rows):7d} rows -> {os.path.basename(path)}")
    print(f"  device total {n} rows")


# ── packet captures (pure-Python pcap reader) ───────────────────────────────
def _file_start(name):
    """epoch of the hour a capture file starts, from plc_/router_YYYYMMDD_HHMMSS."""
    m = re.search(r"(\d{8}_\d{6})", name)
    if not m:
        return None
    return time.mktime(time.strptime(m.group(1), "%Y%m%d_%H%M%S"))


def pcap_tcp(path):
    """Yield (ts, src, dst, sport, dport, payload_len, outgoing) for IPv4 TCP.
    Handles Ethernet (1), Linux cooked v1 (113) and v2 (276); `outgoing` is True
    for a cooked-capture copy the capturing host sent (packet type 4)."""
    ipcache = {}

    def ip(b):
        s = ipcache.get(b)
        if s is None:
            s = ipcache[b] = ".".join(str(x) for x in b)
        return s

    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            end = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            end = ">"
        else:
            raise ValueError(f"{path}: not a classic pcap file")
        div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        link = struct.unpack(end + "I", gh[20:24])[0] & 0x0FFFFFFF
        if link not in (1, 113, 276):
            raise ValueError(f"{path}: unsupported link type {link}")
        rec = struct.Struct(end + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            sec, frac, incl, _ = rec.unpack(h)
            data = f.read(incl)
            if len(data) < incl:
                return
            outgoing = False
            if link == 1:
                if incl < 14:
                    continue
                et, off = (data[12] << 8) | data[13], 14
                while et in (0x8100, 0x88A8) and incl >= off + 4:
                    et, off = (data[off + 2] << 8) | data[off + 3], off + 4
            elif link == 113:
                if incl < 16:
                    continue
                outgoing = ((data[0] << 8) | data[1]) == 4
                et, off = (data[14] << 8) | data[15], 16
            else:
                if incl < 20:
                    continue
                et, outgoing, off = (data[0] << 8) | data[1], data[10] == 4, 20
            if et != 0x0800 or incl < off + 20 or data[off + 9] != 6:
                continue
            ihl = (data[off] & 0x0F) * 4
            t = off + ihl
            if incl < t + 14:
                continue
            tot = (data[off + 2] << 8) | data[off + 3]
            doff = (data[t + 12] >> 4) * 4
            yield (sec + frac / div, ip(data[off + 12:off + 16]), ip(data[off + 16:off + 20]),
                   (data[t] << 8) | data[t + 1], (data[t + 2] << 8) | data[t + 3],
                   max(0, tot - ihl - doff), outgoing)


def _keep(kind, client, server, plc_ip, outgoing=False):
    """One capture per packet: the PLC capture for traffic touching the PLC,
    the router capture (inbound copies only) for everything else."""
    touches = plc_ip in (client, server)
    if kind == "plc":
        return touches
    if kind == "router":
        return not touches and not outgoing
    return False


def modbus_measured(pcap_dir, t0, t1, sl, plc_ip):
    """(window, client, server) -> [src_bytes, dst_bytes, src_pkts, dst_pkts, client_port]"""
    bins = defaultdict(lambda: [0, 0, 0, 0, 0])
    for path in sorted(glob.glob(os.path.join(pcap_dir, "*.pcap"))):
        name = os.path.basename(path)
        kind = "plc" if name.startswith("plc_") else "router" if name.startswith("router_") else None
        fs = _file_start(name)
        if kind is None or fs is None or fs > t1 or fs + 3700 < t0:
            continue
        n = 0
        for ts, s, d, sp, dp, pay, outgoing in pcap_tcp(path):
            if dp == MODBUS_PORT:
                client, server, cport, up = s, d, sp, True
            elif sp == MODBUS_PORT:
                client, server, cport, up = d, s, dp, False
            else:
                continue
            if not (t0 <= ts <= t1) or not _keep(kind, client, server, plc_ip, outgoing):
                continue
            b = bins[(int(ts // sl) * sl, client, server)]
            if up:
                b[0] += pay; b[2] += 1
            else:
                b[1] += pay; b[3] += 1
            b[4] = cport
            n += 1
        print(f"    {name}: {n} Modbus packets kept")
    return bins


# ── network stream ──────────────────────────────────────────────────────────
NET_COLS = ["ts", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "service",
            "duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts",
            "conn_state", "mb_read", "mb_write",
            # OT protocol semantics: the write function(s) used in the window, and
            # (when extract.sh's modbus_detail.zeek ran) the target register + value
            "mb_func", "mb_reg", "mb_val",
            "label", "type"]
READ_FUNCS = {"READ_COILS", "READ_DISCRETE_INPUTS", "READ_HOLDING_REGISTERS",
              "READ_INPUT_REGISTERS"}


def _zeek_lines(path):
    if not os.path.exists(path):
        return
    for line in open(path, errors="ignore"):
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except Exception:
                pass


def _zeek_dirs(zdir):
    """(kind, dir) for each capture: PLC dirs as is; router dirs from the
    inbound-filtered run (<name>_in) when extract.sh made them."""
    dirs = sorted(glob.glob(os.path.join(zdir, "*")))
    router_in = [d for d in dirs if os.path.basename(d).startswith("router_")
                 and d.endswith("_in")]
    out = [("plc", d) for d in dirs if os.path.basename(d).startswith("plc_")]
    if router_in:
        out += [("router", d) for d in router_in]
    else:
        print("  WARNING: no inbound-filtered router Zeek runs; forwarded flows that "
              "do not touch the PLC may be double counted (re-run extract.sh)")
        out += [("router", d) for d in dirs if os.path.basename(d).startswith("router_")]
    return out


def _state(up, down):
    return "SF" if up and down else "S0" if up else "OTH"


def convert_network(lab, out, labels, t0, t1, sl, plc_ip):
    zdirs = _zeek_dirs(os.path.join(lab, "intermediate", "zeek"))
    rows = []

    # 1) every non-Modbus flow from Zeek conn.log, each from one capture only
    for kind, d in zdirs:
        for c in _zeek_lines(os.path.join(d, "conn.log")):
            ts = c.get("ts")
            if ts is None or not (t0 <= ts <= t1) or c.get("id.resp_p") == MODBUS_PORT:
                continue
            if not _keep(kind, c.get("id.orig_h", ""), c.get("id.resp_h", ""), plc_ip):
                continue
            lab_, typ = labels.label(ts, "n")
            rows.append({
                "ts": round(ts, 3),
                "src_ip": c.get("id.orig_h", ""), "dst_ip": c.get("id.resp_h", ""),
                "src_port": c.get("id.orig_p", 0), "dst_port": c.get("id.resp_p", 0),
                "proto": c.get("proto", ""), "service": c.get("service", "-"),
                "duration": c.get("duration", 0) or 0,
                "src_bytes": c.get("orig_bytes", 0) or 0,
                "dst_bytes": c.get("resp_bytes", 0) or 0,
                "src_pkts": c.get("orig_pkts", 0) or 0,
                "dst_pkts": c.get("resp_pkts", 0) or 0,
                "conn_state": c.get("conn_state", "OTH"),
                "mb_read": 0, "mb_write": 0, "mb_func": "", "mb_reg": "", "mb_val": "",
                "label": lab_, "type": typ})
    n_other = len(rows)

    # 2) Modbus per fixed window: sizes measured from the captures ...
    print("  measuring Modbus from the captures ...")
    meas = modbus_measured(os.path.join(lab, "pcap"), t0, t1, sl, plc_ip)
    # ... and read / write request counts + the write FUNCTION(s) from modbus.log
    func = defaultdict(lambda: [0, 0, set()])          # read, write, {write func names}
    for kind, d in zdirs:
        for m in _zeek_lines(os.path.join(d, "modbus.log")):
            ts = m.get("ts")
            if ts is None or not (t0 <= ts <= t1) or m.get("pdu_type") != "REQ":
                continue
            client, server = m.get("id.orig_h", ""), m.get("id.resp_h", "")
            if not _keep(kind, client, server, plc_ip):
                continue
            f = func[(int(ts // sl) * sl, client, server)]
            fn = (m.get("func") or "").upper()
            if fn in READ_FUNCS:
                f[0] += 1
            else:
                f[1] += 1
                if fn:
                    f[2].add(fn)
    # ... and the target register + value, when modbus_detail.zeek produced the log
    detail = defaultdict(lambda: [set(), set()])       # {registers}, {values}
    for kind, d in zdirs:
        for m in _zeek_lines(os.path.join(d, "modbus_detail.log")):
            ts = m.get("ts")
            if ts is None or not (t0 <= ts <= t1):
                continue
            client, server = m.get("orig", ""), m.get("resp", "")
            if not _keep(kind, client, server, plc_ip):
                continue
            g = detail[(int(ts // sl) * sl, client, server)]
            if m.get("address") is not None:
                g[0].add(str(m.get("address")))
            if m.get("value") is not None:
                g[1].add(str(m.get("value")))
    for key in set(meas) | set(func):
        wstart, client, server = key
        b = meas.get(key, [0, 0, 0, 0, 0])
        fr, fw, wfuncs = func.get(key, [0, 0, set()])
        regs, vals = detail.get(key, [set(), set()])
        lab_, typ = labels.label(wstart + sl / 2.0, "n")
        rows.append({
            "ts": round(wstart + sl / 2.0, 3), "src_ip": client, "dst_ip": server,
            "src_port": b[4], "dst_port": MODBUS_PORT, "proto": "tcp", "service": "modbus",
            "duration": sl, "src_bytes": b[0], "dst_bytes": b[1],
            "src_pkts": b[2], "dst_pkts": b[3], "conn_state": _state(b[2], b[3]),
            "mb_read": fr, "mb_write": fw,
            "mb_func": ";".join(sorted(wfuncs)) if wfuncs else ("READ" if fr else ""),
            "mb_reg": ";".join(sorted(regs)), "mb_val": ";".join(sorted(vals)),
            "label": lab_, "type": typ})

    rows.sort(key=lambda r: r["ts"])
    path = os.path.join(out, "Network_lab.csv")
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=NET_COLS)
        w.writeheader()
        w.writerows(rows)
    print(f"  network {len(rows)} rows ({len(rows) - n_other} modbus-window, "
          f"{n_other} other) -> {os.path.basename(path)}")


# ── host stream (atop) ──────────────────────────────────────────────────────
# Indices into `fields` = the tokens AFTER the process state, i.e. after the
# prefix  label host epoch date time interval PID (comm) state.
# All confirmed on this build (atop 2.12.1) against live samples (FIELD_MAP.md).
PRM = {"VSIZE": 1, "RSIZE": 2, "VGROW": 4, "RGROW": 5, "MINFLT": 6, "MAJFLT": 7}
PRC = {"HERTZ": 0, "UTIME": 1, "STIME": 2}     # CPU% = 100*(utime+stime)/(hertz*interval)
PRD_WRDSK = 4                                  # KB written this interval
# atop writes a line for the process (flag 'y', totals over its threads) and one
# per extra thread (flag 'n'). Only process lines are kept: thread lines repeat
# the process's memory and would count it once per thread.
ISPROC = {"PRC": 10, "PRM": 13, "PRD": 9}      # PRG: five tokens before the cgroup paren
MAX_INTERVAL = 60      # longer samples are since-boot or after a gap: their growth
                       # and fault counts cover more than one interval, so skip them
FEATS = ["CPU", "MEM", "VSZ", "WRDSK", "VGROW", "RGROW", "MINFLT", "MAJFLT", "TRUN"]
HOST_COLS = ["ts", "PID", "CMD", "CONT"] + FEATS + ["label", "type"]
CONT_COLS = ["ts", "CONT", "CMD", "NPROC"] + FEATS + ["label", "type"]


_ATOP_LINE = re.compile(r"^(\w{3} \S+ \d+ \S+ \S+ \d+ \d+) \((.*?)\) ([A-Za-z]) ?(.*)$")


def _atop_split(line):
    """Split a parseable atop line into (prefix tokens, command name, [state, fields...]).
    Anchored on the single-letter state after the name, so names that contain
    spaces or parentheses ('rs:main Q:Reg', '(sd-pam)') parse correctly."""
    m = _ATOP_LINE.match(line.rstrip("\n"))
    if not m:
        return None
    return m.group(1).split(), m.group(2), [m.group(3)] + m.group(4).split()


def _docker_names():
    """short container id -> name, for containers whose hostname atop reports as
    the bare id (a container without a hostname set, e.g. the HMI)."""
    try:
        import subprocess
        out = subprocess.run(["docker", "ps", "-a", "--format", "{{.ID}} {{.Names}}"],
                             capture_output=True, text=True, timeout=15).stdout
        return {i[:12]: n for i, n in (l.split(None, 1) for l in out.splitlines() if " " in l)}
    except Exception:
        return {}


def _prg(fields):
    """TRUN, container name and process flag from a PRG record. The command line
    is a parenthesised token that may contain spaces; TRUN is two tokens after
    its close-paren (PPID first). The container name is two tokens before the
    final (cgroup) paren ('-' = outside any container), the process flag five."""
    cs = next((i for i, t in enumerate(fields) if t.startswith("(")), None)
    if cs is None:
        return None, "host", None
    ce = next((j for j in range(cs, len(fields)) if fields[j].endswith(")")), cs)
    trun = None
    if ce + 2 < len(fields):
        try:
            trun = float(fields[ce + 2])
        except ValueError:
            pass
    cg = max((i for i, t in enumerate(fields) if t.startswith("(")), default=cs)
    cont = fields[cg - 2] if cg > ce and cg >= 2 else "-"
    isproc = fields[cg - 5] if cg > ce and cg >= 5 else None
    return trun, ("host" if cont in ("-", "") else cont), isproc


def _host_rows(path_glob, t0, t1, names=None):
    """Yield (epoch, {pid: rec}, thread_lines) one atop sample at a time.

    Thread lines (flag 'n') are skipped as they are read. The main thread of a
    multi-threaded program carries the same id as its process line, so merging
    the two by id would let the thread line overwrite the process totals."""
    names = names or {}
    cur, proc, nthr = None, {}, 0
    for f in sorted(glob.glob(path_glob)):
        for line in open(f, errors="ignore"):
            kind = line[:3]
            if kind not in ("PRC", "PRM", "PRD", "PRG"):
                continue
            s = _atop_split(line)
            if not s:
                continue
            head, comm, tail = s
            try:
                epoch, interval, pid = int(head[2]), int(head[5]), int(head[6])
            except (IndexError, ValueError):
                continue
            if epoch != cur:
                if proc:
                    yield cur, proc, nthr
                cur, proc, nthr = epoch, {}, 0
            if not (t0 <= epoch <= t1) or not (0 < interval <= MAX_INTERVAL):
                continue
            fields = tail[1:]
            if kind == "PRG":
                trun, cont, flag = _prg(fields)
            else:
                flag = fields[ISPROC[kind]] if len(fields) > ISPROC[kind] else None
            if flag == "n":
                nthr += kind == "PRG"                   # one PRG line per thread
                continue
            rec = proc.get(pid)
            if rec is None:
                rec = proc[pid] = {"PID": pid, "CMD": comm, "CONT": "host",
                                   **{k: 0.0 for k in FEATS}}

            def gi(i):
                try:
                    return float(fields[i])
                except (IndexError, ValueError):
                    return 0.0
            if kind == "PRM":
                rec["MEM"], rec["VSZ"] = gi(PRM["RSIZE"]), gi(PRM["VSIZE"])
                rec["VGROW"], rec["RGROW"] = gi(PRM["VGROW"]), gi(PRM["RGROW"])
                rec["MINFLT"], rec["MAJFLT"] = gi(PRM["MINFLT"]), gi(PRM["MAJFLT"])
            elif kind == "PRC":
                hz = gi(PRC["HERTZ"]) or 100.0
                rec["CPU"] = 100.0 * (gi(PRC["UTIME"]) + gi(PRC["STIME"])) / (hz * interval)
            elif kind == "PRD":
                rec["WRDSK"] = gi(PRD_WRDSK)
            else:
                if trun is not None:
                    rec["TRUN"] = trun
                rec["CONT"] = names.get(cont, cont)
    if proc:
        yield cur, proc, nthr


def convert_host(lab, out, labels, t0, t1):
    pp = os.path.join(out, "Host_lab.csv")
    cp = os.path.join(out, "Host_lab_container.csv")
    names = _docker_names()
    if names:
        print(f"  container ids resolved by docker: {len(names)}")
    n_all = n_threads = n_kept = n_cont = n_samples = 0
    with open(pp, "w", newline="") as fp, open(cp, "w", newline="") as fc:
        wp = csv.DictWriter(fp, fieldnames=HOST_COLS, extrasaction="ignore")
        wc = csv.DictWriter(fc, fieldnames=CONT_COLS)
        wp.writeheader(); wc.writeheader()
        for epoch, proc, nthr in _host_rows(os.path.join(lab, "intermediate", "atop", "*.txt"),
                                            t0, t1, names):
            n_samples += 1
            n_threads += nthr
            lab_, typ = labels.label(epoch, "h")
            agg = {}
            for pid in sorted(proc):
                rec = proc[pid]
                n_all += 1
                a = agg.setdefault(rec["CONT"], {"NPROC": 0, **{k: 0.0 for k in FEATS}})
                a["NPROC"] += 1
                for k in FEATS:
                    a[k] += rec[k]
                if any(rec[k] for k in FEATS):     # drop idle all-zero rows
                    wp.writerow({"ts": epoch, **rec, "label": lab_, "type": typ})
                    n_kept += 1
            for cont in sorted(agg):
                wc.writerow({"ts": epoch, "CONT": cont, "CMD": cont, **agg[cont],
                             "label": lab_, "type": typ})
                n_cont += 1
    print(f"  host {n_samples} samples: {n_all} process rows ({n_threads} thread lines skipped), "
          f"{n_kept} kept after dropping idle all-zero rows -> {os.path.basename(pp)}")
    print(f"  host {n_cont} container-rows -> {os.path.basename(cp)}")


def verify_atop(path):
    """Print the first rows of each record type as this parser reads them."""
    shown = defaultdict(int)
    for line in open(path, errors="ignore"):
        k = line[:3]
        if k not in ("PRC", "PRM", "PRD", "PRG") or shown[k] >= 3:
            continue
        s = _atop_split(line)
        if not s:
            continue
        head, comm, tail = s
        fields = tail[1:]
        print(f"\n{k}  pid={head[6]} comm={comm} interval={head[5]}")
        if k == "PRG":
            trun, cont, isproc = _prg(fields)
            print(f"   TRUN={trun} container={cont} process={isproc}")
        elif k in ISPROC and len(fields) > ISPROC[k]:
            print(f"   process={fields[ISPROC[k]]}")
        print("   all:", list(enumerate(fields)))
        shown[k] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", default=os.path.expanduser("~/catf-lab"))
    ap.add_argument("--out", default=os.path.expanduser("~/catf-lab/csv"))
    ap.add_argument("--labels", default=None)
    ap.add_argument("--start", type=float, default=0)
    ap.add_argument("--end", type=float, default=2**40)
    ap.add_argument("--slice", type=int, default=10)
    ap.add_argument("--plc-ip", default=PLC_IP_DEFAULT)
    ap.add_argument("--only", default="device,network,host",
                    help="comma list of streams to convert (default: all three)")
    ap.add_argument("--verify-atop", default=None)
    a = ap.parse_args()

    if a.verify_atop:
        verify_atop(a.verify_atop)
        return

    only = {s.strip() for s in a.only.split(",")}
    os.makedirs(a.out, exist_ok=True)
    labels = Labels(a.labels)
    print(f"labels: {len(labels.win)} window(s) | window {a.start:.0f}..{a.end:.0f} | {sorted(only)}")
    if "device" in only:
        convert_devices(a.lab, a.out, labels, a.start, a.end)
    if "network" in only:
        convert_network(a.lab, a.out, labels, a.start, a.end, a.slice, a.plc_ip)
    if "host" in only:
        convert_host(a.lab, a.out, labels, a.start, a.end)
    print(f"done -> {a.out}")


if __name__ == "__main__":
    main()
