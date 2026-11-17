#!/usr/bin/env python3
"""Local backend for the CATF-IDS operator console -- wires the designed UI to the live
agent, the alert bus, the KB, and the guards validator. Pure stdlib (no Flask).

  python serve_console.py                 # http://localhost:8750
  python serve_console.py --port 8750 --model qwen2.5:3b

Serves console.html (drop the designed HTML next to this file as console.html) and:
  GET  /api/alerts?since=600          recent alerts off the bus (newest first)
  GET  /api/state                     mode (AUTO/MANUAL), latest pressure, counters
  GET  /api/kb                        frozen bands, vocabulary, ATT&CK map
  POST /api/chat     {question}       agent answer + tool-call trace + fact chips
  POST /api/propose  {param,value,rationale}   validated guards.yaml diff + verdict
  POST /api/approve  {param,value}    apply to guards.yaml + git commit (human-approved)

The UI makes NO external requests; everything is this localhost backend + a local model.
"""
import os, sys, json, time, glob, subprocess, argparse
import http.server, socketserver
import agent  # same dir

HERE = os.path.dirname(os.path.abspath(__file__))
KBP = agent.KB

def read_alerts(since_s=600):
    path = agent.ALERTS
    if not os.path.exists(path):
        return []
    cut = time.time() - since_s
    out = []
    for line in open(path, errors="ignore"):
        line = line.strip()
        if not line: continue
        try: a = json.loads(line)
        except Exception: continue
        if a.get("ts", 0) >= cut:
            out.append(a)
    # command alerts already collapsed in the bus; keep the latest per (src,func,register)
    cmd_latest = {}
    phys = []
    for a in out:
        if a.get("det") == "command":
            cmd_latest[(a.get("src"), a.get("func"), a.get("register"))] = a
        else:
            phys.append(a)
    merged = phys + list(cmd_latest.values())
    merged.sort(key=lambda a: a.get("ts", 0), reverse=True)
    return merged

LAYER = {"command": "L3", "band": "L1", "cusum": "L1", "varcollapse": "L2", "emd": "L2"}
STATE_PATH = os.path.join(os.path.dirname(agent.ALERTS), "state.json")
# device -> (primary signal, band, nature)
DEVICES = [("tank", "pressure", [2693, 2702], "steady"),
           ("feed1", "f1_flow", [640.5, 640.5], "steady"),
           ("feed2", "f2_flow", [0, 3.3], "idle"),
           ("product", "product_flow", [8, 213], "cycling"),
           ("purge", "purge_flow", [0, 1794], "cycling"),
           ("analyzer", "A_in_purge", [0.47, 0.51], "muted")]

def live_signals():
    try:
        return json.load(open(STATE_PATH)).get("signals", {})
    except Exception:
        return {}

def state():
    al = read_alerts(600)
    now = time.time()
    sig = live_signals()
    manual = any(a.get("det") == "command" and a.get("func") == "WRITE_SINGLE_COIL"
                 and a.get("register") == 0 and a.get("ts", 0) >= now - 120 for a in al)
    # per-device highest live severity (from current alerts on that device)
    dev_sev = {}
    for a in al:
        d = a.get("device")
        if a.get("sev") == "high": dev_sev[d] = "high"
        elif dev_sev.get(d) != "high" and a.get("sev") == "med": dev_sev[d] = "med"
    tiles = [{"device": dev, "signal": s, "value": sig.get(s), "band": band,
              "nature": nat, "sev": dev_sev.get(dev, "ok")} for dev, s, band, nat in DEVICES]
    pres_live = sig.get("pressure")
    if pres_live is None:
        pres_live = (next((a for a in al if a.get("signal") == "pressure"), {}) or {}).get("value")
    win = [a for a in al if a.get("ts", 0) >= now - 600]
    counts = {"high": sum(1 for a in win if a.get("sev") == "high"),
              "med": sum(1 for a in win if a.get("sev") == "med"),
              "L3": sum(1 for a in win if LAYER.get(a.get("det")) == "L3"),
              "L2": sum(1 for a in win if LAYER.get(a.get("det")) == "L2"),
              "L1": sum(1 for a in win if LAYER.get(a.get("det")) == "L1")}
    return {"mode": "MANUAL" if manual else "AUTO",
            "pressure": {"value": pres_live, "band": [2693, 2702], "normal": 2698},
            "signals": sig, "tiles": tiles, "counters": counts}

def kb_static():
    bands = {"pressure": [2693, 2702], "liquid_level": [43.87, 44.14], "f1_flow": [640.5, 640.5],
             "f1_valve_pos": [100, 100], "f2_flow": [0, 3.3], "f2_valve_pos": [0, 8],
             "product_flow": [8, 213], "product_valve_pos": [4, 100], "purge_flow": [0, 1794],
             "purge_valve_pos": [0, 100]}
    vocab = {"src": "192.168.95.2", "func": "WRITE_MULTIPLE_REGISTERS", "register": 1}
    attack = {"unauthorized_write": "T0855", "coil0": "T0858",
              "setpoint_write": "T0836", "hold_or_takeover": "T0831",
              "tactic": "Impair Process Control"}
    return {"bands": bands, "vocabulary": vocab, "attack": attack}

def apply_guard(param, value):
    """Write a validated value into guards.yaml and git-commit (human already approved)."""
    import yaml, copy
    gpath = os.path.join(KBP, "guards.yaml")
    g = yaml.safe_load(open(gpath)); node = g; keys = param.split(".")
    for k in keys[:-1]: node = node[k]
    node[keys[-1]] = value
    yaml.safe_dump(g, open(gpath, "w"), sort_keys=False)
    try:
        subprocess.run(["git", "-C", os.path.dirname(KBP), "add", gpath], check=False)
        subprocess.run(["git", "-C", os.path.dirname(KBP), "commit", "-m",
                        f"guards: {param} -> {value} (approved via console)"], check=False)
        return "committed"
    except Exception as e:
        return f"written (git commit failed: {e})"

class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def log_message(self, *a): pass

    def do_GET(self):
        p = self.path.split("?")[0]
        q = dict(x.split("=") for x in self.path.split("?")[1].split("&")) if "?" in self.path else {}
        if p in ("/", "/console.html"):
            f = os.path.join(HERE, "console.html")
            if os.path.exists(f):
                return self._send(200, open(f, "rb").read(), "text/html; charset=utf-8")
            return self._send(404, b"console.html not found -- drop the designed HTML here", "text/plain")
        if p == "/api/alerts":
            return self._send(200, read_alerts(int(q.get("since", 600))))
        if p == "/api/state":
            return self._send(200, state())
        if p == "/api/kb":
            return self._send(200, kb_static())
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/api/chat":
            return self._send(200, agent.ask_traced(body.get("question", "")))
        if self.path == "/api/propose":
            r = agent.propose_guard_change(body.get("param"), body.get("value"), body.get("rationale", ""))
            try: r = json.loads(r)
            except Exception: r = {"raw": r}
            return self._send(200, r)
        if self.path == "/api/approve":
            return self._send(200, {"result": apply_guard(body.get("param"), body.get("value"))})
        return self._send(404, {"error": "not found"})

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8750)
    ap.add_argument("--model", default=agent.MODEL)
    a = ap.parse_args()
    agent.MODEL = a.model
    print(f"CATF-IDS console backend on http://localhost:{a.port}")
    print(f"  model {agent.MODEL} | bus {agent.ALERTS} | KB {KBP}")
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", a.port), H) as srv:
        srv.serve_forever()

if __name__ == "__main__":
    main()
