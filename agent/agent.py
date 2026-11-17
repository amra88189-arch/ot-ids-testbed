#!/usr/bin/env python3
"""CATF-IDS operator agent -- a KB-grounded, human-in-the-loop OT-IDS assistant.

Runs on the SOC-side host against a local Ollama model (default qwen2.5:7b). Every
answer is grounded in the flat-file KB via typed tools; it never invents thresholds and
never changes anything live -- guard edits are emitted as a validated diff for a human.

  python agent.py "which layer catches the modbus injection?"      # KB-grounded
  python agent.py --bare "..."                                     # model only, no tools (for the contrast)
  python agent.py                                                   # interactive
  python agent.py --model qwen2.5:3b "..."                          # pick the model

Config via env: CATF_MODEL, OLLAMA_URL, CATF_ALERTS (path to alerts.jsonl on the share),
CATF_DEVICE (device-feed dir, if bridged). Deps: pyyaml (stdlib urllib for Ollama REST).
"""
import os, sys, json, glob, time, subprocess, difflib, re, inspect, urllib.request
try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

HERE   = os.path.dirname(os.path.abspath(__file__))
KB     = os.path.join(HERE, "kb")
MODEL  = os.environ.get("CATF_MODEL", "qwen2.5:7b")
OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434") + "/api/chat"
# the IDS writes its alert bus into the share; point here to wherever Windows sees it
ALERTS = os.environ.get("CATF_ALERTS",
            os.path.join(os.path.expanduser("~"), "OneDrive", "Desktop",
                         "CATF-IDS-repo", "alerts.jsonl"))
DEVICE = os.environ.get("CATF_DEVICE", "")   # device-feed dir if bridged; else read_signal is a no-op

SYSTEM = (
 "You are the CATF-IDS operator assistant for an industrial control system. You have NO "
 "reliable ICS knowledge of your own and must not use any -- every ATT&CK ID, CVE, "
 "threshold, band, AUC, and mitigation MUST come from the knowledge base via tools. "
 "MANDATORY PROCESS for every question: (1) call kb_lookup with the key terms BEFORE "
 "answering. (2) Read the returned [fact] lines and quote their exact values/IDs "
 "VERBATIM -- e.g. the ATT&CK id 'T0858', the band '[2693, 2702]', the mitigation "
 "'M0807', the exact CVE id. (3) NEVER substitute an ATT&CK id, CVE, threshold, or "
 "mitigation from your own memory; enterprise ATT&CK ids like T1xxx are WRONG for ICS. "
 "If kb_lookup returns a relevant [fact], use it; if it returns nothing relevant, say "
 "'the KB has no entry for that' and stop -- do not guess. CVE questions are answered by "
 "kb_lookup (it covers the live cve_feed). You are read-only on the plant and propose-"
 "only on config: propose_guard_change emits a diff for a human, you never apply it. "
 "Be concise and cite the fact keys you used.")

# ----------------------------- the typed tools -----------------------------
def kb_lookup(question: str) -> str:
    """Exact facts + prose rationale from the KB (numbers are looked up, never guessed)."""
    try:
        out = subprocess.run([sys.executable, os.path.join(HERE, "retriever.py"), question],
                             capture_output=True, text=True, timeout=30)
        return (out.stdout or "").strip() or "(no KB match)"
    except Exception as e:
        return f"(kb_lookup error: {e})"

def read_alerts(since_minutes: float = 10, detector: str = "", signal: str = "") -> str:
    """Recent entries from the live alert bus (alerts.jsonl), optionally filtered."""
    if not os.path.exists(ALERTS):
        return f"(no alert bus at {ALERTS}; set CATF_ALERTS)"
    try: sm = float(since_minutes)
    except Exception: sm = 10
    if sm <= 0: sm = 10                      # 0/negative -> sensible default, not "nothing"
    detector = "" if str(detector).lower() in ("all", "any", "none", "") else detector
    signal = "" if str(signal).lower() in ("all", "any", "none", "") else signal
    cut = time.time() - sm * 60
    rows = []
    for line in open(ALERTS, errors="ignore"):
        line = line.strip()
        if not line: continue
        try: a = json.loads(line)
        except Exception: continue
        if a.get("ts", 0) < cut: continue
        if detector and a.get("det") != detector: continue
        if signal and a.get("signal") != signal: continue
        rows.append(a)
    from collections import Counter
    by = Counter((a.get("det"), a.get("signal")) for a in rows)
    summary = "; ".join(f"{d}/{s}:{n}" for (d, s), n in by.most_common())
    return json.dumps({"window_min": since_minutes, "count": len(rows),
                       "by_detector_signal": summary, "latest": rows[-5:]}, default=str)

def read_signal(signal: str, window_s: float = 120) -> str:
    """Recent values of one signal from the device feed (read-only; needs CATF_DEVICE bridged)."""
    if not DEVICE or not os.path.isdir(DEVICE):
        return "(device feed not bridged to this host; use read_alerts instead)"
    cut = time.time() - float(window_s); vals = []
    for f in sorted(glob.glob(os.path.join(DEVICE, "device_*.jsonl")))[-2:]:
        for line in open(f, errors="ignore"):
            try: r = json.loads(line)
            except Exception: continue
            if r.get("ts", 0) < cut: continue
            d = r.get("data", {}); m = dict(d.get("measured", {}), **d.get("state", {}))
            if signal in m and isinstance(m[signal], (int, float)): vals.append(m[signal])
    if not vals: return f"(no recent samples for {signal})"
    return json.dumps({"signal": signal, "n": len(vals), "min": min(vals), "max": max(vals),
                       "last": vals[-1]})

def explain_alert(detector: str, signal: str = "") -> str:
    """Compose a grounded explanation for an alert. For physics alerts: the frozen band,
    the detector's job, and the ATT&CK linkage. For a network 'command' alert: the command
    vocabulary rule and the ATT&CK technique the write maps to."""
    if detector == "command":
        parts = [kb_lookup("command layer normal writer rule unauthorized modbus write"),
                 kb_lookup("coil0 manual mode change operating mode T0858"),
                 kb_lookup("manual setpoint write modify parameter T0836"),
                 kb_lookup("why freeze the command vocabulary")]
    else:
        parts = [kb_lookup(f"device profile band for {signal}"),
                 kb_lookup(f"what does the {detector} detector catch"),
                 kb_lookup(f"which ATT&CK technique and layer for {signal} {detector}")]
    return "\n".join(p for p in parts if p and p != "(no KB match)")

def propose_guard_change(param: str, value, rationale: str = "") -> str:
    """Propose a change to guards.yaml. VALIDATES against hard_limits.yaml and returns a
    unified diff for a HUMAN to commit. Never writes. param is a dotted path, e.g.
    'physics.cusum.h_sigma'."""
    gpath = os.path.join(KB, "guards.yaml"); hpath = os.path.join(KB, "hard_limits.yaml")
    g = yaml.safe_load(open(gpath)); h = yaml.safe_load(open(hpath))
    # resolve + set dotted path on a copy
    import copy; g2 = copy.deepcopy(g); node = g2; keys = param.split(".")
    try:
        for k in keys[:-1]: node = node[k]
        old = node.get(keys[-1]); node[keys[-1]] = value
    except Exception:
        return f"INVALID: '{param}' is not a path in guards.yaml"
    # validate against hard_limits by leaf name
    leaf = keys[-1]; hl = h.get("physics", {})
    limit = hl.get(leaf) or hl.get(f"cusum_{leaf}") or hl.get(f"{leaf}")
    verdict = "VALID"
    if param.endswith("enforce_vocabulary") or leaf == "mode":
        return "INVALID: command vocabulary / frozen mode are immutable (hard_limits const)"
    if isinstance(limit, dict) and "min" in limit:
        try:
            if not (limit["min"] <= float(value) <= limit["max"]):
                verdict = f"INVALID: {value} outside hard limit [{limit['min']},{limit['max']}]"
        except Exception:
            verdict = "INVALID: value not numeric"
    diff = "".join(difflib.unified_diff(
        yaml.safe_dump(g, sort_keys=False).splitlines(True),
        yaml.safe_dump(g2, sort_keys=False).splitlines(True),
        fromfile="guards.yaml", tofile="guards.yaml (proposed)"))
    return json.dumps({"param": param, "old": old, "new": value, "validation": verdict,
                       "rationale": rationale, "diff": diff,
                       "action": "HUMAN must review and commit; agent did not write."}, default=str)

TOOLS = {
 "kb_lookup": kb_lookup, "read_alerts": read_alerts, "read_signal": read_signal,
 "explain_alert": explain_alert, "propose_guard_change": propose_guard_change,
}
TOOL_SCHEMAS = [
 {"type": "function", "function": {"name": "kb_lookup",
   "description": "Look up exact facts (thresholds, bands, AUCs, ATT&CK technique IDs, ATT&CK mitigations, and the live CVE threat feed) plus rationale from the IDS knowledge base. Call this before ANY factual claim, including CVE and ATT&CK questions.",
   "parameters": {"type": "object", "properties": {"question": {"type": "string"}}, "required": ["question"]}}},
 {"type": "function", "function": {"name": "read_alerts",
   "description": "Read recent entries from the live IDS alert bus. Filter by detector (band|cusum|varcollapse|emd) or signal.",
   "parameters": {"type": "object", "properties": {"since_minutes": {"type": "number"}, "detector": {"type": "string"}, "signal": {"type": "string"}}}}},
 {"type": "function", "function": {"name": "read_signal",
   "description": "Recent min/max/last of one process signal from the device feed (read-only).",
   "parameters": {"type": "object", "properties": {"signal": {"type": "string"}, "window_s": {"type": "number"}}, "required": ["signal"]}}},
 {"type": "function", "function": {"name": "explain_alert",
   "description": "Explain an alert: the frozen band, the ATT&CK linkage, and the rationale, given its detector and signal.",
   "parameters": {"type": "object", "properties": {"detector": {"type": "string", "description": "band|cusum|varcollapse|emd|command"}, "signal": {"type": "string", "description": "signal name for physics alerts; omit for command alerts"}}, "required": ["detector"]}}},
 {"type": "function", "function": {"name": "propose_guard_change",
   "description": "Propose a change to a detection threshold in guards.yaml. Validates against immutable hard_limits and returns a diff for a HUMAN to commit. Never applies it.",
   "parameters": {"type": "object", "properties": {"param": {"type": "string", "description": "dotted path e.g. physics.cusum.h_sigma"}, "value": {}, "rationale": {"type": "string"}}, "required": ["param", "value"]}}},
]

# ----------------------------- the Ollama loop -----------------------------
def call_tool(fn, args):
    """Run a tool, tolerating malformed arguments from weak models (wrong arg names, etc.)."""
    if fn not in TOOLS:
        return f"(unknown tool {fn})"
    f = TOOLS[fn]
    if not isinstance(args, dict):
        args = {}
    try:
        return f(**args)
    except TypeError:
        # weak models mis-name args -> map the provided values onto the real params by position
        params = list(inspect.signature(f).parameters)
        vals = list(args.values())
        try:
            return f(*vals[:len(params)])
        except Exception as e:
            return f"(tool {fn} argument error: {e})"
    except Exception as e:
        return f"(tool {fn} error: {e})"

def _post(payload):
    req = urllib.request.Request(OLLAMA, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)

def _text_toolcall(content):
    """Some small models emit a tool call as text (```json {"name":..,"arguments":..}```)
    instead of a structured tool_call. Recover it so the loop still executes the tool."""
    if not content:
        return []
    m = re.search(r'"name"\s*:\s*"(\w+)"\s*,\s*"(?:arguments|parameters)"\s*:\s*(\{.*?\})',
                  content, re.S)
    if not m:
        return []
    name = m.group(1)
    if name not in TOOLS:
        return []
    try:
        args = json.loads(m.group(2))
    except Exception:
        args = {}
    return [{"function": {"name": name, "arguments": args}}]

def ask(question, use_tools=True, max_iters=6, verbose=False):
    messages = [{"role": "system", "content": SYSTEM if use_tools else
                 "You are a concise ICS security assistant."},
                {"role": "user", "content": question}]
    for _ in range(max_iters):
        payload = {"model": MODEL, "messages": messages, "stream": False}
        if use_tools: payload["tools"] = TOOL_SCHEMAS
        resp = _post(payload)
        msg = resp.get("message", {})
        calls = msg.get("tool_calls") or []
        if not calls and use_tools:                       # fallback: tool call emitted as text
            calls = _text_toolcall(msg.get("content", ""))
        if not calls:
            return msg.get("content", "").strip()
        messages.append(msg)
        for c in calls:
            fn = c["function"]["name"]; args = c["function"].get("arguments", {})
            if isinstance(args, str):
                try: args = json.loads(args)
                except Exception: args = {}
            if verbose: print(f"  -> {fn}({args})")
            result = call_tool(fn, args)
            messages.append({"role": "tool", "content": str(result)})
    return "(stopped: tool loop did not converge)"

def ask_traced(question, max_iters=6):
    """KB-grounded answer for the UI: returns {answer, tool_calls, chips}. chips are the
    exact [fact] key=value pairs the agent retrieved (for the UI's fact-chip row)."""
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": question}]
    trace, chips = [], []
    for _ in range(max_iters):
        resp = _post({"model": MODEL, "messages": messages, "stream": False, "tools": TOOL_SCHEMAS})
        msg = resp.get("message", {})
        calls = msg.get("tool_calls") or _text_toolcall(msg.get("content", ""))
        if not calls:
            return {"answer": (msg.get("content", "") or "").strip(),
                    "tool_calls": trace, "chips": chips}
        messages.append(msg)
        for c in calls:
            fn = c["function"]["name"]; args = c["function"].get("arguments", {})
            if isinstance(args, str):
                try: args = json.loads(args)
                except Exception: args = {}
            result = call_tool(fn, args)
            trace.append({"name": fn, "args": args})
            for line in str(result).splitlines():
                if line.startswith("[fact]") and " = " in line:
                    k, v = line[6:].split(" = ", 1)
                    chips.append({"key": k.strip(), "value": v.strip()})
            messages.append({"role": "tool", "content": str(result)})
    return {"answer": "(tool loop did not converge)", "tool_calls": trace, "chips": chips}

def main():
    args = sys.argv[1:]; bare = False; verbose = "-v" in args
    if "--bare" in args: bare = True; args.remove("--bare")
    if "-v" in args: args.remove("-v")
    if "--model" in args:
        i = args.index("--model"); globals()["MODEL"] = args[i+1]; del args[i:i+2]
    q = " ".join(args).strip()
    print(f"[model {MODEL} | {'BARE (no KB)' if bare else 'KB-grounded'}]")
    if q:
        print(ask(q, use_tools=not bare, verbose=verbose)); return
    while True:
        try: q = input("\nanalyst> ").strip()
        except (EOFError, KeyboardInterrupt): break
        if q.lower() in ("exit", "quit"): break
        if q: print(ask(q, use_tools=not bare, verbose=verbose))

if __name__ == "__main__":
    main()
