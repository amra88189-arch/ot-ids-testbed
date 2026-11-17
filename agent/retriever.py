#!/usr/bin/env python3
"""Hybrid KB retriever for the OT-IDS operator agent.

Exact lookup (flattened YAML/JSON) for numbers and relations; hand-rolled BM25
over Markdown prose for rationale. Numbers are NEVER semantically retrieved.
Only dependency: pyyaml.

The real agent's LLM routes via tool calls (it picks the key / structured query).
This deterministic keyword router is the fast fallback; an optional kb/aliases.yaml
(key -> natural-language phrases) sharpens it where config terms differ from how a
person asks. Run:

  python3 retriever.py "what auc did the frozen envelope get on the drift"
  python3 retriever.py "why freeze the baseline"
"""
import sys, json, math, re, glob, os
try:
    import yaml
except ImportError:
    yaml = None
KB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kb")

# decimals survive as one token; every other non-alphanumeric (dots in key paths,
# underscores, brackets) is a separator.
def tok(s):
    return re.findall(r"\d+\.\d+|[a-z0-9]+", str(s).lower())

STOP = set("the a an of to in on is are was for and or by with it this that what "
           "which who how does did get got do we our my your at as be from".split())

def _flatten(d, pre=""):
    out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            out.update(_flatten(v, f"{pre}.{k}" if pre else str(k)))
    elif isinstance(d, list):
        for i, v in enumerate(d):
            out.update(_flatten(v, f"{pre}[{i}]"))
    else:
        out[pre] = d
    return out

def load_facts():
    f = {}
    # recurse so kb/threat/*.{yaml,json} (ATT&CK linkage, CVE feed) are included too
    for p in glob.glob(KB + "/**/*.yaml", recursive=True) + glob.glob(KB + "/**/*.yml", recursive=True):
        if os.path.basename(p) == "aliases.yaml":
            continue
        if yaml:
            f.update(_flatten(yaml.safe_load(open(p)), os.path.basename(p).split(".")[0]))
    for p in glob.glob(KB + "/**/*.json", recursive=True):
        f.update(_flatten(json.load(open(p)), os.path.basename(p).split(".")[0]))
    return f

def load_aliases():
    p = os.path.join(KB, "aliases.yaml")
    return (yaml.safe_load(open(p)) or {}) if (yaml and os.path.exists(p)) else {}

class BM25:
    def __init__(self, docs, k1=1.5, b=0.75):
        self.d = [tok(x) for x in docs]; self.k1, self.b = k1, b
        self.N = len(self.d); self.avgdl = sum(len(x) for x in self.d) / max(self.N, 1)
        df = {}
        for doc in self.d:
            for w in set(doc): df[w] = df.get(w, 0) + 1
        self.idf = {w: math.log(1 + (self.N - n + 0.5) / (n + 0.5)) for w, n in df.items()}
    def scores(self, q):
        out = []
        for doc in self.d:
            s, dl = 0.0, len(doc)
            for w in tok(q):
                if w not in self.idf: continue
                fr = doc.count(w)
                s += self.idf[w] * fr * (self.k1 + 1) / (fr + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
            out.append(s)
        return out

FACTS = load_facts()
ALIASES = load_aliases()
# routing signature per fact = key tokens + value tokens + alias phrase tokens, minus stopwords
_FK = {}
for k, v in FACTS.items():
    sig = set(tok(k)) | set(tok(v))
    for ph in ALIASES.get(k, []):
        sig |= set(tok(ph))
    _FK[k] = sig - STOP
PROSE = sorted(glob.glob(KB + "/prose/*.md"))
_BM = BM25([open(p).read() for p in PROSE]) if PROSE else None

def lookup(q, topk=6):
    qs = set(tok(q)) - STOP
    scored = sorted(((len(qs & sig), k) for k, sig in _FK.items()), reverse=True)
    top = [k for s, k in scored[:topk] if s > 0]
    # pull siblings of the best match (same parent) so a matched entity returns ALL its
    # fields -- e.g. matching tank.primary.signal also returns tank.primary.band (the number)
    if top:
        parent = top[0].rsplit(".", 1)[0]
        for k in FACTS:
            if k.rsplit(".", 1)[0] == parent and k not in top:
                top.append(k)
    return [(k, FACTS[k]) for k in top]

def search_prose(q):
    if not _BM: return None, None
    sc = _BM.scores(q); i = max(range(len(sc)), key=lambda j: sc[j])
    return os.path.basename(PROSE[i]), open(PROSE[i]).read().strip()

def answer(q):
    facts = lookup(q)
    if q.strip().lower().startswith("why"):
        n, t = search_prose(q)
        return {"kind": "prose", "source": n, "text": t, "items": facts[:4]}
    return {"kind": "facts", "items": facts}

if __name__ == "__main__":
    q = " ".join(sys.argv[1:]) or "what auc did the frozen envelope get on the drift"
    r = answer(q)
    if r["kind"] == "prose":
        print(f"[prose] {r['source']}: {r['text']}")
        for k, v in r.get("items", []):
            print(f"[fact] {k} = {v}")
    else:
        for k, v in r["items"]:
            print(f"[fact] {k} = {v}")
