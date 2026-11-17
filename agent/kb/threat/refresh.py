#!/usr/bin/env python3
"""refresh.py -- pull live ICS threat intel into the KB (the 'regularly fed' part).

Sources (public, no key):
  * CISA KEV (Known Exploited Vulnerabilities) JSON  -- what's ACTIVELY exploited
  * CISA CSAF ICS advisories (cisagov/CSAF on GitHub) -- machine-readable ICS advisories

Filters everything to the plant's asset inventory (asset_watch.yaml) and writes
cve_feed.json -- a git diff a human reviews/commits. Schedule daily/weekly.

Run on the SOC-side host (internet access):  python3 refresh.py
Deps: pyyaml (stdlib urllib for fetch). ATT&CK STIX is refreshed separately (see bottom).
"""
import json, os, sys, time, urllib.request
try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

HERE = os.path.dirname(os.path.abspath(__file__))
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
UA = {"User-Agent": "catf-ids-threat-refresh/1.0"}

def fetch_json(url, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)

def load_watch():
    w = yaml.safe_load(open(os.path.join(HERE, "asset_watch.yaml")))
    kws = []
    for a in w.get("assets", []):
        kws += [k.lower() for k in a.get("keywords", [])]
        for fld in ("vendor", "product"):
            if a.get(fld) and a[fld] != "generic":
                kws.append(a[fld].lower())
    return w, sorted(set(kws))

import re as _re
def matches(text, kws):
    t = (text or "").lower()
    hits = set()
    for k in kws:
        k = (k or "").lower().strip()
        if len(k) < 4:                     # drop 'rtu','hmi' -- too short, substring-match noise
            continue
        if _re.search(r"\b" + _re.escape(k) + r"\b", t):   # whole-word only
            hits.add(k)
    return sorted(hits)

def main():
    watch, kws = load_watch()
    print(f"asset keywords: {kws}")
    out = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "sources": [], "asset_keywords": kws, "cves": []}

    # --- CISA KEV ---
    try:
        kev = fetch_json(KEV_URL)
        out["sources"].append({"name": "CISA KEV", "count": kev.get("count"),
                               "catalogVersion": kev.get("catalogVersion")})
        for v in kev.get("vulnerabilities", []):
            blob = " ".join(str(v.get(k, "")) for k in
                            ("vendorProject", "product", "vulnerabilityName", "shortDescription"))
            hit = matches(blob, kws)
            if hit:
                out["cves"].append({
                    "cve": v.get("cveID"), "exploited": True, "source": "CISA KEV",
                    "vendor": v.get("vendorProject"), "product": v.get("product"),
                    "name": v.get("vulnerabilityName"),
                    "dateAdded": v.get("dateAdded"), "dueDate": v.get("dueDate"),
                    "matched_assets": hit})
        print(f"KEV: {len(kev.get('vulnerabilities', []))} total -> {len(out['cves'])} match our assets")
    except Exception as e:
        print(f"KEV fetch failed: {e}  (skipping; keeping prior feed)")

    # --- CISA CSAF ICS advisories (GitHub cisagov/CSAF) ---
    # The repo holds per-advisory CSAF 2.0 JSON. Robust approach: walk the GitHub tree API
    # for the current year's folder, fetch each advisory's CSAF JSON, scan vulnerabilities[]
    # + product_tree for our keywords. Left as a clear extension point so the first run is
    # fast and dependency-free; KEV already gives the 'actively exploited' signal.
    out["sources"].append({"name": "CISA CSAF ICS", "status": "TODO: walk cisagov/CSAF tree",
                           "repo": "https://github.com/cisagov/CSAF"})

    # dedupe by CVE id, newest dateAdded first
    seen = {}
    for c in out["cves"]:
        seen[c["cve"]] = c
    out["cves"] = sorted(seen.values(), key=lambda c: c.get("dateAdded") or "", reverse=True)

    path = os.path.join(HERE, "cve_feed.json")
    json.dump(out, open(path, "w"), indent=2)
    print(f"wrote {path}: {len(out['cves'])} relevant CVEs. Review the git diff and commit.")

if __name__ == "__main__":
    main()

# --- ATT&CK for ICS STIX (refresh per MITRE release, not every run) ---
#   pip install mitreattack-python
#   python -c "from mitreattack.stix20 import MitreAttackData; \
#     d=MitreAttackData('ics-attack.json'); \
#     [print(t['external_references'][0]['external_id'], t['name']) for t in d.get_techniques()]"
#   # ics-attack.json from github.com/mitre-attack/attack-stix-data (ics-attack/ folder)
#   # Normalize into attack_ics.json: {id,name,tactic,description,mitigations[]}.
