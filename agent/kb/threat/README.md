# kb/threat — the real-world threat layer (keeps the agent tethered beyond the sim)

Same philosophy as the rest of the KB: exact relations in YAML/JSON (direct lookup),
rationale in prose. This layer maps our *observed* detections on the simulated plant to
the *real* adversary framework (MITRE ATT&CK for ICS) and to *live* vulnerability intel
(CISA KEV + CISA CSAF ICS advisories), so the agent reasons about the plant in the
language of real ICS defence — not a closed-world sim.

| file | role | source / refresh |
|---|---|---|
| `asset_watch.yaml` | the plant's vendor/product inventory; filters the CVE feed | hand-authored |
| `technique_links.yaml` | our detectors/attacks -> ATT&CK for ICS technique IDs (the bridge) | hand-authored, verified vs STIX |
| `attack_ics.json` | ATT&CK for ICS techniques (id, name, tactic, desc, mitigations) | STIX via mitreattack-python, versioned |
| `mitigations.yaml` | ATT&CK M-codes for our techniques -> recommended controls | STIX |
| `cve_feed.json` | CVEs affecting our assets, tagged exploited + ATT&CK ref | `refresh.py` (KEV + CSAF), git-committed |

## Refresh (the "regularly fed" part)
`python3 refresh.py` pulls CISA KEV + CISA CSAF ICS advisories, filters to
`asset_watch.yaml`, and writes `cve_feed.json` (a git diff a human reviews). Schedule it
daily/weekly. `attack_ics.json` is refreshed per MITRE ATT&CK release (manual, versioned).

## Design guarantee (unchanged)
Numbers and relations are never embedded/semantically retrieved — the agent looks them
up exactly. Threat prose (technique descriptions) is BM25-retrievable. Everything diffs
and audits in git.
