# agent/kb — the operator agent's knowledge base (flat files + hybrid retrieval)

Exact numbers and relations live in YAML/JSON and are served by direct lookup;
rationale lives in `prose/*.md` and is served by BM25. Numbers are never embedded
or semantically retrieved. Everything diffs and audits in git.

| file | role |
|---|---|
| `guards.yaml` | the frozen thresholds — the ONLY file the agent proposes changes to |
| `hard_limits.yaml` | IMMUTABLE bounds; the agent can never cross these |
| `device_profiles.yaml` | per-device nature + bands (fill 6 devices from the machine) |
| `command_vocab.json` | the frozen normal write vocabulary (fill full set from the machine) |
| `attack_map.yaml` | which layer catches which attack class |
| `prose/*.md` | rationale the analyst cites |

Retriever: `python3 ../retriever.py "<question>"` (dep: pyyaml).

## To finalise from the resumed machine
1. Per-device nature + value bands -> `device_profiles.yaml` (phys_envelope CV classifier on clean normal).
2. The full normal write vocabulary -> `command_vocab.json` (net_command_baseline on clean normal).
3. The real tank-pressure alarm band -> `hard_limits.yaml process_safety`.
