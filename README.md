# CATF-IDS — a four-layer, frozen-baseline intrusion detection stack for ICS, with a KB-grounded operator agent

A defensive intrusion-detection system for an industrial control system (a live GRFICSv3
chemical-process testbed — a Tennessee-Eastman-style reactor with a soft PLC, Modbus
field devices, an HMI, a routed DMZ↔ICS network, and attacker hosts). It pairs a frozen,
physics-aware detector with an air-gapped, KB-grounded LLM operator agent — and it is
evaluated with deliberate intellectual honesty: every headline number is a run on the live
testbed, and the methodology is designed to *surface* the ways ICS IDS evaluations usually
mislead, not hide them.

> **One-line thesis:** learn *normal* once, freeze it, and alert on deviation at four
> independent layers — so novel attacks are caught *because* you never trained on attacks —
> then let a local, read-only agent explain the alerts in the language of MITRE ATT&CK for
> ICS and live CVEs.

---

## Why this exists

Most ICS IDS results look great on a benchmark and fall apart in deployment. This project
starts from that failure and builds around it:

- A supervised fusion scores **F1 0.996** under random cross-validation — and **injection
  recall collapses from 0.76 → 0.00** under a temporal (train-past / test-future) split.
  The headline number was a time-leakage artefact.
- A baseline *fit on incoming data* **inverts under attack** (network-flow AUC **0.154 vs
  0.973 frozen**): when attacks dominate the window, the "baseline" becomes the attack.
- A detector trained on a public benchmark (TON_IoT) **floods at the plant (FPR ≈ 0.99)** —
  the negative control that motivates per-environment baselining.

So CATF-IDS freezes each layer's notion of normal on clean data and never rebuilds it from
live traffic.

## The four layers (all live on one alert bus)

| layer | question | signal | detectors |
|---|---|---|---|
| **L3 · command / network** | *who touched the PLC, was it allowed?* | Modbus writes | out-of-vocabulary `(src, func, register)` |
| **L1 · process safety** | *is the plant physically safe?* | pressure, level | static value band + **CUSUM** |
| **L2 · control integrity** | *is the process being manipulated?* | feed/outlet valves, mode | **variance-collapse** + **EMD** |
| **L4 · fusion / threat** | *what's the verdict?* | — | KB-grounded agent: ATT&CK mapping + live CVE feed |

An attack propagates *down* the stack — unauthorized write → manual-mode flip → pinned
valves → pressure excursion — and each layer catches it at a different stage.

## Headline results (all demonstrated on the live testbed)

- **Modbus command injection:** 10/10 flagged, **0 false positives of 4,476** normal writes —
  and now a **live** streaming detector, flagging the attacker's writes by source IP in real time.
- **Subtle in-band attack (the hard case):** pressure held at 2704 kPa *inside* the band for
  5 min; the static band fired **0**, **CUSUM fired 58**. Verified with Modbus coil-0 read-back.
- **PASAD baseline:** against the field-standard stealth detector (Aoudi et al., CCS 2018) on
  the same recording, **CUSUM matches the best PASAD config** (93.3 % detection, 11 s
  first-alarm, 0 false positives) — honestly scoped: PASAD's edge is for cyclic/structured
  signals, which this steady-signal bias doesn't exercise.
- **Per-layer detection latency:** L3 command **+1.4 s**, L1 CUSUM **+14.3 s**, L2 EMD +28 s,
  band +69 s, variance-collapse +111 s — the network layer sees the intrusion **13–110 s
  before** the physical consequence appears.
- **Prevention (inline command firewall):** blocks **6/6** varied, *novel* unauthorized writes
  (distinct from the known attack) while passing all legitimate reads, process undisturbed.
- **Detection catches what prevention can't:** a field-device bypass scored **command 0 /
  physics 108** — proving the layers cover different failure modes (compromised source,
  field-direct write, physical fault).
- **KB-grounded agent (LLM-judged):** grounding lifts a local 7B from **0/20 → 9/20** (bare
  cannot answer a single plant-specific or live-CVE question); 3B 1/20 → 4/20. A keyword
  metric *over-credited* the bare model via hallucinations — reported honestly.

See **[docs/TECHNICAL_REPORT.md](docs/TECHNICAL_REPORT.md)** for the full write-up, the
epistemic tiers (demonstrated / attribution / analytical), and the honest limitations.

## The operator agent + console

A local, **air-gapped** assistant (Qwen2.5 via Ollama) over a flat-file knowledge base of
frozen plant facts, detector rationale, **MITRE ATT&CK for ICS** mappings, and a **live CISA
KEV** CVE feed filtered to the plant's assets. It is **read-only on the plant and
propose-only on config** — a threshold change is emitted as a validated `git` diff for a
human to approve, rejected if it crosses an immutable hard-limit. A single-page **operator
console** (`agent/console.html` + `agent/serve_console.py`) tails the live bus, shows the
four layers and the live PLC panel, and runs the agent with its tool-trace and fact-chips.

## Repository layout

```
detector/   the frozen multi-detector physics IDS (ids.py + baselines.json)
network/    Layer 3: Modbus command-vocabulary sniffer, inline firewall, red-team probe,
            field-bypass attack, and the live state/alert bridges
agent/      the KB-grounded operator agent, retriever, knowledge base, LLM-judge benchmark,
            and the operator console (backend + single-page UI)
analysis/   offline evaluations (PASAD vs CUSUM)
attacks/    the subtle-hold attacker regulator (coil-0 verified in-band manipulation)
docs/       the technical report and the UI design brief
testbed/    notes for the GRFICSv3 lab-side scripts (added from your VM)
```

Each directory has its own README. Start with **[docs/TECHNICAL_REPORT.md](docs/TECHNICAL_REPORT.md)**.

## Quick start

**Detector (replay / live), stdlib only:**
```bash
python3 detector/ids.py --freeze CLEAN.jsonl            # learn + freeze normal
python3 detector/ids.py --replay SESSION.jsonl          # score a recording
python3 detector/ids.py --device-dir ~/catf-lab/device  # live tail -> alerts.jsonl
```

**Agent (local, needs Ollama + a Qwen2.5 model):**
```bash
python agent/agent.py "which ATT&CK technique is the Modbus injection?"   # KB-grounded
python agent/serve_console.py --model qwen2.5:7b                           # console at :8750
```

**Live command layer (passive detect, then optional inline enforce) in the PLC netns:**
```bash
sudo nsenter -t <plc-pid> -n python3 network/modbus_sniff.py --learn 120   # freeze write vocab
sudo nsenter -t <plc-pid> -n python3 network/modbus_sniff.py --detect       # stream alerts
sudo nsenter -t <plc-pid> -n python3 network/modbus_firewall.py             # block out-of-vocab
```

## Honesty notes (read these)

- **One simulated instance.** "Live OT" means a live ICS *simulation*, not field hardware;
  no cross-instance generalisation is claimed.
- **Metrics are reported with their biases.** The agent's keyword score is shown only to
  demonstrate that it over-credits hallucinations; the LLM-judge number is the one that counts.
- **The small local agent is imperfect even when grounded** (7B ≈ 45 %): it fails via refusals,
  wrong-fact retrieval, and muddled synthesis. Grounding is decisive but not magic.
- **Prevention is scoped.** On this plant nothing legitimately writes *to* the PLC, so "block
  any inbound write" is trivially safe here; a plant with operator setpoint writes must include
  those in the fair test.

## Related work

Positioned against **PASAD** (process-aware stealth detection; we baseline against it directly),
**KIDS** (ARES 2025, process monitoring + threat intelligence; closest neighbour — our
differentiator is the LLM-agent fusion and live CVE feed), the **Reality-Gap taxonomy** (MAKE
2026, operating-point/temporal shift), and the **SoK on ICS IDS evaluation** (which backs the
CV-mirage and benchmark-transfer findings). The read-only / propose-only agent design follows
the emerging best practice (OWASP GenAI 2026 "Excessive Agency"; "Parallax").

## License

MIT — see [LICENSE](LICENSE).
