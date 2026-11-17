# UI Design Brief — CATF-IDS Operator Console (FINAL)

> Paste this whole file into the design chat. It is fully self-contained: product story,
> the four-layer model that organises everything, the screens, the workflows, the real
> data shapes, and the visual direction. Design a high-fidelity console for it.

---

## 1. What this is
An **operator console for an OT/ICS intrusion-detection system** defending a chemical-
process plant (a Tennessee-Eastman-style reactor). A frozen, physics-aware IDS plus a
live network sniffer watch the plant and raise alerts on any deviation from a learned-
and-frozen "normal." A **local, air-gapped AI agent** (a small model + a knowledge base)
reads the live alert bus and explains alerts to the analyst in the language of real
threat intelligence — MITRE ATT&CK for ICS and live CVEs. The agent is **read-only on
the plant and propose-only on config**: it never acts, it drafts a change for a human to
approve. This console is the human's window into all of it.

Think **factory SOC / control-room**, not a consumer app. Serious, high-trust, dense but
calm, dark theme.

## 2. User & environment
- **User:** an OT security analyst (blue team). Needs to read plant state in seconds,
  triage fast, and trust every number. Not a data scientist.
- **Runs:** locally, air-gapped, on the IT/SOC side, reading plant telemetry across a
  boundary. No internet dependency. Single-page web app, desktop-first (analyst monitor).

## 3. THE FOUR-LAYER MODEL (the organising principle — design around this)
Everything an attacker does to this plant shows up as manipulation of a reactor's in/out
balance to drive **pressure** (the safety-critical variable) somewhere dangerous. The
console shows the attack propagate **down** four layers — and the whole point is that a
good analyst catches it at the top (the network write) long before the bottom (the
pressure excursion) hurts anyone. All four are **live on one alert bus today.**

| layer | question it answers | plant devices | detectors (live) |
|---|---|---|---|
| **L3 · Command / Network** | *Who touched the PLC, and was it allowed?* | the Modbus wire to the PLC | out-of-vocabulary write (src·func·register) |
| **L1 · Process safety** | *Is the plant physically safe?* | Tank (pressure, level) | static band + CUSUM |
| **L2 · Control integrity** | *Is someone manipulating the process?* | Feed-1/2 (in), Product/Purge (out), AUTO/MANUAL mode | variance-collapse + EMD |
| **L4 · Fusion / threat** | *What's the verdict?* | — | the KB-grounded agent: correlates, maps to ATT&CK, cites CVEs |

**The attack chain to tell visually:** unauthorized Modbus write (L3) → flip to MANUAL
mode (L3/L2) → pin feed/outlet valves (L2) → pressure excursion (L1) → agent correlates
and names the ATT&CK technique (L4). A console that shows only pressure is a plant that
already got hit.

**Lab-specific facts that shape the UI:**
- **Pressure is the crown jewel** (normal ~2698 kPa). A real takeover ran it to 3200; a
  fault dropped it to 1733. Always visible, central.
- **The subtle attack stays *inside* the band** (held at ~2704) — invisible to L1's static
  band but caught by CUSUM, and simultaneously by L2 (pinned valves) and L3 (the write).
  That multi-layer *correlation* on one event is the thing a SOC most wants surfaced.
- **Only one source legitimately writes** to the PLC (192.168.95.2, the control loop).
  Any write from another IP (e.g. 192.168.90.6, an attacker) is hostile by source alone.
- **Feed-2 is normally idle** (~0); its activation is inherently suspicious. Per-device
  "what's normal" matters — there is no single global rule.
- **AUTO vs MANUAL mode** is a first-class state. Normal is always AUTO; a flip to MANUAL
  (attacker disabling the control loops) is one of the loudest possible signals.

## 4. What the SOC must see (four panels, from the four layers)
1. **Process-safety panel** — pressure & level vs their frozen bands, with trend arrows
   (rising = feeds exceeding outlets = takeover; falling = the reverse). The "is the plant
   OK" glance.
2. **Control-integrity panel** — the four valves (feeds/outlets) vs their normal cycling,
   the feed↔outlet mass balance, and a bold **AUTO / MANUAL mode indicator**.
3. **Command-activity feed** — live Modbus writes (source · function · register) flagged
   against the frozen vocabulary; the earliest, most attributable signal.
4. **Correlated-alert / verdict panel** — the fused detector hits for one event stacked to
   show defense-in-depth, with the ATT&CK technique and any related CVE, and the agent's
   grounded explanation.

## 5. Screens / information architecture

### A. Live Operations Dashboard (home)
- **Plant status strip:** the 6 devices (Tank, Feed-1, Feed-2, Product, Purge, Analyzer)
  as tiles — primary signal's live value vs frozen band, health dot (green in-band / amber
  medium / red high). A prominent **AUTO/MANUAL** badge.
- **Live alert feed:** reverse-chronological stream off the bus, severity-coded, each row:
  time · layer (L1/L2/L3) · device/signal or src·func·register · detector · value ·
  severity. Auto-updates. Filter by layer, detector, device, severity. Repeated identical
  command writes are **collapsed into one row with a ×count** (the bus already dedups).
- **Summary counters:** alerts last 1/10/60 min, by layer and severity.
- **Quiet empty state** that reads as *reassuring* (plant healthy), not broken.

### B. Alert Detail / Triage (opens from an alert)
- The signal/write, its device, its **frozen band** or **vocabulary rule**, the **live
  value**, plotted/shown against normal.
- **Why it fired**, in plain language per detector (band / CUSUM / variance-collapse / EMD
  / command-vocabulary).
- **MITRE ATT&CK for ICS** technique(s): id + name + tactic.
- **Related CVEs** from the live feed, if the implicated asset has any.
- **Correlation:** other alerts from the same event/time across layers (the defense-in-
  depth stack).
- **The agent's grounded explanation**, with its tool-call trace shown small
  (`read_alerts → explain_alert`).
- Actions: *Ask the agent about this* · *Propose a threshold change*.

### C. Agent Chat (side panel or full view)
- Analyst asks ("what's firing now?", "why CUSUM on pressure?", "who wrote coil 0?",
  "any exploited CVE on OpenPLC?").
- The agent's **tool calls render inline** as it works (`kb_lookup(...)`,
  `read_alerts(since=10m)`, `explain_alert(command)`) — transparency; the analyst sees it
  reason over real data.
- Grounded answer with **cited fact-key chips** linking to the KB value used.
- Model badge: "local · Qwen2.5 · air-gapped." (Note: runs a 7B or a lighter 3B.)

### D. Guard Change Review (the approval moment)
- **What** (parameter, old → new), **why** (agent's rationale).
- **Validation verdict** vs immutable hard-limits: green **VALID**, or red **INVALID: out
  of bounds [min,max]** / **INVALID: immutable**.
- The **unified diff** of `guards.yaml`.
- **Approve** (commits to git) / **Reject**. Approve enabled only when VALID; immutable
  items (e.g. "disable command vocabulary") are hard-blocked.

### E. Threat Intelligence (reference)
- **ATT&CK coverage:** the techniques the detectors cover, each tile → which layer catches
  it + the demonstrated result.
- **Live CVE feed:** currently-exploited (CISA KEV) CVEs filtered to the plant's assets
  (OpenPLC, Modbus/ScadaBR), each with id, title, date added, due date, matched asset.

### F. Process / Baseline view (nice-to-have)
The 6 devices with all signals: frozen band, nature (steady/cycling), which detectors
guard each. The "what normal looks like" reference.

## 6. Hero workflows
1. **Triage:** red alert on dashboard → open → read grounded explanation + ATT&CK + the
   correlated stack → ask the agent a follow-up → decide.
2. **Live detect-and-explain (the hero):** an attack is happening; L3 fires first (the
   write), then L2 (pinned valves) and L1 (CUSUM on pressure); the analyst asks the agent
   "what's firing and what does it mean," and it names the ATT&CK technique across layers.
   Make the live feed → correlation → agent explanation feel like one connected story.
3. **Safe tuning:** agent proposes lowering a threshold → diff + VALID verdict → approve →
   committed. An out-of-bounds proposal is clearly refused.

## 7. Visual direction
- **Dark, control-room.** Near-black background, high-contrast text.
- **Severity palette:** high = red, medium = amber, healthy/info = green/teal. Sparing, so
  red means something.
- **Accent:** one cool accent (cyan / electric blue) for interactive + "agent" elements, so
  the AI's voice is visually distinct from ground-truth facts.
- **Facts vs narration (important):** facts (bands, IDs, values, CVEs, diffs) in a mono/
  technical treatment and chips; the agent's prose in a readable body font. The analyst
  must never confuse "the model said" with "the sensor/KB said."
- **Layers:** give L1/L2/L3 a consistent colour/label so an alert's layer is instantly
  readable.
- **Type:** a clean technical sans (Inter / IBM Plex Sans) + a mono (JetBrains Mono / IBM
  Plex Mono) for values, IDs, diffs.
- **Density:** information-dense but calm — generous spacing between groups, tight within.
- **Motion:** minimal; a subtle pulse on a new high-severity alert, nothing playful.

## 8. Constraints
- Runs locally; inline everything (no external fonts/CDNs assumed reachable).
- Data = an append-only **JSONL alert bus** + static KB files + the agent via a local
  model endpoint. For the mockup, use the sample data below.
- Desktop-first (wide analyst monitor); graceful down to a laptop.

---

## 9. Real data shapes (use for realistic mockups)

### Alert bus — one JSON object per line (`alerts.jsonl`). Five detector types:
```json
{"ts":1794692696.3,"det":"command","device":"plc","src":"192.168.90.6","func":"WRITE_SINGLE_COIL","register":0,"value":65280,"count":1,"first_ts":1794692696.3,"sev":"high"}
{"ts":1794692981.1,"det":"command","device":"plc","src":"192.168.90.6","func":"WRITE_MULTIPLE_REGISTERS","register":12,"value":2,"count":37,"first_ts":1794692944.0,"sev":"high"}
{"ts":1794692696.3,"det":"cusum","device":"tank","signal":"pressure","value":2704.0,"cusum":27.9,"sev":"med"}
{"ts":1794692696.3,"det":"band","device":"tank","signal":"liquid_level","value":44.4,"z":4.5,"sev":"med"}
{"ts":1794692696.3,"det":"varcollapse","device":"purge","signal":"purge_valve_pos","value":0.0,"rollstd":0.0,"norm":34.68,"sev":"high"}
{"ts":1794692696.3,"det":"emd","device":"product","signal":"product_flow","value":211.8,"emd":19.75,"sev":"med"}
```
- `command` (L3): a Modbus write not in the frozen vocabulary. Fields: `src, func,
  register, value, count` (repeats collapsed), `first_ts`. `sev` high.
- `band` (L1): steady signal left its frozen range (`z` = sigma past the band).
- `cusum` (L1): small *sustained* in-band bias (`cusum` = accumulator).
- `varcollapse` (L2): a normally-cycling valve got stuck (`rollstd` collapsed vs `norm`).
- `emd` (L2): a cycling signal's distribution shifted (`emd` = distance).

### Devices & signals (frozen bands + nature)
| device | signal | nature | frozen band | layer / detectors |
|---|---|---|---|---|
| Tank | pressure | steady | [2693, 2702] (~2698) | L1 band + CUSUM |
| Tank | liquid_level | steady | [43.87, 44.14] | L1 band |
| Feed-1 | f1_flow | steady (const) | ~640.5 | L1 band |
| Feed-1 | f1_valve_pos | steady (const) | 100 | L1 band |
| Feed-2 | f2_flow | steady (idle) | ~0–3.3 | L1 band (activation = flag) |
| Feed-2 | f2_valve_pos | steady (idle) | ~0–8 | L1 band |
| Product | product_flow | cycling | [8, 213] | L2 varcollapse + EMD |
| Product | product_valve_pos | cycling | [4, 100] | L2 varcollapse + EMD |
| Purge | purge_flow | cycling | [0, 1794] | L2 varcollapse + EMD |
| Purge | purge_valve_pos | cycling | [0, 100] | L2 varcollapse + EMD |
| Analyzer | A_in_purge / C_in_purge | steady | ~0.47–0.51 | (muted) |

Plus a plant-wide **mode** state: `AUTO` (normal) or `MANUAL` (control loops off — attack).

### Command vocabulary (L3)
Normal writer: **192.168.95.2 (the PLC) · WRITE_MULTIPLE_REGISTERS · register 1** — the
only legitimate write. Anything else is flagged. Attack examples the console will show:
`192.168.90.6 · WRITE_SINGLE_COIL · reg 0` (engage MANUAL mode) and `192.168.90.6 ·
WRITE_MULTIPLE_REGISTERS · reg 12` (manual setpoint write).

### Detection thresholds (guards — the agent can propose changing these)
```
fire_sigma 3.0 | window 150 | cusum: h_sigma 8, k_sigma 0.5
varcollapse_ratio 0.30 | emd: margin 1.3, nq 40 | command: enforce_vocabulary true
```
Immutable hard-limits (agent can never cross): fire_sigma∈[2,6], window∈[60,300],
cusum_h_sigma∈[4,12], varcollapse_ratio∈[0.1,0.5], emd_margin∈[1.1,2.0]; command-
vocabulary enforcement = always on; network baseline = always "frozen".

### MITRE ATT&CK for ICS linkage
| attack | technique(s) | tactic | caught by |
|---|---|---|---|
| Network scan | T0846 Remote System Discovery | Discovery | L3 network-flow |
| Modbus injection / any unauthorized write | T0855 Unauthorized Command Message | Impair Process Control | L3 command vocabulary |
| Engage manual mode (write coil 0) | T0858 Change Operating Mode | Impair Process Control | L3 command + L2 mode |
| Manual setpoint writes (reg 10–13) | T0836 Modify Parameter | Impair Process Control | L3 command + L2 |
| Manual-mode takeover | T0858, T0836, T0831 Manipulation of Control | Impair Process Control | L1/L2 physics |
| Subtle in-band hold | T0831 Manipulation of Control | Impair Process Control | L1 CUSUM (+L2, +L3) |

### Live CVE feed sample (CISA KEV, filtered to plant assets)
```json
{"cve":"CVE-2021-26829","exploited":true,"source":"CISA KEV","product":"ScadaBR",
 "name":"Cross-site Scripting Vulnerability","dateAdded":"2025-11-28","dueDate":"2025-12-19",
 "matched_assets":["openplc","scadabr"]}
```

### Agent tools (render as the inline trace when the agent works)
`kb_lookup(question)` · `read_alerts(since_minutes, detector, signal)` ·
`read_signal(signal, window_s)` · `explain_alert(detector, signal)` ·
`propose_guard_change(param, value, rationale)` → returns a validated diff for approval.

### Example agent explanations (for the chat / detail mockup)
> **L1:** The `cusum` detector is firing on **tank / pressure**. The frozen band is
> **[2693, 2702]** and the value is holding ~**2704 kPa** — above the mean but inside the
> band's tolerance, which the static band can't see but CUSUM (h_sigma=8) catches. Matches a
> **subtle in-band hold → ATT&CK T0831 (Manipulation of Control)**. Severity medium.

> **L3:** A **command** alert from **192.168.90.6** writing **coil 0** (`WRITE_SINGLE_COIL`).
> The only legitimate writer is the PLC (192.168.95.2); this is out-of-vocabulary. Writing
> coil 0 **engages MANUAL mode — disabling the control loops → ATT&CK T0858 (Change
> Operating Mode)**. Earliest signal of a takeover; investigate the source host.

## 10. Deliverable from the design chat
A high-fidelity mockup (or interactive HTML prototype wired to the sample data) of the
console — at minimum the **Live Operations Dashboard**, the **Alert Detail / Triage**
view (showing the cross-layer correlation), the **Agent Chat**, and the **Guard Change
Review** approval moment — in the dark control-room style above, populated with the real
sample data, organised around the four-layer model. Desktop-first.
