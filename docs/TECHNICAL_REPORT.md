# CATF-IDS on a live OT testbed — consolidated findings

Evaluation of a multi-modal IDS (CATF-IDS) on a live GRFICSv3 testbed (a
Tennessee-Eastman-style chemical process with a soft PLC, remote-I/O field devices,
an operator HMI, a routed DMZ<->ICS network, and attacker hosts), across **two
independent attack sessions**:

- **Session A** — a self-run session: network scan, Modbus command-injection, host
  resource-load, and a benign noise-floor fault that drove a sustained process upset.
- **Session B** — attacks from an external open-source toolset (Aaron Moorcroft's
  *OT Lab Command Centre*, `CyberZombi3/ot-lab-command-centre`): reconnaissance,
  field-device injection, and a manual-mode takeover.

Both sessions were scored against the **same frozen baselines** — learn normal once,
freeze, alert on deviation. Session B required no retraining and no re-freeze; the
plant's normal was verified to match the frozen band before each run.

Results are reported in three epistemic tiers, kept strictly separate:
**demonstrated detection**, **demonstrated attribution**, and
**analytically identified** gaps that were *not* shown empirically.

---

## 1. Evaluation methodology — why the headline number is a mirage

The full nine-stage pipeline, trained and tested on the plant:

- **Random 5-fold CV: F1 0.996, ROC-AUC ~1.000, false-alarm rate 0.7%.**

That number does not survive contact with deployment. The CV is
`StratifiedKFold(shuffle=True)`; on a single continuous recording it shuffles time and
leaks near-duplicate rows across folds. Re-scored as a deployed detector sees data —
**train on the past, test strictly on the future**:

| split | aggregate F1 | scan recall | injection recall |
|---|---|---|---|
| random 60/40 (the CV regime) | 0.998 | 1.00 | **0.76** |
| temporal 60/40 (past -> future) | 0.899 | 1.00 | **0.00** |

The injection score was a shuffling artefact (0.76 -> 0.00). A supervised detector
catches attack *types it has seen* and misses *novel* ones; random CV hides that.
Everything below is therefore reported **temporally / frozen**, never on shuffled CV.

---

## 2. Detection-in-depth scorecard (both sessions)

Each layer carries an independent frozen baseline; nothing can vote another layer's
alarm down. Status tier in brackets.

| layer | attack | session | result | tier |
|---|---|---|---|---|
| network — flow | scan | A | AUC 0.98; frozen vs batch-fit 0.973 vs 0.154 (inverts) | demonstrated |
| network — command | Modbus injection | A | **10/10 flagged, 0 FP** of 4476 normal writes | demonstrated |
| network — command (LIVE) | manual-mode + setpoint writes | trial | **flagged live**, attributed to attacker IP; streams to the bus | demonstrated |
| network — source/asset | attacker on the bus | B | **41/41 flagged** (attacker is sole Modbus source) | demonstrated (unknown-source case) |
| device — physics | benign sustained drift (down to 1733 kPa) | A | **AUC 0.97**, 94% flagged, fires in 139 s | demonstrated |
| device — physics | manual-mode takeover (up to 3200 kPa) | B | **98% detected, 0% FP, AUC 0.995** | demonstrated |
| host | resource-load | A | AUC 0.999 | demonstrated |
| device — physics | subtle +6 kPa in-band hold (2704 kPa, 5 min) | trial | band 0, **CUSUM 58** — trend layer catches it | **demonstrated** (section 2b) |

The physics envelope catches a large excursion in **either direction** — the benign
fault *down* (AUC 0.97) and the attack *up* (AUC 0.995) — against the one frozen band.

---

---

## 2a. Multi-detector physics layer (v2) — demonstrated on real clean-normal + real takeover

The Session-A/B physics result above used a single static band on pressure. That band
is the right detector for a steady signal but is **blind on cycling signals** (valves
and flows that swing across their whole range in normal operation) and on **small
sustained within-band offsets**. Session B's takeover held the plant by *pinning*
cycling valves — exactly the case a single band misses. The v2 layer closes this by
selecting a detector per signal *nature*, every detector frozen once from real
clean-normal and never rebuilt from attack data.

**Taxonomy (device-nature-aware):**

| signal nature | detector | catches |
|---|---|---|
| steady (value) | **static band** | excursion out of the frozen range |
| steady (non-integrating) | **CUSUM** on residual | small *sustained* within-band bias |
| cycling | **variance-collapse** | signal pinned / stuck (variance drops) |
| cycling | **EMD** (1-D Wasserstein vs frozen quantiles) | distribution shift / bias in the cycle |

**Validation — frozen from the real pre-takeover window, replayed over the full
recording (3598 records, 12 signals):**

- **0 false positives** on the entire clean pre-takeover window (after tuning: CUSUM
  reset-on-fire + an opt-out on the integrating tank level, whose natural within-band
  wander is not an anomaly and is already covered by its band).
- Full attack coverage, each signal under the detector matched to its nature:

| detector | signals fired (during takeover) |
|---|---|
| band | liquid_level, pressure, feed-2 flow/valve, feed-1 flow/valve |
| cusum | pressure (sustained offset; 0 pre-takeover) |
| **varcollapse** | **product valve/flow, purge valve/flow** (pinned) |
| **emd** | **product valve/flow, purge valve/flow** (distribution shift) |

The four cycling signals — the pinned purge/product valves that were *how the takeover
held the plant* — are the strongest cycling detections in the set, and were entirely
invisible to the v1 single-band layer. Variance-collapse alone flagged the pinned
valves on **80–81 %** of the takeover-window samples with **0 %** false positives on
the pre-takeover normal.

**Epistemic scope (unchanged honesty):** the v2 suite is *demonstrated* to (i) not
false-alarm on real clean-normal and (ii) catch the real loud takeover across all
manipulated signals including the cycling ones. CUSUM's unique job — catching a
*subtle sustained within-band* bias — is validated on **synthetic** signals matched to
the lab's statistics (298/300 on a +9 kPa held offset), but on the *real* recording
CUSUM only fired on pressure's loud excursion (redundant with the band there). A real
subtle-attack demonstration with manual mode verifiably engaged is still pending
(section 5), so CUSUM is reported as **implemented and FP-clean on real data,
synthetic-validated for the subtle case, and now **real-data demonstrated** on a
controlled subtle attack (section 2b).

**Live-deployment hardening (and a second honest validation regime).** Deploying the
v2 layer on the live plant surfaced two failure modes a single historical replay hid,
both now fixed and the fixes themselves validated:

- *Cycle/window aliasing.* The product loop's cycle period (~60-70 s) equalled the
  original 60 s detection window, so a window could sit on one phase and look
  distribution-shifted. The window was widened to 150 s (~2-3 cycles). Purge is a fast
  ~4 s square wave and was never affected.
- *Non-stationary baseline + fragile threshold.* A short freeze window plus a Gaussian
  `mean+ksigma` EMD threshold produced false positives when the live operating point
  differed from the frozen one (e.g. a feed stream idle in one session and lightly
  active in another). Fixed by (i) refreshing each steady signal's band edges from the
  live clean range on every freeze, and (ii) replacing the Gaussian EMD threshold with
  an **empirical clean ceiling** (fire only above the max clean window-distance x a
  margin) - robust to the bounded, skewed distance distribution. CUSUM was also made
  edge-triggered (reset on fire) and disabled on the integrating tank level, whose
  within-band wander is normal.

After these fixes the detector was validated in two independent regimes: **live**
(0 alerts over 3 min of real running on the current plant, re-frozen from live
clean-normal) and **historical** (Nov-7 takeover replay: 0 pre-takeover, full coverage
of all manipulated signals). It is deployed as a permanent, reboot-surviving lab
service (systemd `catf-lab.service`): on boot it brings up the GRFICS stack, starts the
OpenPLC program, waits for live pressure, then launches the frozen detector on the
device feed.

---

## 2b. Subtle in-band attack — CUSUM catches what the static band cannot (demonstrated, real data)

The method's claimed strength is catching *slow / small* manipulations, not just loud
excursions. Session B's takeover slammed pressure ~200 sigma out of band (any threshold
catches that); this trial tests the hard case directly, on the live plant.

**Attack.** Reactor pressure is an integrator of (feed - outlet), so there is no
open-loop steady state — a held bias requires the attacker to run their own regulator.
A pymodbus script (`subtle_hold.py`, on the attacker host in Kali) wrote Modbus **coil 0
(manual_mode) = True and read it back True** — the verification the earlier attempts
lacked — then PI-regulated the purge/product outlet setpoints (holding registers 12/13)
to hold pressure at a malicious **2704 kPa** target: ~+6 kPa above the 2698 mean, above
the raw static band `[2693, 2702]` but **below where that band actually fires**
(hi + 3 sigma tol ~ 2709.4). Hard safety rails aborted on any excursion past the
envelope, so it could not degrade into the loud attack.

**Held cleanly for 5 minutes:** pressure 2699.0-2705.8 kPa, **300/300 samples inside
the static band**, settled to 2704.0 +/- 0.1.

**IDS verdict over the 5-minute window:**

| detector / signal | fired | reading |
|---|---|---|
| **band / pressure** | **0** | the static band is blind to the in-band bias (as designed) |
| **cusum / pressure** | **58** | the trend layer catches the sustained +6 kPa offset |
| varcollapse + emd / purge + product | 157-255 each | the pinned outlet valves (attacker had to hold the normally-cycling valves steady to regulate) |
| band / liquid_level | 212 | mass-balance side effect of throttling the outlets |

So the subtle attack was **invisible to pressure's static band but caught by
pressure's CUSUM** — the specific gap the trend layer was added to close, now shown on
real data with manual mode verified. It was additionally caught through three
independent paths (variance-collapse and distribution-shift on the pinned outlets, and
the tank-level band), so even with one detector blind, **detection-in-depth flags the
attack**. Honest scope: this is an attacker-maintained regulated hold (a continuous
manipulation), not a single stealthy write; and the ~6 kPa bias is bounded by how far
the band's tolerance reaches before the band itself fires.

## 2b-i. PASAD baseline for the subtle hold (CUSUM is not beaten)

The CUSUM layer was compared against **PASAD** (Aoudi et al., CCS 2018) -- the standard
process-aware stealthy-attack detector -- on the *same* recorded subtle-hold pressure
series, false-positive-matched (both trained on clean-only, thresholds set from the
clean-train max, so 0 clean-test false positives for both). Result:

| detector | clean-test FP | detection | first alarm |
|---|---|---|---|
| CUSUM (deployed h=8 sd) | 0 | 90.9% | 15 s |
| CUSUM (clean-max threshold) | 0 | 93.3% | 11 s |
| PASAD r=1 | 0 | 93.3% | 11 s |
| PASAD r=3 | 0 | 84.8% | 25 s |
| PASAD r=5 | 0 | 83.0% | 28 s |

CUSUM matches the best PASAD configuration (r=1) exactly and beats its higher-dimensional
ones. The reason is structural, not tuning: the pressure signal is effectively
one-dimensional (dominant singular value 3.67e5 vs ~148 for the rest) -- a steady level
plus noise -- so PASAD's subspace has no cyclic/correlation structure to exploit, and at
r=1 it reduces to tracking the level, which is what CUSUM does; extra dimensions fold in
noise and hurt. The attack is a sustained mean-shift, precisely CUSUM's design case.

Honest scope: **for a sustained in-band bias on a steady signal, a lightweight CUSUM
matches the standard stealth detector at equal false-alarm rate.** PASAD's documented
advantage manifests on cyclic/structured signals, which this bias does not exercise --
future work is the same comparison on a cycling-signal attack, where the variance-collapse/
EMD layer operates and PASAD should pull ahead.

---

## 2d. Per-layer detection latency (detection-in-depth, quantified)

On a single subtle-hold attack with all layers live, first-fire time relative to attack
onset: **L3 command +1.4 s** (the coil-0 write), **L1 CUSUM/pressure +14.3 s**, L2 EMD
+28.3 s, L1 band +69.3 s, L2 variance-collapse +111.3 s. So the network/command layer
detected the intrusion **~13 s before the fastest physics detector and 68-110 s before the
slower ones.** The ordering is fundamental, not incidental: the command layer observes the
*write itself* immediately, whereas the physics layers must wait for the physical *effect*
to accumulate -- pressure to drift, CUSUM to integrate the small bias, and the
variance-collapse window (150 samples) to fill with pinned data. This quantifies
detection-in-depth: the command layer is the earliest warning (maximising operator
response time and minimising physical risk), while the physics layers catch the consequence
and the attacks the command layer cannot see (section 2c). The attack is visibly observed
propagating down the stack over ~110 s, each layer flagging it at a different stage.

---

## 2c. Prevention vs detection, and layers catching different things (demonstrated)

Two complementary results on the command layer:

**Prevention (inline enforcement).** The frozen `(src,func,register)` vocabulary was put
inline as a Modbus command firewall (netfilter-queue in the PLC netns) that *drops* out-of-
vocabulary writes instead of only alerting. A fair red-team probe -- six **novel**
unauthorized writes to unused coils/registers, *distinct from the known attack*, plus
legitimate reads as controls -- gave: enforcement OFF **0/6 blocked, 3/3 reads pass**;
enforcement ON **6/6 blocked, 3/3 reads pass**, process undisturbed. Because the
vocabulary is frozen on clean-normal only (attack-blind) and the blocked writes were never
used to build it, this measures attack-agnostic enforcement, not memorisation of one
attack. (Honest scope: on this plant nothing legitimately writes to the PLC, so "block any
inbound write" is trivially safe here; a plant with operator setpoint writes must include
those in the fair test.)

**Detection catches what prevention cannot (the answer to "why keep the IDS if the
firewall blocks everything").** With the command firewall and sniffer running, a
**field-device bypass** attack wrote the purge valve's remote I/O directly
(192.168.95.12), a path that never traverses the PLC where the command layer taps.
Result over the 60 s attack: **command-layer alerts = 0** (it never saw the traffic),
**physics-layer alerts = 108** (band + CUSUM on pressure) -- the sustained field writes won
contention against the control loop and drove pressure to ~2805 kPa, caught purely by its
physical effect. So the two layers demonstrably catch *different* things: the physics
envelope catches the compromised-source / field-direct / fault cases that route around the
command layer. A nuance: it fired on *pressure*, not the purge valve (the PLC contested the
valve, so its variance never cleanly collapsed) -- the direct manipulation was contested,
its downstream consequence was not. Also corrects an earlier note: a *single* field write
is overwritten in <100 ms, but *sustained* writes (~50/s) do move the plant.

Framing: prevention stops what it can see at the command layer; detection catches what it
cannot -- a compromised legitimate source, a field-side write, or a physical fault -- and
records every attempt, blocked ones included. Run passive detection everywhere; add inline
enforcement where the safety case allows. The same frozen baseline feeds both.

---

## 3. The supervised fusion vs the frozen baselines — the thesis, twice

The supervised layer-model fusion catches what it was trained on and misses novel
attacks: injection recall **0.76 -> 0.00** under the temporal split (Session A), and
the manual-mode takeover (Session B) is an attack type it never saw. In both cases the
**frozen baselines caught what the supervised fusion could not** — the command
vocabulary on the injection, the physics envelope on the takeover. That is the core
detection-in-depth result, now demonstrated on two independent sessions.

The fusion is repositioned accordingly: the per-layer frozen envelopes are the
**floor** (each alarms on its own deviation, un-vetoable); the fusion is the
**ceiling** (it correlates across layers to prioritise and contextualise, not to
permit or deny).

---

## 4. Attribution — scope stated honestly

Session B's network result (attacker flagged 41/41) is the **unknown-source** case: a
host in the attacker zone speaking Modbus to the ICS at all. It is not the harder
**compromised-legitimate-source** case (an allowed IP issuing an abnormal command).
Function/register detail was unavailable for Session B (the on-VM extract produced no
`modbus_detail`, and the PLC tap recorded 0 Modbus packets). The richer command-
vocabulary result — normal `(src, func, register)` vocabulary vs. abnormal writes,
including the compromised-source case — is Session A's, not Session B's.

---

## 5. Limitations (unified, nothing hidden)

- **Single instance, one testbed, and it is a simulation.** No cross-instance
  generalisation; "live OT" means a live ICS *simulation*, not field hardware.
- **Random CV is optimistic** — reported only flagged as such, with temporal/frozen as
  the honest companion.
- **The strongest-looking score (AUC 0.995) is on an easy target** — the takeover
  slammed pressure ~200 sigma out of band; any threshold catches that. The method's
  claimed strength (subtle/slow attacks) is addressed separately and now demonstrated
  on the controlled +6 kPa in-band hold (section 2b), not left to analysis alone.
- **The subtle-attack test is now a demonstrated result (previously inconclusive).**
  Earlier attempts could not confirm manual mode was engaged. A controlled trial
  (section 2b) fixed that: coil 0 was written **and read back True**, and an attacker
  PI-regulator held reactor pressure at a malicious +6 kPa offset *inside* the static
  band for 5 minutes (300/300 samples in-band). Result: `band/pressure` fired **0**,
  `cusum/pressure` fired **58** — the trend layer caught the bias the static band is
  blind to. This is a demonstrated catch, not an analytical claim.
- **Benchmark transfer fails** — a TON_IoT-trained detector floods at the plant
  (FPR ~0.99); the negative control that motivates per-environment baselining.
- **Pipeline fragility** — repeated plant stalls on suspend/resume, a flaky shared
  folder, PLC-tap interface swaps, and Zeek/Modbus decode gaps affected what some
  captures could see; reproducibility is weak.

---

## 5a. Operator agent — a KB-grounded assistant, and what the KB is worth

**The LLM is never in the detection or control loop.** Detection is performed entirely by
the deterministic, frozen per-layer detectors (sections 2–2d); the agent only reads the
alerts they raise and explains them, and it is read-only on the plant and propose-only on
config. This separation is deliberate: a non-deterministic model (the LLM-judge below puts a
local 7B at ~45% factual reliability even when grounded) must never make the catch-or-miss
decision on a safety-critical process. The detectors catch; the agent narrates and proposes.

A retrieval-grounded, human-in-the-loop assistant over the frozen baselines, built to be
*deployable* rather than closed on the simulation: a local model (Qwen2.5-7B in Ollama,
fully air-gapped on the SOC-side host) plus a flat-file knowledge base. The KB holds the
frozen plant facts (bands, thresholds, AUCs), the rationale prose, the detections mapped
to **MITRE ATT&CK for ICS**, and a **live CISA KEV CVE feed** filtered to the plant's
assets (OpenPLC, Modbus). Five typed tools: `kb_lookup`, `read_alerts`, `read_signal`,
`explain_alert` (all read-only) and `propose_guard_change`. The agent never acts on the
plant and never edits config live — a guard change is emitted as a validated git diff for
a human, and is rejected if it crosses the immutable `hard_limits` (demonstrated: a CUSUM
threshold past 12 sigma is refused; disabling the command vocabulary is refused).

**The value question, measured.** Does the KB actually add knowledge, or is the model
already good enough? A 12-question A/B (same model, bare vs KB-grounded), scored on
whether the grounded fact appears:

| category | bare | KB | what it isolates |
|---|---|---|---|
| plant_fact (frozen bands, CUSUM h, window, netflow AUCs) | **0/4** | **4/4** | facts that exist only in our runs — unhallucinatable |
| rationale (why frozen / temporal / CUSUM) | 2/3 | 2/3 | depth vs generic ML advice |
| attack_ref (ATT&CK technique + mitigation IDs) | 2/3 | **3/3** | exact framework mapping |
| live_cve (currently-exploited OpenPLC/Modbus CVEs) | 1/2 | 1/2 | knowledge newer than the model |
| **overall** | **5/12** | **10/12** | |

The headline (5 -> 10) *understates* the gap, because the keyword scorer has two biases
that both flatter the bare model: it credits bare for hallucinated or generic "hits"
(e.g. bare "answered" the CVE question by telling the user to visit the CISA website; it
"answered" the temporal question by rambling about leakage) and penalises grounded KB
answers phrased without the exact token. On the one category that cannot be gamed —
plant_fact — it is **0/4 vs 4/4**. The decisive qualitative contrast: asked for an
actively-exploited OpenPLC CVE, the bare model waved at the CISA website; the KB-grounded
agent cited **CVE-2021-26829 (XSS in OpenPLC's ScadaBR), added to CISA KEV 2025-11-28** —
a real, dated, currently-exploited vulnerability the base model could not know.

**Live demonstration (the detect-and-explain loop, end to end).** With the frozen IDS
running live on the plant and the agent on the SOC-side host reading the alert bus across
the share, a stealth attack was run in real time (the `subtle_hold` regulator holding
pressure at 2704 kPa, in-band). Unprompted, the agent called `read_alerts` to pull the
live bus, then `explain_alert`, and produced a grounded diagnosis: it identified the
`cusum/pressure` detection, cited the frozen band [2693, 2702] and the configured
`h_sigma=8`, mapped it to ATT&CK **T0831/T0836 (Impair Process Control)**, recognised the
+6 kPa in-band-hold signature, and offered to propose a (human-approved) threshold change.
So the full operational loop was shown on real-time data: attacker manipulates the plant
in-band -> the frozen CUSUM layer detects it -> the KB-grounded agent reads the bus and
explains it in the language of real ICS defence, all local and air-gapped. (A 7B wording
imperfection was noted -- it blurred the CUSUM accumulator value with the pressure reading
-- though every fact it cited was correct.)

**Hardened metric (LLM-judge, the honest number).** The keyword scorer above over-credits
hallucinated and generic "hits", so the 20-question set was re-graded with a strict
LLM-judge (grading each answer against a gold fact, accepting paraphrases, rejecting
hallucinations and refusals). Results (bare -> KB-grounded):

| model | keyword (bare/kb) | LLM-judge (bare/kb) |
|---|---|---|
| 7B | 6/20 -> 12/20 | **0/20 -> 9/20** |
| 3B | 4/20 -> 10/20 | **1/20 -> 4/20** |

Three honest reads: (1) the bare model scores ~0 under the judge -- its keyword "hits" were
all hallucinations ("consult CISA") or generic hedging -- confirming these are facts it
cannot know, so grounding is decisive. (2) The keyword metric also *over*stated the KB
(7B 12->9, 3B 10->4): the model sometimes retrieves the wrong fact (quoting the liquid-level
band for the pressure question) or refuses ("the KB has no entry"), and token-matching
counted those. (3) Even grounded, a small local model is imperfect (7B 45%, 3B 20%),
failing via refusals, wrong-fact retrieval, and muddled synthesis -- and a 7B uses the KB
more than twice as effectively as a 3B. So grounding helps decisively but does not make a
small local model a reliable analyst; the earlier keyword "5/12 -> 10/12" should be read as
the optimistic metric, with this judge result as the honest companion.

**Honest findings about agentic RAG with a small local model (these are results too):**

- *Grounding discipline is fragile.* Out of the box the 7B answered ATT&CK questions from
  memory, inventing enterprise IDs (T1097, T1019) that are wrong for ICS. A hard
  "quote the retrieved fact, never substitute your own" system prompt fixed it — but
  over-corrected into occasionally refusing a partial match ("the KB has no entry"). The
  trade between hallucination and over-refusal is real and has to be tuned.
- *The KB must store the whole fact.* The model first returned the correct technique IDs
  but hallucinated their names (calling T0858 "Data Manipulation" rather than its true
  name, *Change Operating Mode*), because the KB stored IDs without names. Adding the
  names closed the gap. A partial fact invites a confident wrong completion.
- *Feed hygiene matters.* Naive substring filtering of the CVE feed matched short asset
  keywords inside unrelated words ("rtu" in "virtual"), producing 29 false CVEs including
  an SAP vulnerability the agent then cited. Whole-word matching cut it to the 2 genuinely
  relevant OpenPLC/Modbus KEV entries. A threat feed that is wrong is worse than empty.

The agent is therefore reported as a *demonstrated, deployable* layer with a *measured*
contribution (the KB roughly doubled factual accuracy and supplied live-CVE knowledge the
model cannot have), with the small-model grounding limitations stated plainly rather than
hidden.

## 6. Future work (identified, not validated)

- **CUSUM / slow-trend layer** — **implemented** in the v2 multi-detector physics layer
  (section 2a), FP-clean on real clean-normal, and now **demonstrated on a real subtle
  attack** (section 2b): it caught a +6 kPa in-band pressure hold the static band
  missed. This item is closed.
- **Matched repeat-capture** — each attack at two separate times, train one / test the
  other, for a real generalisation number.
- ~~A clean subtle-attack trial with manual-mode engagement verified~~ — **done**
  (section 2b): the blind region is exploitable and CUSUM catches it on real data.
- ~~The operator-assistant agent~~ — **built and measured** (section 5a): a local
  KB-grounded assistant; the KB roughly doubled factual accuracy (5/12 -> 10/12) and
  supplied live-CVE knowledge the model cannot have. Remaining work is tuning the
  grounding/over-refusal trade and wiring the full ATT&CK STIX + CSAF feeds.

---

## One-line summary

Across two independent sessions, frozen per-layer baselines demonstrably caught loud
and fast attacks that a supervised fusion missed — Modbus injection (10/10), a benign
drift *down* (AUC 0.97), and an attacker takeover *up* (AUC 0.995) — with clean
attacker-source attribution; the main remaining caveat is a single simulated instance.
The v2 multi-detector physics layer adds two demonstrated results of its own: frozen
from real clean-normal, it alarms on every manipulated signal of the real takeover —
including the pinned cycling valves a single static band was blind to — with zero false
positives on the clean window; and on a controlled subtle attack (manual mode verified
via coil-0 read-back), it held pressure at a +6 kPa in-band offset for 5 minutes that
the static band never flagged (0 alerts) while **CUSUM-on-pressure caught it (58)** —
closing the previously inconclusive subtle-attack gap on real data, with
detection-in-depth (pinned-valve and tank-level layers) flagging the same attack
through three other paths.
