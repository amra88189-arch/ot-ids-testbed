# CATF-IDS on a live OT testbed — findings

Evaluation of CATF-IDS on a real industrial-control testbed (GRFICSv3, a
Tennessee-Eastman-style chemical process) rather than only the TON_IoT corpus.
All numbers are from one recorded session on the testbed; code is under `lab/`.

## 1. Testbed and data

GRFICSv3 in Docker: a soft PLC (OpenPLC), a 3-D physics simulation with six
remote-I/O devices, a ScadaLTS HMI, a routed DMZ↔ICS network, Kali/Caldera
attackers. Three streams recorded on one clock and converted to CATF-IDS's
schema: **network** (Zeek conn+modbus over PLC and router taps), **device**
(physics engine, 6 devices, 1 Hz), **host** (atop). Attacks: network **scan**,
**Modbus command-injection**, **host resource-load**, and a benign **noise-floor
fault** that drove a **sustained process upset** (tank pressure 2697→1733 kPa
over ~35 min).

## 2. The whole system, end-to-end — and why the headline is a mirage

Running the complete nine-stage pipeline (config D, policy disabled — no site
policy in a bare testbed), trained and tested on the plant:

- **Random 5-fold CV: F1 0.996, ROC-AUC ~1.000, false-alarm rate 0.7%.**

That number does not survive contact with reality. The pipeline's CV is
`StratifiedKFold(shuffle=True)`; on a single continuous recording it shuffles
time and leaks near-duplicate rows across folds. Re-scored as a deployed
detector sees data — **train on the past, test strictly on the future**:

| split | aggregate F1 | scan recall | injection recall |
|---|---|---|---|
| random 60/40 (the CV regime) | 0.998 | 1.00 | **0.76** |
| temporal 60/40 (past→future) | 0.899 | 1.00 | **0.00** |

The scan detection is real (holds under temporal split — a scan is homogeneous).
**The injection score was a shuffling artefact: 0.76 → 0.00.** A supervised
detector catches attack *types it has seen* and misses *novel* ones; random CV
hides that. (This is specific to the single-recording plant eval; TON_IoT, a
heterogeneous corpus, tolerates random folds.)

**Implication:** report CV *flagged as optimistic*, a temporal number as the
honest companion, and get a **repeat-capture** (each attack at two separate
times) for a real generalisation claim — which is the paper's own matched-control
"both time-halves" design, not yet recorded.

## 3. The fix: a frozen, unsupervised baseline on every layer

Learn only *normal*, **freeze** it (never adapt online — a drifting baseline
absorbs a slow attack), alert on deviation per layer. Unsupervised ⇒ catches
attacks never trained on — exactly what the temporal test proved the supervised
fusion cannot.

**Network — flow baseline.** CATF's statistical layer fits its baseline on the
incoming batch ("proxy baseline"). When attacks dominate, the baseline *becomes*
the attack:

| network flow deviation (unsupervised) | AUC |
|---|---|
| baseline fit on batch (current) | **0.154** (inverts — ranks attacks as more normal than normal) |
| baseline frozen on clean normal (fix) | **0.973** |

Combined with the behavioural indicators (fan-out, port-entropy, fail-rate):
**AUC 0.978, scan flagged 1.000 unsupervised.**

**Network — command baseline (OT protocol semantics).** The flow baseline is
blind to the injection: an unauthorised Modbus write is protocol-valid, correct
size, normal destination — invisible on the wire. CATF inherits the TON_IoT
*flow* schema and discards the command. We extended the converter
(`modbus_detail.zeek` + `lab_convert.py`) to capture `mb_func` / `mb_reg` /
`mb_val`, then froze the **normal command vocabulary** from clean normal:

- normal write vocabulary = exactly `(PLC, WRITE_MULTIPLE_REGISTERS, register 1)`
- the injection `(Kali, WRITE_MULTIPLE_COILS, register 40, value T)` → **10/10 flagged, 0 false positives** (of 4,476 normal writes)
- the **compromised-source** case — the PLC *itself* writing coil 40 — is **also flagged**, because the *command* is out-of-vocabulary regardless of source. That is the compromised-HMI / French-supermarket class, caught.

**Device — physics baseline.** `phys_delta` (rate of change) is structurally
wrong for a *sustained* excursion — a slow drift has almost no rate of change, so
it ranks the upset below normal noise. A device-nature-aware frozen envelope
(value band for steady signals; variance-collapse / out-of-range for cycling
valves):

| device layer, on the real sustained drift | AUC | % of event flagged |
|---|---|---|
| phys_delta (rate of change) | 0.31 (below chance) | 0.2% |
| frozen operating envelope | **0.97** | 94% (fires in 139 s) |

Four of six device streams corroborate the one event (mean env_dev AUC 0.973 vs
phys_delta 0.399); feeds/analyzer correctly silent where the process held.

**Host — resource baseline.** A resource attack is a *host-level* event, but the
stream is per-process and window-labelled, so the supervised RF caps at 0.83.
Aggregating to per-sample host totals + a frozen band on disk-write (tail
corrected): **AUC 0.999** (heavy-tailed — threshold on a normal quantile, not σ).

## 4. The fusion, repositioned

Fusion did not get removed — it stopped being the **gate** and became the
**context**. The per-layer frozen envelopes are the **floor**: every layer alarms
on its own deviation and *nothing can vote that alarm down* (fixing the
net-weighted vote that suppressed single-stream attacks). The fusion is the
**ceiling**: it correlates across layers to *prioritise* (a corroborated
multi-stream alarm is urgent) and to *contextualise* (an uncorroborated benign
fault stays low priority) — not to permit or deny. Two kinds of corroboration
now exist: *supervised* fusion of layer probabilities (known attacks) and
*simultaneous envelope breach* across layers (novel attacks, no training).

## 5. Readiness by design — baseline + intent

You cannot safeguard every component individually. The direction is a
**statistical baseline for the whole system**, watched as one block: detect the
*deviation in behaviour*, not necessarily the named attack — and in OT that
baseline must include the **command semantics** (who may write which register),
because the dangerous commands are protocol-valid. The baseline is frozen against
*undeclared* change and moved only by **declared operator intent** (CATF already
has a basic intent hook: `parse_intent` / `apply_context`). The agent's real job
is turning *approved* intent into the enforced statistical ceilings and floors,
inside hard safety limits it can never widen past.

## 6. Limitations

- **Single-pass recording** → no generalisation numbers; needs the repeat-capture.
- **Host-load disjoint** (recorded after the session) → time-aligned into the fused run for the whole-system test; a session-concurrent host attack is the clean version.
- **Scan dominance** inflates aggregate metrics; read per-class.
- **Benchmark transfer fails** — a TON_IoT-trained detector floods at the plant (FPR ≈ 0.99); the negative control that motivates per-environment baselining.
- Host envelope rests on a small positive sample (18 windows).
