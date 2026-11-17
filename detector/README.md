# detector/ — the frozen multi-detector physics IDS

`ids.py` (pure stdlib) learns a per-signal notion of normal once, **freezes** it, and
alerts on deviation. Device-nature-aware: steady signals get a static value **band +
CUSUM** (small sustained in-band bias); cycling signals get **variance-collapse** (stuck
valve) + **EMD** (1-D Wasserstein distribution shift). It never rebuilds the baseline from
live data.

```
python3 ids.py --freeze CLEAN.jsonl [--fstart TS --fend TS]   # learn + freeze -> baselines.json
python3 ids.py --replay SESSION.jsonl                          # score a recording
python3 ids.py --device-dir ~/catf-lab/device                 # live tail -> alerts.jsonl
```

`baselines.json` holds the global knobs (fire_sigma 3, window 150, cusum h_sigma 8,
varcollapse_ratio 0.30, emd_margin 1.3) plus the frozen per-signal stats. Frozen values are
regenerated per environment with `--freeze`; the committed copy is a reference.

Key design points (see ../docs/TECHNICAL_REPORT.md):
- CUSUM is **edge-triggered** (resets on fire) and **disabled on the integrating tank level**,
  whose within-band wander is normal.
- EMD fires above an **empirical clean ceiling** (robust to the skewed distance distribution),
  not a Gaussian mean+kσ threshold.
- The 150-sample window spans ≥2 cycles of the slowest cycling signal (fixes cycle/window
  aliasing that produced EMD false positives at window 60).
