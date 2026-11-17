# analysis/ — offline evaluations

`pasad_vs_cusum.py` — a fair, false-positive-matched comparison of the CUSUM layer against
**PASAD** (singular-spectrum / subspace stealth detector) on a recorded pressure series.
Both train on clean-only; thresholds are set from the clean-train max; it reports clean
false positives, first-alarm latency, and detection rate.

```bash
python3 pasad_vs_cusum.py --csv pressure.csv --attack-start <epoch> --L 50 --r 3
```

Result on the subtle in-band hold: CUSUM matches the best PASAD config (r=1) at 93.3 %
detection / 11 s / 0 FP; PASAD's higher-dimensional subspaces are worse because a steady
pressure signal is ~1-dimensional. See ../docs/TECHNICAL_REPORT.md §2b-i.
