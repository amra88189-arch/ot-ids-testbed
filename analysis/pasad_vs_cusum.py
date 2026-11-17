#!/usr/bin/env python3
"""PASAD vs CUSUM on one pressure series, fairly compared.

Input CSV: two columns `ts,pressure` (1 Hz). --attack-start is the epoch when the subtle
hold began (labels clean vs attack). Trains both detectors on clean-only, sets each
threshold from the clean-TRAIN max (so 0 train false alarms by construction), then reports
clean-test false positives, first-alarm latency, and detection rate on the attack -- an
apples-to-apples, false-positive-matched comparison.

  python3 pasad_vs_cusum.py --csv pressure.csv --attack-start 179xxxxxxx [--L 50 --r 3]
"""
import argparse, csv
import numpy as np

def load(path):
    ts, p = [], []
    for row in csv.reader(open(path)):
        try:
            ts.append(float(row[0])); p.append(float(row[1]))
        except Exception:
            continue
    return np.array(ts), np.array(p)

# ---- PASAD ----
def pasad_train(sig, L, r):
    K = len(sig) - L + 1
    X = np.column_stack([sig[i:i+L] for i in range(K)])      # L x K trajectory matrix
    U, S, _ = np.linalg.svd(X, full_matrices=False)
    Ur = U[:, :r]
    c = (Ur.T @ X).mean(axis=1)                               # centroid in the signal subspace
    return Ur, c, S

def pasad_score(sig, L, Ur, c):
    out = np.full(len(sig), np.nan)
    for i in range(len(sig) - L + 1):
        p = Ur.T @ sig[i:i+L]
        out[i+L-1] = np.sum((p - c) ** 2)                    # departure at the window's last sample
    return out

# ---- CUSUM (same form as the deployed IDS) ----
def cusum_score(sig, mean, k):
    chi = clo = 0.0; out = np.zeros(len(sig))
    for i, v in enumerate(sig):
        chi = max(0.0, chi + (v - mean) - k)
        clo = max(0.0, clo + (mean - v) - k)
        out[i] = max(chi, clo)
    return out

def metrics(score, thr, mask_clean_test, mask_attack, ts, attack_start):
    fp = int(np.nansum((score > thr) & mask_clean_test))
    hits = (score > thr) & mask_attack
    det_rate = float(np.nansum(hits)) / max(int(mask_attack.sum()), 1)
    lat = None
    idx = np.where(hits)[0]
    if len(idx):
        lat = float(ts[idx[0]] - attack_start)
    return fp, det_rate, lat

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--attack-start", type=float, required=True)
    ap.add_argument("--L", type=int, default=50)
    ap.add_argument("--r", type=int, default=3)
    ap.add_argument("--train-frac", type=float, default=0.7)   # of the clean region
    a = ap.parse_args()

    ts, p = load(a.csv)
    clean = ts < a.attack_start
    n_clean = int(clean.sum())
    split = int(n_clean * a.train_frac)
    train_idx = np.where(clean)[0][:split]
    ctest_idx = np.where(clean)[0][split:]
    mask_ctest = np.zeros(len(p), bool); mask_ctest[ctest_idx] = True
    mask_attack = ts >= a.attack_start
    print(f"samples {len(p)} | clean {n_clean} (train {len(train_idx)}, test {len(ctest_idx)}) "
          f"| attack {int(mask_attack.sum())}")
    print(f"pressure: mean {p[train_idx].mean():.2f} sd {p[train_idx].std():.3f} | "
          f"attack mean {p[mask_attack].mean():.2f}")

    # PASAD
    Ur, c, S = pasad_train(p[train_idx], a.L, a.r)
    print(f"PASAD L={a.L} r={a.r} | top singular values {np.round(S[:6],1)}")
    ps = pasad_score(p, a.L, Ur, c)
    thr_p = np.nanmax(ps[train_idx])                           # 0 train FP by construction
    fp_p, dr_p, lat_p = metrics(ps, thr_p, mask_ctest, mask_attack, ts, a.attack_start)

    # CUSUM (k=0.5 sd; threshold set the same way -- clean-train max -- for a fair match)
    mean = p[train_idx].mean(); sd = p[train_idx].std()
    cs = cusum_score(p, mean, 0.5 * sd)
    thr_c = cs[train_idx].max()
    fp_c, dr_c, lat_c = metrics(cs, thr_c, mask_ctest, mask_attack, ts, a.attack_start)
    # also the deployed CUSUM threshold h = 8 sd (edge-triggered not modelled here; raw sum)
    h8 = 8 * sd
    fp_c8, dr_c8, lat_c8 = metrics(cs, h8, mask_ctest, mask_attack, ts, a.attack_start)

    def row(name, fp, dr, lat):
        print(f"  {name:28s} clean-test FP {fp:3d} | detect {dr*100:5.1f}% | "
              f"first-alarm {('%.0f s' % lat) if lat is not None else 'never'}")
    print("\n=== fair comparison (thresholds = clean-train max, FP-matched) ===")
    row("PASAD (subspace)", fp_p, dr_p, lat_p)
    row("CUSUM (clean-train max)", fp_c, dr_c, lat_c)
    print("=== CUSUM at deployed h=8 sigma (reference) ===")
    row("CUSUM (h=8 sd)", fp_c8, dr_c8, lat_c8)

if __name__ == "__main__":
    main()
