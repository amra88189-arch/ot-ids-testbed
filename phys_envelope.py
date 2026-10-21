#!/usr/bin/env python3
"""phys_envelope.py — device-nature-aware frozen-baseline physical anomaly signal.

Each plant device has a different normal *nature*, and the right anomaly signal
differs accordingly:

  STEADY   (tank pressure, feed flows, analyzer) sit near a fixed value. An
           attack/fault shows as a VALUE EXCURSION outside a tight frozen band.
  CYCLING  (purge / product valves and flows) swing across their whole range as
           normal operation, so a value band is meaningless. An attack/fault
           shows as the cycle STOPPING (variance collapse = a stuck/frozen valve)
           or the value leaving the cycle's own extremes.

The band is learned once from clean normal and FROZEN — it never adapts online,
so a slow sustained drift cannot be absorbed into "normal" (the failure mode a
drifting baseline has). Deviation is reported in units of the device's normal
spread, so it is comparable across devices and feeds fusion like phys_delta does.

This complements phys_delta (rate of change, good for transients); the envelope
is what catches a *sustained* off-normal hold that phys_delta blips past.
"""
import numpy as np, pandas as pd

ROLL = 10  # samples for the rolling-variance (stuck) estimate


class PhysEnvelope:
    def __init__(self, cv_cycle=0.3, q=0.005, fire_sigma=3.0, fire_stuck=0.7):
        self.cv_cycle = cv_cycle      # CV above this -> device nature is "cycling"
        self.q = q                    # band quantiles (q, 1-q)
        self.fire_sigma = fire_sigma  # steady / out-of-range fires beyond this many sigma
        self.fire_stuck = fire_stuck  # cycling fires when this fraction of its swing is lost
        self.dev = {}

    def fit_device(self, name, x, stuck_win=60):
        s = pd.to_numeric(pd.Series(x), errors="coerce").dropna()
        mean, std = s.mean(), s.std()
        cv = (std / abs(mean)) if abs(mean) > 1e-9 else (0.0 if std < 1e-9 else np.inf)
        nature = "cycling" if cv > self.cv_cycle else "steady"
        if nature == "steady":
            lo, hi = np.quantile(s, self.q), np.quantile(s, 1 - self.q)
            rs_med = 0.0; win = ROLL
        else:
            # a cycling device legitimately visits its extremes -> band at the true
            # min/max, and "stuck" is judged over a sustained window (one sample flat
            # at a turning point is not a frozen valve)
            lo, hi = np.quantile(s, 0.001), np.quantile(s, 0.999)
            win = stuck_win
            rs_med = float(s.rolling(win, min_periods=win // 2).std().median() or 0.0)
        self.dev[name] = dict(
            nature=nature, lo=float(lo), hi=float(hi),
            sd=float(max(std, 1e-6)),            # steady spread; floored for constants
            rs_med=rs_med, rs_floor=float(max(rs_med, 1e-6)), win=win, cv=float(cv))
        return self.dev[name]

    def deviation(self, name, x):
        """Nature-appropriate deviation score per sample (>=0; higher = more anomalous)."""
        d = self.dev[name]
        xs = pd.to_numeric(pd.Series(x), errors="coerce").ffill().fillna(0.0)
        below = (d["lo"] - xs).to_numpy() / d["sd"]
        above = (xs - d["hi"]).to_numpy() / d["sd"]
        out_of_band = np.maximum.reduce([np.zeros(len(xs)), below, above])  # sigma outside band
        if d["nature"] == "steady":
            return out_of_band
        # cycling: a SUSTAINED variance collapse (frozen valve) over the stuck window,
        # or the value beyond the cycle's own extremes
        rs = xs.rolling(d["win"], min_periods=max(2, d["win"] // 2)).std().fillna(d["rs_med"]).to_numpy()
        stuck = np.clip((d["rs_med"] - rs) / d["rs_floor"], 0.0, None)       # ~1 fully stuck
        stuck_sigma = stuck * self.fire_sigma / max(self.fire_stuck, 1e-6)   # fire_stuck frac -> fire_sigma
        return np.maximum(stuck_sigma, out_of_band)

    def fires(self, name, x):
        return self.deviation(name, x) >= self.fire_sigma

    # convenience: fit every device from a {name: normal_values} mapping
    def fit(self, normal_by_device):
        for name, x in normal_by_device.items():
            self.fit_device(name, x)
        return self


if __name__ == "__main__":
    import glob, os
    LAB = {"feed1": "f1_flow", "feed2": "f2_flow", "purge": "purge_flow",
           "product": "product_flow", "tank": "pressure", "analyzer": "A_in_purge"}
    env = PhysEnvelope()
    print(f"{'device':<9}{'nature':<9}{'CV':>8}{'band':>22}{'normal roll-std':>18}")
    for p in sorted(glob.glob(os.path.join(os.path.dirname(__file__), "csv_session", "IoT_*.csv"))):
        dev = os.path.basename(p).replace("IoT_", "").replace(".csv", "").lower()
        if dev not in LAB:
            continue
        df = pd.read_csv(p)
        df["label"] = df["label"].apply(lambda v: 0 if str(v).strip() in ("0", "normal", "Normal") else 1)
        d = env.fit_device(dev, df.loc[df.label == 0, LAB[dev]])
        band = "[%.2f, %.2f]" % (d["lo"], d["hi"])
        print(f"  {dev:<8}{d['nature']:<9}{d['cv']:>8.3f}{band:>22}{d['rs_med']:>18.3f}")
