#!/usr/bin/env python3
"""Frozen Modbus command baseline — the OT-protocol detection layer.

Learns the normal (source, function, register) write vocabulary from clean-normal
traffic, freezes it, and flags any command outside it. Catches an unauthorised
write AND a legitimate source issuing an abnormal command — unsupervised, no
training on attacks. An unauthorised Modbus write is protocol-valid and invisible
to a bytes-and-packets baseline; reading the command semantics is what catches it.

Standalone (pandas only). Run on a Network_lab.csv produced by lab_convert.py with
the Modbus semantics columns (mb_func / mb_reg / mb_val).

  python3 net_command_baseline.py [csv_session/Network_lab.csv]
"""
import sys
import pandas as pd

path = sys.argv[1] if len(sys.argv) > 1 else "csv_session/Network_lab.csv"
n = pd.read_csv(path, low_memory=False)
n["label"] = n["label"].apply(lambda x: 0 if str(x).strip() in ("0", "normal", "Normal") else 1)

w = n[n["mb_func"].astype(str).str.contains("WRITE", na=False)].copy()
w["cmd"] = list(zip(w["src_ip"].astype(str), w["mb_func"].astype(str), w["mb_reg"].astype(str)))

vocab = set(w[w.label == 0]["cmd"])                       # frozen from clean normal only
print("normal write-command vocabulary (frozen):")
for c in sorted(vocab):
    print("   ", c)

w["flagged"] = ~w["cmd"].isin(vocab)
atk = w[w.label == 1]
fp = int(w[w.label == 0]["flagged"].sum())
print(f"\nattack-window writes flagged as out-of-vocabulary: {int(atk.flagged.sum())} / {len(atk)}")
print(f"false positives on {int((w.label == 0).sum())} normal writes: {fp}")
if atk.flagged.any():
    print("\nflagged commands (source · function · register · value):")
    print(atk[atk.flagged][["src_ip", "mb_func", "mb_reg", "mb_val"]].drop_duplicates().to_string(index=False))

# compromised-source test: a LEGITIMATE source issuing the attack command is still
# out-of-vocabulary, because the command itself is abnormal regardless of who sent it.
if atk.flagged.any():
    bad = atk[atk.flagged].iloc[0]
    for src in sorted(set(w[w.label == 0]["src_ip"].astype(str))):
        probe = (src, str(bad["mb_func"]), str(bad["mb_reg"]))
        print(f"\ncompromised-source test — {src} issuing {bad['mb_func']} reg {bad['mb_reg']}: "
              f"flagged = {probe not in vocab}")
