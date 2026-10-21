# Attack-session shot list (GRFICSv3)

The plan for one recording session. Matched-control design: every attack burst is
wrapped in normal, each class is repeated so it appears in both time-halves (valid
train/test split), and the plant holds one operating point throughout so normal is
a stable reference. Execution follows GRFICS's own exercise guides and Caldera's
abilities, inside the isolated VM — this file is the measurement plan, not attack
instructions.

## Environment (confirmed)

| Host | Zone | Address |
|------|------|---------|
| PLC (OpenPLC) | ICS | 192.168.95.2 |
| simulation + remote I/O | ICS | .45, devices .10–.15 |
| EWS (engineering workstation) | ICS | 192.168.95.5 |
| HMI (ScadaLTS) | DMZ | 192.168.90.107 |
| Kali (attacker) | DMZ | 192.168.90.6 |
| Caldera (emulation server) | DMZ | 192.168.90.250 |
| router / firewall | 3.5 | ICS .95.200 ↔ DMZ .90.200 |

Two attack origins, which matters for what each capture sees:
- **Kali / Caldera in the DMZ** → traffic into the plant crosses the router (router capture sees it).
- **EWS inside the ICS** → to the PLC it's seen by the PLC capture; **directly to a remote-I/O device it is seen by neither network tap** (intra-ICS, not via the router, not addressed to the PLC) — only the device and host streams catch it.

## Classes

| # | Class | Origin | Streams that should react | Nearest TON_IoT | Stealth | Capture |
|---|-------|--------|---------------------------|-----------------|---------|---------|
| 1 | Network reconnaissance / scan | Kali → ICS | network | scanning | loud | router |
| 2 | Unauthorised command / setpoint write | EWS → PLC | network + device | injection | medium | PLC (+router if via Kali) |
| 3 | Adversary-in-the-middle, HMI↔PLC | Kali/EWS | network + device | mitm | subtle | router + PLC |
| 4 | Denial of service on PLC or HMI | Kali → ICS/DMZ | network + host + device | dos | loud | router (+PLC) |
| 5 | PLC logic / program change | EWS → PLC | network + device | — (generalisation) | medium | PLC |
| 6 | Direct device write, bypassing PLC | EWS → remote I/O | **device + host only** | injection | subtle | **neither net tap** |
| 7 | Host resource-signature load | EWS / VM host | host | ransomware / mining | medium | host (atop) |
| 8 | Benign physical fault (noise floor) | fault dashboard | device | normal (benign) | n/a | device (self-labels) |

Diversity covered: loud (1,4) vs subtle (3,5,6); single-stream (1,7,8) vs multi-stream (2,3,4,5,6); with a TON_IoT equivalent (1–4) vs without (5,6); and the two "traps" — a host-only event (7) and a device-only *benign* event (8) that a good fused detector must tell apart from a real multi-stream attack.

Class 7 uses **benign load generators** (`stress-ng`, `dd` to a scratch file) that reproduce the resource *signatures* host detection keys on — no malware. Pair it with a benign heavy-load look-alike so we can measure whether the detector separates malicious-signature load from ordinary heavy load.

Class 8 is **self-labelling**: the fault dashboard writes `*_fault_mode` / `*_stuck` into the plant state the device poller already records, so its windows come straight from the device stream.

## Session timeline (≈5 h; trim to ~2 h for an anomaly-only first pass)

```
00:00  normal lead-in            45 min   (idle, all containers up — the container-inclusive normal)
--- pass A ---
00:45  pad 5 | scan 10 | pad 5                     class 1
01:05  pad 5 | command write 12 | pad 5            class 2
01:27  pad 5 | DoS 10 | pad 5                       class 4
01:47  pad 5 | PLC logic change 12 | pad 5          class 5
02:09  host-load burst 15 (+ benign look-alike 10)  class 7
--- pass B (same classes again -> both time-halves) ---
02:34  pad 5 | MITM 12 | pad 5                       class 3
02:56  pad 5 | direct device write 12 | pad 5        class 6
03:18  pad 5 | scan 10 | pad 5                       class 1 (repeat)
03:38  pad 5 | command write 12 | pad 5             class 2 (repeat)
04:00  pad 5 | DoS 10 | pad 5                        class 4 (repeat)
04:20  normal tail 20 min
```

Noise-floor (class 8) runs in the background during two of the normal pads, so it never overlaps an attack window (keeps "benign fault" cleanly separable from "attack").

For a **2 h first pass**: keep the 45 min lead-in, run one burst each of classes 1, 2, 4, 7, 8 (the ones with the clearest expected signatures), skip the repeats. Enough to score the anomaly and transfer stories; extend later only if the supervised phase needs more per-class volume.

## Labelling (automatic where possible)

Each class's window goes into `labels.csv` as `start_ts,end_ts,scenario_id,type,streams`:

- **Caldera-driven classes** → the operation report's per-step timestamps (the extractor reads the report JSON).
- **Class 8 (fault)** → the `*_fault_mode` / `*_stuck` fields in the device stream (self-labelling).
- **Manual Kali/EWS steps** → `mark.sh <class> start` / `mark.sh <class> stop` writes to `events.log`; the extractor reads it.

Guard band: the extractor trims a few seconds at each edge so records straddling a transition aren't mislabeled.

`streams` per class: 1=`n`, 2=`nd`, 3=`nd`, 4=`ndh`, 5=`nd`, 6=`dh`, 7=`h`, 8=`d`.

## Before and during the session

- Plant verified `ALIVE` immediately before, and again after (a frozen plant voids the run).
- Recorders + watchdog + health log running; **do not suspend the VM** (it corrupts the plant).
- One operating point held throughout; HMI only observed, not changed, except where a class explicitly drives it.
- Disk checked (session ≈1–2 GB of captures); Zeek trimmed to `conn.log` + `modbus.log` for the convert.
