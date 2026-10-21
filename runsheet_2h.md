# Runsheet — 2 h first pass

Five classes, one burst each: the clearest signatures for scoring the anomaly and
transfer stories. Follow top to bottom. Every attack is bracketed with `mark.sh`
so its window lands in `labels.csv`; Caldera-driven steps also self-timestamp.
Execution of the offensive classes follows GRFICS's own exercise guides and
Caldera's interface — this sheet is the timing, the labelling and the benign steps.

`M() { bash /mnt/hgfs/CATF/lab/mark.sh "$1" "$2"; }`  ← paste once, then `M scan start` etc.

Keep the recorders, watchdog and health log running the whole time. Hold one plant
operating point (don't touch the HMI except where a class drives it). Run
`python3 ~/catf-lab/plantcheck.py 5` at each normal gap — if it ever prints NOT
HEALTHY, stop and tell me (a frozen plant voids the records from that point).

| # | slot | class | how to drive it | label | expect |
|---|------|-------|-----------------|-------|--------|
| 0 | 0–30 min | normal lead-in | nothing — just record | (none) | baseline, containers idle |
| 1 | +10 min | scan | Kali → ICS, or Caldera discovery ability | `M scan start` … `M scan stop` | network only; router capture |
| — | +5 min | normal gap | plantcheck | | |
| 2 | +12 min | command-write | from EWS or Caldera Modbus-write ability → PLC | `M command_write start` … `stop` | network **and** device (a valve moves, pressure/level shift) |
| — | +5 min | normal gap | plantcheck | | |
| 3 | +10 min | DoS | Kali → PLC/HMI, or Caldera DoS ability | `M dos start` … `M dos stop` | network + host + device (control disrupted) |
| — | +5 min | normal gap | plantcheck | | |
| 4 | +15 min | host-load (benign) | the two commands below, on the VM | `M hostload start` … `M hostload stop` | host only |
| 5 | during a gap | benign fault | the fault dashboard — self-labels, no mark needed | (auto) | device only |
| 6 | +10 min | normal tail | nothing — just record | (none) | closes the session |

## The two benign classes (explicit — these are safe to run as-is)

**Class 4, host-load** — reproduces the resource signatures host detection keys on,
with standard load tools, no malware. Run on the VM (install once):

```bash
sudo apt install -y stress-ng
bash /mnt/hgfs/CATF/lab/mark.sh hostload start
stress-ng --cpu 2 --vm 1 --vm-bytes 512M --hdd 1 --hdd-bytes 1G --timeout 900s
bash /mnt/hgfs/CATF/lab/mark.sh hostload stop
```

For the benign look-alike (ordinary heavy work, to test the detector separates it
from the "attack" load), a few minutes of a normal compile or a big file copy, with
`M benign_load start` / `stop` around it.

**Class 5, benign fault** — open the simulation's fault dashboard (the 3D view at
`http://localhost`, fault-injection panel) and trigger one sensor-noise or
sticky-valve fault for ~5 minutes, then clear it. No `mark.sh` needed: it writes
`*_fault_mode` / `*_stuck` into the plant state, and `make_labels.py` reads those
directly.

## The three attack classes

Drive each from Caldera (load the OT plugin, pick the ability group) **or** follow
the matching GRFICS exercise from its documentation, from Kali (DMZ) or the EWS
(ICS). Whatever the method, bracket it with `M <class> start` / `M <class> stop`
(Caldera also logs its own timestamps, which the extractor can read from the
operation report). Keep each burst to roughly the minutes in the table.

- **scan** — reconnaissance of the ICS from the DMZ. Should light up the network stream only.
- **command_write** — an unauthorised Modbus write to the PLC. Should show in the network stream *and*, a few seconds later, in the device stream as a valve/flow/pressure deviation. This is the cross-stream case.
- **dos** — flooding the PLC or HMI. Should show in the network stream, the host stream (resource strain), and the device stream (control disrupted).

## After the session

1. `python3 ~/catf-lab/plantcheck.py 5` — confirm still `ALIVE`.
2. Build labels (reads marks + fault fields; add `--caldera report.json` if you exported one):
   ```bash
   python3 /mnt/hgfs/CATF/lab/make_labels.py --lab ~/catf-lab --out /mnt/hgfs/CATF/lab/labels.csv \
     --start <SESSION_NORMAL_START epoch> --end $(date +%s)
   ```
3. Tell me — I'll check `labels.csv` against the runsheet, then we extract + convert with labels and move to Phase 2.
