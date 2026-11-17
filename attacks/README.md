# attacks/ — the subtle in-band manipulation

`subtle_hold.py` — an attacker regulator (runs on the Kali host). It writes Modbus **coil 0
to engage manual mode, reads it back to verify**, then PI-regulates the outlet setpoints to
**hold reactor pressure at a malicious target inside the IDS static band** (e.g. 2704 kPa).
Hard safety rails abort and restore auto if pressure leaves the envelope, so it cannot
degrade into a loud runaway. This is the attack behind the demonstrated band-0 / CUSUM-58
result and the PASAD comparison.

```bash
python3 subtle_hold.py 2704 300      # hold 2704 kPa for 300 s; undo with back_to_auto.py
```

The loud takeover, Modbus injection, and recon scripts come from the GRFICSv3 testbed /
Aaron Moorcroft's *OT Lab Command Centre* and are not redistributed here.
