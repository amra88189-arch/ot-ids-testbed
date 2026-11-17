#!/usr/bin/env python3
"""Fair red-team probe for the Modbus command firewall.

Fairness design: the firewall's vocabulary was frozen on clean-normal only (attack-blind).
To show it generalises and isn't tuned to the known subtle_hold attack, this probe sends
VARIED, NOVEL, physically-harmless unauthorized writes -- to UNUSED coils/registers that
are DIFFERENT from the subtle_hold targets (coil 0, regs 12/13) -- plus legitimate reads as
controls. Each op uses its own TCP connection so a blocked write can't head-of-line-block a
later read. Reports a confusion matrix.

Run from Kali, with the firewall OFF (baseline) then ON (enforced), and compare:
  python3 redteam_probe.py
"""
import sys
from pymodbus.client import ModbusTcpClient

PLC = "192.168.95.2"

# novel, out-of-vocabulary, harmless targets -- unused coils/registers, NOT the attack's
# (coil 0 / regs 12,13). Blocking these proves attack-agnostic enforcement, not memorisation.
UNAUTH_WRITES = [
    ("write_coil",      40,  True),
    ("write_coil",      50,  False),
    ("write_register",  200, 1234),
    ("write_register",  500, 4321),
    ("write_registers", 300, [1, 2, 3]),
    ("write_coil",      99,  True),
]
# legitimate reads -- must keep passing under enforcement (no collateral damage)
LEGIT_READS = [
    ("read_input_registers",   100, 10),
    ("read_holding_registers",   1, 4),
    ("read_coils",               0, 8),
]

def one(fn, reg, arg, is_write):
    """Fresh connection per op; return True if it SUCCEEDED (landed/passed)."""
    c = ModbusTcpClient(PLC, port=502, timeout=2)
    try:
        if not c.connect():
            return False
        if fn == "write_coil":          r = c.write_coil(reg, arg, slave=1)
        elif fn == "write_register":    r = c.write_register(reg, arg, slave=1)
        elif fn == "write_registers":   r = c.write_registers(reg, arg, slave=1)
        else:                           r = getattr(c, fn)(reg, count=arg, slave=1)
        return not r.isError()
    except Exception:
        return False
    finally:
        c.close()

def run():
    print("=== unauthorized writes (novel targets; expect BLOCKED when firewall ON) ===")
    wb = 0
    for fn, reg, val in UNAUTH_WRITES:
        landed = one(fn, reg, val, True)
        print(f"  {fn:16s} reg={reg:4d} -> {'landed' if landed else 'BLOCKED'}")
        wb += (0 if landed else 1)
    print(f"  unauthorized writes blocked: {wb}/{len(UNAUTH_WRITES)}")

    print("=== legitimate reads (controls; expect PASS in both modes) ===")
    rp = 0
    for fn, reg, cnt in LEGIT_READS:
        ok = one(fn, reg, cnt, False)
        print(f"  {fn:22s} reg={reg} -> {'pass' if ok else 'FALSE-BLOCK'}")
        rp += (1 if ok else 0)
    print(f"  legitimate reads passed: {rp}/{len(LEGIT_READS)}")

    print(f"\nSUMMARY  unauthorized-writes-blocked {wb}/{len(UNAUTH_WRITES)}  |  "
          f"legit-reads-passed {rp}/{len(LEGIT_READS)}")
    print("fair result = (OFF: 0 blocked, all reads pass) vs (ON: all blocked, all reads pass)")

if __name__ == "__main__":
    run()
