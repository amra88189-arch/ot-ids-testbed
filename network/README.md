# network/ — Layer 3 (command / network) and the live bridges

Pure-stdlib Modbus tooling, run inside the PLC's network namespace.

| file | role |
|---|---|
| `modbus_sniff.py` | passive detector: `--learn` freezes the normal `(src,func,register)` write vocabulary; `--detect` streams out-of-vocabulary writes to the alert bus (deduped); `--stats` inspects traffic |
| `modbus_firewall.py` | **inline enforcer** (netfilterqueue): drops out-of-vocabulary writes before the PLC — the prevention counterpart to the sniffer |
| `redteam_probe.py` | fair red-team: sends varied **novel** unauthorized writes + legitimate reads as controls, to measure attack-agnostic enforcement (not memorisation of one attack) |
| `field_takeover.py` | field-device **bypass** attack (writes the remote I/O directly) — demonstrates detection catching what the command firewall can't see |
| `state_bridge.py` | mirrors the plant's latest live values to a `state.json` snapshot for the console |

```bash
PID=$(docker inspect -f '{{.State.Pid}}' plc)
sudo nsenter -t $PID -n python3 modbus_sniff.py --learn 120    # during clean operation
sudo nsenter -t $PID -n python3 modbus_sniff.py --detect       # live detection
sudo nsenter -t $PID -n python3 modbus_firewall.py             # inline enforcement
```

Dep for the firewall only: `python3-netfilterqueue`. Everything else is stdlib.
