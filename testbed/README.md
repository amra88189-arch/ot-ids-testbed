# testbed/ — GRFICSv3 lab-side scripts (add from your VM)

The detector, agent, and network tooling in this repo run against a **GRFICSv3** Docker
testbed. The lab-side glue lives on the VM and is referenced here rather than committed, as
it is environment-specific. To complete the repo, copy from your lab:

- `device_poller.py`  — polls the PLC/plant and writes the device feed (`device_*.jsonl`)
- `plantcheck.py`     — plant-health check over the device stream
- `lab_boot.sh`       — boot orchestration: Docker up → restart sim/plc → start OpenPLC →
                        wait for live pressure → launch poller + IDS (+ optionally the
                        command detector and the console bridges)
- `catf-lab.service`  — systemd unit that runs `lab_boot.sh` on boot (reboot-survivable)

GRFICSv3: https://github.com/Fortiphyd/GRFICSv3
