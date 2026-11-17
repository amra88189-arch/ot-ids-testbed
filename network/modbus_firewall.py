#!/usr/bin/env python3
"""Inline Modbus command firewall -- ENFORCE the frozen write vocabulary (not just alert).

Sits inline via a netfilter queue in the PLC's network namespace: every Modbus request to
port 502 is inspected; reads and in-vocabulary writes are ACCEPTED, any out-of-vocabulary
write is DROPPED before it reaches the PLC. This is the prevention counterpart to
modbus_sniff.py -- it stops the attack (e.g. the coil-0 manual-mode engage never lands),
not merely records it. Blocked writes are logged to the alert bus as action="blocked".

Run inside the PLC container's netns, as root (it installs + removes its own iptables rule):
  PID=$(docker inspect -f '{{.State.Pid}}' plc)
  sudo nsenter -t $PID -n python3 modbus_firewall.py \
       --vocab ~/catf-lab/live/command_vocab_frozen.json --alerts ~/catf-lab/alerts.jsonl

Deps: netfilterqueue (pip). Needs libnetfilter-queue + an iptables NFQUEUE target.
"""
import sys, os, json, time, socket, struct, argparse

WRITE_FUNCS = {5: "WRITE_SINGLE_COIL", 6: "WRITE_SINGLE_REGISTER",
               15: "WRITE_MULTIPLE_COILS", 16: "WRITE_MULTIPLE_REGISTERS"}

def parse_ip(data):
    """Parse an IP packet (as delivered by NFQUEUE) -> a Modbus WRITE dict, or None."""
    try:
        ihl = (data[0] & 0x0F) * 4
        if data[9] != 6:                       # TCP
            return None
        src = socket.inet_ntoa(data[12:16]); dst = socket.inet_ntoa(data[16:20])
        tcp = data[ihl:]
        if struct.unpack("!H", tcp[2:4])[0] != 502:
            return None
        doff = (tcp[12] >> 4) * 4
        mb = tcp[doff:]
        if len(mb) < 10:                       # no full Modbus write PDU (e.g. bare ACK)
            return None
        func = mb[7]
        if func not in WRITE_FUNCS:            # a read -> not our concern
            return None
        reg = struct.unpack("!H", mb[8:10])[0]
        return {"src": src, "dst": dst, "func": WRITE_FUNCS[func], "register": reg}
    except Exception:
        return None

def key(w):
    return f'{w["src"]}|{w["func"]}|{w["register"]}'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vocab", default=os.path.expanduser("~/catf-lab/live/command_vocab_frozen.json"))
    ap.add_argument("--alerts", default=os.path.expanduser("~/catf-lab/alerts.jsonl"))
    ap.add_argument("--queue", type=int, default=1)
    ap.add_argument("--chain", default="INPUT", help="iptables chain (INPUT for the PLC netns)")
    a = ap.parse_args()

    try:
        from netfilterqueue import NetfilterQueue
    except ImportError:
        sys.exit("need netfilterqueue: sudo apt-get install -y libnetfilter-queue-dev build-essential && "
                 "pip3 install netfilterqueue --break-system-packages")

    if not os.path.exists(a.vocab):
        sys.exit(f"no frozen vocabulary at {a.vocab} -- run modbus_sniff.py --learn first")
    allow = {f'{w["src"]}|{w["func"]}|{w["register"]}'
             for w in json.load(open(a.vocab))["authorized_writes"]}
    af = open(a.alerts, "a")
    rule = f"-p tcp --dport 502 -j NFQUEUE --queue-num {a.queue}"
    os.system(f"iptables -I {a.chain} {rule}")
    print(f"ENFORCING: {len(allow)} authorized write patterns; dropping all others on port 502")
    print("(Ctrl+C removes the rule and restores normal forwarding)")

    def cb(pkt):
        w = parse_ip(pkt.get_payload())
        if w is None or key(w) in allow:          # read, non-modbus, or authorized write
            pkt.accept()
        else:                                      # out-of-vocabulary write -> BLOCK
            pkt.drop()
            alert = dict(ts=round(time.time(), 2), det="command", device="plc",
                         src=w["src"], func=w["func"], register=w["register"],
                         action="blocked", sev="high")
            af.write(json.dumps(alert) + "\n"); af.flush()
            print(f"BLOCKED {w['src']} {w['func']} reg={w['register']}")

    nfq = NetfilterQueue()
    nfq.bind(a.queue, cb)
    try:
        nfq.run()
    except KeyboardInterrupt:
        pass
    finally:
        nfq.unbind()
        os.system(f"iptables -D {a.chain} {rule}")
        print("\nrule removed; forwarding restored")

if __name__ == "__main__":
    main()
