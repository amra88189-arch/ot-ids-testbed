#!/usr/bin/env python3
"""Multi-detector physics IDS over the live device feed (frozen baselines, stdlib).

  steady  signals -> static band (value) + CUSUM (slow sustained offset)
  cycling signals -> variance-collapse (stuck) + EMD (distribution shift)

  python3 ids.py --freeze CLEAN.jsonl       # learn + freeze normal stats
  python3 ids.py --replay FILE.jsonl        # score a recording
  python3 ids.py --device-dir ~/catf-lab/device   # live tail
"""
import sys, os, json, time, glob, argparse, math
from collections import deque, defaultdict

def measured(rec):
    d=rec.get("data",{}); out={}
    for v in d.values():
        if isinstance(v,dict): out.update({k:x for k,x in v.items() if isinstance(x,(int,float))})
    for k,x in d.items():
        if isinstance(x,(int,float)): out[k]=x
    return out
def pstd(xs):
    n=len(xs)
    if n<2: return 0.0
    m=sum(xs)/n; return math.sqrt(sum((v-m)**2 for v in xs)/n)
def q_of(sv, nq):
    n=len(sv)
    return [0.0]*(nq+1) if n==0 else [sv[min(n-1,int(round(q/nq*(n-1))))] for q in range(nq+1)]
def emd1d(win, ref_q, nq):
    wq=q_of(sorted(win), nq); return sum(abs(a-b) for a,b in zip(wq,ref_q))/(nq+1)
def records(path, lo=None, hi=None):
    paths=sorted(glob.glob(os.path.join(path,"device_*.jsonl"))) if os.path.isdir(path) else [path]
    for p in paths:
        for line in open(p, errors="ignore"):
            line=line.strip()
            if not line: continue
            try: r=json.loads(line)
            except Exception: continue
            t=r.get("ts")
            if lo is not None and (t is None or t<lo or t>hi): continue
            yield r

def do_freeze(clean, base, out, lo=None, hi=None):
    W=base["window"]; NQ=base["emd_nq"]; buf=defaultdict(list)
    for rec in records(clean, lo, hi):
        m=measured(rec)
        for name in base["signals"]:
            if name in m: buf[name].append(m[name])
    for name,s in base["signals"].items():
        xs=buf.get(name,[])
        if len(xs)<W: print(f"  warn {name}: {len(xs)} samples"); continue
        if s["nature"]=="steady":
            s["mean"]=round(sum(xs)/len(xs),4); s["sd"]=round(max(pstd(xs),1e-9),6)
            s["lo"]=round(min(xs),4); s["hi"]=round(max(xs),4)   # refresh band edges to live clean range
        else:
            rs=[pstd(xs[i-W:i]) for i in range(W,len(xs)+1)]
            s["norm_rollstd"]=round(sum(rs)/len(rs),4)
            ref=q_of(sorted(xs),NQ); s["ref_q"]=[round(v,4) for v in ref]
            em=[emd1d(xs[i-W:i],ref,NQ) for i in range(W,len(xs)+1)]
            s["emd_mean"]=round(sum(em)/len(em),4); s["emd_sd"]=round(max(pstd(em),1e-9),4)
            s["emd_hi"]=round(max(em),4)   # empirical clean ceiling (robust, non-Gaussian)
    json.dump(base, open(out,"w"), indent=2); print(f"froze {len(base['signals'])} signals -> {out}")

class Detector:
    def __init__(self, b):
        self.b=b; self.W=b["window"]; self.fs=b["fire_sigma"]; self.tf=b["steady_tol_frac"]
        self.ck=b["cusum"]["k_sigma"]; self.ch=b["cusum"]["h_sigma"]
        self.vr=b["varcollapse_ratio"]; self.ek=b["emd_k_sigma"]; self.nq=b["emd_nq"]; self.em=b.get("emd_margin",1.3)
        self.win=defaultdict(lambda: deque(maxlen=self.W)); self.chi=defaultdict(float); self.clo=defaultdict(float)
    def step(self, rec):
        ts=rec.get("ts"); m=measured(rec); out=[]
        for name,s in self.b["signals"].items():
            if s.get("alert") is False or name not in m: continue
            v=m[name]; self.win[name].append(v); dev=s["device"]
            if s["nature"]=="steady":
                lo,hi=s["lo"],s["hi"]; c=(lo+hi)/2; sd=(hi-lo)/4.66
                tol=self.fs*sd if sd>1e-6*max(abs(c),1) else self.tf*abs(c)
                if v>hi+tol or v<lo-tol:
                    z=(v-hi)/sd if (v>hi and sd>1e-9) else ((lo-v)/sd if sd>1e-9 else 99)
                    out.append(dict(ts=ts,det="band",device=dev,signal=name,value=round(v,2),z=round(z,1),sev="high" if abs(z)>10 else "med"))
                mean=s.get("mean",c); csd=s.get("sd",max(sd,1e-9))
                if s.get("cusum",True) is not False and csd>1e-6*max(abs(mean),1):   # skip CUSUM if signal opts out, or is effectively constant (band covers it)
                    k=self.ck*csd; h=self.ch*csd
                    self.chi[name]=max(0,self.chi[name]+(v-mean)-k); self.clo[name]=max(0,self.clo[name]+(mean-v)-k)
                    if self.chi[name]>h or self.clo[name]>h:
                        out.append(dict(ts=ts,det="cusum",device=dev,signal=name,value=round(v,2),cusum=round(max(self.chi[name],self.clo[name]),1),sev="med"))
                        self.chi[name]=0.0; self.clo[name]=0.0   # reset after signalling -> edge-triggered
            elif len(self.win[name])>=self.W:
                rs=pstd(self.win[name]); nr=s.get("norm_rollstd")
                if nr and rs<self.vr*nr:
                    out.append(dict(ts=ts,det="varcollapse",device=dev,signal=name,value=round(v,2),rollstd=round(rs,2),norm=round(nr,2),sev="high"))
                if s.get("ref_q"):
                    e=emd1d(self.win[name],s["ref_q"],self.nq)
                    thr=s["emd_hi"]*self.em if s.get("emd_hi") is not None else s.get("emd_mean",0)+self.ek*s.get("emd_sd",1e9)
                    if e>thr:
                        out.append(dict(ts=ts,det="emd",device=dev,signal=name,value=round(v,2),emd=round(e,2),sev="med"))
        return out

def show(a): print(f"ALERT [{a['det']:11s}] {a['device']}/{a['signal']}={a['value']} {a.get('z',a.get('cusum',a.get('rollstd',a.get('emd',''))))} [{a['sev']}]")
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--baselines", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),"baselines.json"))
    ap.add_argument("--device-dir", default=os.path.expanduser("~/catf-lab/device"))
    ap.add_argument("--alerts", default=os.path.expanduser("~/catf-lab/alerts.jsonl"))
    ap.add_argument("--freeze"); ap.add_argument("--replay"); ap.add_argument("--fstart",type=float); ap.add_argument("--fend",type=float)
    a=ap.parse_args(); base=json.load(open(a.baselines))
    if a.freeze: return do_freeze(a.freeze, base, a.baselines, a.fstart, a.fend)
    det=Detector(base); af=open(a.alerts,"a")
    print(f"IDS up: {len(base['signals'])} signals; detectors band/cusum/varcollapse/emd")
    if a.replay:
        from collections import Counter
        n=0; c=Counter()
        for rec in records(a.replay):
            n+=1
            for al in det.step(rec): af.write(json.dumps(al)+"\n"); c[al['det']]+=1
        print(f"replay: {n} records; alerts by detector: {dict(c)}"); return
    def latest(): fsx=sorted(glob.glob(os.path.join(a.device_dir,"device_*.jsonl"))); return fsx[-1] if fsx else None
    cur=latest();
    if not cur: sys.exit("no device feed")
    f=open(cur); f.seek(0,2); print(f"live on {os.path.basename(cur)}")
    while True:
        line=f.readline()
        if not line:
            nl=latest()
            if nl and nl!=cur: cur=nl; f=open(cur)
            time.sleep(0.5); continue
        line=line.strip()
        if not line: continue
        try: rec=json.loads(line)
        except Exception: continue
        for al in det.step(rec): af.write(json.dumps(al)+"\n"); af.flush(); show(al)
if __name__=="__main__": main()
