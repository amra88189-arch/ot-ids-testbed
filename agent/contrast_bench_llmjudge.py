#!/usr/bin/env python3
"""Hardened bare-vs-KB benchmark: LLM-judge scoring (+ legacy keyword, for contrast).

For a candidate model, generates bare and KB-grounded answers to every question, then an
LLM-JUDGE (a separate model, default qwen2.5:7b) grades each answer CORRECT/INCORRECT
against the question's `gold` fact -- accepting paraphrases, rejecting hallucinations and
refusals, which the keyword metric cannot. Also computes the legacy keyword score so the
two metrics can be compared (the keyword metric over-credits hallucinated/generic hits).

To avoid Ollama reloading models back-and-forth, it generates ALL answers first (candidate
loaded once), then grades ALL (judge loaded once).

  python contrast_bench_llmjudge.py --model qwen2.5:3b --judge qwen2.5:7b
  python contrast_bench_llmjudge.py --model qwen2.5:7b --judge qwen2.5:7b   # 7b self-judge (noted)
"""
import os, sys, json, time, argparse, urllib.request
try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")
import agent  # same dir -- reuse ask() for candidate answers

HERE = os.path.dirname(os.path.abspath(__file__))
OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434") + "/api/chat"

def keyword_hit(answer, tokens):
    a = (answer or "").lower()
    return any(t.lower() in a for t in tokens)

def judge(judge_model, q, gold, answer):
    prompt = (
        "You are grading an answer to an ICS security question against the known correct "
        "fact. Be strict but fair.\n\n"
        f"Question: {q}\nKnown correct fact: {gold}\nCandidate answer: {answer}\n\n"
        "Does the candidate answer correctly convey the known correct fact? A paraphrase "
        "that conveys the same fact is CORRECT. A wrong value, a hallucinated or different "
        "CVE/ID, a vague non-answer, or a refusal ('I don't know', 'check the website') is "
        "INCORRECT. Reply with exactly one word: CORRECT or INCORRECT.")
    payload = {"model": judge_model, "stream": False, "options": {"temperature": 0},
               "messages": [{"role": "user", "content": prompt}]}
    req = urllib.request.Request(OLLAMA, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            txt = json.load(r).get("message", {}).get("content", "").upper()
    except Exception as e:
        return None
    if "INCORRECT" in txt:
        return False
    if "CORRECT" in txt:
        return True
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5:7b", help="candidate model under test")
    ap.add_argument("--judge", default="qwen2.5:7b", help="grader model")
    a = ap.parse_args()
    qs = yaml.safe_load(open(os.path.join(HERE, "contrast_questions.yaml")))["questions"]
    agent.MODEL = a.model
    print(f"candidate {a.model} | judge {a.judge} | {len(qs)} questions")
    if a.model == a.judge:
        print("note: self-judging (same model grades its own answers) -- a known limitation")

    # ---- phase 1: generate all answers (candidate model loaded once) ----
    print("generating answers...")
    rows = []
    for i, item in enumerate(qs, 1):
        q = item["q"]
        bare = agent.ask(q, use_tools=False)
        kb = agent.ask(q, use_tools=True)
        rows.append({"id": item["id"], "cat": item["category"], "gold": item["gold"],
                     "expect": item["expect_any"], "q": q, "bare": bare, "kb": kb})
        print(f"  [{i}/{len(qs)}] {item['id']}")

    # ---- phase 2: judge all answers (judge model loaded once) ----
    print("judging...")
    for r in rows:
        r["bare_kw"] = keyword_hit(r["bare"], r["expect"])
        r["kb_kw"]   = keyword_hit(r["kb"],   r["expect"])
        r["bare_j"]  = judge(a.judge, r["q"], r["gold"], r["bare"])
        r["kb_j"]    = judge(a.judge, r["q"], r["gold"], r["kb"])

    # ---- tally: keyword vs judge, bare vs kb, per category ----
    cats = {}
    for r in rows:
        d = cats.setdefault(r["cat"], {"n": 0, "bkw": 0, "kkw": 0, "bj": 0, "kj": 0})
        d["n"] += 1
        d["bkw"] += bool(r["bare_kw"]); d["kkw"] += bool(r["kb_kw"])
        d["bj"]  += bool(r["bare_j"]);  d["kj"]  += bool(r["kb_j"])
    print("\n" + "=" * 78)
    print(f"{'category':14s}  {'KEYWORD bare/kb':>16s}   {'JUDGE bare/kb':>16s}")
    tot = {"n":0,"bkw":0,"kkw":0,"bj":0,"kj":0}
    for c, d in sorted(cats.items()):
        print(f"  {c:12s}  {d['bkw']:>6d}/{d['kkw']:<7d}      {d['bj']:>6d}/{d['kj']:<7d}   (n={d['n']})")
        for k in tot: tot[k] += d.get(k, d['n'] if k=='n' else 0)
    print("-" * 78)
    print(f"  {'OVERALL':12s}  {tot['bkw']:>6d}/{tot['kkw']:<7d}      {tot['bj']:>6d}/{tot['kj']:<7d}   (n={tot['n']})")
    print("\nKEYWORD = legacy token match (over-credits hallucinations); JUDGE = LLM graded vs gold.")

    out = os.path.join(HERE, f"contrast_results_{a.model.replace(':','_')}.json")
    json.dump({"model": a.model, "judge": a.judge, "overall": tot, "by_cat": cats,
               "rows": rows}, open(out, "w"), indent=2, default=str)
    print(f"saved {out}")

if __name__ == "__main__":
    main()
