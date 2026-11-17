# agent/ — the KB-grounded operator agent and console

A local, air-gapped assistant (Qwen2.5 via Ollama) over a flat-file knowledge base. It is
**read-only on the plant and propose-only on config**.

| file | role |
|---|---|
| `agent.py` | the agent loop: 5 typed tools (`kb_lookup`, `read_alerts`, `read_signal`, `explain_alert`, `propose_guard_change`), robust to small-model tool-call quirks |
| `retriever.py` | hybrid KB retriever — exact lookup for numbers/relations, BM25 for prose; numbers are never embedded |
| `kb/` | the knowledge base: frozen `guards`/`hard_limits`, `device_profiles`, `attack_map`, rationale `prose/`, and `threat/` (ATT&CK-for-ICS links, live CVE feed via `refresh.py`, mitigations) |
| `serve_console.py` | stdlib backend: tails the bus, runs the agent with a tool-trace, validates guard proposals |
| `console.html` | single-page operator console (four layers, live PLC panel, agent chat, guard review) |
| `contrast_bench_llmjudge.py` + `contrast_questions.yaml` | the bare-vs-KB benchmark, LLM-judged (20 questions, gold answers) |

```bash
python agent.py "which ATT&CK technique is the Modbus injection?"   # KB-grounded, CLI
python serve_console.py --model qwen2.5:7b                           # console at http://localhost:8750
python kb/threat/refresh.py                                          # pull live CISA KEV into the feed
```

Guardrails: a proposed threshold change is validated against immutable `hard_limits.yaml`
(e.g. cusum h_sigma ∈ [4,12]); command-vocabulary enforcement and the frozen network
baseline can never be disabled. The agent emits a diff; a human approves.
