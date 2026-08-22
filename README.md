<p align="center"><strong>dvarapala</strong> — द्वारपाल, "the door guardian"</p>

# Dvarapala

**Permission gates + tamper-evident audit logs for AI agents and MCP servers. 3 lines to add.**

Agents execute tools, run commands, move money. When something goes wrong
you need to answer two questions: *should that have been allowed?* and
*exactly where did the run go wrong?* Dvarapala answers both — before
(gating) and after (audit) — with zero dependencies.

```python
import dvarapala

gate = dvarapala.Gate(policy="policy.json", audit="audit.jsonl")

@gate(risk="critical")
def refund(customer_id: str, amount_cents: int):
    ...  # nothing runs unless policy + consent approve; every decision is hash-chained
```

## Why

- **Gate (before):** declarative policy (`allow` / `warn` / `confirm` / `deny`),
  heuristic risk scoring, consent ladder (once / session / always), kill switch,
  rate limiter.
- **Audit (during → after):** append-only JSONL with a SHA-256 chain per record.
  Editing or deleting history breaks verification: `dvarapala verify audit.jsonl`.
- **Causal fields from day one:** every record carries `run_id`, `step`,
  `parent_step`, `context_refs`, `alternatives_considered`, `state_delta` — so
  "why did the agent do that?" attribution can be built on top without
  re-instrumenting anything.

## 30-second tour

```python
gate = dvarapala.Gate(
    policy={
        "rules": [
            {"id": "reads-free",   "match": {"tool": "read_*"}, "effect": "allow"},
            {"id": "refunds-human","match": {"tool": "refund"}, "effect": "confirm"},
            {"id": "no-drop",      "match": {"keywords": ["drop table"]}, "effect": "deny"},
        ]
    },
    audit=".dvara/audit.jsonl",
)
```

Annotate *where* a call happens in your agent loop:

```python
with dvarapala.step(run_id="r1", step_no=17,
                    alternatives_considered=["cancel_order"]):
    refund("c1", 5000)     # audited with step=17, alternatives recorded
```

Denied calls raise `dvarapala.Denied` (a `PermissionError`) — catch it and let
the model retry something else.

## Surfaces

| Surface | Import |
|---|---|
| Decorator for any sync/async function | `dvarapala.Gate` |
| ASGI middleware for HTTP tool endpoints | `from dvarapala.middleware import ASGIGateMiddleware` |
| MCP server tool handlers | `from dvarapala.mcp import gated_tool` |
| CLI | `dvarapala verify audit.jsonl` · `dvarapala tail -n 20 audit.jsonl` |

## Design rules

- **Stdlib-only core.** No dependencies; YAML policies are an optional extra.
- **Deny-safe defaults.** Non-interactive sessions deny instead of prompting;
  unknown shell commands assess as MEDIUM; destructive tokens as CRITICAL.
- **The log is evidence.** Chain verification is one command, no server needed.

## Status

v0.1.0 (alpha). The gate and audit core are stable; adapters and the
failure-attribution layer (`why did step 24 fail because of step 6?`) are on
the roadmap. MIT licensed. Contributions welcome.

## Install

```bash
pip install dvarapala          # core, stdlib-only
pip install dvarapala[yaml]    # + YAML policy support
pip install dvarapala[dev]     # + pytest/ruff
```

## License

MIT — see [LICENSE](LICENSE).
