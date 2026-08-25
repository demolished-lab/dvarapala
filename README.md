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
| MCP stdio proxy (any server, no code changes) | `dvarapala proxy -- <server command>` |
| CLI | `dvarapala verify audit.jsonl` · `dvarapala tail -n 20 audit.jsonl` · `dvarapala anchor audit.jsonl` |

## Design rules

- **Stdlib-only core.** No dependencies; YAML policies are an optional extra.
- **Deny-safe defaults.** Non-interactive sessions deny instead of prompting;
  unknown shell commands assess as MEDIUM; destructive tokens as CRITICAL.
- **The log is evidence.** Chain verification is one command, no server needed.

## Production hardening (v0.2)

| Threat | Defense |
|---|---|
| Trailing entries deleted | **Chain anchoring** — every append updates a `<log>.head` sidecar; `verify()` compares the tip. `verify --strict` fails without a matching anchor. |
| Log rewritten mid-history | SHA-256 chain breaks; the verifier names the first bad entry. |
| Crash mid-write / torn lines | Unreadable lines **fail verification** instead of being skipped. `Gate(durable=True)` fsyncs every append. |
| Two processes, one log | Advisory file locking (fcntl/msvcrt) + tip re-scan inside the lock — chains interleave correctly across processes. |
| Secrets in the evidence file | `Gate(redact="secrets")` (default) scrubs API keys, bearer tokens, and JWTs from args, results, and errors at the audit boundary; `"strict"` adds emails and Luhn-checked cards; `None` disables. |
| Runaway tools | Per-tool budgets: `tool_rate_limits={"deploy_*": (3, 3600)}` alongside the global rate limit. |
| Consent amnesia after restart | `Gate(consent_store="path.json")` persists "always" approvals; `clear_all_consents()` wipes it. |
| Policy edits require restarts | File policies hot-reload on mtime change; a broken edit keeps the last good rules running. |

```bash
dvarapala verify audit.jsonl          # chain integrity
dvarapala verify --strict audit.jsonl # chain + anchor present and matching
dvarapala anchor audit.jsonl          # re-anchor after intentional pruning
```

### MCP proxy: gate any server, zero code changes

```bash
dvarapala proxy --config policy.json --audit audit.jsonl -- node my-mcp-server.js
```

Point any MCP client at the proxy instead of the server:

- every `tools/call` runs the full pipeline (policy → risk → consent →
  audit); blocked calls get JSON-RPC `-32001` naming the rule that denied them;
- policy-denied tools are stripped from `tools/list`, so the agent never sees
  what it cannot call (`--no-hide-denied` to disable);
- everything else passes through untouched.

## EU AI Act / compliance mapping

Audit records are shaped for the traceability questions regulators ask
(EU AI Act Art. 12 record-keeping & integrity, Art. 14 oversight evidence,
ISO/IEC 42001 monitoring, SOC 2 CC7.2–CC7.3):

| Requirement | Where dvarapala provides it |
|---|---|
| Automatic event logging (Art. 12) | Every gate decision + execution outcome appended as structured JSONL |
| Integrity / tamper evidence (Art. 12) | SHA-256 chain + anchored head; one-command verification, CI-friendly exit codes |
| Traceability of decisions | Causal fields: `run_id`, `step`, `parent_step`, `context_refs`, `alternatives_considered` |
| Human-oversight evidence (Art. 14) | Confirm-gated actions record consent level + reason on every approval |
| Data minimization | Redaction at the audit boundary; argument snapshots truncated |

## Status

v0.2.0 (beta). Gate + anchored audit core are stable; the failure-attribution
layer on top of the causal fields (`why did step 24 fail because of step 6?`)
is on the roadmap. MIT licensed. Contributions welcome.

## Install

```bash
pip install dvarapala          # core, stdlib-only
pip install dvarapala[yaml]    # + YAML policy support
pip install dvarapala[dev]     # + pytest/ruff
```

## License

MIT — see [LICENSE](LICENSE).
