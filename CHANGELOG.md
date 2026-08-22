# Changelog

## 0.1.0 — 2026-08-23

Initial release (alpha).

- `Gate`: policy → risk → consent pipeline around any sync/async callable.
- Declarative JSON policies (`allow` / `warn` / `confirm` / `deny`),
  YAML supported with the `[yaml]` extra.
- Consent ladder: once / session / always, cached per tool.
- Heuristic risk assessment for commands, file writes, web fetches,
  and generic tool calls.
- Tamper-evident SHA-256 hash-chained audit log (JSONL) with causal
  fields (`run_id`, `step`, `parent_step`, `context_refs`,
  `alternatives_considered`, `state_delta`) captured from day one.
- `dvarapala.step()` context manager for run/step attribution.
- Pluggable confirmers: CLI prompt, AutoApprove, DenyAll, or your own.
- ASGI middleware for gating mutating HTTP requests.
- MCP helper decorator for gating tool handlers.
- CLI: `dvarapala verify <log>` / `dvarapala tail <log>`.
- Kill switch + sliding-window rate limiter.
