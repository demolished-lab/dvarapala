# Changelog

## 0.2.0 — 2026-08-25

Production-hardening release.

- **Chain-head anchoring.** Every append atomically updates a
  `<log>.head` sidecar; `verify()` now detects trailing truncation and
  tail rewrites (a bare hash chain cannot). `verify --strict` requires
  an anchor; `dvarapala anchor <log>` re-anchors after intentional pruning.
- **Corruption detection.** Torn/unreadable lines fail verification
  instead of being silently skipped.
- **Cross-process appends.** Advisory file locking (fcntl/msvcrt) plus
  tip re-scan inside the lock; multiple processes can share one audit log.
- **Durability mode.** `Gate(durable=True)` / `AuditLog(path, durable=True)`
  fsyncs every append.
- **Redaction.** `Gate(redact="secrets"|"strict"|None|names)` scrubs
  credentials (and optionally emails/cards) from args, results, and error
  text at the audit boundary. New `args` field on audit records (schema v2).
- **Per-tool rate limits.** `Gate(tool_rate_limits={"deploy_*": (3, 3600)})`.
- **Persistent consents.** `Gate(consent_store=path)` survives restarts
  for "always"; `clear_all_consents()` wipes the store.
- **Policy hot reload.** Policies loaded from files re-read on mtime change;
  broken edits keep the previous rules running.
- **MCP stdio proxy.** `dvarapala proxy -- node server.js` gates any MCP
  server without code changes: tools/call enforced, denied tools stripped
  from tools/list, JSON-RPC -32001 errors on block.
- **Hardened risk normalization.** `$IFS`/`${IFS}` expansion, whitespace
  collapse, leading env-assignment stripping, exact first-token reads;
  substring fragments no longer misfire ("confirm" no longer trips "rm ",
  "model" no longer trips "del ").
- New adversarial test suite: truncation, torn lines, two-process sharing,
  redaction leaks, policy-reload resilience, proxy filtering. 63 tests.

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
