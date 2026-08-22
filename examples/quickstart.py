"""Dvarapala in 30 seconds.

Run:  python examples/quickstart.py

Two tools. One policy. Every decision lands in a tamper-evident audit
log with causal context (which run, which step, what else was considered).
"""
import dvarapala

gate = dvarapala.Gate(
    policy={
        "rules": [
            {"id": "reads-free", "match": {"tool": "read_customer"},
             "effect": "allow"},
            {"id": "refunds-need-human", "match": {"tool": "refund"},
             "effect": "confirm",
             "message": "money leaves the company"},
        ]
    },
    audit=".dvara/audit.jsonl",     # SHA-256 hash-chained JSONL
    confirmer=dvarapala.AutoApprove("demo"),  # swap for CLIConfirmer() live
)


@gate(risk="critical")
def refund(customer_id: str, amount_cents: int, verified: bool = False):
    return f"refunded {amount_cents}c to {customer_id}"


@gate()
def read_customer(customer_id: str):
    return {"id": customer_id, "tier": "gold"}


# 1) Reads sail through (policy: allow)
print(read_customer("4821"))

# 2) The refund needs consent; the audit record captures WHERE the
#    decision happened and WHAT ELSE was considered.
try:
    with dvarapala.step(run_id="run_today_01", step_no=17,
                        context_refs=["ticket:991"],
                        alternatives_considered=["cancel_order"]):
        print(refund("4821", 5000))
except dvarapala.Denied as exc:
    print(f"DENIED: {exc}  (rule={exc.rule_id})")

# 3) Prove the log hasn't been touched.
ok, msg = gate.verify()
print(f"{msg}")
print(gate.tail(5)[-1].brief())
