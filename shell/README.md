# MNDe Shell Authorization (deny-by-default)

Deny-by-default authorization for shell / SSH / infra tools exposed over MCP.

A command runs only if it is explicitly allowed. Unknown commands are not inspected — they are refused. The aim is not to recognize every dangerous command; it is to refuse anything not on the allowlist.

```bash
npm run shell-demo     # the four cases below, each with a verifiable receipt
npm run test:shell     # policy + receipt tests (incl. tamper detection)
```

## Decisions

| Command | Decision | Why |
|---|---|---|
| `ls` | **ALLOW** | allowlisted, low blast radius |
| `restart_service nginx` | **APPROVAL_REQUIRED** | sensitive but legitimate — human in the loop |
| `rm -rf /` | **REFUSE** (`ERR_DENYLISTED`) | known-destructive |
| `some-weird-command-never-seen-before` | **REFUSE** (`ERR_NOT_ALLOWLISTED`) | **unknown → not trusted** |

The last row is the one a security team cares about. Not "did you catch `rm -rf`." **"What happens when you don't know?"** In this shell MCP path, the unknown command is refused before simulated execution.

## What it is

- [`policy.mjs`](./policy.mjs) — pure, deterministic deny-by-default policy (allow / approval / deny / not-allowlisted).
- [`receipt.mjs`](./receipt.mjs) — signs each decision into a `mnde.shell.receipt.v1` receipt using the **same Ed25519 authority chain** as every other MNDe receipt, and verifies it offline by replaying the policy and checking the signature against the trusted authority manifest. A tampered command or decision fails closed.
- [`../mcp/shell-mcp-server.mjs`](../mcp/shell-mcp-server.mjs) — an MCP `run_command` tool that gates every call through the policy. Execution is **simulated** (it never runs a real shell); a refused command leaves no trace, which the demo/tests verify across process boundaries.

## Note

The allow/approval/deny lists here are intentionally small and illustrative. The defensible claim is the **posture** (deny-by-default + verifiable receipts), not the completeness of the lists — a real deployment co-designs the allowlist with the operator. Matching against the program name is coarse on purpose; argument-level policy is a deliberate next step.
