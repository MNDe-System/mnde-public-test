// MNDe shell authorization policy — DENY BY DEFAULT.
//
// The point is not "we recognize every dangerous command." The point is the
// opposite: a command runs only if it is explicitly allowed. Anything unknown is
// not trusted — it is refused, not inspected. Sensitive-but-legitimate commands
// route to human approval. Known-destructive commands are refused with a clear
// reason. Everything else falls through to REFUSE / NOT_ALLOWLISTED.

import { createHash } from "node:crypto";
import { canonicalizeJson } from "../shared/json.ts";

export const SHELL_POLICY_ID = "shell-allowlist.v1";

// Programs that may run without approval (read-only / low blast radius).
const ALLOW = ["ls", "pwd", "whoami", "cat", "echo", "date", "df", "du", "uptime", "head", "tail", "env", "hostname", "id", "stat", "wc"];
// Sensitive but legitimate — require a human in the loop.
const APPROVAL = ["restart_service", "systemctl", "service", "deploy", "kubectl", "docker", "helm", "terraform"];
// Known-destructive — refuse with an explicit reason.
const DENY = ["rm", "dd", "mkfs", "shutdown", "reboot", "halt", "poweroff", "fdisk", "chown", "chmod"];

const POLICY = { policy_id: SHELL_POLICY_ID, allow: ALLOW, approval: APPROVAL, deny: DENY };

export function shellPolicyHash() {
  return createHash("sha256").update(canonicalizeJson(POLICY)).digest("hex");
}

function program(command) {
  return String(command ?? "").trim().split(/\s+/)[0] ?? "";
}

// Pure, deterministic. Returns one of:
//   ALLOW / OK_ALLOWLISTED
//   APPROVAL_REQUIRED / APPROVAL_REQUIRED
//   REFUSE / ERR_DENYLISTED
//   REFUSE / ERR_NOT_ALLOWLISTED   <-- the deny-by-default case
//   REFUSE / ERR_EMPTY_COMMAND
export function decideCommand(command) {
  const prog = program(command);
  if (prog === "") return { decision: "REFUSE", reason_code: "ERR_EMPTY_COMMAND" };
  if (DENY.includes(prog)) return { decision: "REFUSE", reason_code: "ERR_DENYLISTED" };
  if (ALLOW.includes(prog)) return { decision: "ALLOW", reason_code: "OK_ALLOWLISTED" };
  if (APPROVAL.includes(prog)) return { decision: "APPROVAL_REQUIRED", reason_code: "APPROVAL_REQUIRED" };
  return { decision: "REFUSE", reason_code: "ERR_NOT_ALLOWLISTED" };
}
