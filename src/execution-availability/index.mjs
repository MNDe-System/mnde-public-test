// Execution availability — the single source of truth for whether MNDe may turn
// an authorization into a real-world effect.
//
// ─────────────────────────────────────────────────────────────────────────────
// THE DISTINCTION THIS MODULE EXISTS TO ENFORCE
//
//   ALLOW  means "policy approved this request."
//   ALLOW  does NOT mean "execution happened" or "execution is permitted now."
//
// Those are two different facts and they are produced by two different
// components. The sidecar decides policy and signs a receipt saying so. The
// executor is the only thing that can turn that receipt into an effect, and it
// is the enforcement point. A consumer holding a signed ALLOW receipt holds
// EVIDENCE OF A POLICY DECISION, not an execution grant.
// ─────────────────────────────────────────────────────────────────────────────
//
// Why execution is currently disabled: a verified receipt is a signature, and a
// signature can be presented twice. Nothing in the receipt makes it single-use,
// so after a crash, a restart, or a restore of executor-local files the same
// authentic ALLOW authorizes the same effect again (finding F-001). Closing that
// needs a durable single-use redemption in a store the executor operator cannot
// roll back. Until that is wired AND proven, every protected effect is refused.
//
// This is deliberately NOT a feature flag. There is no environment variable and
// no caller option that re-enables dispatch; re-enabling is a reviewed code
// change that also has to satisfy the freshness suite.

// Stamped into the signed receipt body when execution is unavailable. Chosen to
// match the existing conditional-field convention in buildPolicyReceipt
// (`approval_enforced`, `policy_bundle_provenance`): absent in the enabled case,
// so receipts issued once dispatch is live are byte-identical to historical ones
// and no conformance vector changes.
export const EXECUTION_STATUS_DISABLED = "DISABLED";

// Reason surfaced to an executor caller that asked for a protected effect.
// Deliberately the code the freshness suite already asserts, rather than a second
// name for the same condition.
export const ERR_EXECUTION_DISABLED = "ERR_FRESHNESS_DEPLOYMENT_DISABLED";

// The deployment-level fact. Hard-coded rather than read from config on purpose:
// see the note above about this not being a flag.
const DISPATCH_ENABLED = false;

// True only when MNDe may perform a protected effect. Everything that could
// cause a side effect must gate on this.
export function isDispatchEnabled() {
  return DISPATCH_ENABLED;
}

// The value for the receipt's `execution_status` field, or undefined when
// execution is enabled (so the field is omitted entirely).
export function receiptExecutionStatus() {
  return DISPATCH_ENABLED ? undefined : EXECUTION_STATUS_DISABLED;
}

// Unsigned response-level metadata, mirroring how ledger status is reported:
// alongside the receipt, never inside it. This is a convenience for operators
// and dashboards. It is NOT the authority — the signed `execution_status` field
// in the receipt body is, because an unsigned envelope field can be stripped in
// transit while a signed one cannot.
export function executionAvailabilityMeta() {
  return {
    dispatchable: DISPATCH_ENABLED,
    status: DISPATCH_ENABLED ? "ENABLED" : EXECUTION_STATUS_DISABLED,
    ...(DISPATCH_ENABLED ? {} : { reason_code: ERR_EXECUTION_DISABLED }),
    note: DISPATCH_ENABLED
      ? "Protected effects are enabled; the executor still enforces the strict execution gate."
      : "A decision receipt is evidence of a policy decision, not an execution grant. Protected effects are refused until durable single-use redemption is wired and proven."
  };
}
