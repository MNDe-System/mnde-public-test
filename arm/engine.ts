import { REASON_CODES, budgetTokenStore, executionAuthorityStore, type ArmTrace, type CanonicalExecutionInput, type OrbitTrace } from "../shared/index.ts";

function multiplyChecked(left: number, right: number): number | null {
  const result = left * right;
  if (!Number.isSafeInteger(result)) {
    return null;
  }
  return result;
}

function projectedCost(input: CanonicalExecutionInput): number | null {
  const execution = input.execution_request.execution;
  const resources = input.execution_request.resources;
  const base = multiplyChecked(resources.gpu_count, resources.hours);
  if (base === null) {
    return null;
  }
  const priced = multiplyChecked(base, input.pricing_data.gpu_hour_cents);
  if (priced === null) {
    return null;
  }
  const scaled = multiplyChecked(priced, execution.auto_scale ? execution.max_scale_multiplier : 1);
  if (scaled === null) {
    return null;
  }
  return multiplyChecked(scaled, execution.retry_on_fail ? execution.max_retries + 1 : 1);
}

export function resetArmStores(): void {
  executionAuthorityStore.reset();
  budgetTokenStore.reset();
}

// Clears ONLY the budget store (committed spend AND any pending holds). This is
// the reset for REPLAY AND TEST ISOLATION between independent deterministic
// runs, where the execution_id ledger must persist but budget accounting must
// start clean.
//
// MUST NOT be called on the live per-request path: doing so wipes committed
// budget between requests and defeats the token spending cap. The live worker
// (sidecar/deterministic_worker.mjs) therefore does not call it.
export function resetTransientArmStores(): void {
  budgetTokenStore.reset();
}

export function defineBudgetToken(token: string, maxBudgetCents: number): void {
  budgetTokenStore.define(token, maxBudgetCents);
}

// Finalizers for the budget hold placed by runStrictArm below. These are called
// by the pipeline AFTER the true, post-Ramona decision is known — never inside
// ARM, because ARM only produces an intermediate verdict that Ramona can still
// overturn. See docs/budget-token-hold-lifecycle.md for the full rationale.
export function commitBudgetHold(token: string, executionId: string): void {
  budgetTokenStore.commit(token, executionId);
}

export function releaseBudgetHold(token: string, executionId: string): void {
  budgetTokenStore.release(token, executionId);
}

export function runStrictArm(input: CanonicalExecutionInput, orbit: OrbitTrace, requestHash: string, options: { enforceExecutionId?: boolean } = {}): ArmTrace {
  const enforceExecutionId = options.enforceExecutionId !== false;
  const projected = projectedCost(input);
  if (projected === null) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.IntegerOverflow,
      projected_total_cost_cents: 0,
      allowed_cost_cents: 0,
      prevented_cost_cents: 0,
      execution_id: input.execution_request.release_request.execution_id,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }

  const allowedCost = Math.min(projected, input.policy_document.rules.max_total_cost_cents);
  const preventedCost = Math.max(projected - allowedCost, 0);
  const executionId = input.execution_request.release_request.execution_id;
  if (enforceExecutionId) {
    const beginStatus = executionAuthorityStore.begin(executionId, requestHash);
    if (beginStatus === "inflight_exists") {
      return {
        layer: "arm",
        decision: "REFUSE",
        reason_code: REASON_CODES.ExecutionIdAlreadyConsumed,
        projected_total_cost_cents: projected,
        allowed_cost_cents: allowedCost,
        prevented_cost_cents: preventedCost,
        execution_id: executionId,
        ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
      };
    }
    if (beginStatus === "allowed_exists") {
      return {
        layer: "arm",
        decision: "REFUSE",
        reason_code: REASON_CODES.ExecutionIdReplayed,
        projected_total_cost_cents: projected,
        allowed_cost_cents: allowedCost,
        prevented_cost_cents: preventedCost,
        execution_id: executionId,
        ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
      };
    }
  }

  if (orbit.decision === "REFUSE") {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: orbit.reason_code,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }

  if (input.execution_request.execution.auto_scale && !input.policy_document.rules.allow_auto_scale) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.AutoScaleDenied,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }
  if (input.execution_request.resources.gpu_count > input.policy_document.rules.max_gpu_count) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.GpuLimit,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }
  if (input.execution_request.resources.hours > input.policy_document.rules.max_hours) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.HoursLimit,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }
  if (input.execution_request.execution.max_retries > input.policy_document.rules.max_retry_count) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.RetryLimit,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }
  if (
    projected > input.policy_document.rules.require_manual_approval_above_cents &&
    input.execution_request.release_request.hold_state !== "APPROVED"
  ) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.ManualApprovalRequired,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }
  if (projected > input.policy_document.rules.max_total_cost_cents) {
    return {
      layer: "arm",
      decision: "REFUSE",
      reason_code: REASON_CODES.CostLimit,
      projected_total_cost_cents: projected,
      allowed_cost_cents: allowedCost,
      prevented_cost_cents: preventedCost,
      execution_id: executionId,
      ...(input.execution_request.budget_token === undefined ? {} : { budget_token: input.execution_request.budget_token })
    };
  }

  const budgetToken = input.execution_request.budget_token;
  if (budgetToken !== undefined) {
    // PLACE A HOLD, do not charge. ARM's ALLOW is only provisional — Ramona
    // still runs after this and can turn the final decision into a REFUSE
    // (kill switch, runtime drift). The hold is committed or released later by
    // the pipeline once that final decision exists (audit/node_runtime.ts).
    // Previously this called reserve(), which mutated consumed_cents here and
    // now — permanently charging budget for executions that Ramona then denied,
    // with no code path able to give it back. That was the no-refund defect.
    const budgetStatus = budgetTokenStore.hold(budgetToken, executionId, projected);
    if (budgetStatus !== "held") {
      // Both "exhausted" (over cap) and "unknown_token" (never provisioned)
      // are unfundable and map to the same caller-visible REFUSE, preserving
      // the pre-existing contract on ERR_BUDGET_TOKEN_EXHAUSTED. No hold was
      // recorded in either case, so there is nothing to release downstream.
      return {
        layer: "arm",
        decision: "REFUSE",
        reason_code: REASON_CODES.BudgetTokenExhausted,
        projected_total_cost_cents: projected,
        allowed_cost_cents: allowedCost,
        prevented_cost_cents: preventedCost,
        execution_id: executionId,
        budget_token: budgetToken
      };
    }
  }

  return {
    layer: "arm",
    decision: "ALLOW",
    reason_code: REASON_CODES.OkArm,
    projected_total_cost_cents: projected,
    allowed_cost_cents: allowedCost,
    prevented_cost_cents: preventedCost,
    execution_id: executionId,
    ...(budgetToken === undefined ? {} : { budget_token: budgetToken })
  };
}

export function commitArmAllow(executionId: string, requestHash: string, decisionHash: string): void {
  executionAuthorityStore.commitAllow(executionId, requestHash, decisionHash);
}
