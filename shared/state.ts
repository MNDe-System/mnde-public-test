export type ExecutionAuthorityState = {
  execution_id: string;
  status: "inflight" | "allowed";
  request_hash: string;
  decision_hash?: string;
};

// A budget token is a spending cap that authorizes MANY actions up to a limit
// (unlike an execution_id, which authorizes exactly one). Its accounting is
// therefore split into two independently tracked quantities:
//
//   consumed_cents  — money that has been COMMITTED to executions that reached
//                     a final ALLOW. This only ever grows, and it is the number
//                     that must survive across requests.
//
//   pending_holds   — capacity that is temporarily RESERVED for an in-flight
//                     decision that has passed ARM but has not yet received its
//                     final (post-Ramona) verdict. A hold is not yet a charge:
//                     it is committed into consumed_cents on final ALLOW, or
//                     discarded on final REFUSE.
//
// Available capacity at any instant is:
//     max_budget_cents - consumed_cents - sum(pending_holds)
// Holding against that sum (not just consumed_cents) is what stops two
// concurrent in-flight requests from each individually "fitting" under the cap
// yet together overspending it.
export type BudgetHold = {
  execution_id: string;
  amount_cents: number;
};

export type BudgetTokenState = {
  budget_token: string;
  max_budget_cents: number;
  consumed_cents: number;
  pending_holds: BudgetHold[];
};

export interface ExecutionAuthorityStore {
  begin(executionId: string, requestHash: string): "created" | "inflight_exists" | "allowed_exists";
  commitAllow(executionId: string, requestHash: string, decisionHash: string): void;
  snapshot(): ExecutionAuthorityState[];
  reset(): void;
}

export interface BudgetTokenStore {
  define(token: string, maxBudgetCents: number): void;
  // Phase 1 — reserve capacity for a decision that has passed ARM. Does NOT
  // charge the token yet. Keyed by execution_id so it can be finalized later.
  //   "held"          → capacity reserved, decision may proceed
  //   "exhausted"     → not enough remaining capacity (this is the REFUSE case)
  //   "unknown_token" → the token was never define()d (fail closed → REFUSE)
  hold(token: string, executionId: string, projectedCostCents: number): "held" | "exhausted" | "unknown_token";
  // Phase 2a — the decision reached a final ALLOW: convert the hold into a
  // permanent charge against consumed_cents.
  commit(token: string, executionId: string): void;
  // Phase 2b — the decision reached a final REFUSE (at ANY layer, including a
  // Ramona runtime-drift/kill-switch refusal that happens after ARM): discard
  // the hold so a denied execution never permanently consumes budget.
  release(token: string, executionId: string): void;
  snapshot(): BudgetTokenState[];
  reset(): void;
}

class InMemoryExecutionAuthorityStore implements ExecutionAuthorityStore {
  private readonly records = new Map<string, ExecutionAuthorityState>();

  begin(executionId: string, requestHash: string): "created" | "inflight_exists" | "allowed_exists" {
    const existing = this.records.get(executionId);
    if (!existing) {
      this.records.set(executionId, {
        execution_id: executionId,
        status: "inflight",
        request_hash: requestHash
      });
      return "created";
    }
    return existing.status === "allowed" ? "allowed_exists" : "inflight_exists";
  }

  commitAllow(executionId: string, requestHash: string, decisionHash: string): void {
    this.records.set(executionId, {
      execution_id: executionId,
      status: "allowed",
      request_hash: requestHash,
      decision_hash: decisionHash
    });
  }

  snapshot(): ExecutionAuthorityState[] {
    return [...this.records.values()];
  }

  reset(): void {
    this.records.clear();
  }
}

class InMemoryBudgetTokenStore implements BudgetTokenStore {
  private readonly records = new Map<string, BudgetTokenState>();

  define(token: string, maxBudgetCents: number): void {
    this.records.set(token, {
      budget_token: token,
      max_budget_cents: maxBudgetCents,
      consumed_cents: 0,
      pending_holds: []
    });
  }

  private outstanding(state: BudgetTokenState): number {
    return state.pending_holds.reduce((sum, h) => sum + h.amount_cents, 0);
  }

  hold(token: string, executionId: string, projectedCostCents: number): "held" | "exhausted" | "unknown_token" {
    const existing = this.records.get(token);
    if (!existing) {
      // A token that was never provisioned cannot fund anything. Fail closed.
      // (Historically reserve() collapsed this into "exhausted"; callers still
      // map both to a REFUSE, so no live behaviour changes — the distinct code
      // just makes the "token does not exist" case legible in logs and tests.)
      return "unknown_token";
    }
    // Idempotency: if this same execution_id already holds capacity (e.g. a
    // retried evaluation of the identical request), replace rather than stack
    // it, so a re-hold can never double-count against the cap.
    const priorForExecution = existing.pending_holds
      .filter((h) => h.execution_id === executionId)
      .reduce((sum, h) => sum + h.amount_cents, 0);
    const committedAndOtherHolds = existing.consumed_cents + this.outstanding(existing) - priorForExecution;
    if (committedAndOtherHolds + projectedCostCents > existing.max_budget_cents) {
      return "exhausted";
    }
    existing.pending_holds = existing.pending_holds.filter((h) => h.execution_id !== executionId);
    existing.pending_holds.push({ execution_id: executionId, amount_cents: projectedCostCents });
    this.records.set(token, existing);
    return "held";
  }

  commit(token: string, executionId: string): void {
    const existing = this.records.get(token);
    if (!existing) {
      return;
    }
    const hold = existing.pending_holds.find((h) => h.execution_id === executionId);
    if (!hold) {
      // Nothing was held for this execution (e.g. token-less request, or a
      // finalize that ran twice). Committing is a no-op — never charge a hold
      // that isn't there.
      return;
    }
    existing.consumed_cents += hold.amount_cents;
    existing.pending_holds = existing.pending_holds.filter((h) => h.execution_id !== executionId);
    this.records.set(token, existing);
  }

  release(token: string, executionId: string): void {
    const existing = this.records.get(token);
    if (!existing) {
      return;
    }
    // Drop the hold without touching consumed_cents. Safe to call even when no
    // hold exists, so finalize paths can release unconditionally.
    existing.pending_holds = existing.pending_holds.filter((h) => h.execution_id !== executionId);
    this.records.set(token, existing);
  }

  snapshot(): BudgetTokenState[] {
    return [...this.records.values()];
  }

  reset(): void {
    this.records.clear();
  }
}

export const executionAuthorityStore = new InMemoryExecutionAuthorityStore();
export const budgetTokenStore = new InMemoryBudgetTokenStore();
