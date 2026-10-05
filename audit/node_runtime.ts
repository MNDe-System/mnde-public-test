import { createHash } from "crypto";
import { readFileSync } from "fs";
import { performance } from "perf_hooks";
import {
  canonicalizeJson,
  hashCanonicalJson,
  REASON_CODES,
  type CanonicalExecutionInput,
  type JsonValue,
  type ExecutionResult,
  type SignedReceipt,
  type TypedFailure
} from "../shared/index.ts";
import { runStrictPreflight } from "../preflight/engine.ts";
import { runStrictOrbit } from "../orbit/engine.ts";
import { commitArmAllow, commitBudgetHold, defineBudgetToken, releaseBudgetHold, resetArmStores, resetTransientArmStores, runStrictArm } from "../arm/engine.ts";
import {
  buildReceipt,
  runStrictRamona,
  verifyReceiptReplay,
  verifyReceiptSignature,
  type ReceiptVerificationOptions
} from "../ram0na/engine.ts";
import { buildSidecarRefusalReceipt } from "../sidecar/refusal_receipt.mjs";

export type PipelineTimingKey =
  | "preflight_ms"
  | "orbit_ms"
  | "arm_ms"
  | "ramona_ms"
  | "canonicalize_ms"
  | "receipt_build_ms"
  | "signing_ms";

export type PipelineTimings = Partial<Record<PipelineTimingKey, number>>;
type PipelineOptions = { timings?: PipelineTimings; enforceExecutionId?: boolean };

function measure<T>(timings: PipelineTimings | undefined, key: PipelineTimingKey, fn: () => T): T {
  const started = performance.now();
  try {
    return fn();
  } finally {
    if (timings) {
      timings[key] = Math.max(0, Math.round(performance.now() - started));
    }
  }
}

function typedFailureFromReceipt(receipt: SignedReceipt): TypedFailure {
  return {
    decision: "REFUSE",
    request_hash: receipt.request_hash,
    decision_hash: receipt.decision_output.decision_hash,
    reason_code: receipt.decision_output.reason_code,
    parse_boundary: true
  };
}

export function executeDeterministicPipeline(rawInput: string, options: PipelineOptions = {}): ExecutionResult | TypedFailure {
  const timings = options.timings;
  const preflight = measure(timings, "preflight_ms", () => runStrictPreflight(rawInput));
  if ("parse_boundary" in preflight) {
    return preflight;
  }

  const preflightTrace = {
    layer: "preflight" as const,
    request_hash: preflight.request_hash,
    policy_hash: preflight.policy_hash,
    policy_version: preflight.parsed_input.policy_document.policy_version
  };
  const orbit = measure(timings, "orbit_ms", () => runStrictOrbit(preflight.parsed_input));
  const arm = measure(timings, "arm_ms", () => runStrictArm(preflight.parsed_input, orbit, preflight.request_hash, { enforceExecutionId: options.enforceExecutionId }));
  if (
    arm.decision === "REFUSE" &&
    (arm.reason_code === REASON_CODES.ExecutionIdAlreadyConsumed || arm.reason_code === REASON_CODES.ExecutionIdReplayed)
  ) {
    const receipt = buildSidecarRefusalReceipt({
      raw_body: rawInput,
      reason_code: arm.reason_code,
      policy_hash: preflight.policy_hash,
      policy_version: preflight.parsed_input.policy_document.policy_version,
      timings,
      request_id: arm.execution_id
    }) as SignedReceipt;
    return {
      receipt,
      receipt_bytes: measure(timings, "canonicalize_ms", () => canonicalizeJson(receipt as unknown as JsonValue))
    };
  }
  let receipt: SignedReceipt;
  try {
    const ramona = measure(timings, "ramona_ms", () => runStrictRamona(preflight.parsed_input, arm));
    receipt = measure(timings, "receipt_build_ms", () => buildReceipt({
      canonical_request: preflight.canonical_input,
      request_hash: preflight.request_hash,
      policy_hash: preflight.policy_hash,
      preflight: preflightTrace,
      orbit,
      arm,
      ramona,
      policy_version: preflight.parsed_input.policy_document.policy_version,
      timings
    }));
  } catch (error) {
    // A hold was placed iff ARM returned ALLOW carrying a budget_token. If Ramona
    // or receipt-build throws after that, release the hold before rethrowing so an
    // errored, never-finalized decision does not leak reserved capacity. Live mode
    // only; releaseBudgetHold is idempotent. (Previously a leaked hold was cleared
    // by the worker's per-task reset, which has been removed to let budget persist
    // across requests — see docs/budget-token-hold-lifecycle.md §4.)
    if (options.enforceExecutionId !== false && arm.decision === "ALLOW" && arm.budget_token !== undefined) {
      releaseBudgetHold(arm.budget_token, arm.execution_id);
    }
    throw error;
  }

  // Finalize authority state against the TRUE, post-Ramona decision. In replay
  // mode (enforceExecutionId === false) we mutate no live authority state at
  // all — neither the execution_id ledger nor the budget ledger — so a stored
  // receipt can be re-run without consuming anything.
  if (options.enforceExecutionId !== false) {
    const finalAllow = receipt.decision_output.decision === "ALLOW";
    if (finalAllow) {
      commitArmAllow(arm.execution_id, preflight.request_hash, receipt.decision_output.decision_hash);
    }
    // A budget hold exists iff ARM itself returned ALLOW carrying a budget_token
    // (hold() is ARM's final gate and only records capacity on success). Commit
    // it on a final ALLOW; release it on ANY final REFUSE — including a Ramona
    // refusal that overturned ARM's provisional ALLOW. That release is the fix
    // for the no-refund defect: budget is no longer charged for denied work.
    if (arm.decision === "ALLOW" && arm.budget_token !== undefined) {
      if (finalAllow) {
        commitBudgetHold(arm.budget_token, arm.execution_id);
      } else {
        releaseBudgetHold(arm.budget_token, arm.execution_id);
      }
    }
  }

  return {
    receipt,
    receipt_bytes: measure(timings, "canonicalize_ms", () => canonicalizeJson(receipt as unknown as JsonValue))
  };
}

export function verifySignedReceipt(receipt: SignedReceipt, options: ReceiptVerificationOptions = {}): boolean {
  return verifyReceiptSignature(receipt, options);
}

export function replayReceiptStore(receiptPath: string, options: ReceiptVerificationOptions = {}): {
  total: number;
  exact_matches: number;
  mismatches: Array<Record<string, string>>;
} {
  const source = readFileSync(receiptPath, "utf8").trim();
  const lines = source.length === 0 ? [] : source.split(/\r?\n/);
  const mismatches: Array<Record<string, string>> = [];
  let exactMatches = 0;

  for (const line of lines) {
    let parsed: SignedReceipt;
    try {
      parsed = JSON.parse(line) as SignedReceipt;
    } catch {
      mismatches.push({ request_hash: "unparseable_receipt", error: REASON_CODES.InvalidJsonSyntax });
      continue;
    }
    if (!verifySignedReceipt(parsed, options)) {
      mismatches.push({ request_hash: parsed.request_hash, error: REASON_CODES.ReceiptSignatureInvalid });
      continue;
    }

    resetRuntimeState();
    const rerun = executeDeterministicPipeline(parsed.canonical_request, { enforceExecutionId: false });
    if ("parse_boundary" in rerun) {
      mismatches.push({ request_hash: parsed.request_hash, error: rerun.reason_code });
      continue;
    }

    const replay = verifyReceiptReplay(parsed, rerun.receipt, options);
    if (!replay.ok) {
      mismatches.push({ request_hash: parsed.request_hash, error: replay.reason_code });
      continue;
    }
    exactMatches += 1;
  }

  return {
    total: lines.length,
    exact_matches: exactMatches,
    mismatches
  };
}

export function hashFileArtifact(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

// Replay/test isolation ONLY — clears budget accounting between independent
// deterministic runs. It MUST NOT run on the live per-request path (that would
// wipe committed budget and defeat the cap); see resetTransientArmStores and
// sidecar/deterministic_worker.mjs.
export function resetRuntimeState(): void {
  resetTransientArmStores();
}

export function seedBudgetToken(token: string, maxBudgetCents: number): void {
  defineBudgetToken(token, maxBudgetCents);
}

export function decisionHashForRawInput(rawInput: string): string {
  return hashCanonicalJson(JSON.parse(rawInput) as JsonValue);
}
