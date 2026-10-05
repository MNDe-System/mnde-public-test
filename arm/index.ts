import { hashCanonicalJson } from "../shared/index.ts";
import type { RequestObject } from "../shared/types.ts";
import type { PolicyTrustResult } from "../policy/types.ts";
import type { OrbitValidationResult } from "../orbit/types.ts";
import type { ArmResult } from "./types.ts";

export function evaluateReleaseControl(
  requestObject: RequestObject,
  orbitResult: OrbitValidationResult,
  policyTrustResult: PolicyTrustResult,
  policyRules: {
    max_total_cost_usd: number;
    allow_auto_scale: boolean;
    max_gpu_count: number;
    max_hours: number;
    require_manual_approval_above_usd: number;
  }
): ArmResult {
  const reasons: string[] = [];

  if (orbitResult.decision !== "PASS") {
    reasons.push(`orbit validation failed with reason ${orbitResult.reason}`);
  }
  if (!policyTrustResult.trusted) {
    reasons.push("policy trust did not pass");
  }

  const baseCost = requestObject.resources.gpu_count * requestObject.resources.hours * requestObject.pricing.gpu_hour_usd;
  const scaleMultiplier = requestObject.execution.auto_scale ? requestObject.execution.max_scale_multiplier : 1;
  const scaledCost = baseCost * scaleMultiplier;
  const retryMultiplier = requestObject.execution.retry_on_fail ? requestObject.execution.max_retries + 1 : 1;
  const totalCost = scaledCost * retryMultiplier;

  if (requestObject.execution.auto_scale && !policyRules.allow_auto_scale) {
    reasons.push(
      `request.execution.auto_scale=${requestObject.execution.auto_scale} violates policy.allow_auto_scale=${policyRules.allow_auto_scale}`
    );
  }
  if (requestObject.resources.gpu_count > policyRules.max_gpu_count) {
    reasons.push(
      `request.resources.gpu_count=${requestObject.resources.gpu_count} exceeds policy.max_gpu_count=${policyRules.max_gpu_count}`
    );
  }
  if (requestObject.resources.hours > policyRules.max_hours) {
    reasons.push(
      `request.resources.hours=${requestObject.resources.hours} exceeds policy.max_hours=${policyRules.max_hours}`
    );
  }
  if (requestObject.execution.retry_on_fail) {
    reasons.push(
      `request.execution.retry_on_fail=${requestObject.execution.retry_on_fail} with max_retries=${requestObject.execution.max_retries} multiplies projected exposure by ${retryMultiplier}`
    );
  }
  if (totalCost > policyRules.max_total_cost_usd) {
    reasons.push(`projected_total_cost_usd=${totalCost} exceeds policy.max_total_cost_usd=${policyRules.max_total_cost_usd}`);
  }

  const preventedCost = Math.max(totalCost - policyRules.max_total_cost_usd, 0);
  const releaseHash = hashCanonicalJson({
    execution_id: requestObject.release_request.execution_id,
    hold_state: requestObject.release_request.hold_state,
    already_consumed: requestObject.release_request.already_consumed,
    one_shot_execution: true
  });

  if (requestObject.release_request.already_consumed) {
    reasons.push("release request is already consumed and cannot be executed again");
  }

  if (reasons.length > 0) {
    return {
      decision: "REFUSE",
      reasons,
      release_hash: releaseHash,
      projected_total_cost_usd: totalCost,
      allowed_cost_usd: policyRules.max_total_cost_usd,
      prevented_cost_usd: preventedCost
    };
  }

  if (
    totalCost > policyRules.require_manual_approval_above_usd &&
    requestObject.release_request.hold_state !== "APPROVED"
  ) {
    return {
      decision: "HOLD",
      reasons: [
        `projected_total_cost_usd=${totalCost} exceeds policy.require_manual_approval_above_usd=${policyRules.require_manual_approval_above_usd}`,
        `release.hold_state=${requestObject.release_request.hold_state} is not APPROVED`
      ],
      release_hash: releaseHash,
      projected_total_cost_usd: totalCost,
      allowed_cost_usd: policyRules.max_total_cost_usd,
      prevented_cost_usd: preventedCost
    };
  }

  return {
    decision: "ALLOW",
    reasons: [],
    release_hash: releaseHash,
    projected_total_cost_usd: totalCost,
    allowed_cost_usd: policyRules.max_total_cost_usd,
    prevented_cost_usd: preventedCost
  };
}
