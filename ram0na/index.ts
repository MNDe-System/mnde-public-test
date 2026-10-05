import { hashCanonicalJson } from "../shared/index.ts";
import type { RequestObject } from "../shared/types.ts";
import type { RamonaResult } from "./types.ts";

export function evaluateRuntimeRefusal(
  requestObject: RequestObject,
  requestHash: string,
  policyHash: string,
  projectedTotalCostUsd: number,
  maxTotalCostUsd: number
): RamonaResult {
  const reasons: string[] = [];
  const runtime = requestObject.runtime_request;

  if (runtime.kill_switch_active) {
    reasons.push("runtime kill switch is active");
  }
  if (runtime.observed_request_hash !== requestHash) {
    reasons.push(`runtime.observed_request_hash=${runtime.observed_request_hash} does not match request_hash=${requestHash}`);
  }
  if (runtime.observed_policy_hash !== policyHash) {
    reasons.push(`runtime.observed_policy_hash=${runtime.observed_policy_hash} does not match policy_hash=${policyHash}`);
  }
  if (runtime.actual_gpu_count > requestObject.resources.gpu_count) {
    reasons.push(
      `runtime.actual_gpu_count=${runtime.actual_gpu_count} exceeds requested gpu_count=${requestObject.resources.gpu_count}`
    );
  }
  if (runtime.actual_hours > requestObject.resources.hours) {
    reasons.push(`runtime.actual_hours=${runtime.actual_hours} exceeds requested hours=${requestObject.resources.hours}`);
  }
  if (runtime.actual_total_cost_usd > projectedTotalCostUsd) {
    reasons.push(
      `runtime.actual_total_cost_usd=${runtime.actual_total_cost_usd} exceeds projected_total_cost_usd=${projectedTotalCostUsd}`
    );
  }
  if (runtime.actual_total_cost_usd > maxTotalCostUsd) {
    reasons.push(
      `runtime.actual_total_cost_usd=${runtime.actual_total_cost_usd} exceeds policy.max_total_cost_usd=${maxTotalCostUsd}`
    );
  }

  const runtimeHash = hashCanonicalJson({
    kill_switch_active: runtime.kill_switch_active,
    observed_request_hash: runtime.observed_request_hash,
    observed_policy_hash: runtime.observed_policy_hash,
    actual_gpu_count: runtime.actual_gpu_count,
    actual_hours: runtime.actual_hours,
    actual_total_cost_usd: runtime.actual_total_cost_usd
  });

  return {
    decision: reasons.length === 0 ? "ALLOW" : "REFUSE",
    reasons,
    runtime_hash: runtimeHash
  };
}
