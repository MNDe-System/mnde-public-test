import type { PolicyObject, RequestObject } from "../shared/types.ts";

export type PreflightInputEnvelope = {
  request: {
    job_id: string;
    user_id: string;
    region: string;
    resources: {
      gpu_type: string;
      gpu_count: number;
      hours: number;
    };
    pricing: {
      gpu_hour_usd: number;
    };
    execution: {
      auto_scale: boolean;
      max_scale_multiplier: number;
      retry_on_fail: boolean;
      max_retries: number;
    };
  };
  orbit: RequestObject["orbit_intent"];
  policy: PolicyObject;
  release: RequestObject["release_request"];
  runtime: Omit<RequestObject["runtime_request"], "observed_request_hash" | "observed_policy_hash">;
};

export type PreflightResult = {
  request_object: RequestObject;
  policy_object: PolicyObject;
  request_hash: string;
};
