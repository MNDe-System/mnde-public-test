// Live dispatch is disabled pending independent-backend deployment proof.
// No caller option, brand, transport, backend object, or environment flag enables it.
// Injectable dispatch exists only in tests/support/offline_freshness_adapter.mjs.
export const ATTEMPT = Object.freeze({ RESPONDED: "RESPONDED", UNKNOWN: "UNKNOWN", REFUSED_BEFORE_DISPATCH: "REFUSED_BEFORE_DISPATCH" });
export function createAdapter() {
  return Object.freeze({
    async attemptMerge() {
      return Object.freeze({ outcome: ATTEMPT.REFUSED_BEFORE_DISPATCH,
        error: "ERR_FRESHNESS_DEPLOYMENT_DISABLED", dispatched: false, request: null });
    },
    dispatchCount: 0
  });
}
