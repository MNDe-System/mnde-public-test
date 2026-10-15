// The Hub's one source of time for request creation and expiry decisions.
//
// Production reads the server clock. Nothing a caller sends, and no environment
// variable, can change it. The test preload (tests/support/hub_observation_hooks.mjs)
// rewrites this module's source so a test can move Hub time without patching
// Date for the executor, the claim store or the HTTP stack.
export function now() {
  return Date.now();
}
