// Minimal test harness for Stage 2 offline units. Per-process counters.
import assert from "node:assert/strict";

let pass = 0, fail = 0;

export function test(name, fn) {
  try { fn(); pass += 1; console.log(`  [PASS] ${name}`); }
  catch (e) { fail += 1; console.log(`  [FAIL] ${name}: ${e.message}`); }
}
export async function atest(name, fn) {
  try { await fn(); pass += 1; console.log(`  [PASS] ${name}`); }
  catch (e) { fail += 1; console.log(`  [FAIL] ${name}: ${e.message}`); }
}
export function done(label) {
  console.log(`${label}: ${pass} pass, ${fail} fail`);
  if (fail > 0) process.exit(1);
}
export { assert };
