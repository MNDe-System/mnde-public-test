// Claim atomicity across BOTH uniqueness keys (namespace,exec) and (namespace,grant).
//
// Boundary audited: the ORIGINAL file backend claimed the two keys in two separate
// O_EXCL writes. A crash between them leaves one identity unclaimed and REUSABLE.
// These tests demonstrate the flaw on the unsafe backend and prove the crash-safe
// backend refuses reuse.
import { atest, done, assert } from "./_t.mjs";
import { createFileClaimBackend, createFileClaimBackendUnsafe, CLAIM } from "../src/claim_store.mjs";
import { tmpDir } from "./_tmp.mjs";

const NS = "mnde:atom";
const rec = (e, g) => ({ namespace: NS, execution_id: e, grant_id: g, subject: "s", executor_id: "x", receipt_hash: "h", aplus_digest: "d" });

await atest("REGRESSION: the non-atomic backend REUSES a grant after a partial claim (the bug)", async () => {
  const b = createFileClaimBackendUnsafe({ dir: tmpDir("atom-unsafe") });
  b.__simulateCrashAfterExec(rec("E1", "G"));      // exec written, grant write lost to a crash
  const r = await b.claim(rec("E2", "G"));         // different exec, SAME grant
  // Documents the defect: the grant was reusable because the claim was not atomic.
  assert.equal(r.status, CLAIM.CLAIMED, "non-atomic backend reuses the grant (this is the flaw being fixed)");
});

await atest("FIX: crash-safe backend refuses grant reuse after a post-commit crash", async () => {
  const b = createFileClaimBackend({ dir: tmpDir("atom-safe") });
  b.__simulateCrashAfterCommit(rec("E1", "G"));    // atomic commit written, index not (crash)
  const r = await b.claim(rec("E2", "G"));         // different exec, SAME grant
  assert.equal(r.status, CLAIM.ALREADY_SPENT, "reconcile heals the commit → grant is spent");
  assert.equal(r.collided_on, "grant_id");
});

await atest("FIX: crash-safe backend refuses exec reuse after a post-commit crash", async () => {
  const b = createFileClaimBackend({ dir: tmpDir("atom-safe-exec") });
  b.__simulateCrashAfterCommit(rec("EX", "GA"));
  const r = await b.claim(rec("EX", "GB"));        // SAME exec, different grant
  assert.equal(r.status, CLAIM.ALREADY_SPENT);
  assert.equal(r.collided_on, "execution_id");
});

await atest("FIX: same authority after a post-commit crash is spent (idempotent recovery)", async () => {
  const b = createFileClaimBackend({ dir: tmpDir("atom-safe-idem") });
  b.__simulateCrashAfterCommit(rec("E1", "G1"));
  assert.equal((await b.claim(rec("E1", "G1"))).status, CLAIM.ALREADY_SPENT);
});

await atest("FIX: independent uniqueness holds on the crash-safe backend", async () => {
  const b = createFileClaimBackend({ dir: tmpDir("atom-uniq") });
  assert.equal((await b.claim(rec("E1", "G1"))).status, CLAIM.CLAIMED);
  assert.equal((await b.claim(rec("E1", "G2"))).status, CLAIM.ALREADY_SPENT); // exec reuse blocked
  assert.equal((await b.claim(rec("E2", "G1"))).status, CLAIM.ALREADY_SPENT); // grant reuse blocked
  assert.equal((await b.claim(rec("E2", "G2"))).status, CLAIM.CLAIMED);
  assert.equal((await b.claim(rec("E3", null))).status, CLAIM.CLAIMED);       // null grant ok
  assert.equal((await b.claim(rec("E4", null))).status, CLAIM.CLAIMED);       // null grants don't collide
});

done("freshness-atomicity");
