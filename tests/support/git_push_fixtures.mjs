// Fixtures for the git.push typed effect suite.
//
// Two things are hard to fake honestly, and neither is faked here: the git
// repositories are real repositories on disk pushed over `file://`, and the
// authorization is a real executor-bound mnde.signed-receipt.v2 envelope that
// goes through the production verifier. What IS substituted is the durable
// claim backend, and that substitution is the one limitation this suite has —
// see the note on inMemoryClaimBackend below.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createPrivateKey, sign as nodeSign } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { buildAuthorityBundle, generateAuthorityKeyPair, signCanonical } from "../../src/custody/index.mjs";
import { issueExecutorCredential } from "../../src/custody/executor-credential.mjs";
import { EXECUTOR_RECEIPT_CAPABILITY } from "../../src/custody/executor-identity.mjs";
import { LIVE_RECEIPT_SIGNING_MODES, signReceiptForDelivery } from "../../src/authority-signing/index.mjs";
import { buildPolicyReceipt } from "../../src/policy-engine/receipt.mjs";
import { canonicalRepositoryIdentity } from "../../src/effects/git-push/validate.mjs";
import { canonicalizeJson } from "../../shared/json.ts";
import { bootstrapReceiptKeys } from "../../scripts/bootstrap_dev_receipt_keys.mjs";

// buildPolicyReceipt signs with the repo-local demo keys before we replace that
// signature, so the keys have to exist. They are development material and never
// become the trust root of anything here: every inner receipt is re-signed.
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
bootstrapReceiptKeys({ repoRoot });

export const EXECUTOR_ID = "mnde:test:prod:executor:gitpush:01";
export const ENVIRONMENT_ID = "prod";
export const SUBJECT_ID = "mnde:test:subject:gitpush";

// A policy that allows exactly the one action under test.
export const GIT_PUSH_POLICY = Object.freeze({
  schema_version: "1.0",
  policy_id: "mnde-git-push-test-policy",
  version: "1",
  state: "ACTIVE",
  rules: [
    { rule_id: "allow-git-push", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "git.push" } }
  ]
});

// A real authority bundle written to a path that is not development key
// material, so production posture is satisfied by trust material of the shape a
// real deployment would use.
export async function productionTrust(dir, { authorityId = "mnde-git-push-test" } = {}) {
  const root = { keyId: "git-push-test-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "git-push-test-receipt", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId,
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    ledgerKeys: [], policyKeys: [], approvalKeys: [], revocation: []
  });
  const bundlePath = join(dir, `published-authority-bundle-${authorityId}.json`);
  writeFileSync(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");

  // The default executor identity, minted once so the same executor both signs
  // the authorization envelope and signs the execution evidence. Hoisting it
  // here is what lets a test verify that the evidence came from the executor
  // the authorization was bound to, rather than from some other holder of a
  // valid credential.
  const executor = await mintExecutor(bundle, root, EXECUTOR_ID, ENVIRONMENT_ID);

  return { bundle, bundlePath, fingerprint: bundle.root_key.fingerprint, root, receipt, authorityId, executor };
}

// An executor key pair plus the root-signed credential that carries its public
// key, and a signer that keeps the private key to itself.
async function mintExecutor(bundle, root, executorId, environmentId, now = "2026-06-14T00:00:00.000Z") {
  const keys = generateAuthorityKeyPair();
  const credential = await issueExecutorCredential({
    authorityBundle: bundle,
    rootPrivatePem: root.privatePem,
    executorId,
    publicPem: keys.publicPem,
    environmentId,
    capabilities: [EXECUTOR_RECEIPT_CAPABILITY],
    issuedAt: now,
    notBefore: "2026-01-01T00:00:00.000Z",
    expiresAt: "2099-01-01T00:00:00.000Z"
  });
  return {
    keys,
    credential,
    identity: {
      executor_id: executorId,
      key_id: credential.key_id,
      credential_id: credential.credential_id,
      environment_id: environmentId,
      credential
    },
    signer: {
      sign: async (body) =>
        nodeSign(null, Buffer.from(body, "utf8"), createPrivateKey(keys.privatePem)).toString("hex")
    }
  };
}

// Re-sign a policy-engine receipt with the production authority.
//
// buildPolicyReceipt signs with the repo-local demo keys, which is exactly the
// trust source execution authority refuses. Replacing the signature makes the
// INNER decision verify against the configured bundle, so the envelope is
// production-trusted at both layers rather than only at the outer one.
function reSignInnerReceipt(receipt, trust) {
  const { verifiable_signature: _drop, ...payload } = receipt;
  const canonical = canonicalizeJson(payload);
  const value = nodeSign(null, Buffer.from(canonical, "utf8"), createPrivateKey(trust.receipt.privatePem)).toString("hex");
  return {
    ...payload,
    verifiable_signature: {
      ...receipt.verifiable_signature,
      authority_id: trust.bundle.authority_id,
      key_id: trust.receipt.keyId,
      public_key_fingerprint: trust.bundle.keys.receipt[0].fingerprint,
      value
    }
  };
}

// Mint an executor-bound authorization for one git.push.
export async function gitPushAuthorization(trust, parameters, {
  executionId = `exec-${Math.random().toString(16).slice(2)}`,
  grantId = `grant-${Math.random().toString(16).slice(2)}`,
  executorId = EXECUTOR_ID,
  environmentId = ENVIRONMENT_ID,
  subject = SUBJECT_ID,
  action = "git.push",
  now = "2026-06-14T00:00:00.000Z",
  repoLocalInner = false
} = {}) {
  // Reuse the trust's default executor when this authorization is for it, so
  // the authorization and any later execution evidence share one identity. A
  // test asking for a different executor gets a freshly minted one.
  const acting =
    executorId === trust.executor.identity.executor_id && environmentId === trust.executor.identity.environment_id
      ? trust.executor
      : await mintExecutor(trust.bundle, trust.root, executorId, environmentId, now);
  const executorKeys = acting.keys;
  const credential = acting.credential;

  const provider = {
    mode: "file-backed-production",
    production: true,
    trustedRootFingerprint: trust.fingerprint,
    signReceipt: async (payload) => ({
      key_id: trust.receipt.keyId,
      value: await signCanonical(payload, trust.receipt.privatePem),
      fingerprint: trust.bundle.keys.receipt[0].fingerprint
    }),
    signPolicy: () => { throw new Error("n/a"); },
    signApproval: () => { throw new Error("n/a"); },
    getPublicBundle: () => structuredClone(trust.bundle)
  };

  const request = {
    schema_version: "1.0",
    request_id: executionId,
    grant_id: grantId,
    timestamp: now,
    principal: { id: subject },
    agent: { id: "mnde-test-agent" },
    tool: { tool_name: action },
    parameters,
    environment: {},
    context: {}
  };

  const built = buildPolicyReceipt(request, GIT_PUSH_POLICY, { now });
  const inner = repoLocalInner ? built : reSignInnerReceipt(built, trust);

  const signed = await signReceiptForDelivery(inner, { mode: "custody", provider }, {
    now,
    signingMode: LIVE_RECEIPT_SIGNING_MODES.EXECUTOR_AND_AUTHORITY,
    executorIdentity: {
      executor_id: executorId,
      key_id: credential.key_id,
      credential_id: credential.credential_id,
      environment_id: environmentId,
      credential
    },
    executorSigner: {
      sign: async (body) => nodeSign(null, Buffer.from(body, "utf8"), createPrivateKey(executorKeys.privatePem)).toString("hex")
    }
  });
  assert.equal(signed.ok, true, `envelope signing failed: ${signed.reason_code ?? ""}`);
  return signed.receipt;
}

function git(args, cwd) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

// A real remote (a bare repository reached over file://) and a real local clone
// with three linear commits plus one divergent commit for the non-fast-forward
// case.
export function makeRepositories(dir) {
  const barePath = join(dir, "remote.git");
  const localPath = join(dir, "work");
  mkdirSync(barePath, { recursive: true });
  git(["init", "--quiet", "--bare", "--initial-branch=main", "."], barePath);

  mkdirSync(localPath, { recursive: true });
  git(["init", "--quiet", "--initial-branch=main", "."], localPath);
  git(["config", "user.email", "git-push-test@mnde.invalid"], localPath);
  git(["config", "user.name", "MNDe git.push test"], localPath);
  git(["config", "commit.gpgsign", "false"], localPath);

  // pathToFileURL, not string concatenation: on Windows a bare path produces
  // file://C:/... , whose drive letter parses as a host. The rest of this suite
  // then compares two different spellings of the same repository and every case
  // fails for the wrong reason.
  const remoteUrl = pathToFileURL(barePath).href;
  git(["remote", "add", "origin", remoteUrl], localPath);

  const commits = [];
  for (const n of [1, 2, 3]) {
    writeFileSync(join(localPath, `file-${n}.txt`), `contents ${n}\n`, "utf8");
    git(["add", "--all"], localPath);
    git(["commit", "--quiet", "--no-verify", "-m", `commit ${n}`], localPath);
    commits.push(git(["rev-parse", "HEAD"], localPath));
  }

  // A commit that is NOT a descendant of commits[1], for the non-fast-forward
  // case. Built on commits[0] so it shares history without extending the tip.
  git(["checkout", "--quiet", "-b", "divergent", commits[0]], localPath);
  writeFileSync(join(localPath, "divergent.txt"), "divergent\n", "utf8");
  git(["add", "--all"], localPath);
  git(["commit", "--quiet", "--no-verify", "-m", "divergent"], localPath);
  const divergent = git(["rev-parse", "HEAD"], localPath);
  git(["checkout", "--quiet", "main"], localPath);

  // Seed the remote at the first commit.
  git(["push", "--quiet", "origin", `${commits[0]}:refs/heads/main`], localPath);

  return {
    barePath,
    localPath,
    remoteUrl,
    commits,
    divergent,
    remoteSha: () => git(["ls-remote", "--refs", remoteUrl, "refs/heads/main"], localPath).split(/\s+/)[0] ?? null,
    setRemoteTo: (sha) => git(["push", "--quiet", "--force", remoteUrl, `${sha}:refs/heads/main`], localPath)
  };
}

// Build the six signed parameters for a push on these repositories.
export function pushParameters(repos, { from, to, targetRef = "refs/heads/main", overrides = {} } = {}) {
  // Derived with the production function rather than a second implementation of
  // the same rule. A duplicate here would only ever test itself, and the rule
  // that `repository` must agree with `remote_url` has its own unit case.
  return {
    repository: canonicalRepositoryIdentity(repos.remoteUrl),
    remote: "origin",
    remote_url: repos.remoteUrl,
    source_commit: to,
    target_ref: targetRef,
    expected_old_sha: from,
    ...overrides
  };
}

// An in-memory stand-in for the durable claim backend.
//
// THE LIMITATION, STATED PLAINLY: this is not durable and proves nothing about
// durability. It implements the same { health, claim, lookup } protocol and the
// same at-most-once semantics, so it exercises the ORDERING this suite is about
// — that nothing is sent unless the claim came back CLAIMED, and that a second
// presentation of the same authority is refused. The durability and
// non-rollback properties of the real backend are established separately, in
// docs/F001-CLAIM-STORE-PROOF.md, at 22 of 22 against PostgreSQL 16.13.
export function inMemoryClaimBackend({ namespace, onClaim = null, healthy = true, throwOnClaim = false } = {}) {
  const byExecution = new Map();
  const byGrant = new Map();
  return {
    kind: "test-in-memory",
    claimed: () => [...byExecution.values()],
    async health() { return { ok: healthy === true }; },
    async claim(record) {
      if (record.namespace !== namespace) throw new Error("ERR_CLAIM_IDENTITY");
      if (onClaim) await onClaim(record);
      if (throwOnClaim) throw new Error("claim submission failed");
      const prior = byExecution.get(record.execution_id) ?? byGrant.get(record.grant_id);
      if (prior) return { status: "ALREADY_SPENT", prior };
      byExecution.set(record.execution_id, record);
      byGrant.set(record.grant_id, record);
      return { status: "CLAIMED", record };
    },
    async lookup(record) {
      const found = byExecution.get(record.execution_id) ?? byGrant.get(record.grant_id);
      return found ? { found: true, record: found } : { found: false };
    },
    // Spend an authority out of band, to model a run that claimed and then died
    // before it could dispatch.
    spend(record) {
      byExecution.set(record.execution_id, record);
      byGrant.set(record.grant_id, record);
    }
  };
}

export function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}
