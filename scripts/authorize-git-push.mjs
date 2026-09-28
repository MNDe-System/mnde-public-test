#!/usr/bin/env node
// authorize-git-push — the operator's approval of ONE git.push.
//
//   node scripts/authorize-git-push.mjs \
//     --remote-url https://github.com/<owner>/<repo>.git \
//     --target-ref refs/heads/<branch> \
//     --expected-old-sha <40-hex sha the branch is at now> \
//     --source-commit <40-hex sha to move it to> \
//     --out <request.json, outside the repository> \
//     [--remote origin] [--subject <who approved>] [--ttl-minutes 30]
//
// It writes the request file `mnde-git-push` takes: the seven request fields plus
// an executor-bound mnde.signed-receipt.v2 authorization for exactly those values.
//
// WHY THIS EXISTS. Execution authority requires BOTH layers of the envelope to
// verify against the operator's own authority bundle (src/execution-authority,
// ERR_REPO_LOCAL_TRUST). buildPolicyReceipt() signs the inner policy decision with
// the repository's demo authority, so neither it nor the sidecar can produce an
// authorization the git.push executor will accept. This tool signs the inner
// decision with the production receipt key instead, then wraps it through the
// same live signing context the sidecar uses (createLiveReceiptSigningContext,
// signLiveReceipt). No new signature format and no new trust path.
//
// WHAT RUNNING IT MEANS. The person who runs this is approving the push. The
// embedded policy allows `git.push` and nothing else, so the policy decision is
// a formality: the approval is holding the receipt key and choosing to sign these
// exact six values. The executor still decides on its own whether the push
// happens (remote state, ancestry, single-use claim, credential scope).
//
// Configuration comes from the environment, the same variables the rest of MNDe
// reads: MNDE_AUTHORITY_BUNDLE, MNDE_RECEIPT_SIGNING_KEY, MNDE_RECEIPT_KEY_ID
// (optional), MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT, the four MNDE_EXECUTOR_*
// variables, and MNDE_GIT_PUSH_ALLOWED_SCHEMES when set. It fails closed on demo
// trust, on a bundle that does not match the pinned root, and if the envelope it
// produced does not verify as execution authority for the configured executor.
// Key material is never printed.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createLiveReceiptSigningContext, loadSigningConfig, signLiveReceipt } from "../src/authority-signing/index.mjs";
import { assertExecutorIdentityReadiness } from "../src/custody/executor-readiness.mjs";
import { randomBytes } from "../src/crypto/provider.mjs";
import { isRepoContained } from "../src/authority-signing/repo-containment.mjs";
import { isProductionExecutionAuthority, verifyExecutionAuthority } from "../src/execution-authority/index.mjs";
import { KNOWN_NON_PRODUCTION_ROOT_FINGERPRINTS } from "../src/effects/git-push/startup.mjs";
import { GIT_PUSH_ACTION, canonicalRepositoryIdentity, validateGitPushParameters } from "../src/effects/git-push/validate.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import { RECEIPT_SIGNATURE_ALGORITHM } from "../shared/index.ts";
import { buildPolicyReceiptPayload, canonicalPayloadWithoutSignature } from "../src/policy-engine/receipt.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// Allows exactly the one action this tool signs. Evaluated and replayed by the
// verifier like any other policy-engine decision.
export const GIT_PUSH_APPROVAL_POLICY = Object.freeze({
  schema_version: "1.0",
  policy_id: "mnde-operator-git-push-approval",
  version: "1",
  state: "ACTIVE",
  rules: [
    { rule_id: "allow-operator-approved-git-push", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: GIT_PUSH_ACTION } }
  ]
});

function fail(detail) {
  return { ok: false, detail };
}

function normalizeFingerprint(value) {
  return String(value ?? "").trim().toLowerCase().replace(/^sha256:/, "");
}

// Pure core. Returns { ok: true, request, summary } or { ok: false, detail }.
export async function authorizeGitPush(input, env = process.env, { now = new Date().toISOString() } = {}) {
  const remoteUrl = input.remoteUrl;
  const parameters = {
    repository: canonicalRepositoryIdentity(remoteUrl) ?? "",
    remote: input.remote ?? "origin",
    remote_url: remoteUrl,
    source_commit: input.sourceCommit,
    target_ref: input.targetRef,
    expected_old_sha: input.expectedOldSha
  };
  // The executor validates again with its own configured scheme list; this only
  // refuses to spend a signature on a push the executor would never build. Same
  // variable and meaning as the executor's startup (unset: https and ssh).
  const allowedSchemes = typeof env.MNDE_GIT_PUSH_ALLOWED_SCHEMES === "string" ? env.MNDE_GIT_PUSH_ALLOWED_SCHEMES.split(",") : undefined;
  const shape = validateGitPushParameters(parameters, { allowedSchemes });
  if (!shape.ok) return fail(`${shape.reason}: ${shape.detail}`);

  const ttlMinutes = input.ttlMinutes ?? 30;
  if (!Number.isInteger(ttlMinutes) || ttlMinutes < 1 || ttlMinutes > 24 * 60) {
    return fail("--ttl-minutes must be a whole number from 1 to 1440");
  }
  const subject = input.subject ?? "operator";
  if (typeof subject !== "string" || !/^[A-Za-z0-9:._@-]{1,128}$/.test(subject)) {
    return fail("--subject must be 1-128 characters of [A-Za-z0-9:._@-]");
  }

  for (const name of ["MNDE_AUTHORITY_BUNDLE", "MNDE_RECEIPT_SIGNING_KEY", "MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT",
    "MNDE_EXECUTOR_ID", "MNDE_EXECUTOR_PRIVATE_KEY", "MNDE_EXECUTOR_CREDENTIAL", "MNDE_EXECUTOR_ENVIRONMENT"]) {
    if (typeof env[name] !== "string" || env[name].length === 0) return fail(`${name} is not set`);
  }
  for (const name of ["MNDE_AUTHORITY_BUNDLE", "MNDE_RECEIPT_SIGNING_KEY", "MNDE_EXECUTOR_PRIVATE_KEY", "MNDE_EXECUTOR_CREDENTIAL"]) {
    if (isRepoContained(resolve(env[name]), REPO_ROOT)) return fail(`${name} is inside the repository; production trust material lives outside it`);
  }

  let bundle;
  try {
    bundle = JSON.parse(readFileSync(env.MNDE_AUTHORITY_BUNDLE, "utf8"));
  } catch (error) {
    return fail(`MNDE_AUTHORITY_BUNDLE could not be read as JSON (${error?.code ?? error?.name ?? "error"})`);
  }
  const pinned = normalizeFingerprint(env.MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT);
  const bundleRoot = normalizeFingerprint(bundle?.root_key?.fingerprint);
  if (KNOWN_NON_PRODUCTION_ROOT_FINGERPRINTS.some((fp) => fp === pinned || fp === bundleRoot)) {
    return fail("the configured trust root is MNDe's shipped demo root");
  }
  if (/local|demo/i.test(String(bundle?.authority_id ?? "")) || /local|demo/i.test(String(bundle?.root_key?.key_id ?? ""))) {
    return fail("the authority bundle is a local or demo authority");
  }
  // file-backed-production custody pins the bundle's own root. That proves only
  // that the bundle is self-consistent, so the operator's out-of-band pin must
  // name the same root.
  if (!pinned || pinned !== bundleRoot) return fail("MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT does not match the authority bundle's root");

  const signingConfig = await loadSigningConfig(
    { ...env, MNDE_RECEIPT_SIGNING_MODE: "custody", MNDE_KEY_CUSTODY: "file-backed-production" },
    { now }
  );
  if (!signingConfig.ok) return fail(`receipt signing unavailable (${signingConfig.reason_code}): ${signingConfig.detail ?? ""}`);

  const readiness = await assertExecutorIdentityReadiness(env, { authorityBundle: bundle, trustedRootFingerprint: bundleRoot });
  if (!readiness.ok || readiness.configured !== true) {
    return fail(`executor identity is not usable (${readiness.reason_code ?? "unknown"}): ${readiness.detail ?? ""}`);
  }
  const context = createLiveReceiptSigningContext(signingConfig, readiness);
  if (!context.ok) {
    readiness.signer?.destroy?.();
    return fail(`signing context unavailable (${context.reason_code})`);
  }

  try {
    const executionId = `exec-${randomBytes(16).toString("hex")}`;
    const grantId = `grant-${randomBytes(16).toString("hex")}`;
    const expiresAt = new Date(Date.parse(now) + ttlMinutes * 60 * 1000).toISOString();
    const decisionRequest = {
      schema_version: "1.0",
      request_id: executionId,
      grant_id: grantId,
      timestamp: now,
      expires_at: expiresAt,
      principal: { id: subject },
      agent: { id: "mnde-authorize-git-push" },
      tool: { tool_name: GIT_PUSH_ACTION },
      parameters,
      environment: {},
      context: {}
    };

    // executionStatus null: this receipt exists to be executed, so it must not
    // carry the "MNDe could not have executed this" marker.
    const payload = buildPolicyReceiptPayload(decisionRequest, GIT_PUSH_APPROVAL_POLICY, { now, executionStatus: null });
    if (payload.decision_output?.decision !== "ALLOW") return fail(`policy did not allow the push (${payload.decision_output?.reason_code ?? "?"})`);

    const innerSignature = await signingConfig.provider.signReceipt(canonicalPayloadWithoutSignature(payload));
    const inner = {
      ...payload,
      verifiable_signature: {
        algorithm: RECEIPT_SIGNATURE_ALGORITHM,
        authority_id: bundle.authority_id,
        key_id: innerSignature.key_id,
        public_key_fingerprint: innerSignature.fingerprint,
        signed_at: now,
        value: innerSignature.value
      }
    };

    const signed = await signLiveReceipt(inner, context.context, { now });
    if (!signed.ok) return fail(`envelope signing failed (${signed.reason_code})`);

    // Verify the result exactly as the executor will, before anyone relies on it.
    const authority = await verifyExecutionAuthority(signed.receipt, {
      authorityBundle: bundle,
      trustedRootFingerprint: bundleRoot,
      environmentId: env.MNDE_EXECUTOR_ENVIRONMENT,
      expectedExecutorId: env.MNDE_EXECUTOR_ID,
      now
    });
    if (!authority.ok || !isProductionExecutionAuthority(authority)) {
      return fail(`the authorization produced does not verify as execution authority (${authority.reason ?? "?"}${authority.detail ? `: ${authority.detail}` : ""})`);
    }
    if (authority.action !== GIT_PUSH_ACTION || canonicalizeJson(authority.parameters) !== canonicalizeJson(parameters)) {
      return fail("the authorization produced does not carry the requested push");
    }

    const request = {
      repository: parameters.repository,
      remote: parameters.remote,
      remoteUrl: parameters.remote_url,
      sourceCommit: parameters.source_commit,
      targetRef: parameters.target_ref,
      expectedOldSha: parameters.expected_old_sha,
      authorization: signed.receipt
    };
    return {
      ok: true,
      request,
      summary: {
        execution_id: executionId,
        grant_id: grantId,
        executor_id: authority.executor_id,
        expires_at: expiresAt,
        authorized: parameters
      }
    };
  } finally {
    readiness.signer?.destroy?.();
  }
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--") || i + 1 >= argv.length) return null;
    args[token.slice(2)] = argv[(i += 1)];
  }
  return args;
}

const USAGE = "usage: node scripts/authorize-git-push.mjs --remote-url <url> --target-ref refs/heads/<branch> "
  + "--expected-old-sha <sha> --source-commit <sha> --out <request.json> [--remote origin] [--subject <id>] [--ttl-minutes 30]\n";
const KNOWN = new Set(["remote-url", "target-ref", "expected-old-sha", "source-commit", "out", "remote", "subject", "ttl-minutes"]);

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args || Object.keys(args).some((key) => !KNOWN.has(key))
    || !args["remote-url"] || !args["target-ref"] || !args["expected-old-sha"] || !args["source-commit"] || !args.out) {
    process.stderr.write(USAGE);
    process.exit(2);
  }
  const out = resolve(args.out);
  if (isRepoContained(out, REPO_ROOT)) {
    process.stderr.write("authorize-git-push: --out must be outside the repository\n");
    process.exit(2);
  }
  const result = await authorizeGitPush({
    remoteUrl: args["remote-url"],
    remote: args.remote,
    targetRef: args["target-ref"],
    expectedOldSha: args["expected-old-sha"],
    sourceCommit: args["source-commit"],
    subject: args.subject,
    ttlMinutes: args["ttl-minutes"] === undefined ? undefined : Number(args["ttl-minutes"])
  });
  if (!result.ok) {
    process.stderr.write(`authorize-git-push: ${result.detail}\n`);
    process.exit(1);
  }
  try {
    writeFileSync(out, `${JSON.stringify(result.request, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  } catch (error) {
    process.stderr.write(`authorize-git-push: could not create ${out} (${error?.code ?? "error"}); it must not already exist\n`);
    process.exit(1);
  }
  process.stdout.write(`${JSON.stringify({ request_path: out, ...result.summary }, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    process.stderr.write(`authorize-git-push: ${error?.message ?? String(error)}\n`);
    process.exit(1);
  });
}
