// EXP-001 Stage 2 — Unit 1: fixed merge-request construction.
//
// Pure, synchronous. Given a VERIFIED declaration (branded by declaration.mjs)
// and trusted adapter config, returns exactly one fixed GitHub operation:
//
//   PUT /repos/{owner}/{repo}/pulls/{number}/merge
//   body: { "sha": A⁺.expected_source_sha, "merge_method": "merge" }
//
// There is no caller-supplied URL, body, merge option, or callback. Every value
// comes solely from the verified declaration + config. Fails closed (throws a
// typed BuildError) on any malformed / mismatched / unverified input BEFORE any
// request object is produced. expected_target_sha is intentionally NOT sent — the
// PR merge endpoint does not enforce it.

import { isVerifiedDeclaration, EXPECTED_MERGE_ACTION, ALLOWED_PARAM_KEYS } from "./declaration.mjs";

const SHA_HEX = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;   // sha-1 or sha-256, lowercase hex
const NAME = /^[A-Za-z0-9._-]+$/;

export class BuildError extends Error {
  constructor(code, detail) { super(code); this.name = "BuildError"; this.code = code; this.detail = detail ?? null; }
}
const fail = (code, detail) => { throw new BuildError(code, detail); };

export function buildMergeRequest(verifiedDeclaration, adapterConfig) {
  // Authorization proof: must be a branded verified declaration, not a plain
  // object that merely says verified:true.
  if (!isVerifiedDeclaration(verifiedDeclaration)) fail("ERR_UNVERIFIED_DECLARATION");
  const d = verifiedDeclaration.declaration;
  if (!d || typeof d !== "object") fail("ERR_NO_DECLARATION");

  // Snapshot primitives up front (declaration is deep-frozen, but this makes the
  // no-mutation guarantee explicit and independent of the source object).
  const action = d.action;
  const owner = d.repository?.owner;
  const repo = d.repository?.repo;
  const number = d.pull_request;
  const sha = d.expected_source_sha;
  const target = d.target_ref;
  const method = d.merge_method;
  const paramKeys = Array.isArray(d.parameterKeys) ? d.parameterKeys : [];

  // Action + option shape.
  if (action !== EXPECTED_MERGE_ACTION) fail("ERR_UNEXPECTED_ACTION", action);
  if (method !== "merge") fail("ERR_UNSUPPORTED_MERGE_METHOD", method);
  for (const k of paramKeys) if (!ALLOWED_PARAM_KEYS.includes(k)) fail("ERR_UNEXPECTED_PARAM", k);

  // Identity + value validation.
  if (typeof owner !== "string" || !NAME.test(owner)) fail("ERR_BAD_REPO", "owner");
  if (typeof repo !== "string" || !NAME.test(repo)) fail("ERR_BAD_REPO", "repo");
  if (!Number.isInteger(number) || number <= 0) fail("ERR_BAD_PR", number);
  if (typeof sha !== "string" || !SHA_HEX.test(sha)) fail("ERR_BAD_SOURCE_SHA", sha);
  if (typeof target !== "string" || target.length === 0) fail("ERR_BAD_TARGET", target);

  // Trusted-config match: the adapter is pinned to one repo + target branch and
  // must refuse a declaration that names anything else.
  if (!adapterConfig || typeof adapterConfig !== "object") fail("ERR_NO_CONFIG");
  if (adapterConfig.owner !== owner || adapterConfig.repo !== repo) fail("ERR_REPO_IDENTITY_MISMATCH");
  if (adapterConfig.target_ref !== target) fail("ERR_TARGET_IDENTITY_MISMATCH");

  // The one and only fixed operation. Frozen so nothing downstream can mutate it.
  return Object.freeze({
    method: "PUT",
    path: `/repos/${owner}/${repo}/pulls/${number}/merge`,
    body: Object.freeze({ sha, merge_method: "merge" })
  });
}
