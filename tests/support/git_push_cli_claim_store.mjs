// TEST SUPPORT ONLY — preload for tests/test_git_push_cli.mjs child processes.
//
// The CLI suite runs the real CLI as separate OS processes, so the claim store
// must outlive each process: a replay is a SECOND process presenting the same
// authority. The in-process double (./claim_backend_double.mjs) cannot do that,
// and CI has no PostgreSQL. This preload installs, through that same double and
// the same module redirect, a backend that keeps its claims as files created
// exclusively (O_EXCL), one per execution id and one per grant id.
//
// THE LIMITATION, STATED PLAINLY: this proves the CLI reaches the claim and that
// a replay across processes is refused BY the claim. It proves nothing about the
// durability or non-rollback of the production store; see
// docs/F001-CLAIM-STORE-PROOF.md and the real-PostgreSQL run in
// docs/F001-REASSESSMENT.md.
//
//   MNDE_TEST_CLAIM_STORE   directory holding the claim files
//   MNDE_TEST_CLAIM_MODE    "" | "throw-on-claim" (claim uncertain, nothing stored)
//                               | "ack-lost" (claim stored, acknowledgement lost)

import "./claim_backend_hooks.mjs";

import { createHash } from "node:crypto";
import { closeSync, existsSync, openSync, readFileSync, writeSync } from "node:fs";
import { join } from "node:path";

import { installClaimBackend } from "./claim_backend_double.mjs";

const dir = process.env.MNDE_TEST_CLAIM_STORE;
const mode = process.env.MNDE_TEST_CLAIM_MODE ?? "";
const namespace = process.env.MNDE_GIT_PUSH_NAMESPACE;

const fileFor = (kind, value) => join(dir, `${kind}-${createHash("sha256").update(String(value)).digest("hex")}.json`);

function readPrior(record) {
  for (const path of [fileFor("execution", record.execution_id), fileFor("grant", record.grant_id)]) {
    if (existsSync(path)) return JSON.parse(readFileSync(path, "utf8"));
  }
  return null;
}

function createExclusive(path, record) {
  const fd = openSync(path, "wx");
  try { writeSync(fd, JSON.stringify(record)); } finally { closeSync(fd); }
}

function store(record) {
  try {
    createExclusive(fileFor("execution", record.execution_id), record);
  } catch (error) {
    if (error?.code === "EEXIST") return false;
    throw error;
  }
  try {
    createExclusive(fileFor("grant", record.grant_id), record);
  } catch (error) {
    if (error?.code === "EEXIST") return false;
    throw error;
  }
  return true;
}

installClaimBackend(dir ? {
  kind: "test-file-claim-store",
  async health() { return { ok: true }; },
  async claim(record) {
    if (record.namespace !== namespace) throw new Error("ERR_CLAIM_IDENTITY");
    if (mode === "throw-on-claim") throw new Error("claim submission failed (test)");
    const prior = readPrior(record);
    if (prior) return { status: "ALREADY_SPENT", prior };
    if (!store(record)) return { status: "ALREADY_SPENT", prior: readPrior(record) };
    if (mode === "ack-lost") throw new Error("claim acknowledgement lost (test)");
    return { status: "CLAIMED", record };
  },
  async lookup(record) {
    const found = readPrior(record);
    return found ? { found: true, record: found } : { found: false };
  }
} : null);
