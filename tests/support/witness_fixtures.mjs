// TEST SUPPORT ONLY — an in-process spend witness: the real server logic (hash-chained
// append-only log, first-writer-wins, signed responses) and the real client, joined by a
// function call instead of a socket. No TLS and no openssl, so it runs on every CI runner.
// Network faults are injected by wrapping `call`.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { generateAuthorityKeyPair } from "../../src/custody/bundle.mjs";
import { sha256 } from "../../src/crypto/provider.mjs";
import { openSpendWitness } from "../../src/freshness/spend_witness.mjs";
import { createWitnessApp, openWitnessLog } from "../../deployment/witness/witness-server.mjs";

export const WITNESS_ID = "mnde-test-witness";

export function newWitnessKey(keyId = "witness-key-1") {
  const pair = generateAuthorityKeyPair();
  return { key_id: keyId, private_pem: pair.privatePem, public_key: pair.publicPem };
}

// A witness "installation": a data directory, a signing key and a token table.
// Several executors may hold different tokens (each bound to one executor and namespace).
export function startInProcessWitness({ dataDir = mkdtempSync(join(tmpdir(), "mnde-witness-")), key = newWitnessKey(), identities = [] } = {}) {
  const tokens = {};
  const secrets = new Map();
  for (const { executor_id, namespace } of identities) {
    const secret = `token-${executor_id}-${namespace}`;
    tokens[sha256(secret)] = { executor_id, namespace };
    secrets.set(`${executor_id}|${namespace}`, secret);
  }
  const log = openWitnessLog(dataDir);
  const app = createWitnessApp({ log, witnessId: WITNESS_ID, keyId: key.key_id, keyPem: key.private_pem, tokens });
  const config = (extra = {}) => ({
    url: "https://witness.invalid", witness_id: WITNESS_ID, caFile: "/unused/ca.pem", tokenFile: "/unused/token",
    witness_keys: [{ key_id: key.key_id, public_key: key.public_key }], timeoutMs: 2000, ...extra
  });
  // A client for one identity. `wrap(call)` lets a test intercept, drop, delay or alter traffic.
  const client = ({ executor_id, namespace }, { wrap = (c) => c, configExtra = {} } = {}) => {
    const token = secrets.get(`${executor_id}|${namespace}`);
    const direct = async ({ method, path, body }) => app({
      method, url: path, authorization: `Bearer ${token}`,
      bodyBuffer: body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8")
    });
    return openSpendWitness(config(configExtra), { call: wrap(direct), readFiles: false });
  };
  return { dataDir, key, log, app, config, client, tokenFor: (id, ns) => secrets.get(`${id}|${ns}`), close: () => log.close() };
}
