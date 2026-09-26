// Deployment adapter. Only the git.push executor's own startup calls this factory
// (src/effects/git-push/index.mjs); nothing hands it a backend, client, driver,
// config object or dispatch callback, and it accepts none.
// Requires the separately provisioned PostgreSQL schema in deployment/freshness.
import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';

// Every backend this factory has returned. claim.mjs mints a push ticket only for
// a claim made through one of these, so an object that merely has the right
// method names — however it was built — can never authorize an effect.
const OPENED = new WeakSet();

export function isExecutorClaimBackend(value) {
  return value !== null && typeof value === 'object' && OPENED.has(value);
}

function configFromExecutor() {
  const path = process.env.MNDE_CLAIM_CONFIG;
  if (!path || !isAbsolute(path)) throw new Error('ERR_CLAIM_CONFIG');
  const c = JSON.parse(readFileSync(path, 'utf8'));
  const keys = ['host', 'port', 'database', 'user', 'namespace', 'passwordFile', 'caFile'];
  if (!c || Object.keys(c).some(k => !keys.includes(k)) || keys.some(k => !Object.hasOwn(c, k))
    || !Number.isInteger(c.port) || c.port < 1 || c.port > 65535
    || keys.filter(k => k !== 'port').some(k => typeof c[k] !== 'string' || !c[k])
    || !isAbsolute(c.passwordFile) || !isAbsolute(c.caFile)) throw new Error('ERR_CLAIM_CONFIG');
  return Object.freeze(c);
}

export async function openExecutorClaimBackend() {
  if (arguments.length) throw new Error('ERR_BACKEND_SUBSTITUTION');
  const config = configFromExecutor();
  // Installed by the operator in the executor runtime; never loaded on disabled paths.
  const { Client } = await import('pg');
  const password = readFileSync(config.passwordFile, 'utf8').trim();
  const ca = readFileSync(config.caFile, 'utf8');
  if (!password || !ca) throw new Error('ERR_CLAIM_CONFIG');
  const clientConfig = Object.freeze({ host: config.host, port: config.port,
    database: config.database, user: config.user, password,
    ssl: { ca, rejectUnauthorized: true }, connectionTimeoutMillis: 3000,
    query_timeout: 3000, statement_timeout: 2500, application_name: 'mnde-freshness' });
  const snapshot = record => {
    const r = structuredClone(record);
    const fields = ['namespace', 'execution_id', 'grant_id', 'subject', 'executor_id', 'receipt_hash', 'aplus_digest'];
    if (!r || Object.keys(r).length !== fields.length || fields.some(k => typeof r[k] !== 'string' || !r[k])
      || r.namespace !== config.namespace) throw new Error('ERR_CLAIM_IDENTITY');
    return r;
  };
  // A new primary connection per operation; no pool retry, replica lookup, or resend.
  async function withPrimary(fn) {
    const client = new Client(clientConfig);
    client.on('error', () => {}); // connection errors also reject the outstanding query
    try {
      await client.connect();
      const check = await client.query("SELECT pg_is_in_recovery() AS replica, current_setting('fsync') AS fsync");
      if (check.rows[0]?.replica !== false || check.rows[0]?.fsync !== 'on') throw new Error('ERR_NOT_DURABLE_PRIMARY');
      return await fn(client);
    } finally { await client.end().catch(() => {}); }
  }
  const backend = Object.freeze({
    kind: 'remote-postgresql',
    async health() {
      try {
        const result = await withPrimary(c => c.query('SELECT mnde_claim.bound_namespace() AS namespace'));
        return { ok: result.rows[0]?.namespace === config.namespace };
      }
      catch { return { ok: false }; }
    },
    async claim(record) {
      const r = snapshot(record);
      return withPrimary(async c => {
        await c.query('BEGIN ISOLATION LEVEL READ COMMITTED');
        try {
          await c.query("SET LOCAL synchronous_commit = 'on'");
          const result = await c.query('SELECT * FROM mnde_claim.first_claim($1::jsonb)', [JSON.stringify(r)]);
          const row = result.rows[0];
          if (!row || typeof row.inserted !== 'boolean') throw new Error('ERR_CLAIM_RESPONSE');
          // Never return CLAIMED before COMMIT acknowledgement. A lost COMMIT reply
          // throws; caller performs lookup and sends nothing, even if a row exists.
          await c.query('COMMIT');
          return row.inserted ? { status: 'CLAIMED', record: row.record }
            : { status: 'ALREADY_SPENT', prior: row.record };
        } catch (error) {
          await c.query('ROLLBACK').catch(() => {});
          throw error;
        }
      });
    },
    async lookup(record) {
      const r = snapshot(record);
      return withPrimary(async c => {
        const result = await c.query('SELECT * FROM mnde_claim.lookup_claim($1::jsonb)', [JSON.stringify(r)]);
        // Zero rows after an uncertain acknowledgement is UNKNOWN, never permission.
        return result.rows.length ? { found: true, record: result.rows[0].record } : { found: false };
      });
    }
  });
  OPENED.add(backend);
  return backend;
}
