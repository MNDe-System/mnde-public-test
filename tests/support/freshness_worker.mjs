// Same-machine SQLite model worker. Every provider operation below is a file record.
import { readFileSync, appendFileSync } from 'node:fs';
import { verifyDeclaration } from '../../experiments/exp-001-stage2/src/declaration.mjs';
import { createSqliteClaimBackend } from '../../experiments/exp-001-stage2/src/claim_store.mjs';
import { createOfflineAdapter } from './offline_freshness_adapter.mjs';
const [fixture, dbPath, events, mode] = process.argv.slice(2);
const { receipt, trustedConfig } = JSON.parse(readFileSync(fixture, 'utf8'));
const decl = await verifyDeclaration(receipt, trustedConfig);
if (!decl.ok) throw new Error(JSON.stringify(decl));
const backend = createSqliteClaimBackend({ dbPath });
const log = r => appendFileSync(events, JSON.stringify(r)+'\n');
if (mode === 'before-claim') process.exit(22);
const adapter = createOfflineAdapter({
  config: { owner: 'mnde-labs', repo: 'exp-001', target_ref: 'main', namespace: trustedConfig.namespace },
  claimBackend: backend,
  beforeDispatch: () => {
    log({ type: 'claim-acknowledgement' });
    if (mode === 'after-claim') process.exit(23);
  },
  transport: async request => {
    log({ type: 'dispatch-attempt', request });
    log({ type: 'model-provider-effect', merged: true });
    if (mode === 'after-start') process.exit(24);
    const response = { status: 200, body: { merged: true } };
    log({ type: 'provider-response', response });
    return response;
  }
});
const result = await adapter.attemptMerge(decl);
backend.close();
process.stdout.write(JSON.stringify(result));
