// Local-only authority surrogate. No network, real credentials or destructive work.
// The synthetic authority value is never recorded; only its presence is reported.
import { appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
const record = event => appendFileSync(process.env.MNDE_F001_LOG, JSON.stringify({ event, syntheticAuthority: process.env.MNDE_F001_SYNTHETIC_AUTHORITY === 'f001-local-fixture' })+'\n');
record('startup');
createInterface({ input: process.stdin }).on('line', line => {
  const m = JSON.parse(line);
  record(m.method);
  if (m.id !== undefined) process.stdout.write(JSON.stringify({ jsonrpc:'2.0', id:m.id, result: m.method === 'tools/list' ? { tools:[{ name:'fixture', inputSchema:{type:'object'} }] } : {} })+'\n');
});
