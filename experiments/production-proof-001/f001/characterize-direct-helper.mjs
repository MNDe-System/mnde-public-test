// Characterization, NOT a passing security/closure test. Demonstrates residual
// authority of a direct import by an already privileged source/package caller.
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStdioClient } from '../../../mcp/stdio-client.mjs';
const log=join(mkdtempSync(join(tmpdir(),'mnde-f001-direct-')),'events.jsonl');
const client=createStdioClient(process.execPath,[fileURLToPath(new URL('./recording-authority.mjs',import.meta.url))],{
  MNDE_F001_LOG:log,MNDE_F001_SYNTHETIC_AUTHORITY:'f001-local-fixture'
});
try { await client.request('ping',{}); } finally { await client.stop(); }
const events=readFileSync(log,'utf8').trim().split('\n').map(JSON.parse);
if (!events.some(e=>e.event==='startup'&&e.syntheticAuthority)) throw Error('characterization did not reproduce');
console.log(JSON.stringify({ classification:'BYPASS', scope:'privileged direct-import capability; no GitHub mutation tested', claimConsumed:false, events }));
