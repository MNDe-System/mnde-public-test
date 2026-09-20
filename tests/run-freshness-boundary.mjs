import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const guard=new URL('../experiments/exp-001-stage2/tests/_guard.mjs',import.meta.url).href;
for(const args of [
 ['--import',guard,'--test','tests/test_freshness_boundary.mjs'],
 ['--test','tests/test_stage1_freshness_boundary.mjs'],
 ['--test','tests/test_mcp_freshness_boundary.mjs']
]) execFileSync(process.execPath,args,{cwd:root,stdio:'inherit',windowsHide:true});
