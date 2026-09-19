// Keep historical tests unchanged and run in separate trees to avoid overwriting
// developer receipts. The old enabled-execution contract is reported, not relaxed.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('../../../',import.meta.url));
const scratch=mkdtempSync(join(tmpdir(),'mnde-f001-compat-'));
const git=(args,cwd)=>{
  const r=spawnSync('git',args,{cwd,windowsHide:true,encoding:'utf8'});
  if(r.status!==0) throw Error(r.stderr);
};
for(const version of ['baseline','remediated']) {
  const cwd=join(scratch,version);
  git(['clone','--no-hardlinks','--no-checkout',root,cwd],root);
  git(['checkout','--detach','2f941741b8b44f177ead69610595f510efc30873'],cwd);
  if(version==='remediated') copyFileSync(join(root,'mcp/mnde-mcp-proxy.mjs'),join(cwd,'mcp/mnde-mcp-proxy.mjs'));
  const r=spawnSync(process.execPath,['tests/test_mcp_proxy.mjs'],{cwd,windowsHide:true,encoding:'utf8',timeout:90000,maxBuffer:4*1024*1024});
  console.log(JSON.stringify({version,cwd,exitCode:r.status,error:r.error?.message??null}));
  process.stdout.write(r.stdout??''); process.stderr.write(r.stderr??'');
  if(r.error) process.exitCode=1;
}
