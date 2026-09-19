// Reproducible candidate inventory. This is a search index, not a call-graph proof.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
const root=fileURLToPath(new URL('../../../',import.meta.url));
const git=(...args)=>execFileSync('git',args,{cwd:root,encoding:'utf8'}).trim();
const files=git('ls-files','-z').split('\0').filter(p=>/\.(mjs|cjs|js|ts|ps1|sh|py)$/.test(p));
const patterns={
  egress:/child_process|\bspawn(?:Sync)?\s*\(|\bexec(?:File|Sync|FileSync)?\s*\(|\bfetch\s*\(|https?:|net\.|tls\.|WebSocket|axios|undici/,
  execution:/\b(?:run|execute|dispatch|attemptMerge|claim|authorize|request|notify)\s*\(|setInterval|setTimeout|new Worker|retry|recovery/i,
  authority:/process\.env|readFile|privateKey|signingKey|bearer|credential|token|signer|grant/i,
  localMutation:/writeFile|appendFile|rename|unlink|rmSync|mkdir|INSERT|UPDATE|DELETE|\.run\s*\(/
};
const index=files.map(path=>{
  const bytes=readFileSync(join(root,path));
  const lines=bytes.toString('utf8').split(/\r?\n/);
  return {path,sha256:createHash('sha256').update(bytes).digest('hex'),matches:Object.fromEntries(Object.entries(patterns).map(([name,re])=>[name,lines.flatMap((line,i)=>re.test(line)?[i+1]:[])]))};
});
const evidence=new URL('./evidence/',import.meta.url);mkdirSync(evidence,{recursive:true});
writeFileSync(new URL('source-inventory.json',evidence),JSON.stringify({head:git('rev-parse','HEAD'),branch:git('branch','--show-current'),frozenTag:git('rev-parse','exp-001-stage2-frozen^{}'),trackedSourceFiles:files.length,note:'Post-fix bytes; paths and candidate line numbers only. Classification requires manual call tracing in AUDIT.md.',files:index},null,2)+'\n',{flag:'wx'});
for(const [name,args] of [
  ['proxy-before.mjs',['show','2f941741b8b44f177ead69610595f510efc30873:mcp/mnde-mcp-proxy.mjs']],
  ['change.patch',['diff','--','mcp/mnde-mcp-proxy.mjs']]
]) writeFileSync(new URL(name,evidence),execFileSync('git',args,{cwd:root}),{flag:'wx'});
writeFileSync(new URL('proxy-after.mjs',evidence),readFileSync(join(root,'mcp/mnde-mcp-proxy.mjs')),{flag:'wx'});
console.log(JSON.stringify({trackedSourceFiles:files.length,head:git('rev-parse','HEAD'),frozenTag:git('rev-parse','exp-001-stage2-frozen^{}')}));
