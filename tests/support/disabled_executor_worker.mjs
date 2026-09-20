import {readFileSync,writeFileSync,appendFileSync} from 'node:fs';
import {join} from 'node:path';
import {createAdapter} from '../../experiments/exp-001-stage2/src/adapter.mjs';
import {verifyDeclaration} from '../../experiments/exp-001-stage2/src/declaration.mjs';
import {createMndeExecutor} from '../../executor/index.mjs';
const [fixture,dir,events]=process.argv.slice(2);
const f=JSON.parse(readFileSync(fixture,'utf8'));
const bundle=join(dir,'bundle.json');writeFileSync(bundle,JSON.stringify(f.trustedConfig.authorityBundle));
globalThis.fetch=async()=>({ok:true,status:200,json:async()=>({decision:'ALLOW',receipt:structuredClone(f.receipt)})});
const exec=createMndeExecutor({receiptsDir:dir,verifyAuthorityBundle:bundle,
 verifyTrustedRootFingerprint:f.trustedConfig.trustedRootFingerprint,
 verifyEnvironmentId:f.trustedConfig.environmentId,verifyExpectedExecutorId:f.trustedConfig.expectedExecutorId,
 claimBackend:{production:true},claimed:true});
const cr=JSON.parse(f.receipt.receipt.canonical_request);
const result=await exec.execute({action:cr.tool.tool_name,input:cr.parameters,executionId:cr.request_id,
 run:()=>appendFileSync(events,'provider-request\n'),claimed:true,claimBackend:{production:true}});
const wrapped=await exec.wrapTool(cr.tool.tool_name,()=>appendFileSync(events,'wrapped-request\n'),{executionId:cr.request_id})(cr.parameters);
const decl=await verifyDeclaration(f.receipt,f.trustedConfig);
const stage2=await createAdapter({config:{requireProductionBackend:true},claimBackend:{production:true,health:()=>({ok:true}),claim:()=>({status:'CLAIMED'})},transport:()=>appendFileSync(events,'stage2-request\n')}).attemptMerge(decl);
process.stdout.write(JSON.stringify({executed:result.executed,reason:result.reason,verified:result.verified,wrapped:wrapped.executed,stage2:stage2.error}));
