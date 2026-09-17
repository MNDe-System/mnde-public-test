import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { mkdtempSync, writeFileSync, existsSync, cpSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { startMndeSidecar } from '../executor/sidecar-harness.mjs';
import { createMndeExecutor } from '../executor/index.mjs';
import { reviewerRequest } from '../scripts/reviewer-request.mjs';
import { reserveExecutionId } from '../sidecar/execution_id_store.mjs';
import { makeRealExecutorBoundReceipt } from '../experiments/exp-001-stage2/tests/_real_receipt.mjs';
const temp=()=>mkdtempSync(join(tmpdir(),'mnde-stage1-freshness-'));
async function port(){const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
const refused='ERR_FRESHNESS_DEPLOYMENT_DISABLED';
test('F-001 Stage 1: unset local cache helper refuses',()=>{
 const old=process.env.MNDE_EXEC_ID_CACHE;delete process.env.MNDE_EXEC_ID_CACHE;
 try{assert.equal(reserveExecutionId('no-cache'),false);}finally{if(old!==undefined)process.env.MNDE_EXEC_ID_CACHE=old;}
});
for(const engine of ['legacy','policy-engine']) {
 test(`F-001 Stage 1 actual ${engine} sidecar: unset/missing/corrupt cache and restart refuse, zero provider calls`,{timeout:60000},async()=>{
  const dir=temp();const corrupt=join(dir,'corrupt');writeFileSync(corrupt,'not a directory');let calls=0;
  for(const cache of [undefined,join(dir,'missing'),corrupt,undefined]) {
   const url=`http://127.0.0.1:${await port()}`;
   const sc=await startMndeSidecar({url,env:{MNDE_EXEC_ID_CACHE:cache,MNDE_DECISION_ENGINE:engine,MNDE_PROFILE:'local'}});
   try {
    const request=reviewerRequest({requestId:'same-stage1-authority',tool:'github.merge',testerId:'FRESHNESS',installationId:'FRESHNESS'});
    for(let i=0;i<2;i++) {
     const response=await fetch(url+'/v1/decisions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(request)});
     const body=await response.json();assert.equal(body.decision,'REFUSE');assert.equal(body.reason_code,refused);
    }
    const exec=createMndeExecutor({sidecarUrl:url,receiptsDir:join(dir,'receipts')});
    const result=await exec.execute({action:'github.merge',executionId:'same-stage1-authority',run:()=>{calls++;}});
    assert.equal(result.executed,false);
    assert.equal((await fetch(url+'/readyz')).status,200);
   }finally{await sc.stop();}
  }
  assert.equal(calls,0);
 });
}
test('F-001 public executor/wrapTool/Stage 2 adapter: authentic v2 refuses across OS restarts and local snapshot restore',()=>{
 return (async()=>{
  const dir=temp(),local=join(dir,'receipt.json'),snap=join(dir,'snapshot.json'),log=join(dir,'provider.log');
  const f=await makeRealExecutorBoundReceipt();writeFileSync(local,JSON.stringify(f));cpSync(local,snap);
  for(let i=0;i<3;i++) {
   if(i===2)cpSync(snap,local);
   const p=spawnSync(process.execPath,['tests/support/disabled_executor_worker.mjs',local,dir,log],{encoding:'utf8',windowsHide:true});
   assert.equal(p.status,0,p.stderr);const r=JSON.parse(p.stdout);assert.equal(r.verified,true);assert.equal(r.executed,false);assert.equal(r.reason,refused);assert.equal(r.wrapped,false);assert.equal(r.stage2,refused);
  }
  assert.equal(existsSync(log),false);
 })();
});
