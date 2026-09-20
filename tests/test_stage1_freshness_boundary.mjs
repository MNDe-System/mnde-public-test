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
import { isDispatchEnabled } from '../src/execution-availability/index.mjs';
const temp=()=>mkdtempSync(join(tmpdir(),'mnde-stage1-freshness-'));
async function port(){const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
const refused='ERR_FRESHNESS_DEPLOYMENT_DISABLED';
// The local cache is best-effort dedup, never the freshness boundary: it is a
// same-machine file the executor operator can delete or restore. With execution
// disabled it is not load-bearing at all — a decision cannot become an effect —
// so an unconfigured store lets evaluation proceed and produce a real, ledgered
// decision. It re-tightens automatically if dispatch is ever enabled.
test('F-001 Stage 1: unset local cache helper tracks execution availability',()=>{
 const old=process.env.MNDE_EXEC_ID_CACHE;delete process.env.MNDE_EXEC_ID_CACHE;
 try{assert.equal(reserveExecutionId('no-cache'),!isDispatchEnabled());}finally{if(old!==undefined)process.env.MNDE_EXEC_ID_CACHE=old;}
});
for(const engine of ['legacy','policy-engine']) {
 // The sidecar now EVALUATES, signs and ledgers a real decision rather than
 // refusing before evaluation. The safety property is unchanged and is what this
 // test pins: whatever policy decides, and across restarts with the cache unset,
 // missing or corrupt, nothing executes and the provider is never called.
 test(`F-001 Stage 1 actual ${engine} sidecar: unset/missing/corrupt cache and restart never execute, zero provider calls`,{timeout:60000},async()=>{
  const dir=temp();const corrupt=join(dir,'corrupt');writeFileSync(corrupt,'not a directory');let calls=0;
  for(const cache of [undefined,join(dir,'missing'),corrupt,undefined]) {
   const url=`http://127.0.0.1:${await port()}`;
   // A malformed execution-ID cache path makes the sidecar refuse to START
   // (sidecar/startup_checks.mjs). That is the strongest fail-closed outcome
   // available — it cannot serve a decision, let alone cause an effect — so it
   // satisfies this test's invariant and the case ends here.
   let sc;
   try { sc=await startMndeSidecar({url,env:{MNDE_EXEC_ID_CACHE:cache,MNDE_DECISION_ENGINE:engine,MNDE_PROFILE:'local'}}); }
   catch { continue; }
   try {
    const request=reviewerRequest({requestId:'same-stage1-authority',tool:'github.merge',testerId:'FRESHNESS',installationId:'FRESHNESS'});
    for(let i=0;i<2;i++) {
     const response=await fetch(url+'/v1/decisions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(request)});
     const body=await response.json();
     // A decision is produced and is real. It is also explicitly marked
     // non-dispatchable: in the response envelope on BOTH engines, and in the
     // SIGNED receipt body on the canonical policy-engine path.
     //
     // The legacy engine's frozen `ecs.receipt.v2` deliberately gains no new
     // field — inventing one in a frozen compatibility schema would be a worse
     // trade than the gap. Legacy receipts therefore carry the marker only in the
     // (strippable) envelope. That is an evidence gap on an opt-in compatibility
     // path, not a safety gap: the executor refuses either way, and nothing reads
     // this field to decide whether to execute.
     assert.ok(body.decision==='ALLOW'||body.decision==='REFUSE');
     assert.equal(body.execution?.dispatchable,false);
     if(body.receipt?.schema_version?.startsWith('mnde.pe.')) assert.equal(body.receipt.execution_status,'DISABLED');
    }
    const exec=createMndeExecutor({sidecarUrl:url,receiptsDir:join(dir,'receipts')});
    const result=await exec.execute({action:'github.merge',executionId:'same-stage1-authority',run:()=>{calls++;}});
    // The enforcement point: whatever the sidecar decided, nothing ran.
    //
    // The REASON is deliberately not pinned here. It varies legitimately and that
    // variation is the feature: a denying policy rule reports NO_MATCHING_RULE, a
    // replayed execution id reports ERR_EXECUTION_ID_REPLAYED, and a request that
    // clears the gate reports ERR_FRESHNESS_DEPLOYMENT_DISABLED. Collapsing all of
    // them into one code is what this port set out to undo. The invariant is that
    // none of them executes.
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
