import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createAdapter } from '../experiments/exp-001-stage2/src/adapter.mjs';
import { createOfflineAdapter } from './support/offline_freshness_adapter.mjs';
import { verifyDeclaration, testOnlyVerifiedDeclaration, makeAPlus } from '../experiments/exp-001-stage2/src/declaration.mjs';
import { deriveClaimRecord } from '../experiments/exp-001-stage2/src/freshness.mjs';
import { createSqliteClaimBackend } from '../experiments/exp-001-stage2/src/claim_store.mjs';
import { makeRealExecutorBoundReceipt, makeRealSignedReceipt } from '../experiments/exp-001-stage2/tests/_real_receipt.mjs';
import { canonicalizeJson } from '../shared/json.ts';
import { openExecutorClaimBackend } from '../src/freshness/postgres_claim.mjs';
const NS = 'freshness-regression';
const config = { owner: 'mnde-labs', repo: 'exp-001', target_ref: 'main', namespace: NS };
const temp = () => mkdtempSync(join(tmpdir(), 'mnde-freshness-'));
async function fixture(over = {}) {
  const f = await makeRealExecutorBoundReceipt(over);
  f.trustedConfig.namespace = NS;
  return f;
}
async function declaration(over = {}) { const f = await fixture(over); return verifyDeclaration(f.receipt, f.trustedConfig); }
const spy = () => { const calls=[]; return { calls, transport: async request => { calls.push(request); return { status:200 }; } }; };
const eventsAt = p => existsSync(p) ? readFileSync(p,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : [];
function child(args) {
  return new Promise((resolve,reject) => {
    const p=spawn(process.execPath, ['--import', new URL('../experiments/exp-001-stage2/tests/_guard.mjs', import.meta.url).href, fileURLToPath(new URL('./support/freshness_worker.mjs',import.meta.url)), ...args], { windowsHide:true, stdio:['ignore','pipe','pipe'] });
    let out='',err='';p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('error',reject);
    p.on('close',code=>resolve({code,out,err,result:out ? JSON.parse(out):null}));
  });
}
async function setup() {
  const dir=temp(), db=join(dir,'backend.sqlite'), local=join(dir,'executor.json'), log=join(dir,'provider.jsonl');
  createSqliteClaimBackend({dbPath:db}).close();
  writeFileSync(local,JSON.stringify(await fixture()));
  return {dir,db,local,log};
}

test('F-001/F-002: production backend substitution and copied flags never call provider', async()=>{
  const decl=await declaration();let claims=0;const t=spy();
  const fake={production:true,kind:'remote-postgresql',health:()=>({ok:true}),claim:()=>{claims++;return {status:'CLAIMED'};}};
  for(const cfg of [undefined, {...config,requireProductionBackend:true}, {...config,requireProductionBackend:false}]) {
    const adapter=createAdapter({config:cfg,claimBackend:fake,transport:t.transport,claimed:true});
    for(const value of [decl, {...decl}, {verified:true,claimed:true}, testOnlyVerifiedDeclaration(makeAPlus())]) {
      assert.equal((await adapter.attemptMerge(value)).error,'ERR_FRESHNESS_DEPLOYMENT_DISABLED');
    }
  }
  assert.equal(claims,0);assert.equal(t.calls.length,0);
});
test('F-002: production factory rejects injected backend/config; absent or corrupt trusted file refuses', async()=>{
  await assert.rejects(openExecutorClaimBackend({production:true}),/ERR_BACKEND_SUBSTITUTION/);
  const old=process.env.MNDE_CLAIM_CONFIG;
  try {
    delete process.env.MNDE_CLAIM_CONFIG;
    await assert.rejects(openExecutorClaimBackend(),/ERR_CLAIM_CONFIG/);
    const p=join(temp(),'config.json');writeFileSync(p,'{"production":true}');process.env.MNDE_CLAIM_CONFIG=p;
    await assert.rejects(openExecutorClaimBackend(),/ERR_CLAIM_CONFIG/);
  } finally { if(old===undefined) delete process.env.MNDE_CLAIM_CONFIG; else process.env.MNDE_CLAIM_CONFIG=old; }
});
test('F-001: verification snapshots before await, freezes identities, hashes canonical A+', async()=>{
  const f=await fixture();const pending=verifyDeclaration(f.receipt,f.trustedConfig);
  f.receipt.receipt.canonical_request='{}';f.trustedConfig.namespace='attacker';
  const decl=await pending;assert.equal(decl.ok,true);
  const record=deriveClaimRecord(decl,{namespace:NS});assert.equal(record.ok,true);
  assert.equal(record.record.aplus_digest,createHash('sha256').update(canonicalizeJson(decl.declaration)).digest('hex'));
  for(const field of ['grant_id','subject','executionId']) assert.throws(()=>decl.declaration[field]='attacker',TypeError);
  assert.throws(()=>decl.trust.executor_id='attacker',TypeError);
  assert.throws(()=>decl.receiptHash='attacker',TypeError);
  assert.equal(deriveClaimRecord({...decl},{namespace:NS}).ok,false);
});
test('F-001: absent/null/empty/non-string grant IDs and null execution IDs refuse',async()=>{
  for(const grant_id of [null,'',0,[],{}]) assert.equal((await declaration({grant_id})).ok,false,JSON.stringify(grant_id));
  assert.equal((await declaration({executionId:null})).ok,false);
  assert.equal((await declaration({omitGrant:true})).ok,false);
  assert.equal((await declaration({expires_at:null})).ok,false);
});
test('F-001: expiry, revoked grant, wrong executor, policy-only and wrong namespace refuse',async()=>{
  assert.equal((await declaration({expires_at:'2026-01-01T00:00:00.000Z'})).reason,'ERR_AUTHORITY_EXPIRED');
  const f=await fixture();
  assert.equal((await verifyDeclaration(f.receipt,{...f.trustedConfig,now:'2027-02-01T00:00:00.000Z'})).ok,false);
  assert.equal((await verifyDeclaration(f.receipt,{...f.trustedConfig,revokedGrantIds:['grant:EXP001S2-EXEC-1']})).reason,'ERR_GRANT_REVOKED');
  assert.equal((await verifyDeclaration(f.receipt,{...f.trustedConfig,expectedExecutorId:'wrong'})).ok,false);
  assert.equal((await verifyDeclaration(f.receipt,{...f.trustedConfig,expectedExecutorId:null})).ok,false);
  const policy=await makeRealSignedReceipt();assert.equal((await verifyDeclaration(policy.receipt,policy.trustedConfig)).ok,false);
  const t=spy();const b=createSqliteClaimBackend({dbPath:join(temp(),'db')});
  const r=await createOfflineAdapter({config:{...config,namespace:'wrong'},transport:t.transport,claimBackend:b}).attemptMerge(await declaration());
  assert.equal(r.error,'ERR_NAMESPACE_MISMATCH');assert.equal(t.calls.length,0);b.close();
});
test('F-001/F-002 model: duplicates independently spend execution/grant, including altered action',async()=>{
  const b=createSqliteClaimBackend({dbPath:join(temp(),'db')});const t=spy();const adapter=createOfflineAdapter({config,transport:t.transport,claimBackend:b});
  const first=await declaration({executionId:'E',grant_id:'G'});assert.equal((await adapter.attemptMerge(first)).dispatched,true);
  for(const over of [{executionId:'E',grant_id:'different'},{executionId:'different',grant_id:'G'},
    {executionId:'E',grant_id:'G',parameters:{repository:first.declaration.repository,pull_request:18,expected_source_sha:'c'.repeat(40),target_ref:'main',expected_target_sha:'b'.repeat(40),merge_method:'merge'}}]) {
    const d=await declaration(over);const r=await adapter.attemptMerge(d);assert.equal(r.dispatched,false);
  }
  assert.equal(t.calls.length,1);b.close();
});
test('F-001/F-002 model: faults, timeout, lost acknowledgement, inconsistent lookup never send',async()=>{
  const d=await declaration();
  const good=createSqliteClaimBackend({dbPath:join(temp(),'db')});
  const faults=[undefined,{health:()=>({ok:false})},{health:()=>{throw Error('outage');}},
    {health:async()=>({ok:true}),claim:()=>{throw Error('timeout');},lookup:()=>({found:false})},
    {health:()=>({ok:true}),claim:async r=>{await good.claim(r);throw Error('lost ack');},lookup:r=>good.lookup(r)},
    {health:()=>({ok:true}),claim:()=>({status:'CLAIMED',record:{}})},
    {health:()=>({ok:true}),claim:()=>{throw Error('timeout');},lookup:()=>({found:true,record:{inconsistent:true}})},
    {health:()=>({ok:true}),claim:()=>({status:'MAYBE'})}];
  for(const b of faults){const t=spy();assert.equal((await createOfflineAdapter({config,transport:t.transport,claimBackend:b}).attemptMerge(d)).dispatched,false);assert.equal(t.calls.length,0);}
  good.close();
});
test('F-001/F-002 same-machine model: two OS executors race, one durable claim and fixed provider request',async()=>{
  const f=await setup();const results=await Promise.all([child([f.local,f.db,f.log,'normal']),child([f.local,f.db,f.log,'normal'])]);
  for(const r of results)assert.equal(r.code,0,r.err);
  assert.equal(results.filter(r=>r.result.dispatched).length,1);
  const attempts=eventsAt(f.log).filter(r=>r.type==='dispatch-attempt');assert.equal(attempts.length,1);
  assert.deepEqual(attempts[0].request,{method:'PUT',path:'/repos/mnde-labs/exp-001/pulls/17/merge',body:{sha:'a'.repeat(40),merge_method:'merge'}});
  const observedOutcome={type:'observed-outcome',source:'model-provider-state-read',merged:eventsAt(f.log).some(r=>r.type==='model-provider-effect')};
  assert.equal(observedOutcome.merged,true);writeFileSync(join(f.dir,'observation.json'),JSON.stringify(observedOutcome));
  assert.equal(eventsAt(f.log).filter(r=>r.type==='provider-response').length,1);
  const b=createSqliteClaimBackend({dbPath:f.db});assert.equal(b.lookup(deriveClaimRecord(await declaration(),{namespace:NS}).record).found,true);b.close();
});
test('F-001/F-002 same-machine model: restart and restored executor snapshot cannot resend',async()=>{
  const f=await setup();const snap=join(f.dir,'snapshot.json');cpSync(f.local,snap);
  assert.equal((await child([f.local,f.db,f.log,'normal'])).result.dispatched,true);
  assert.equal((await child([f.local,f.db,f.log,'normal'])).result.error,'ERR_AUTHORITY_SPENT');
  cpSync(snap,f.local);
  assert.equal((await child([f.local,f.db,f.log,'normal'])).result.error,'ERR_AUTHORITY_SPENT');
  assert.equal(eventsAt(f.log).filter(r=>r.type==='dispatch-attempt').length,1);
});
for(const [mode,code,count] of [['before-claim',22,1],['after-claim',23,0],['after-start',24,1]]) {
  test(`F-001/F-002 same-machine model: process crash ${mode}, recovery never resends uncertain attempt`,async()=>{
    const f=await setup();assert.equal((await child([f.local,f.db,f.log,mode])).code,code);
    const recovery=await child([f.local,f.db,f.log,'normal']);assert.equal(recovery.code,0,recovery.err);
    assert.equal(recovery.result.dispatched,mode==='before-claim');
    const events=eventsAt(f.log);assert.equal(events.filter(r=>r.type==='dispatch-attempt').length,count);
    assert.equal(events.filter(r=>r.type==='provider-response').length,mode==='before-claim'?1:0);
    if(mode==='after-start') assert.equal(events.filter(r=>r.type==='model-provider-effect').length,1);
  });
}

test('F-001: conflicting signed execution/grant aliases refuse',async()=>{
  const base=await declaration();
  const er={request_id:'A',release_request:{execution_id:'B',grant_id:'G2'},grant_id:'G1',actor:{user_id:'s'},tool_calls:[{tool:'github.pull_request.merge',parameters:{repository:base.declaration.repository,pull_request:17,expected_source_sha:'a'.repeat(40),target_ref:'main',expected_target_sha:'b'.repeat(40),merge_method:'merge'}}]};
  assert.equal((await declaration({requestPatch:{request_id:'A',grant_id:'G1',execution_request:er}})).reason,'ERR_AUTHORITY_IDENTITY');
  er.release_request.execution_id='A';
  assert.equal((await declaration({requestPatch:{execution_request:er}})).reason,'ERR_AUTHORITY_IDENTITY');
});
test('F-001: signed revocation after receipt issuance blocks new execution authority',async()=>{
  const f=await fixture({revocation:[{key_id:'mnde-exp001s2-authority-receipt',revoked_at:'2026-07-01T00:00:00.000Z'}]});
  const result=await verifyDeclaration(f.receipt,{...f.trustedConfig,now:'2026-08-01T00:00:00.000Z'});
  assert.equal(result.ok,false);assert.equal(result.reason,'ERR_CURRENT_KEY_UNTRUSTED');
});
