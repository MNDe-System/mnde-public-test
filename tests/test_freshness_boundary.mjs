import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
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
// ── SQLite startup-contention harness ────────────────────────────────────────
// The claim factory is synchronous: once a worker calls it, that process is
// blocked inside SQLite until it returns or throws. The competing writer must
// therefore live in this process, which is the only one still able to release
// it on a timer.
const STARTUP_WORKER = fileURLToPath(new URL('./support/sqlite_claim_startup_worker.mjs', import.meta.url));
const GUARD = new URL('../experiments/exp-001-stage2/tests/_guard.mjs', import.meta.url).href;
const HANDSHAKE_MS = 10000;   // bounded handshake
const WATCHDOG_MS = 20000;    // outer per-case bound
const LOCK_HOLD_MS = 500;     // transient contention, comfortably under busy_timeout=3000
const nowMs = () => Number(process.hrtime.bigint() / 1000000n);
// Same lazy-require convention as claim_store.mjs.
const sqlite = () => createRequire(import.meta.url)('node:sqlite');

// WAL is a property of the file, unlike busy_timeout and synchronous, which are
// per-connection and cannot be observed from a different one.
function journalModeOf(dbPath) {
  const { DatabaseSync } = sqlite();
  const db = new DatabaseSync(dbPath);
  try { return String(db.prepare('PRAGMA journal_mode').get()?.journal_mode ?? '').toLowerCase(); }
  finally { try { db.close(); } catch { /* already closed */ } }
}

// A competing writer holding the exclusive lock the factory needs to switch the
// journal mode. Always released in teardown, whether or not the case got there.
function holdExclusiveLock(dbPath) {
  const { DatabaseSync } = sqlite();
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode=DELETE');
  db.exec('CREATE TABLE IF NOT EXISTS lock_probe(x)');
  db.exec('BEGIN EXCLUSIVE');
  db.exec('INSERT INTO lock_probe VALUES (1)');
  let releasedAt = null;
  return {
    get releasedAt() { return releasedAt; },
    release() {
      if (releasedAt !== null) return releasedAt;
      releasedAt = nowMs();
      try { db.exec('ROLLBACK'); } catch { /* transaction already gone */ }
      try { db.close(); } catch { /* already closed */ }
      return releasedAt;
    }
  };
}

function startupWorker() {
  const proc = spawn(process.execPath, ['--import', GUARD, STARTUP_WORKER], { windowsHide:true, stdio:['ignore','pipe','pipe','ipc'] });
  const inbox=[], waiters=[]; let noise='', exit=null;
  proc.stderr.on('data', b => { noise += b; });
  proc.stdout.on('data', b => { noise += `[unexpected stdout] ${b}`; });   // the worker speaks over IPC only
  proc.on('message', m => { inbox.push(m); pump(); });
  proc.on('error', e => { exit = { spawnError: String(e?.message ?? e) }; pump(); });
  proc.on('exit', (code,signal) => { exit = { code, signal }; pump(); });
  const drop = w => { const i=waiters.indexOf(w); if(i>=0) waiters.splice(i,1); };
  // The two open outcomes are mutually exclusive, so the wrong one is a result,
  // not something to wait out until the watchdog fires.
  const OPPOSITE = { opened:'open-error', 'open-error':'opened' };
  function pump() {
    for (const waiter of [...waiters]) {
      const index = inbox.findIndex(m => m?.type === waiter.type);
      if (index >= 0) { drop(waiter); waiter.settle(null, inbox.splice(index,1)[0]); continue; }
      const contrary = OPPOSITE[waiter.type] ? inbox.find(m => m?.type === OPPOSITE[waiter.type]) : null;
      if (contrary) { drop(waiter); waiter.settle(new Error(`awaiting ${waiter.type} but the worker reported ${JSON.stringify(contrary)}`)); continue; }
      const failure = inbox.find(m => m?.type === 'worker-error');
      if (failure) { drop(waiter); waiter.settle(new Error(`worker reported an error while awaiting ${waiter.type}: ${JSON.stringify(failure)}`)); continue; }
      if (exit) { drop(waiter); waiter.settle(new Error(`worker exited ${JSON.stringify(exit)} before ${waiter.type}; stderr: ${noise}`)); }
    }
  }
  function expect(type, timeoutMs = HANDSHAKE_MS) {
    return new Promise((resolve, reject) => {
      const waiter = { type, settle:(error,value) => { clearTimeout(waiter.timer); if(error) reject(error); else resolve(value); } };
      waiter.timer = setTimeout(() => { drop(waiter); reject(new Error(`timed out after ${timeoutMs}ms awaiting ${type}; inbox ${JSON.stringify(inbox)}; stderr: ${noise}`)); }, timeoutMs);
      waiters.push(waiter); pump();
    });
  }
  return {
    expect,
    send(message) { proc.send(message); },
    async stop() {
      if (!exit) { try { proc.send({ cmd:'exit' }); } catch { /* channel already gone */ } }
      const exited = exit ? Promise.resolve() : new Promise(resolve => proc.on('exit', () => resolve()));
      const forced = setTimeout(() => { try { proc.kill('SIGKILL'); } catch { /* already gone */ } }, 2000);
      await exited; clearTimeout(forced);
      try { proc.disconnect(); } catch { /* already disconnected */ }
    }
  };
}

test('F-001 startup: an uncontended open yields a usable backend whose claim survives reopen',async()=>{
  const dbPath=join(temp(),'startup-uncontended.sqlite');
  const record=deriveClaimRecord(await declaration({executionId:'STARTUP-UNCONTENDED',grant_id:'G-STARTUP-UNCONTENDED'}),{namespace:NS}).record;
  const worker=startupWorker();
  try {
    await worker.expect('ready');
    worker.send({cmd:'open',dbPath});await worker.expect('opening');
    const opened=await worker.expect('opened',WATCHDOG_MS);
    assert.equal(opened.kind,'sqlite');assert.equal(opened.production,false);
    worker.send({cmd:'claim',record});assert.equal((await worker.expect('claimed')).status,'CLAIMED');
    worker.send({cmd:'close'});await worker.expect('closed');
  } finally { await worker.stop(); }
  assert.equal(journalModeOf(dbPath),'wal');
  const reopened=createSqliteClaimBackend({dbPath});
  try { assert.equal(reopened.lookup(record).found,true); } finally { reopened.close(); }
});
test('F-001 startup: a transient startup lock is waited out, not refused',async()=>{
  const dbPath=join(temp(),'startup-transient.sqlite');
  const record=deriveClaimRecord(await declaration({executionId:'STARTUP-TRANSIENT',grant_id:'G-STARTUP-TRANSIENT'}),{namespace:NS}).record;
  const lock=holdExclusiveLock(dbPath);const worker=startupWorker();let timer=null;
  try {
    await worker.expect('ready');
    worker.send({cmd:'open',dbPath});
    const opening=await worker.expect('opening');
    timer=setTimeout(()=>lock.release(),LOCK_HOLD_MS);   // released independently, while the child blocks
    const opened=await worker.expect('opened',WATCHDOG_MS);
    assert.notEqual(lock.releasedAt,null,'the competing writer was never released, so this run proves nothing');
    // An open that returned before meeting the competing writer is not evidence
    // of anything; reject the run rather than count it as a pass.
    assert.ok(opened.durationMs>=LOCK_HOLD_MS/2,
      `open finished in ${opened.durationMs}ms (opening at ${opening.at}, lock released at ${lock.releasedAt}) without waiting for the competing writer: this run did not establish contention`);
    worker.send({cmd:'claim',record});assert.equal((await worker.expect('claimed')).status,'CLAIMED');
    worker.send({cmd:'close'});await worker.expect('closed');
  } finally { if(timer) clearTimeout(timer); lock.release(); await worker.stop(); }
  const reopened=createSqliteClaimBackend({dbPath});
  try { assert.equal(reopened.lookup(record).found,true); } finally { reopened.close(); }
});
test('F-001 startup: a persistent startup lock refuses with BUSY, cleans up, and leaves the process usable',async()=>{
  const dbPath=join(temp(),'startup-persistent.sqlite');
  const record=deriveClaimRecord(await declaration({executionId:'STARTUP-PERSISTENT',grant_id:'G-STARTUP-PERSISTENT'}),{namespace:NS}).record;
  const lock=holdExclusiveLock(dbPath);const worker=startupWorker();
  try {
    await worker.expect('ready');
    worker.send({cmd:'open',dbPath,probeClose:'observe'});await worker.expect('opening');
    const failed=await worker.expect('open-error',WATCHDOG_MS);
    assert.equal(failed.errcodeBase,5,`expected SQLITE_BUSY, got ${JSON.stringify(failed)}`);
    assert.ok(failed.durationMs>=2000,`refused after only ${failed.durationMs}ms: the busy timeout was not in force at the contended statement`);
    // Observed while the opener is still alive; process exit would release the
    // handle regardless and so proves nothing about the factory.
    assert.ok(failed.closes>=1,`the factory left its connection open after a failed initialization: ${JSON.stringify(failed)}`);
    lock.release();
    worker.send({cmd:'open',dbPath});await worker.expect('opening');
    await worker.expect('opened',WATCHDOG_MS);
    worker.send({cmd:'claim',record});assert.equal((await worker.expect('claimed')).status,'CLAIMED');
    worker.send({cmd:'close'});await worker.expect('closed');
  } finally { lock.release(); await worker.stop(); }
});
test('F-001 startup: a failing cleanup never masks the original initialization error',async()=>{
  const dbPath=join(temp(),'startup-cleanup.sqlite');
  const lock=holdExclusiveLock(dbPath);const worker=startupWorker();
  try {
    await worker.expect('ready');
    worker.send({cmd:'open',dbPath,probeClose:'throw'});await worker.expect('opening');
    const failed=await worker.expect('open-error',WATCHDOG_MS);
    assert.ok(failed.closes>=1,'the factory did not attempt cleanup');
    assert.equal(failed.errcodeBase,5,`the cleanup sentinel replaced the initialization error: ${JSON.stringify(failed)}`);
    assert.ok(!/E_PROBE_CLOSE_SENTINEL/.test(failed.message),failed.message);
  } finally { lock.release(); await worker.stop(); }
});
test('F-001/F-002 same-machine model: two OS executors race, one durable claim and fixed provider request',async()=>{
  const f=await setup();const results=await Promise.all([child([f.local,f.db,f.log,'normal']),child([f.local,f.db,f.log,'normal'])]);
  for(const r of results)assert.equal(r.code,0,r.err);
  assert.equal(results.filter(r=>r.result.dispatched).length,1);
  const losers=results.filter(r=>!r.result.dispatched);
  assert.equal(losers.length,1);
  assert.equal(losers[0].result.error,'ERR_AUTHORITY_SPENT',JSON.stringify(losers[0].result));
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
