import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStdioClient } from '../../../mcp/stdio-client.mjs';
const proxy = fileURLToPath(new URL('../../../mcp/mnde-mcp-proxy.mjs', import.meta.url));
const fixture = fileURLToPath(new URL('./recording-authority.mjs', import.meta.url));
async function probe(fn) {
  const dir = mkdtempSync(join(tmpdir(),'mnde-f001-'));
  const log = join(dir,'events.jsonl');
  const client = createStdioClient(process.execPath,[proxy],{
    MNDE_PROXY_UPSTREAM_COMMAND:process.execPath,
    MNDE_PROXY_UPSTREAM_ARGS:JSON.stringify([fixture]),
    MNDE_F001_SYNTHETIC_AUTHORITY:'f001-local-fixture', MNDE_F001_LOG:log,
    MNDE_MCP_RECEIPTS_DIR:dir, MNDE_SIDECAR_URL:'http://127.0.0.1:1',
    MNDE_PROXY_UPSTREAM_TIMEOUT_MS:'1500'
  });
  try { await client.request('initialize',{}); await fn(client); await client.request('ping',{}); }
  finally { await client.stop(); }
  const events = existsSync(log) ? readFileSync(log,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : [];
  console.log(JSON.stringify({ evidence:'local-upstream-events', events }));
  return events;
}
test('F-001: disabled proxy never starts an authority-bearing upstream',async()=>{
  const events = await probe(async()=>{});
  assert.equal(events.length,0,'upstream started before any authorization or atomic claim');
});
test('F-001: discovery never transfers inherited authority',async()=>{
  const events = await probe(async c => { await c.request('tools/list',{}); });
  assert.equal(events.filter(e=>e.syntheticAuthority).length,0,'synthetic credential reached upstream without a claim');
});
test('F-001: inspection and lifecycle methods cannot reach an authority-bearing handler',async()=>{
  const events = await probe(async c => {
    for (const method of ['resources/read','prompts/get','resources/list','resources/templates/list','prompts/list']) {
      await c.request(method,{ uri:'fixture://local',name:'fixture' }).catch(()=>{});
    }
    c.notify('notifications/initialized',{});
    c.notify('notifications/cancelled',{requestId:123});
  });
  assert.equal(events.length,0,'protocol names are not a claim boundary');
});
test('F-001: tools, custom requests, notifications and restarts never reach upstream',async()=>{
  for(let restart=0;restart<2;restart++) {
    const events = await probe(async c => {
      const result=await c.request('tools/call',{name:'github.pull_request.merge',arguments:{}});
      assert.equal(result.isError,true);
      await assert.rejects(c.request('custom/write',{}));
      c.notify('tools/call',{name:'github.pull_request.merge',arguments:{}});
      c.notify('custom/write',{});
    });
    assert.equal(events.length,0,'disabled proxy must not acquire upstream capability, even on restart');
  }
});
