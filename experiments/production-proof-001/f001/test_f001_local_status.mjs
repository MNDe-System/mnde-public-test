import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createStdioClient } from '../../../mcp/stdio-client.mjs';

test('F-001: proxy exposes only truthful local status and refuses alternate calls',async()=>{
  const client=createStdioClient(process.execPath,[fileURLToPath(new URL('../../../mcp/mnde-mcp-proxy.mjs',import.meta.url))],{
    MNDE_PROXY_UPSTREAM_COMMAND:'nonexistent-f001-command',
    MNDE_PROXY_UPSTREAM_ARGS:'not-json',
    MNDE_CLAIM_CONFIG:'nonexistent-f001-config',
    MNDE_PROFILE:'production'
  });
  try {
    const init=await client.request('initialize',{});
    assert.equal(init.serverInfo.name,'mnde-proxy');
    assert.deepEqual((await client.request('tools/list',{})).tools.map(t=>t.name),['mnde_proxy_status']);
    const status=await client.request('tools/call',{name:'mnde_proxy_status',arguments:{}});
    assert.equal(status.isError,false);
    assert.deepEqual(JSON.parse(status.content[0].text),{executionEnabled:false,upstreamStarted:false,reason:'ERR_FRESHNESS_DEPLOYMENT_DISABLED'});
    await assert.rejects(client.request('tools/call',{name:'mnde_proxy_status',arguments:{command:'ignored'}}),/takes no arguments/);
    await assert.rejects(client.request('tools/call',{name:'merge',arguments:[]}),/arguments must be an object/);
    await assert.rejects(client.request('tools/call',{}),/non-empty string name/);
    for (const method of ['resources/read','prompts/get','custom/write']) await assert.rejects(client.request(method,{}),/ERR_FRESHNESS_DEPLOYMENT_DISABLED/);
    for (const name of ['github.pull_request.merge','read_status','restart_service','delete_backups']) {
      const response=await client.request('tools/call',{name,arguments:{claimed:true,production:true}});
      assert.equal(response.isError,true);
      const mnde=JSON.parse(response.content[1].text).mnde;
      assert.deepEqual(mnde,{decision:'REFUSE',reason:'ERR_FRESHNESS_DEPLOYMENT_DISABLED',executed:false,forwarded:false,receiptPath:null,verified:false,failClosed:true});
    }
  } finally { await client.stop(); }
});
