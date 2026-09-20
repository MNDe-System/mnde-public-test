import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStdioClient } from '../mcp/stdio-client.mjs';
const temp=()=>mkdtempSync(join(tmpdir(),'mnde-mcp-freshness-'));
for(const entry of ['mcp/mnde-mcp-server.mjs','mcp/mnde-mcp-proxy.mjs']) {
 test(`F-001 ${entry}: restart refuses tools; discovery remains; proxy unknown requests and notifications cannot bypass`,async()=>{
  const dir=temp(),log=join(dir,'upstream.jsonl');
  const sidecar=http.createServer((req,res)=>{req.resume();res.setHeader('content-type','application/json');res.end(JSON.stringify({decision:'REFUSE',reason_code:'ERR_FRESHNESS_DEPLOYMENT_DISABLED'}));});
  await new Promise(r=>sidecar.listen(0,'127.0.0.1',r));
  try {
   for(let restart=0;restart<2;restart++){
    const client=createStdioClient(process.execPath,[entry],{
     MNDE_SIDECAR_URL:`http://127.0.0.1:${sidecar.address().port}`,MNDE_MCP_RECEIPTS_DIR:dir,
     MNDE_PROXY_UPSTREAM_COMMAND:process.execPath,MNDE_PROXY_UPSTREAM_ARGS:JSON.stringify(['tests/support/recording_upstream.mjs']),MNDE_TEST_UPSTREAM_LOG:log
    });
    try {
     await client.request('initialize',{});
     const discovery=await client.request('tools/list',{});assert.ok(discovery.tools.length);
     const result=await client.request('tools/call',{name:'read_status',arguments:{}});assert.equal(result.isError,true);
     const evidence=JSON.parse(result.content[1].text).mnde;assert.equal(evidence.executed,false);
     client.notify('tools/call',{name:'read_status',arguments:{}});
     client.notify('custom/write',{value:1});
     await assert.rejects(client.request('custom/write',{value:1}));
     await client.request('ping',{}); // FIFO round-trip barrier for notifications
    }finally{await client.stop();}
   }
   if(existsSync(log)) {
    const calls=readFileSync(log,'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(calls.filter(c=>c.method==='tools/call'||c.method==='custom/write').length,0);
   }
  }finally{await new Promise(r=>sidecar.close(r));}
 });
}
