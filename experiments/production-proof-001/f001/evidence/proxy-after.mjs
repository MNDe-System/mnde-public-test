#!/usr/bin/env node
// Deployment hold: this process must not acquire upstream execution authority.
// No child process, transport, credential client, or forwarding callback exists.
// Discovery is local status only, never an invocation of upstream code.
// Enabling execution requires a separately reviewed claim-consuming dispatcher.

const REASON = 'ERR_FRESHNESS_DEPLOYMENT_DISABLED';
const STATUS_TOOL = Object.freeze({
  name: 'mnde_proxy_status',
  description: 'Read local MNDe proxy status. Upstream execution and discovery are disabled.',
  inputSchema: { type: 'object', properties: {}, additionalProperties: false }
});
const status = Object.freeze({ executionEnabled: false, upstreamStarted: false, reason: REASON });
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const send = message => process.stdout.write(JSON.stringify(message)+'\n');
const result = (id, value) => send({ jsonrpc:'2.0', id, result:value });
const error = (id, code, message) => send({ jsonrpc:'2.0', id, error:{code,message} });

function handle(message) {
  if (!plain(message)) { error(null,-32600,'invalid request'); return; }
  const { id, method, params } = message;
  // Notifications cannot start upstream work (including lifecycle messages).
  if (id === undefined || id === null) return;
  switch(method) {
    case 'initialize':
      result(id, { protocolVersion:'2025-06-18', capabilities:{tools:{listChanged:false}}, serverInfo:{name:'mnde-proxy',version:'0.1.0'}, instructions:'Protected execution is disabled. Only local proxy status is available.' });
      return;
    case 'ping': result(id,{}); return;
    case 'tools/list': result(id,{tools:[STATUS_TOOL]}); return;
    case 'tools/call': {
      if (!plain(params) || typeof params.name !== 'string' || !params.name) {
        error(id,-32602,'tools/call requires a non-empty string name'); return;
      }
      if (params.arguments !== undefined && !plain(params.arguments)) {
        error(id,-32602,'tools/call arguments must be an object'); return;
      }
      if (params.name === STATUS_TOOL.name) {
        if (Object.keys(params.arguments ?? {}).length) { error(id,-32602,'mnde_proxy_status takes no arguments'); return; }
        result(id,{content:[{type:'text',text:JSON.stringify(status)}],isError:false});
        return;
      }
      result(id, { content:[
        {type:'text',text:`FAIL-CLOSED — MNDe blocked ${params.name} (${REASON}). Upstream is not started.`},
        {type:'text',text:JSON.stringify({mnde:{decision:'REFUSE',reason:REASON,executed:false,forwarded:false,receiptPath:null,verified:false,failClosed:true}})}
      ], isError:true });
      return;
    }
    default: error(id,-32601,REASON);
  }
}

let buffer='';
process.stdin.setEncoding('utf8');
process.stdin.on('data',chunk=>{
  buffer+=chunk;
  let newline;
  while((newline=buffer.indexOf('\n'))>=0) {
    const line=buffer.slice(0,newline).trim(); buffer=buffer.slice(newline+1);
    if (!line) continue;
    let message;
    try { message=JSON.parse(line); } catch { error(null,-32700,'parse error'); continue; }
    handle(message);
  }
});
process.stdin.on('end',()=>process.exit(0));
process.stderr.write('[mnde-proxy] protected execution disabled; upstream not started; local status only\n');
