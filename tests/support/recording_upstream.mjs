// Recording upstream used only by the protocol-boundary regression.
import { appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
const log=process.env.MNDE_TEST_UPSTREAM_LOG;
const rl=createInterface({input:process.stdin});
rl.on('line',line=>{
 const m=JSON.parse(line);appendFileSync(log,JSON.stringify({method:m.method})+'\n');
 if(m.id!==undefined)process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:m.method==='tools/list'?{tools:[{name:'read_status',inputSchema:{type:'object'}}]}:{}})+'\n');
});
