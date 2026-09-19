// Preserve raw output and the actual exit status; never overwrite evidence.
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
const [label, ...args] = process.argv.slice(2);
if (!/^[a-z0-9-]+$/.test(label ?? '') || !args.length) throw Error('usage: capture.mjs LABEL NODE_ARGS...');
const root = fileURLToPath(new URL('../../../', import.meta.url));
const dir = new URL(`./evidence/${label}/`, import.meta.url);
mkdirSync(dir, { recursive: true });
// Reserve this evidence name before running anything.
writeFileSync(new URL('started.json', dir), JSON.stringify({ command: [process.execPath, ...args], cwd: root, started: new Date().toISOString(), node: process.version }, null, 2)+'\n', { flag: 'wx' });
const result = spawnSync(process.execPath, args, { cwd: root, windowsHide: true, timeout: 240000, maxBuffer: 16*1024*1024 });
const out = result.stdout ?? Buffer.alloc(0), err = result.stderr ?? Buffer.alloc(0);
writeFileSync(new URL('stdout.txt', dir), out, { flag: 'wx' });
writeFileSync(new URL('stderr.txt', dir), err, { flag: 'wx' });
const summary = { exitCode: result.status, signal: result.signal, error: result.error?.message ?? null, stdoutSHA256: createHash('sha256').update(out).digest('hex'), stderrSHA256: createHash('sha256').update(err).digest('hex') };
writeFileSync(new URL('result.json', dir), JSON.stringify(summary, null, 2)+'\n', { flag: 'wx' });
console.log(JSON.stringify({ label, ...summary }));
process.exitCode = result.status ?? 1;
