// Test-time network guard. Imported via `node --import` before any test module,
// so an accidental real network call fails immediately. Everything in Stage 2's
// offline build uses injected stubs; nothing here should ever egress.

import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";

function blocked(what) {
  return () => { throw new Error(`E_NETWORK_BLOCKED: ${what} is disabled in EXP-001 Stage 2 offline tests`); };
}

// fetch throws synchronously so `assert.throws` catches it.
globalThis.fetch = blocked("fetch");

http.request = blocked("http.request");
http.get = blocked("http.get");
https.request = blocked("https.request");
https.get = blocked("https.get");
net.connect = blocked("net.connect");
net.createConnection = blocked("net.createConnection");
tls.connect = blocked("tls.connect");
