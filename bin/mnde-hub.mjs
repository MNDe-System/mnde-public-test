#!/usr/bin/env node
import { startHub } from "../src/hub/service.mjs";

try {
  const hub = await startHub();
  let closing = false;
  const close = () => {
    if (closing) return;
    closing = true;
    hub.close().then(() => { process.exitCode = 0; }, () => { process.exitCode = 1; });
  };
  process.on("SIGTERM", close);
  process.on("SIGINT", close);
} catch {
  process.stderr.write("MNDe Hub startup failed; check deployment configuration.\n");
  process.exitCode = 1;
}
