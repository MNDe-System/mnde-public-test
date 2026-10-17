// TEST SUPPORT ONLY — wraps the real `pg` driver for fault injection (see faults.mjs).
// The adapter under test, src/freshness/postgres_claim.mjs, is not modified.
import { createRequire } from "node:module";
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const require = createRequire(fileURLToPath(new URL("../../package.json", import.meta.url)));
// Absolute path: a bare "pg" would come straight back through the resolve hook.
const real = require(fileURLToPath(new URL("../../node_modules/pg/lib/index.js", import.meta.url)));
const fault = process.env.MNDE_F001_FAULT ?? "";
const log = (line) => { try { if (process.env.MNDE_F001_LOG) appendFileSync(process.env.MNDE_F001_LOG, `${line}\n`); } catch { /* best effort */ } };
const die = (where) => { log(`SIGKILL@${where}`); process.kill(process.pid, "SIGKILL"); };

export class Client extends real.Client {
  query(config, ...rest) {
    const sql = typeof config === "string" ? config : config?.text ?? "";
    if (fault === "sql-before-claim" && sql.includes("first_claim")) die(fault);
    if (sql === "COMMIT") {
      if (fault === "sql-before-commit") die(fault);
      if (fault === "sql-during-commit") {
        super.query(config, ...rest).catch(() => {});
        die(fault); // COMMIT is already written to the socket; the reply is never read
      }
      if (fault === "sql-after-commit") return super.query(config, ...rest).then((r) => { die(fault); return r; });
      if (fault === "sql-lost-ack") {
        return super.query(config, ...rest).then(() => { log("SIMULATED lost commit acknowledgement"); throw new Error("simulated lost acknowledgement"); });
      }
    }
    return super.query(config, ...rest);
  }
}
export default { ...real, Client };
