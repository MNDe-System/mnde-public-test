import { homedir } from "node:os";
import { join } from "node:path";

// Writable authority material belongs to the current user, outside this source checkout.
process.env.MNDE_HOME ||= join(process.env.LOCALAPPDATA || join(homedir(), "AppData", "Local"), "MNDe", "app-runtime");
await import("./start-sidecar.mjs");
