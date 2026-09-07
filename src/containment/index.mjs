import { canonicalizeJson } from "../../shared/json.ts";
import { sha256 } from "../crypto/provider.mjs";

export const CONTAINMENT_MANIFEST_SCHEMA = "mnde.containment-manifest.v1";
export const CONTAINMENT_EVIDENCE_SCHEMA = "mnde.containment-evidence.v1";

export const CONTAINMENT_CAPABILITIES = Object.freeze({
  SAFE: Object.freeze([
    "compute.local",
    "filesystem.read.private",
    "filesystem.write.private",
    "memory.session",
    "observability.read"
  ]),
  BLOCKED: Object.freeze([
    "audit.modify",
    "control_plane.modify",
    "credentials.read",
    "credentials.write",
    "external.publish",
    "filesystem.read.host",
    "filesystem.write.host",
    "filesystem.write.shared",
    "host.admin",
    "inter_agent.communicate",
    "model_weights.read",
    "model_weights.write",
    "monitoring.modify",
    "network.egress",
    "network.listen",
    "package.install",
    "persistence.create",
    "process.spawn",
    "sandbox.modify",
    "secrets.access"
  ])
});

const SAFE_CAPABILITIES = new Set(CONTAINMENT_CAPABILITIES.SAFE);
const KNOWN_CAPABILITIES = new Set([
  ...CONTAINMENT_CAPABILITIES.SAFE,
  ...CONTAINMENT_CAPABILITIES.BLOCKED
]);

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function copyAndValidateManifest(manifest) {
  if (!isPlainObject(manifest) || manifest.schema_version !== CONTAINMENT_MANIFEST_SCHEMA || !isPlainObject(manifest.tools)) {
    return { ok: false, reason: "ERR_CONTAINMENT_MANIFEST_INVALID" };
  }

  const tools = {};
  for (const [toolName, rawCapabilities] of Object.entries(manifest.tools)) {
    if (typeof toolName !== "string" || toolName.length === 0 || !Array.isArray(rawCapabilities) || rawCapabilities.length === 0) {
      return { ok: false, reason: "ERR_CONTAINMENT_MANIFEST_INVALID" };
    }
    if (rawCapabilities.some((capability) => typeof capability !== "string" || !KNOWN_CAPABILITIES.has(capability))) {
      return { ok: false, reason: "ERR_CONTAINMENT_MANIFEST_INVALID" };
    }
    const capabilities = [...new Set(rawCapabilities)].sort();
    if (capabilities.length !== rawCapabilities.length) {
      return { ok: false, reason: "ERR_CONTAINMENT_MANIFEST_INVALID" };
    }
    tools[toolName] = capabilities;
  }

  const normalized = { schema_version: CONTAINMENT_MANIFEST_SCHEMA, tools };
  return {
    ok: true,
    manifest: normalized,
    manifestDigest: `sha256:${sha256(canonicalizeJson(normalized))}`
  };
}

export function createContainmentGuard({ mode = "off", manifest } = {}) {
  if (mode !== "off" && mode !== "strict") {
    throw new TypeError("containment mode must be 'off' or 'strict'");
  }

  if (mode === "off") {
    return Object.freeze({
      mode,
      assess() {
        return { ok: true, mode, evidence: null };
      }
    });
  }

  const checked = copyAndValidateManifest(manifest);
  if (!checked.ok) {
    return Object.freeze({
      mode,
      assess() {
        return { ok: false, mode, reason: checked.reason };
      }
    });
  }

  const manifestSnapshot = checked.manifest;
  const manifestDigest = checked.manifestDigest;
  return Object.freeze({
    mode,
    manifestDigest,
    assess(action) {
      if (typeof action !== "string" || action.length === 0) {
        return { ok: false, mode, reason: "ERR_CONTAINMENT_ACTION_INVALID" };
      }
      if (!Object.hasOwn(manifestSnapshot.tools, action)) {
        return { ok: false, mode, reason: "ERR_CONTAINMENT_TOOL_UNREGISTERED" };
      }

      const capabilities = manifestSnapshot.tools[action];
      const blockedCapability = capabilities.find((capability) => !SAFE_CAPABILITIES.has(capability));
      if (blockedCapability) {
        return {
          ok: false,
          mode,
          reason: "ERR_CONTAINMENT_CAPABILITY_BLOCKED",
          capability: blockedCapability
        };
      }

      return {
        ok: true,
        mode,
        evidence: {
          schema_version: CONTAINMENT_EVIDENCE_SCHEMA,
          mode,
          action,
          capabilities: [...capabilities],
          manifest_digest: manifestDigest
        }
      };
    }
  });
}

