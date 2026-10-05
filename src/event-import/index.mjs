import { sha256 } from "../crypto/provider.mjs";
import {
  EXECUTION_REQUEST_SCHEMA,
  validateExecutionRequest
} from "../execution-gate/schema.mjs";

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireObject(value, path) {
  if (!isPlainObject(value)) {
    throw new TypeError(`invalid imported event: ${path} must be an object`);
  }
  return value;
}

function requireString(value, path) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`invalid imported event: ${path} must be a non-empty string`);
  }
  return value;
}

function optionalString(value, path) {
  if (value === undefined) return undefined;
  return requireString(value, path);
}

// A stable, collision-resistant ID that is accepted by the durable execution-ID
// store. Hashing an encoded tuple avoids both unsafe separators and ambiguity
// between values such as ["a-b", "c"] and ["a", "b-c"].
export function importedExecutionId(sourceType, sourceEventId) {
  const type = requireString(sourceType, "source_type");
  const id = requireString(sourceEventId, "source_event_id");
  return `import-${sha256(JSON.stringify([type, id]))}`;
}

// Imported events have not yet passed trusted identity, risk, cost, or approval
// classification. Their defaults therefore make the execution gate refuse even
// if a caller later verifies the principal: unknown security facts must never be
// silently interpreted as low risk.
export function normalizeImportedEvent(source) {
  const event = requireObject(source, "source");
  const actor = requireObject(event.actor, "actor");
  const action = requireObject(event.action, "action");
  const resource = requireObject(event.resource, "resource");
  const evidence = requireObject(event.evidence, "evidence");

  const sourceType = requireString(event.source_type, "source_type");
  const sourceEventId = requireString(event.source_event_id, "source_event_id");
  const command = optionalString(action.command, "action.command");
  const owner = optionalString(resource.owner, "resource.owner");

  const normalized = {
    schema_version: EXECUTION_REQUEST_SCHEMA,
    execution_id: importedExecutionId(sourceType, sourceEventId),
    requested_at: requireString(event.occurred_at, "occurred_at"),

    action: {
      type: requireString(action.type, "action.type"),
      name: requireString(action.name, "action.name"),
      ...(command === undefined ? {} : { command }),
      dry_run: false
    },

    principal: {
      id: requireString(actor.id, "actor.id"),
      type: requireString(actor.type, "actor.type"),
      issuer: requireString(actor.issuer, "actor.issuer"),
      verified: false,
      claims: {}
    },

    resource: {
      kind: requireString(resource.kind, "resource.kind"),
      id: requireString(resource.id, "resource.id"),
      name: requireString(resource.name, "resource.name"),
      ...(owner === undefined ? {} : { owner })
    },

    environment: {
      name: requireString(event.environment, "environment")
    },

    risk: {
      level: "critical",
      destructive: true,
      reversible: false,
      touches_secrets: true,
      touches_customer_data: true,
      blast_radius: "global"
    },

    cost: {
      estimated_cents: Number.MAX_SAFE_INTEGER,
      dimensions: { classification: "unclassified_import" }
    },

    approval: {
      required: true
    },

    evidence: {
      repo: requireString(evidence.repo, "evidence.repo"),
      commit_sha: requireString(evidence.commit_sha, "evidence.commit_sha"),
      branch: requireString(evidence.branch, "evidence.branch")
    }
  };

  const validation = validateExecutionRequest(normalized);
  if (!validation.ok) {
    throw new TypeError(`invalid imported event: ${validation.errors.join("; ")}`);
  }
  return normalized;
}
