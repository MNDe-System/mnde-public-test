// Policy drafting layer.
//
// Enumerates tools, inspects schemas, categorizes capabilities, and produces a
// RECOMMENDATION. It never approves tools, never modifies an active policy, and
// never enables permissions. Output is a draft for explicit human review.
//
// This is not the authority policy engine. MNDe does not enforce policy.draft.json.

const DESTRUCTIVE = /\b(delete|destroy|drop|wipe|format|shutdown|reboot|kill|terminate|rm|rmdir|unlink|truncate)\b/;
const MUTATING = /\b(write|update|create|modify|patch|put|post|exec|execute|run|spawn|shell|command|deploy|install|publish|transfer|pay|refund|charge|send|move|rename|chmod|chown)\b/;
const READ_ONLY = /\b(read|list|get|status|search|fetch|query|describe|show|view|inspect|count|head|stat|ls|cat)\b/;

// Deterministic capability classification of a single tool.
export function categorizeTool(tool) {
  const text = `${tool?.name ?? ""} ${tool?.description ?? ""} ${JSON.stringify(tool?.inputSchema ?? {})}`
    .toLowerCase()
    .replace(/[_-]+/g, " ");
  if (DESTRUCTIVE.test(text)) return { capability: "destructive", recommended: "deny" };
  if (MUTATING.test(text)) return { capability: "mutating", recommended: "approval" };
  if (READ_ONLY.test(text)) return { capability: "read-only", recommended: "allow" };
  return { capability: "unclassified", recommended: "deny" };
}

// servers: [{ name, client?, tools?: [{ name, description, inputSchema }] }]
// `tools` is present only when a caller enumerated them (e.g. via an MCP probe).
// Pure and deterministic given identical input.
export function draftPolicy(servers, options = {}) {
  const generatedAt = options.now ?? new Date().toISOString();
  const entries = (servers ?? []).map((server) => {
    const toolsEnumerated = Array.isArray(server.tools);
    const tools = toolsEnumerated
      ? server.tools.map((tool) => ({ tool: tool.name, ...categorizeTool(tool) }))
      : [];
    return {
      server: server.name,
      client: server.client ?? null,
      tools_enumerated: toolsEnumerated,
      tools,
      note: toolsEnumerated ? null : "Tools not enumerated. Run with --probe, or fill in tool rules before activation."
    };
  });
  return {
    schema_version: "mnde.policy.draft.v1",
    generated_at: generatedAt,
    default_decision: "REFUSE",
    review_required: true,
    note: "DRAFT ONLY — NOT ACTIVE. MNDe does not enforce this file. Review every recommendation and convert it into an explicit, versioned policy before enabling enforcement.",
    servers: entries,
    summary: {
      servers: entries.length,
      tools_recommended_allow: entries.reduce((n, e) => n + e.tools.filter((t) => t.recommended === "allow").length, 0),
      tools_recommended_approval: entries.reduce((n, e) => n + e.tools.filter((t) => t.recommended === "approval").length, 0),
      tools_recommended_deny: entries.reduce((n, e) => n + e.tools.filter((t) => t.recommended === "deny").length, 0)
    }
  };
}
