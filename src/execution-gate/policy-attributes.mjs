// Policy attribute extraction for execution gate requests.
//
// Produces a flat key-value map from a validated execution request. This map is
// the surface exposed to policy engines for attribute-based matching. All keys
// are dotted paths; values are the raw field values (string, boolean, or number).
// Optional fields that are absent produce an undefined entry (omitted from the
// result) — callers that need a missing-field check should use `hasOwnProperty`.

export function extractPolicyAttributes(req) {
  const attrs = {};

  // action
  attrs["action.type"] = req.action?.type;
  attrs["action.name"] = req.action?.name;
  attrs["action.dry_run"] = req.action?.dry_run;

  // principal
  attrs["principal.id"] = req.principal?.id;
  attrs["principal.type"] = req.principal?.type;
  attrs["principal.issuer"] = req.principal?.issuer;
  attrs["principal.verified"] = req.principal?.verified;

  // resource
  attrs["resource.kind"] = req.resource?.kind;
  attrs["resource.id"] = req.resource?.id;
  attrs["resource.name"] = req.resource?.name;

  // environment
  attrs["environment.name"] = req.environment?.name;

  // risk
  attrs["risk.level"] = req.risk?.level;
  attrs["risk.destructive"] = req.risk?.destructive;
  attrs["risk.reversible"] = req.risk?.reversible;
  attrs["risk.touches_secrets"] = req.risk?.touches_secrets;
  attrs["risk.touches_customer_data"] = req.risk?.touches_customer_data;
  attrs["risk.blast_radius"] = req.risk?.blast_radius;

  // cost
  attrs["cost.estimated_cents"] = req.cost?.estimated_cents;

  // evidence
  attrs["evidence.repo"] = req.evidence?.repo;
  attrs["evidence.commit_sha"] = req.evidence?.commit_sha;
  attrs["evidence.branch"] = req.evidence?.branch;
  if (req.evidence?.workflow_run_id !== undefined) attrs["evidence.workflow_run_id"] = req.evidence.workflow_run_id;
  if (req.evidence?.artifact_digest !== undefined) attrs["evidence.artifact_digest"] = req.evidence.artifact_digest;

  // approval
  attrs["approval.required"] = req.approval?.required;
  if (req.approval?.approval_id !== undefined) attrs["approval.approval_id"] = req.approval.approval_id;
  if (req.approval?.approver_principal !== undefined) attrs["approval.approver_principal"] = req.approval.approver_principal;

  // Remove undefined entries (absent optional fields)
  for (const key of Object.keys(attrs)) {
    if (attrs[key] === undefined) delete attrs[key];
  }

  return attrs;
}
