# MNDe Public Test Docs

Start here:

- `first-tester-onboarding.md`
- `mnde-cli-v1-spec.md` - unified `mnde` CLI, first iteration (git/docker-style command tree)
- `execution-firewall-overview.md` - pre-execution authorization layer overview
- `execution-receipt-spec-v1.md`
- `executor-bound-receipts.md`
- `mnde-policy-engine-production-spec-v1.md`
- `production-readiness.md` - includes current Policy Engine implementation slice coverage, and why a runtime-health refusal replaces a decision-specific one
- `independent-verification.md`
- `integration-guide.md`
- `openclaw-integration-spec.md`
- `demo-scenarios.md`
- `tester-id-implementation.md`
- `feedback-workflow.md`

Release and safety review:

- `APPROVAL-GATE.md` - what a human approves in MNDe's self-maintenance loop, and what the code enforces without one
- `F001-CLAIM-STORE-PROOF.md` - what the durable single-use claim store was proven to do against a real PostgreSQL primary, and what remains open on F-001
- `F001-REASSESSMENT.md` - F-001 asked again against the merged typed effect, question by question: what is established, what is only indicated, and the exact blockers that remain
- `GIT-PUSH-EFFECT.md` - the first narrow typed production effect: what it does, the order it does it in, and what it does not establish
- `PRODUCTION-TRUST-BOUNDARY.md` - what the git.push executor trusts, where its push credential and trust material come from, how to deploy it under its own OS identity, and what is still not enforced in code
- `NEXT-MILESTONES.md` - ranked assessment of what MNDe needs next: required security work separated from optional product work
- `UC-002-SECURITY-REVIEW.md` - the approval-gate fail-open, the guarded-issuance fix, the caller matrix, compatibility and migration
- `F001-ACCEPTANCE-MATRIX.md` - F-001 requirement by requirement: ESTABLISHED / PARTIALLY / NOT / BLOCKED, with the exact action that closes each, and the pending action
- `F001-PROOF-PROTOCOL.md` - the operator procedure for the independent-database and GitHub-push proof (written, not executed)
- `AUTHORITY-BUNDLE-PUBLICATION-PLAN.md` - what an external verifier needs and a plan to publish and rotate the trust root (a plan; nothing published)
- `KNOWN-ISSUES.md` - problems carried rather than fixed, each with why it is safe to defer, plus the findings whose classification is still open and the ones that have since been closed
- `release-891ceda-onboarding.md`
- `release-checklist.md`
- `security-review-checklist.md`
