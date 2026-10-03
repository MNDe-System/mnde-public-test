# Scoped security claims

| Claim | Implemented boundary | Limit |
| --- | --- | --- |
| The Hub starts locked and relocks on reboot. | `src/hub/state.mjs` writes a locked epoch at startup; the executor reads it. | An administrator or compromised host is outside the boundary. |
| Production `git.push` authority is single-use. | The typed executor requires a PostgreSQL first claim before dispatch. | Database rollback by its owner remains possible. |
| A push is bound to an exact effect. | Signed authority, configured repository and remote, target ref, old SHA, source commit, executor, and environment are checked. | Other GitHub write credentials can bypass MNDe. |
| An ambiguous action is never automatically retried. | A spent claim and execution-start record distinguish refusal, observed outcome, and `INDETERMINATE`. | Sudden power loss and storage rollback need further qualification. |
| Authorization and execution are evidenced separately. | Signed policy authorization and signed execution evidence have distinct verification paths. | An `ALLOW` receipt alone proves no GitHub mutation. |
| Production credentials are executor-owned. | The GitHub credential provider is opened inside `src/effects/git-push/index.mjs`. | Operational credential exclusivity is required. |

The supported production effect in this release is `git.push`. No universal non-bypassability claim is made. Tests use isolated claim adapters; real PostgreSQL and hardware qualification are separate release gates.
