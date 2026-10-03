# Signed approvals

The signed policy bundle can require review. The Hub then exposes `REVIEW` while retaining the signed policy refusal for approval required. An operator supplies existing approval artifacts; the Hub does not sign or invent them. It verifies request binding, scope, expiry, issuer trust, signature, and any policy threshold. Repeated issuer key IDs do not count twice.

Approval only re-evaluates the same durable request. It cannot change repository, remote, target ref, old SHA, source commit, or original expiry. A valid approval can lead to a new signed `ALLOW` authorization; an invalid, wrong-scope, expired, or insufficient set cannot. Operator cancellation ends the workflow and does not forge a signed policy refusal.
