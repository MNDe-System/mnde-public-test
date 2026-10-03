# Receipts and evidence

The Hub's signed policy authorization and the executor's signed execution evidence are separate artifacts. `ALLOW` proves a signed policy decision for exact parameters; it does not prove a network effect. Execution evidence describes what the executor observed and the final outcome, including ambiguity or evidence persistence failure.

`tools/verify.mjs` verifies authorization receipts offline with configured authority and policy trust inputs. It retains historical `ecs.receipt.v2` verification through the preserved compatibility engines. `scripts/verify-git-push-evidence.mjs` verifies the `mnde.execution-evidence.v1` envelope offline. Keep format fields and canonicalization unchanged when promoting future revisions.

The repository includes a **public demo authority manifest and root public key solely for historical compatibility tests**. They are not production trust roots. Production startup rejects the known demo fingerprint and demo/local authority identifiers. Operators must pin independently generated production roots out of band.
