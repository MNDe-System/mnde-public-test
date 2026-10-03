# MNDe Execution Firewall

MNDe sits between an authenticated agent or caller and a protected effect. This release supports one production effect: **`git.push`**.

```text
caller → MNDe Hub → signed policy decision → executor-bound authorization
       → executor-side gate → PostgreSQL one-use claim → git.push
       → observed remote result → signed execution evidence
```

The Hub begins **locked** on every boot. An authenticated operator must unlock it after readiness checks pass. Required storage, signed policy, trust material, signing keys, executor identity, credential configuration, and the PostgreSQL claim primary must be available; failure refuses execution. Production does not fall back to an in-memory claim backend.

An `ALLOW` decision authorizes an exact request. It is **not proof of execution**. The executor separately verifies the signed authority, repository, remote name and URL, target ref, old SHA, source commit, executor identity, environment, expiry, and one-use claim. It acquires and controls the GitHub credential. The Hub API never returns that credential. The executor observes the remote afterward and persists separate signed execution evidence. Replayed authority and duplicate Hub request IDs are refused. Ambiguous effects are not automatically retried.

## Run and verify

Node.js 24 or newer, Git, and PostgreSQL are required. The `pg` runtime driver is locked in `package-lock.json` and installed by `npm ci`. Deployment requires separately provisioned trust, keys, credentials, durable storage, and the PostgreSQL schema; do not place real secrets in this repository.

The retained `LICENSE` permits evaluation and technical review; production use requires a separate written agreement.

```sh
npm ci
npm test
npm run build
npm run hub
```

The service listens on loopback. See [deployment](docs/deployment.md) before starting a production instance. `bin/mnde-git-push.mjs` is a second caller of the same typed executor for an operator-approved authorization. Verify authorization with `tools/verify.mjs`; verify the observed result with `scripts/verify-git-push-evidence.mjs`. They verify different artifacts.

The source is directly executable; the build check validates its release package and import closure. `npm run test:postgres` is a separate live qualification command for a **disposable test primary** and is not part of the local unit suite.

## Security boundary

MNDe governs only actions routed through its executor. It does not prove universal non-bypassability. If another valid credential has equivalent GitHub write authority outside MNDe, that credential can bypass this firewall. Credential exclusivity must be enforced operationally. Root or administrator compromise, OS tampering, physical extraction of unencrypted storage, database or storage rollback, and sudden power loss are outside the present software proof. The production effect supported here is only `git.push`.

Read [architecture](docs/architecture.md), [Hub operation](docs/hub.md), [Git push](docs/git-push.md), [approvals](docs/approvals.md), [PostgreSQL claims](docs/postgres.md), [receipt formats](docs/receipt-formats.md), [security model](docs/security-model.md), and [known limitations](docs/limitations.md) for the exact behavior and limits.

## Release promotion

Development and adversarial testing remain in `MNDe-System/mnde-public-test`. A release candidate is selected by exact source revision, and only validated production changes are promoted here. This repository runs its own complete suite; release commits are reviewed before any approved tag. Future promotion should itself require MNDe authorization. This repository is for building, running, deploying, verifying, testing, and releasing the supported firewall. See the [release promotion workflow](docs/release-workflow.md).

Initial source revision: `MNDe-System/mnde-public-test` at `178342be20fcc0e4a74afc3ffef91bd00f5900fd`.
