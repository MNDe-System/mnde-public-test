# MNDe Hub: first Pi prototype

MNDe Hub is a headless Node service around MNDe's existing execution firewall.
It accepts typed `git.push` requests, evaluates a provisioned signed policy,
produces an executor-bound authorization, and calls `createGitPushExecutor`.
It does not construct Git commands, hold a second claim store, accept a caller's
executor or claim backend, or retry an execution. Decision receipts and signed
execution evidence keep their existing formats and distinct meanings.

## Trust boundary and limitations

The agent has an API credential, not the GitHub push credential. The existing
executor-owned credential provider reads/mints the push credential on the Hub;
the Hub API never returns that credential, raw executor errors, local evidence
paths, Git stderr, configuration, or environment variables. Normal logs are
fixed event names, timestamps and server-validated UUIDs. Receipt signing and
executor identity keys are separate existing trust roles. Keep the root and
policy/approval private keys off the running appliance.

**The Hub does not make MNDe non-bypassable if another valid credential still
exists outside the Hub.** Production must eventually give the Hub the only
credential authorized to perform the protected action. GitHub permissions and
repository rules must enforce this operationally; merely moving a token does
not revoke other credentials. This PR neither creates nor rotates real keys.

The boundary protects against an agent submitting malformed, unapproved,
replayed, misbound, or locked requests. It does not protect against root or the
Hub service account being compromised, physical extraction of unencrypted
storage, malicious administrator policy, a compromised GitHub account, other
valid push credentials, or a tampered operating system. API operators are
trusted to lock/unlock and reject requests; they cannot turn REVIEW into ALLOW
without a valid existing signed approval. Policies that require additional
authority grants will refuse: this first API does not accept grant attachments.

## Architecture and Pi target

Use Raspberry Pi OS Lite 64-bit on a Pi 3 with Ethernet, Node **24 or newer**
(the repository's native TypeScript runtime requirement), Git, and the `pg`
driver installed in the executor runtime. No Docker or desktop stack is needed.
One Hub process admits one action at a time and caps connections at 16, request
bodies at 64 KiB, approvals at eight, and HTTP request time at ten seconds.
The systemd example caps Node's old heap at 192 MiB and the service at 512 MiB.
These are initial limits, not measurements: Pi 3 RAM, Git pack sizes, latency,
thermal and storage endurance need hardware acceptance testing.

```
PC/agent -- authenticated SSH tunnel --> loopback Hub API
  -> existing signed-policy activation + deterministic policy engine
  -> existing production authority/executor receipt signing and verification
  -> existing typed git.push executor
  -> executor lock check -> executor-owned GitHub credential
  -> remote prestate + ancestry -> PostgreSQL durable one-use claim
  -> fsynced execution start -> final lock check -> existing push transport
  -> observed remote poststate -> existing signed execution evidence
```

The Hub listens only on `127.0.0.1`. Use an authenticated SSH tunnel, for example
`ssh -N -L 8790:127.0.0.1:8790 operator@hub`, then connect the PC to localhost.
There is no unauthenticated LAN listener, CORS allowance, or TLS termination in
this prototype. Browser Origin requests are refused. Do not expose port 8790
with a public TCP forward. API bearer tokens use the existing sidecar token-file
format `{ "token": "caller-id" }`. `MNDE_HUB_OPERATORS` is a JSON array of those
caller IDs allowed to use control endpoints. These permissions govern the API;
all protected-action authorization still goes through MNDe's policy/verifier.

## API and git.push flow

`GET /healthz` is unauthenticated process liveness. `GET /readyz` is a secret-free
dependency/state probe: 200 only when ACTIVE, 503 while LOCKED or DEGRADED.
All `/v1/` routes require the existing bearer authentication.

| Route | Meaning |
| --- | --- |
| `GET /v1/status` | ACTIVE, LOCKED or DEGRADED; executor/storage/signing readiness; `powerLossProtection: "not_installed"` |
| `POST /v1/actions` | Durably register, authorize, and execute one typed push if ALLOW |
| `POST /v1/actions/:id/approve` | Operator submits existing signed approvals; re-evaluate the same immutable request |
| `POST /v1/actions/:id/refuse` | Operator terminates a REVIEW; body `{}` |
| `POST /v1/lock` | Operator locks the executor; body `{}` |
| `POST /v1/unlock` | Operator unlocks only with ready dependencies and no action in progress; body `{}` |
| `GET /v1/receipts` | Up to 100 action summaries; caller-owned records, or all records for an operator |
| `GET /v1/receipts/:id` | Summary, unchanged signed authorization, and existing signed execution evidence if available |
| `GET /v1/events` | Operator-only recent observational events, capped at 100; not an audit/authority store |

STARTING is the internal initialization state before HTTP listening. Missing
storage/trust dependencies yield a live but DEGRADED service; invalid API auth
configuration prevents startup. A startup/configuration or persistence failure
requires operator repair and restart. PostgreSQL health failures refuse work;
readiness may recover when the same configured primary recovers.

The conceptual repository/branch/commit input is insufficient to bind a safe
push. The first API deliberately requires the existing six typed fields plus
the action and a **client-chosen UUID** for durable request deduplication:

```json
{
  "id": "a6061e83-0242-433e-a872-59039ed24f47",
  "action": "git.push",
  "repository": "https:github.com/MNDe-System/mnde-public-test",
  "remote": "origin",
  "remoteUrl": "https://github.com/MNDe-System/mnde-public-test.git",
  "targetRef": "refs/heads/main",
  "expectedOldSha": "<full lowercase 40-hex current remote SHA>",
  "sourceCommit": "<full lowercase 40-hex approved commit SHA>"
}
```

The example SHA placeholders must be replaced before submitting. Objects for
both commits must already exist in the configured Hub repository. Repository
synchronization/upload is outside this PR. Unknown fields/actions and invalid
JSON (including duplicate keys) fail closed. The principal is the authenticated
caller, not request data. The Hub generates a grant ID and a five-minute expiry.
A duplicate UUID returns 409 and never creates fresh authority. A lost response
must be followed by `GET /v1/receipts/:id`; **do not automatically submit a new
UUID**. Hub metadata is not the at-most-once effect guarantee: the existing
PostgreSQL execution/grant claim remains authoritative across requests/processes.

ALLOW is a policy decision, not proof of a push. Inspect `execution.outcome`:
EXECUTED, REFUSED, RECONCILED_NOT_APPLIED, INDETERMINATE, or
EFFECT_EXECUTED_EVIDENCE_FAILURE retain the executor's meaning. The Hub never
retries any of them. A crash after an EXECUTING record is exposed as
INDETERMINATE on restart, even if a later evidence file exists. An operator must
reconcile PostgreSQL, the existing execution-start/evidence files and remote
ref. Unfinished REQUESTED records are not automatically resumed either.

REVIEW means the existing policy returned `REFUSE / APPROVAL_REQUIRED`. That
signed refusal receipt is not modified to say REVIEW. `approve` accepts
`{"approvals":[<existing signed approval artifact>]}`; each artifact must name
this UUID in `scope.request_id`, and issuer key IDs must be distinct. The
existing approval verifier checks signature, trust, scope, time and threshold.
The Hub does not mint approvals or hold the approval private key. Changing a
boolean or clicking an unauthenticated UI button cannot approve. A new policy
decision/receipt is issued after approval; a final request cannot be approved
again. The original five-minute expiry is preserved. Operator refusal is a
workflow cancellation; it does not forge a new policy refusal signature.

Verify the returned `authorization` with `tools/verify.mjs`, passing the existing
authority bundle, root fingerprint, executor/environment, approval anchors and
historical signed-policy bundle/authority options. Verify `executionEvidence`
with `scripts/verify-git-push-evidence.mjs`. See their CLI usage and
[receipt formats](receipt-formats.md). Neither proof is accepted in place of
the other. `/v1/receipts` exposes summaries, not raw transport evidence.

## Storage, locking, and power loss

Provision and mount USB storage before starting. The Hub will not create its
data directory or fall back to microSD when it is absent. On POSIX it requires
a real private directory (0700); trust/secret files follow existing ownership
and permission checks. The example mount must be durable across boots, with an
appropriate filesystem and `/etc/fstab` entry selected by the operator.

| State | Authoritative location |
| --- | --- |
| One-use execution/grant claims, uniqueness and ambiguous claim outcomes | Existing PostgreSQL primary and `mnde_claim` schema; never Hub files or an in-memory cache |
| Lock epoch and action request/workflow/authorization records | `MNDE_HUB_DATA_DIR` (`lock.json`, `action-<UUID>.json`) |
| Storage probe | `MNDE_HUB_DATA_DIR/storage-probe.json`; not execution authority |
| Existing execution start, unsigned local evidence and signed execution evidence | `MNDE_GIT_PUSH_EVIDENCE_DIR`, example `/mnt/mnde-data/evidence`; API records reference these files |
| Existing policy serial floor/activation state | `MNDE_PE_POLICY_BUNDLE_STATE`, example `/mnt/mnde-data/policy-bundle-state.json` |
| Credentials and pinned public trust/configuration | Existing configured paths, example `/etc/mnde`; never moved automatically |
| Optional existing authority/nonce/ledger state | Existing MNDe paths; not relocated or replaced by Hub |

Use the existing PostgreSQL TLS config and provisioning scripts under
`deployment/freshness/`. It may be a remote primary to conserve Pi RAM. Its
fsync, synchronous commit, uniqueness, no-replica and no-resend protections are
unchanged. Install `pg` in `/opt/mnde` (for example `npm install --no-save
--package-lock=false pg@8` in that deployment checkout); the base repository
still treats it as an operator-provisioned runtime adapter.

Every boot begins LOCKED. Lock state is read **inside the executor**, before
credential acquisition and before protected dispatch. Missing/corrupt lock state
refuses. Each lock/unlock writes a fresh epoch so an operation from an earlier
epoch cannot resume after a quick unlock. Lock acknowledgement waits for admitted
execution to drain/release its credential. A remote operation already dispatched
cannot be recalled; credential acquisition already underway may finish, but the
next guard prevents a newly dispatched push. Shutdown locks, stops admission and
waits for admitted work. Forced termination leaves existing recovery evidence.
Deploy exactly one systemd-managed Hub per data directory and executor identity.
An OS administrator who launches another executor without the Hub configuration
is outside the software boundary.

Hub file updates write a private temporary file, fsync it, rename it, and fsync
the parent directory on Linux. Existing executor durability writes are unchanged.
Windows development skips directory fsync for Hub metadata and is **not a
production durability qualification**. USB flash does not solve sudden power
loss: controller caches, filesystem loss, torn writes and rollback remain open
hardware risks. Do not delete action records or reset PostgreSQL claims to retry.
Storage capacity/retention and crash reconciliation remain operator tasks.

## Installation and configuration

Use the reviewed source checkout under `/opt/mnde` (read-only to the service),
configuration under `/etc/mnde`, a local object repository under `/var/lib/mnde`,
and the USB mount under `/mnt/mnde-data`. Install a supported arm64 Node 24+
runtime at `/usr/bin/node`, Git and the PostgreSQL driver. Provision existing
production trust, signed policy, approval public anchors, API tokens, credential
provider config and PostgreSQL access using the existing runbooks. Do not copy
demo keys into production; no setup code here creates real credentials.
The repository's CI currently pins Node 24.14.1 because newer Node releases
have triggered an HTTP-client teardown assertion in the existing tests. Match
that pin for reproducible testing; qualify runtime updates before deployment.

Example directory/unit setup, after mounting USB and reviewing the paths:

```sh
sudo useradd --system --home-dir /var/lib/mnde --shell /usr/sbin/nologin mnde
sudo install -d -o mnde -g mnde -m 0700 /var/lib/mnde /mnt/mnde-data/hub /mnt/mnde-data/evidence
sudo install -d -o root -g mnde -m 0750 /etc/mnde
sudo install -o root -g mnde -m 0640 deployment/hub/hub.env.example /etc/mnde/hub.env
# Edit the environment file and provision the referenced files separately.
sudo install -m 0644 deployment/hub/mnde-hub.service /etc/systemd/system/mnde-hub.service
sudo systemctl daemon-reload
sudo systemctl enable --now mnde-hub
```

Secret files must be owned by `mnde` with mode 0600; public trust/config files
must be owned by `mnde` or root and not writable by others. The unit contains
no secrets, waits for network-online, requires the USB mount, runs non-root,
restarts unexpected failures, and gives shutdown 120 seconds before forced
termination. Adapt both `RequiresMountsFor`/`ConditionPathIsMountPoint` and
`ReadWritePaths` if the mount changes. `ProtectSystem=strict` allows only the
declared durable paths and private temporary storage to be written.

New variables: `MNDE_HUB_DATA_DIR` (required absolute preexisting private
directory), `MNDE_HUB_PORT` (default 8790), `MNDE_HUB_OPERATORS` (required JSON
caller-ID array). Existing variables are listed in `hub.env.example` and
[GIT-PUSH-CLI.md](GIT-PUSH-CLI.md): all executor trust/identity, Git credential
config, claim config, evidence directory and namespace remain required. Hub
also requires `MNDE_AUTHORITY_BUNDLE`, `MNDE_RECEIPT_SIGNING_KEY`, signed policy
bundle/authority/pinned-root/state variables and
`MNDE_PE_APPROVAL_TRUST_ANCHORS`. An empty `approval_keys` array may be provisioned
for policies without REVIEW, but approval-required rules then cannot approve.
Use `MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE` only if required by the existing encrypted
signing-key loader; do not put passphrases in unit files or command lines.
Restart after trust, credentials, policy or approval-anchor changes.

## Verification and future hardware

`npm run test:hub` exercises the real policy, signing/verifiers, HTTP API and
typed local Git transport; its only claim backend is the existing test-only
adapter substituted with an ESM preload. It does not contact production GitHub.
`npm test` includes this suite. Real PostgreSQL/TLS, GitHub credential custody on
the deployed Pi, systemd behavior on Raspberry Pi OS, arm64 packaging/resource
measurements and power interruption tests are deployment acceptance blockers.

Prototype validation on Windows, 2026-09-30: all 109 test scripts passed using
the CI-pinned Node 24.14.1 (`npm exec --yes --package=node@24.14.1 -- npm test`),
including 17 Hub tests, 35 production Git CLI cases and 14 static reachability
checks. The reviewer kit and whitespace check passed. An initial Node 24.20.0
run exposed three integration issues that were fixed (crypto-provider imports,
the reviewed executor-caller allowlist, and the generated SBOM) plus the known
dashboard HTTP-client assertion. The latter reproduced on clean `main` at
`ff55bd3`; it is not a Hub-specific failure.

The Hub test suite also uses a test-only observation hook to count real executor
and credential-provider calls, pause acquisition for a deterministic lock race,
and inject a fake secret-bearing provider exception. Those hooks do not ship.
Production credential acquisition is not mocked by the service. No production
GitHub push or real credential provisioning was performed in this validation.

The event stream vocabulary includes hub.started/ready/locked/unlocked,
action.requested/review_required/allowed/refused, execution.started/completed/
failed, receipt.signed and storage.degraded. Events are observational and may
be lost on restart; they are not execution authority. A future OLED process
should display a read-only status feed and hold no control credentials or
security logic. A future isolated GPIO service must use the same authenticated
lock mechanism; it must never maintain a second display-only lock. OLED, GPIO,
a secure element for keys, UPS monitoring and safe shutdown are future work.
No custom OS image, consumer UI or hardware power-loss guarantee is provided.
