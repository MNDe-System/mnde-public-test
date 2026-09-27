# Production trust boundary: `mnde-git-push`

What the git.push executor trusts, where each piece of its trust material comes
from, who may hold the credential that can write to the protected repository,
and what is still a deployment property rather than something the code enforces.

Status on 2026-09-27: this describes code on `main` plus the change that adds the
push credential provider. **It does not close F-001.** See the last section.

## The boundary

```
UNTRUSTED                      may be controlled by an attacker
  Agent                        writes commits, writes request.json
  Application                  invokes mnde-git-push, cannot configure it
  Repository contents          the local repository, including its .git/config
  request.json                 seven fields; checked against the signed authorization
        │
        ▼
CONTROLLED ENTRY
  mnde-git-push <request.json> one process per request; configuration from its
                               own environment, never from the request
        │
        ▼
TRUSTED EXECUTION BOUNDARY     the executor's OS identity and nothing else
  Authorization verifier       src/execution-authority, pinned root
  Executor identity            MNDE_EXECUTOR_* key + root-signed credential
  Claim coordinator            src/freshness/claim.mjs + PostgreSQL adapter
  External witness             NOT IMPLEMENTED (see "Rollback witness")
  Credential provider          src/effects/git-push/credential-provider.mjs
  Typed git.push transport     src/effects/git-push/transport.mjs
  Execution evidence signer    src/effects/git-push/evidence.mjs
        │
        ▼
PROTECTED EXTERNAL SYSTEM
  Git remote                   accepts writes only from the executor's credential
```

What each zone may do:

| Zone | Trusted for | Never trusted for |
| --- | --- | --- |
| Agent, application | Proposing a push and presenting a signed authorization | Choosing a credential, trust root, claim store, key, namespace, evidence path, scheme or transport variable. Holding any push credential. |
| Repository contents | Supplying the objects of the approved commits (the remote recomputes every object id) | Any git configuration, hook or remote rewrite. The effect runs in an executor-owned staging repository that reads only the objects. |
| request.json | Naming the push. Every field must equal the signed authorization. | Anything else. An unknown field exits `3` before the executor exists. |
| Executor boundary | Deciding whether the push happens, spending the authority, holding the push credential for one execution, signing what it observed | Being honest about a store it does not control: the claim store's owner can still restore a backup (F-001 Q6). |
| Git remote | Being the authority on what the ref now is | Nothing about the request. The executor reads the pre- and post-state itself. |

## Part 1: the push credential

### The property

Only the git.push executor holds a credential that can write to the protected
repository. The agent, the application, the sidecar and the request never do,
so a `git push` attempted anywhere else fails for lack of authorization.

The code enforces the half of this that is inside the executor. The other half,
that nobody else holds a working credential, is a property of how the repository
host and the operating system are configured. The table below says which is
which.

| Requirement | Enforced by | Where |
| --- | --- | --- |
| Credential comes only from deployment configuration | Code | `MNDE_GIT_CREDENTIAL_CONFIG` is the only source. `createGitPushExecutor` refuses a `credentialProvider` argument (`ERR_GIT_CREDENTIAL_SUBSTITUTION`). The request has no field for it. |
| Missing configuration fails closed | Code | `mnde-git-push` exits `4`; the executor constructor throws. There is no fallback. |
| No ambient credentials: `~/.gitconfig`, system config, credential helpers, credential manager, `gh` login, `GITHUB_TOKEN`/`GH_TOKEN`, inherited ssh-agent, default ssh keys, `.netrc`, askpass | Code | The git environment is built from empty (`buildTransportEnv`). `HOME` is an empty per-execution directory. `GIT_CONFIG_GLOBAL`/`SYSTEM` point at a file that never exists. ssh runs with `-F none`, `IdentityAgent=none`, `IdentitiesOnly=yes`. Observed end to end in `tests/test_git_push_cli.mjs` case P3 from the remote's own hook. |
| Operator transport variables cannot select a credential | Code | `MNDE_GIT_PUSH_TRANSPORT_ENV` now accepts only `PATH` and `GIT_SSL_CAINFO`. `HOME`, `SSH_AUTH_SOCK` and `GIT_SSH_COMMAND` were removed. |
| Credential is scoped to the protected repository | Code | `repositories` in the config is an allowlist of canonical identities (`https:host/owner/repo`). A push anywhere else refuses with `ERR_GIT_CREDENTIAL_SCOPE` before the claim. |
| Credential authenticates one transport | Code | Each kind has one scheme. `GIT_ALLOW_PROTOCOL` is pinned to it for the three remote operations and is empty for everything else, so no local git step can reach a network or an `ext::` helper. |
| Only remote-facing git processes see the credential | Code | Local steps (reading the repository, staging, commit checks) run without it. `withPushCredential` refuses a handle that sets anything but `GIT_CONFIG_{COUNT,KEY_n,VALUE_n}`, `GIT_SSH_COMMAND`, `GIT_SSH_VARIANT`. |
| An https token goes to one URL only | Code | `http.<remote-url>.extraHeader` passed through `GIT_CONFIG_COUNT` (git 2.31 or later), redirects refused. `tests/test_git_push_credential_custody.mjs` observes real git sending it to the scoped URL and not to another. |
| No credential in evidence, stdout, errors, claims | Code | Metadata only (kind, scope, expiry, a truncated sha256 for static secrets). Every string the executor writes after acquiring a credential is passed through the handle's redactor. The claim record has no credential field. |
| Secret files private | Code on POSIX, operator on Windows | Owned by the executor user, not a symlink, mode `0600`, outside the local repository and the package. Windows ACLs are not checked; the result says `checked: false`. |
| No module other than the executor obtains the credential or pushes | Code | `tests/test_git_push_reachability.mjs` layers 1–7: one importer of the transport and of the provider, one spawner with git mutation vocabulary, no git library, GitHub SDK or ref-write endpoint in the package. |
| The agent's OS account cannot read the credential | **Deployment** | Run the executor under its own OS user (below). |
| The caller cannot set the executor's environment | **Deployment** | All configuration is environment variables. Whoever sets them chooses the trust root. See "Launching the executor". |
| No other credential for the repository exists | **Deployment** | Branch protection and the repository's collaborator list, on the host. MNDe cannot see these. |

### Credential kinds, in order of preference

`MNDE_GIT_CREDENTIAL_CONFIG` names one JSON file:

```json
{
  "schema": "mnde.git-credential-config.v1",
  "kind": "github-app",
  "repositories": ["https:github.com/acme/widgets"],
  "app_id": "123456",
  "installation_id": "78901234",
  "private_key_file": "/etc/mnde/secrets/github-app.pem",
  "api_base_url": "https://api.github.com"
}
```

Unknown fields are refused, never ignored.

1. **`github-app`** — preferred. Per execution, the executor signs a ten-minute
   app JWT and asks for an installation token for exactly one repository with
   `contents: write`. The response is checked: a token with any other permission
   (other than GitHub's implicit `metadata: read`), another repository, or an
   expiry more than two hours out is revoked and refused. After the post-state
   read the token is revoked (`DELETE /installation/token`); if revocation fails
   that is recorded, and the token still expires within the hour. The app
   private key never leaves the executor. **Tested against a stub of the GitHub
   API, not against GitHub.** `api_base_url` has no default so GitHub Enterprise
   Server works the same way.
2. **`https-token-file`** — a token file kept current by the deployment's secret
   mechanism (a Vault or cloud secret-manager agent, a mounted secret). Use a
   short-lived token when the secret service can mint one. Optional `username`
   (default `x-access-token`).
3. **`ssh-key-file`** — a deploy key for one repository plus a pinned
   `known_hosts_file`. Long-lived by nature. Optional absolute `ssh_executable`.
   **Checked by the command it builds; no sshd was contacted in tests.**
4. **`none`** — `file://` remotes only. There is no credential; authorization is
   the executor user's filesystem access to the remote.

Never use a person's own GitHub credential. Grant repository contents write on
the protected repository and nothing else: no organization administration, no
other repositories, no workflow or secrets scopes.

### Order of operations

```
 1  profile + posture              local
 2  verify authorization           local
 3  action, parameters, binding    local
 6  local remote URL matches       local repository, no credential, no network
 6b staging repository             no credential, no network
 7-8 both SHAs are local commits   no credential, no network
 8b ACQUIRE CREDENTIAL             ← secret read or minted here
 9  read remote pre-state          credential
 10 fast-forward check             no credential
 11 CLAIM (authority spent)        durable, before anything is sent
 11b durable start record
 12 push                           credential
 13 read remote post-state         credential
    RELEASE CREDENTIAL             revoke / drop; runs on every path
    write + sign evidence          scrubbed of the credential
```

This differs from the order proposed in the brief in two places, deliberately:

- **The credential is acquired before the claim, not after.** Step 9 reads the
  remote, and a private remote cannot be read without authenticating. Acquiring
  after the claim would also mean that a secret-service outage or a refused
  mint burns the authority. As built, a credential failure refuses with nothing
  sent and nothing spent (case P2 shows the same authorization then executing).
- **The credential is released after the post-state read, not before.** Reading
  the result back is the same authenticated operation as reading the pre-state.
  It is released before evidence is written and signed.

### Secret destruction

Key and token buffers read from disk are zeroed after use. Installation tokens
are revoked. No secret is written to a temporary file: the https header travels
in the git child's environment (`GIT_CONFIG_*`), the ssh key is referenced by
path. JavaScript strings cannot be reliably erased, and the token is in the
environment of the git child processes for the length of one execution, where
the same OS user (and root) can read it through `/proc`. That is why the
executor needs its own OS user.

## Running the executor under its own identity

Recommended model on Linux:

| Account | Holds | Can |
| --- | --- | --- |
| `mnde-agent` | Nothing of MNDe's | Write commits to the work repository; write request files to the spool directory |
| `mnde-app` | Nothing of MNDe's | Launch the executor through one fixed entry point |
| `mnde-executor` | Executor key, credential, push credential or app key, claim-store password, witness credential (once it exists) | Read those; write evidence; no login shell |

```
useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/mnde mnde-executor
install -d -o mnde-executor -g mnde-executor -m 0700 /etc/mnde/secrets /var/lib/mnde/git-push-evidence
install -o mnde-executor -g mnde-executor -m 0600 github-app.pem /etc/mnde/secrets/
install -o root -g root -m 0644 git-credential.json claim-config.json authority.bundle.json /etc/mnde/
```

### Launching the executor

Every setting is an environment variable, and the pinned root fingerprint is
one of them. **A caller that can set the executor's environment can choose its
trust root.** The code narrows this (every trust file must be owned by the
executor user or root and not writable by others, so a caller cannot point at a
file it wrote), but the real control is that the caller never sets the
environment. Two launch patterns keep it that way:

- **sudo with a fixed wrapper.** A root-owned wrapper sets the environment and
  runs the CLI; the caller may run only the wrapper, and `sudo`'s default
  `env_reset` drops the caller's environment.
  ```
  # /usr/local/libexec/mnde-git-push-prod   (root:root 0755)
  #!/bin/sh
  set -eu
  set -a; . /etc/mnde/git-push.env; set +a       # root:root 0644
  exec /usr/bin/node /opt/mnde/dist/bin/mnde-git-push.mjs "$1"

  # /etc/sudoers.d/mnde
  mnde-app ALL=(mnde-executor) NOPASSWD: /usr/local/libexec/mnde-git-push-prod /var/spool/mnde/requests/*
  ```
- **A service manager unit** (`systemd` with `User=mnde-executor`,
  `EnvironmentFile=`, `NoNewPrivileges=yes`, `ProtectHome=yes`,
  `PrivateTmp=yes`), started per request by the application.

The request file must be readable by `mnde-executor`. Nothing it contains is
configuration.

Containers: the same separation applies. Do not mount executor secrets into a
container the agent runs in. Secret files are refused if they are symlinks, so a
Kubernetes secret volume must be mounted with `subPath` or copied into place.

Windows: run the executor as a dedicated local or managed service account and
set ACLs so only that account can read the secret files. MNDe does not check
Windows ACLs.

## Part 2: production trust material

Each item has one role. None may be reused for another.

| Item | Purpose | Generated by | Lives | Must not |
| --- | --- | --- | --- | --- |
| Authority root key | Signs authority bundles and executor credentials | `npm run authority:init` on an air-gapped machine, or an external root signer (`docs/key-custody.md`) | Offline / HSM | Be on the executor host, or be any other key |
| Authority signing keys | Sign authorizations (receipts) | Same ceremony; rotated with `npm run authority` | Authority service, not the agent's environment | Double as the executor key |
| Trusted root fingerprint | Pins the root | Printed by `authority:init` | `MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT`, obtained out of band | Be MNDe's demo root |
| Authority bundle | Public keys + revocations, root-signed | `authority:init` / `mnde-authority rotate|revoke` | `MNDE_VERIFY_AUTHORITY_BUNDLE`, root-owned | Name itself `local`/`demo`; sit inside the repository or package |
| Executor key + credential | Signs execution evidence; identifies the executor | `node scripts/trust-enroll-executor.mjs` (short-lived credential) | `MNDE_EXECUTOR_PRIVATE_KEY` (0600), `MNDE_EXECUTOR_CREDENTIAL` | Be an authority key; come from the request, the repository or a demo |
| Executor id | Binds authorizations to this executor | Operator | `MNDE_EXECUTOR_ID` = `MNDE_VERIFY_EXPECTED_EXECUTOR_ID` | Default |
| Environment id | Binds authorizations to this environment | Operator, e.g. `prod-us-east-1` | `MNDE_EXECUTOR_ENVIRONMENT` = `MNDE_VERIFY_ENVIRONMENT_ID` | Default |
| Claim-store credential | Restricted login that can only call the claim functions | `deployment/freshness/postgres.sql` | `passwordFile` named in `MNDE_CLAIM_CONFIG` | Be the database owner's login |
| Push credential | Write to the protected repository | GitHub App (preferred), secret service, or deploy key | `MNDE_GIT_CREDENTIAL_CONFIG` and the files it names | Be a person's credential; reach other repositories |
| Witness credential | — | Not applicable yet | — | — |

What startup checks, and refuses with exit `4`:

| Check | Code |
| --- | --- |
| Every required variable set; paths absolute | `ERR_GIT_PUSH_CLI_CONFIG` |
| Bundle, claim config, executor credential and key: not in the repository or package; on POSIX owned correctly and not writable (key: not readable) by others | `ERR_GIT_PUSH_TRUST_FILE_INSECURE` |
| Root fingerprint is not MNDe's shipped demo root; authority and root key id not `local`/`demo` | `ERR_GIT_PUSH_DEMO_TRUST_MATERIAL` |
| Executor credential verifies against the pinned bundle and the key matches it | existing `assertExecutorIdentityReadiness` codes |
| Executor key is not the root or any authority key | `ERR_GIT_PUSH_TRUST_ROLE_REUSE` |
| Executor id and environment match what authorizations must be bound to | `ERR_GIT_PUSH_STARTUP_CONFIG` |
| Push credential configuration present, exact, scoped, secret files private | `ERR_GIT_CREDENTIAL_*` |

Not checked: that the claim store is reachable (a push refuses at the claim
instead, nothing sent), and anything about a witness.

Where secrets may live: files readable only by the executor user, populated by
the deployment's secret mechanism. Never in the repository, a request, the npm
package, a container image, shell history, documentation, test fixtures or
evidence. `tests/test_pack_no_private_keys.mjs` guards the package.

## Rollback witness

The brief asks for "the previously approved F-001 external monotonic witness
design". **No such design exists in the repository or the project files.** What
exists:

- the owner's decision (2026-09-20, `docs/F001-REASSESSMENT.md`) that a claim
  stronger than "the executor cannot roll the claim store back" needs an
  external monotonic witness, as v-next;
- `src/witness/` and `docs/witnessed-authority-checkpoints.md`, which witness
  authority *bundle* checkpoints against equivocation. They do not record claim
  state and cannot, as written, stop a restored claim database from reviving a
  spent authority.

So nothing here is a witness, `mnde-git-push` has no witness setting, and there
is no witness-disable switch because there is no witness. The design choice is
the owner's and is set out in the pull request that adds this document.

## What this still does not establish

- **F-001 is not closed.** Q4 (power loss) and Q6 (claim-store owner restores a
  backup) are unchanged, and there has been no run with production trust
  material against a production remote.
- **The executor process is trusted.** Code running inside it can read the
  credential while it is held. The boundary is the executor's OS identity.
- **Repository-side exclusivity is not visible to MNDe.** Whether anyone else
  can push is decided by the host's settings.
- **Signed evidence does not yet name the credential.** The kind, scope and
  expiry are in the local evidence record and the CLI output. Adding them to the
  signed `mnde.git-push-execution-evidence.v1` body changes that schema and is a
  separate decision.
