# First production `git.push`: from no trust material to one real push

This runbook takes an operator from nothing to one push that MNDe's typed
`git.push` executor performs on the real GitHub repository, against a throwaway
branch, with trust material nobody else has seen. It is written for Windows
PowerShell because that is where it will first be run. The POSIX equivalents
are the same commands with `export` instead of `$env:`.

**Where this runs.** On your own device. Every private key is generated there and
stays there. None of it goes into the repository, a pull request, a chat, or a
cloud session. The scripts never print key material; if a step ever shows you a
line starting `-----BEGIN`, stop and do not paste it anywhere.

**What it proves when it works.** A push reached GitHub only after: an
authorization signed by a root you generated verified at both layers; the remote
was read back at the approved old SHA; a single-use claim was written to a real
PostgreSQL store through a login that cannot delete it; and a push credential
scoped to one repository with `contents: write` was minted for that one push and
revoked afterwards. The signed evidence then verifies offline against your root.

**What it does not prove.** F-001 stays open after this run. Power loss is still
untested, the database owner can still restore an old backup and revive spent
authority, the claim-state witness decision is still pending, and your own
account can still push to the repository directly. In this first run the
approval key and the executor sit on the same device, which is fine for proving
the path and is not the target custody (see "After the first run").

## Why there are three scripts

| Script | Does | Reuses |
| --- | --- | --- |
| `scripts/prepare-git-push-trust.mjs` | Generates a new authority (root, receipt, ledger, activation keys, signed bundle) and a new executor key with a root-signed credential; writes the env files. | `init-production-authority.mjs`, `trust-enroll-executor.mjs`, unchanged. |
| `scripts/authorize-git-push.mjs` | Your approval of one push: signs one executor-bound authorization for six exact values and writes the request file. | The sidecar's live signing path (`loadSigningConfig`, `createLiveReceiptSigningContext`, `signLiveReceipt`). |
| `scripts/verify-git-push-evidence.mjs` | Checks the signed evidence offline. | `verifyExecutionEvidence`. |

`authorize-git-push` exists because nothing else in the repository can produce
an authorization the executor accepts. The executor requires both layers of the
envelope to verify against *your* bundle (`ERR_REPO_LOCAL_TRUST`), and
`buildPolicyReceipt()`, which the sidecar uses, always signs the inner decision
with the repository's demo authority. The script signs the same payload with
your receipt key instead. It verifies its own output exactly as the executor
will before writing anything.

The three scripts are run from a source checkout and are excluded from the npm
package.

## 0. Prerequisites

- Node.js 24 or later (`node -v`).
- Git for Windows, which also provides `openssl.exe`.
- Admin rights on the device, for the PostgreSQL install in step 3.
- Owner access to the `MNDe-System` GitHub organization, for the App in step 2.

```powershell
git clone https://github.com/MNDe-System/mnde-public-test.git C:\mnde-src
cd C:\mnde-src
npm ci
npm install --no-save pg      # the claim-store driver; not a package dependency
```

Pick one directory for trust material, outside every repository and outside any
folder that syncs to the cloud (OneDrive, Dropbox, iCloud). This runbook uses
`C:\mnde-trust`.

## 1. Generate the trust material

```powershell
node scripts\prepare-git-push-trust.mjs `
  --out C:\mnde-trust `
  --authority-id mnde-system-prod `
  --executor-id mnde-system:prod:executor:gitpush:01
```

It prints a JSON summary: the root fingerprint, the files it wrote, and when the
executor credential expires (7 days by default; `--executor-ttl-hours` changes
it). Keep the root fingerprint. It is the value anyone verifying your evidence
must pin.

Then, straight away:

1. **Move the root key offline.** Copy `C:\mnde-trust\authority\root.key.pem` to a
   USB drive you keep unplugged, and delete it from the device. It is needed
   again only to enrol a new executor or rotate keys, never to push.
2. **Restrict the directory to your account.** On Windows the executor does not
   check file permissions (`docs/PRODUCTION-TRUST-BOUNDARY.md`), so do it here:

   ```powershell
   icacls C:\mnde-trust /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F"
   ```

The same folder now holds `mnde-git-push.env.ps1`, which sets every variable the
next steps need. Two of its entries point at files you create in steps 2 and 3:
`claim-config.json` and `git-credential.json`.

## 2. Create the GitHub App (the push credential)

The executor pushes with a GitHub App installation token that it mints per push,
scoped to one repository with `contents: write`, and revokes afterwards. No
long-lived token exists on disk; only the App's private key does.

1. On GitHub, open the organization **MNDe-System**, then **Settings**.
2. In the left sidebar, scroll to **Developer settings** and click **GitHub Apps**,
   then **New GitHub App**.
3. Fill in:
   - **GitHub App name:** `mnde-git-push-executor` (names are global; add a suffix
     if it is taken).
   - **Homepage URL:** `https://github.com/MNDe-System/mnde-public-test`
   - **Webhook:** untick **Active**.
   - **Repository permissions → Contents:** `Read and write`. Leave everything
     else at `No access`. (Metadata becomes `Read-only` on its own; that is
     expected and allowed.)
   - **Where can this GitHub App be installed?** `Only on this account`.
4. Click **Create GitHub App**. On the page that opens, note the **App ID**.
5. Scroll to **Private keys** and click **Generate a private key**. A `.pem` file
   downloads. Move it to `C:\mnde-trust\github-app.pem` and delete the copy in
   Downloads.
6. In the left sidebar click **Install App**, then **Install** next to
   MNDe-System. Choose **Only select repositories**, pick `mnde-public-test`, and
   click **Install**.
7. The browser is now at a URL ending `/settings/installations/<number>`. That
   number is the **installation ID**.

Write the credential configuration, replacing the two numbers:

```powershell
@'
{
  "schema": "mnde.git-credential-config.v1",
  "kind": "github-app",
  "repositories": ["https:github.com/MNDe-System/mnde-public-test"],
  "app_id": 1234567,
  "installation_id": 12345678,
  "private_key_file": "C:\\mnde-trust\\github-app.pem",
  "api_base_url": "https://api.github.com"
}
'@ | Set-Content -Encoding ascii C:\mnde-trust\git-credential.json
```

The executor refuses a token that comes back with any permission other than
`contents: write` and `metadata: read`, or for any repository other than this
one.

## 3. Set up the claim store (PostgreSQL 16 over TLS)

The claim store is what makes an authorization single-use. The adapter only
connects over verified TLS, so the server needs a certificate. These steps were
run on Linux against PostgreSQL 16 with the same SQL and settings; the
Windows-specific parts (installer, service name, paths) were not run by the
author of this document.

1. Install PostgreSQL 16 from <https://www.postgresql.org/download/windows/>.
   Keep port `5432`, set a password for the `postgres` account, and skip Stack
   Builder.
2. In an **admin** PowerShell, create the server certificate in the data
   directory:

   ```powershell
   $data = "C:\Program Files\PostgreSQL\16\data"
   & "C:\Program Files\Git\usr\bin\openssl.exe" req -x509 -newkey rsa:2048 -nodes -days 365 `
     -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" `
     -keyout "$data\server.key" -out "$data\server.crt"
   Copy-Item "$data\server.crt" C:\mnde-trust\claim-ca.pem
   ```

3. Open `$data\postgresql.conf` in Notepad (as admin), find `#ssl = off`, and
   change it to `ssl = on`.
4. Open `$data\pg_hba.conf` and replace the two `host ... scram-sha-256` lines
   for `127.0.0.1/32` and `::1/128` with:

   ```
   hostssl all all 127.0.0.1/32 scram-sha-256
   hostssl all all ::1/128      scram-sha-256
   ```

5. Restart the server: `Restart-Service postgresql-x64-16`.
6. Create the database, the schema, and the restricted executor login. The
   namespace must be the one `mnde-git-push.env.ps1` sets
   (`mnde-system-prod-git-push` with the authority id above):

   ```powershell
   $psql = "C:\Program Files\PostgreSQL\16\bin\psql.exe"
   node -e "process.stdout.write(require('node:crypto').randomBytes(24).toString('base64url'))" |
     Out-File -NoNewline -Encoding ascii C:\mnde-trust\claim-password
   $pw = Get-Content C:\mnde-trust\claim-password
   & $psql -h localhost -U postgres -c "CREATE DATABASE mnde_claims"
   & $psql -h localhost -U postgres -d mnde_claims -v ON_ERROR_STOP=1 -f deployment\freshness\postgres.sql
   & $psql -h localhost -U postgres -d mnde_claims -v executor_password="$pw" `
     -v namespace=mnde-system-prod-git-push -f deployment\freshness\provision-executor-login.sql
   ```

   `postgres` acts as the database owner here. The executor login
   (`mnde_executor`) can call the three claim functions and nothing else; it
   cannot update, delete or truncate a claim.

7. Write the claim configuration:

   ```powershell
   @'
   {
     "host": "localhost",
     "port": 5432,
     "database": "mnde_claims",
     "user": "mnde_executor",
     "namespace": "mnde-system-prod-git-push",
     "passwordFile": "C:\\mnde-trust\\claim-password",
     "caFile": "C:\\mnde-trust\\claim-ca.pem"
   }
   '@ | Set-Content -Encoding ascii C:\mnde-trust\claim-config.json
   ```

Optional, and only on a claim database nothing else uses yet: run the 22-case
claim-store proof (`docs/F001-CLAIM-STORE-PROOF.md`) against it. It writes rows
that cannot be deleted.

```powershell
$env:MNDE_CLAIM_CONFIG = "C:\mnde-trust\claim-config.json"
node deployment\freshness\claim-store-proof.mjs
```

## 4. Prepare the throwaway branch and the commit to push

The executor only moves an existing branch from one exact SHA to a descendant of
it; it never creates or deletes a ref. So you create the branch yourself first,
with your own account, and give the executor a separate clone to push from.

```powershell
git clone https://github.com/MNDe-System/mnde-public-test.git C:\mnde-work\mnde-public-test
cd C:\mnde-work\mnde-public-test
git push origin origin/main:refs/heads/mnde-proof/first-push
git switch -c mnde-proof/first-push origin/main
New-Item -ItemType Directory -Force proofs | Out-Null
"First push performed by the MNDe git.push executor." | Set-Content -Encoding ascii proofs\first-push.txt
git add proofs\first-push.txt
git commit -m "Record the first MNDe executor push"

$url = git remote get-url origin
$old = (git ls-remote origin refs/heads/mnde-proof/first-push).Split("`t")[0]
$new = git rev-parse HEAD
"$url`n$old`n$new"
```

`$url` must print exactly `https://github.com/MNDe-System/mnde-public-test.git`.
The executor compares the authorized URL with the clone's `origin` byte for byte
and refuses on any difference. Use a branch name no repository ruleset covers;
the executor's App is not a bypass actor.

## 5. Load the environment

In a new PowerShell window:

```powershell
cd C:\mnde-src
. C:\mnde-trust\mnde-git-push.env.ps1
$env:MNDE_GIT_PUSH_REPO_PATH = "C:\mnde-work\mnde-public-test"
```

## 6. Approve the push

This is the human authorization step. Running it means you approve moving
`mnde-proof/first-push` from `$old` to `$new` on that repository, and nothing
else. The authorization expires after 30 minutes (`--ttl-minutes`).

```powershell
New-Item -ItemType Directory -Force C:\mnde-trust\requests | Out-Null
node scripts\authorize-git-push.mjs `
  --remote-url $url `
  --target-ref refs/heads/mnde-proof/first-push `
  --expected-old-sha $old `
  --source-commit $new `
  --subject mndesystems-ship-it `
  --out C:\mnde-trust\requests\first-push.json
```

It prints the execution id, grant id, expiry and the six approved values. A
non-zero exit means nothing was written; the message says why.

## 7. Execute

```powershell
node bin\mnde-git-push.mjs C:\mnde-trust\requests\first-push.json |
  Tee-Object -FilePath C:\mnde-trust\first-push-result.json
"exit $LASTEXITCODE"
```

Success is exit `0` with `"outcome":"EXECUTED"`, `claim.decision` `CLAIMED`, and
`observed.after` equal to `$new`. The branch on GitHub now points at your commit.
Every other exit code is explained in `docs/GIT-PUSH-CLI.md`. Exit `4` means
startup refused the configuration before anything was attempted, and the
`detail` names the variable or file at fault. Do not re-run a request after a
non-zero exit expecting a different result; issue a new authorization.

## 8. Verify the evidence offline

```powershell
$evidence = (Get-Content C:\mnde-trust\first-push-result.json | ConvertFrom-Json).signed_evidence_path
node scripts\verify-git-push-evidence.mjs $evidence `
  --authority-bundle $env:MNDE_VERIFY_AUTHORITY_BUNDLE `
  --root-fingerprint $env:MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT `
  --expected-executor-id $env:MNDE_EXECUTOR_ID
```

Exit `0` with `"ok":true,"outcome":"EXECUTED"`. Anyone holding the published
bundle and your root fingerprint can run the same check; it needs no keys and no
network.

## 9. Show that the authorization is spent

Run the same request again. It refuses with `ERR_GIT_PUSH_REMOTE_MOVED`, because
the branch is no longer at the approved old SHA. To see the claim itself refuse,
put the branch back with your own account and try once more:

```powershell
cd C:\mnde-work\mnde-public-test
git push --force-with-lease=refs/heads/mnde-proof/first-push:$new origin "${old}:refs/heads/mnde-proof/first-push"
cd C:\mnde-src
node bin\mnde-git-push.mjs C:\mnde-trust\requests\first-push.json
```

This time it refuses with `ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT` and
`claim.decision` `SPENT`, and the branch does not move.

## 10. Clean up and report

- Delete the branch: `git push origin --delete mnde-proof/first-push` (from the
  work clone).
- Keep `C:\mnde-trust\evidence`, `first-push-result.json` and the line step 8
  printed. They contain no secrets and are the record of this run. Share those,
  not the folder.
- If you are not continuing, uninstall the App (organization **Settings → GitHub
  Apps → Configure → Uninstall**). The executor credential expires on its own.

## After the first run

Two custody changes turn this rehearsal layout into the intended one. Neither is
needed to prove the path.

1. **Separate approval from execution.** `MNDE_RECEIPT_SIGNING_KEY` (used only by
   `authorize-git-push`) belongs on the approver's device. The executor host
   needs only the bundle, its own key and credential, the claim config and the
   App key. Nothing in the executor reads the receipt key.
2. **Independent database owner.** Here `postgres` on your device owns the claim
   store, so you can restore it. `docs/F001-REASSESSMENT.md` records this as an
   accepted v1.0 boundary.
