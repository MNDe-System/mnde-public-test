# Packaging `@mnde/sidecar` — status & path to publish

Goal (roadmap): `npx @mnde/sidecar init → doctor → start`, **first receipt < 2 min**.

Release identity, `mnde version`, checksums, and the full install/reinstall/
uninstall contract are documented in [`docs/RELEASE.md`](docs/RELEASE.md).

## What's built (on `main`)

Two problems blocked every earlier packaging attempt, both fixed:

1. **This repo runs `.ts` files via Node's native type-stripping, which Node refuses
   for any file under `node_modules`** (`ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING`).
   Fixed with a real build step, [`build/build-package.mjs`](build/build-package.mjs)
   (wired as `prepack`): compiles every `.ts` to type-stripped `.js` and rewrites relative
   `.ts`/`.mts` import specifiers to `.js`/`.mjs`, mirroring the source tree into `dist/`
   unchanged in logic. `npm pack` / `npm install` now installs something Node can actually run.
2. **`init` wrote signing keys and policy into the package's own directory**
   (`shared/receipt_keys/`, `.mnde-sidecar/`) — correct for a cloned repo, wrong for an
   installed package (never write into `node_modules`). Fixed with `MNDE_HOME`: an env var
   (default `./.mnde` under the caller's CWD) that separates the writable *data root* from
   the read-only *code root*. Every module in the signing/authority/receipt path that used
   to hardcode a path relative to its own `import.meta.url` now checks `MNDE_HOME` first —
   see `shared/receipt-signing.ts`, `src/policy-engine/receipt.mjs`,
   `src/policy-engine/authority-grants.mjs`, `shell/receipt.mjs`, `scripts/start-sidecar.mjs`,
   `mnde-local-sidecar.mjs`, `bin/mnde-sidecar.mjs`.

The CLI itself, [`bin/mnde-sidecar.mjs`](bin/mnde-sidecar.mjs), is wired as three bin names
(`mnde-sidecar`, `sidecar`, `mnde`) and reuses the repo's audited signing, verification,
policy, and authority modules unchanged — no new trust path.

A separate bin, `mnde-git-push` ([`bin/mnde-git-push.mjs`](bin/mnde-git-push.mjs)), is the
production caller of the typed `git.push` executor. It is not part of the sidecar CLI; see
[docs/GIT-PUSH-CLI.md](docs/GIT-PUSH-CLI.md).

| Command | Does | Reuses |
|---|---|---|
| `init` | generate receipt keys + local authority + starter policy under `MNDE_HOME` (idempotent, never overwrites) | `bootstrapReceiptKeys` |
| `doctor` | fail-closed readiness check; exit 1 on any hard failure | key validity (`receiptSigningKeyStatus`), `authorityPaths`, `loadAuthorityBundle`, runtime/policy/write/port checks |
| `start` | run the sidecar (foreground) with the starter policy | `scripts/start-sidecar.mjs` |
| `smoke` | one decision → signed receipt → **offline-verified**; prints elapsed time | `reviewer-request`, `tools/verify.mjs` |

**Proven, from a real packed artifact:** `npm pack` → `npm install <tarball>` into a clean
temp project → `init → doctor → smoke` yields a verified receipt in **~0.5–0.6 s** (well under
2 min). Also proven installed under the `@mnde/sidecar` alias
(`npm install @mnde/sidecar@file:<tarball>`), confirming the `sidecar` bin name (matching the
unscoped half of that scoped name) resolves the way npm's own bin-selection rule for scoped
packages requires.

Covered by:
- [`tests/test_conformance_installed_artifact.mjs`](tests/test_conformance_installed_artifact.mjs) —
  real `npm pack` + real `npm install` into a clean temp dir (not tar extraction), full
  init/doctor/smoke, re-init idempotency, and an independent re-check that no private key
  material is in the shipped file list.
- [`tests/test_sidecar_cli_hostile.mjs`](tests/test_sidecar_cli_hostile.mjs) — partial
  initialization (self-heals via re-derivable manifest), corrupt signing key (fails closed,
  doctor and smoke both), occupied port (fails fast, no hang), malformed policy (fails closed),
  interrupted startup (recovers cleanly on the next run).

Both are wired into `expected-test-scripts.json` / `npm test`, so they run in CI.

## Uninstall / cleanup

This package writes to exactly one place: `MNDE_HOME` (default `./.mnde` under the directory
you ran the CLI from). It never writes anywhere under its own install location.

- **Remove local state only** (keys, authority manifest, starter policy, receipts): delete the
  `MNDE_HOME` directory (`./.mnde` by default) — `rm -rf ./.mnde` / `Remove-Item -Recurse .mnde`.
  Nothing else on disk references it; there is no OS-level registration, no service, no
  scheduled task, no global config.
- **Remove the package itself**: `npm uninstall @mnde/sidecar` (or `mnde-public-test` / `sidecar`,
  whichever name you installed it under) — ordinary npm package removal, no extra step.
- **Full removal**: do both. Order doesn't matter; deleting `MNDE_HOME` first still leaves a
  normally-uninstallable npm package, and uninstalling the package first still leaves an
  ordinary directory you can delete whenever you like.
- Nothing is written to a shared/global location (no `~/.mnde`, no system directory) unless you
  explicitly set `MNDE_HOME` to point there yourself.

## Known limitations (do not treat local smoke success as production readiness)

1. **Package identity.** Still published conceptually as `mnde-public-test` (`private: true`);
   the actual rename to `@mnde/sidecar` (or a dedicated publish package) is a deliberate,
   separate decision, not yet made. The bin-name convention (`sidecar` matching the unscoped
   half of `@mnde/sidecar`) is already in place for whenever that decision lands.
2. **`npx @mnde/sidecar <cmd>` end-to-end could only be partially verified locally.** Testing
   used `npm install @mnde/sidecar@file:<tarball>` (npm's alias-install syntax) to prove the
   bin-resolution convention is correct, and confirmed `npx sidecar`/`npx mnde-sidecar` run the
   installed package correctly. `npx @mnde/sidecar <cmd>` itself falls back to a public-registry
   lookup in this environment (the scoped name isn't actually published), which is a property of
   testing an unpublished rename locally, not a defect in the packaging — but it means the exact
   literal command has not been exercised end-to-end against a real registry.
3. **Demo signing secret default.** `scripts/start-sidecar.mjs` defaults
   `MNDE_RECEIPT_HMAC_SECRET` to a hardcoded demo value when unset — a convenience for the
   zero-config **local** experience. It is env-overridable and is **rejected under
   `MNDE_PROFILE=production`**: a production sidecar refuses to start on legacy signing and
   leaves no listener behind (proven by `test_release_truth.mjs` REL-06). The demo constant is
   confined to local/demo bootstrap files and never appears in the decision/signing/verification
   trust core (proven by REL-15); it is not a private key and cannot sign production receipts.
   Gating local demo signing behind an explicit opt-in remains a future follow-up, not a
   packaging defect.
4. **`doctor`'s port check is a liveness probe, not a bind-availability check.** It calls the
   sidecar's own `/healthz` over HTTP; a non-HTTP process silently occupying the port reads as
   "available" until `start`/`smoke` actually try to bind and fail. `start`/`smoke` do fail
   closed in that case (see the occupied-port hostile test) — `doctor` alone would not have
   warned you in advance.

## Try it now

From a packed artifact (recommended — this is what an end user actually gets):

```
npm pack
mkdir /tmp/try-mnde && cd /tmp/try-mnde && npm init -y
npm install <path-to-tarball>
npx mnde-sidecar init
npx mnde-sidecar doctor
npx mnde-sidecar smoke     # prints "First verifiable receipt in <n>s"
```

From a clone, against source directly (fast local iteration):

```
node bin/mnde-sidecar.mjs init
node bin/mnde-sidecar.mjs doctor
node bin/mnde-sidecar.mjs smoke
```
