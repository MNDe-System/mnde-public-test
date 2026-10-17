# Reproducing the F-001 results independently

Do not trust a summary. Everything below runs from a clean checkout. Needs: Linux, Node 24, git, PostgreSQL 16 server binaries, `openssl`, root (to create two OS users).

```bash
git clone https://github.com/MNDe-System/mnde-public-test && cd mnde-public-test
git checkout <commit named in docs/F001-FINAL-CLOSURE-REPORT.md>      # verify: git rev-parse HEAD ; git status --porcelain (empty)
node --version                                                         # v24.x
npm ci && npm test                                                     # 112+ suites, expect all PASS
```

## Real-infrastructure harness

```bash
# 1. users and a Node binary both can execute
useradd --system --no-create-home --shell /usr/sbin/nologin mnde-exec ; useradd --system --no-create-home --shell /usr/sbin/nologin mnde-witness
mkdir -p /opt/node24/bin && cp "$(command -v node)" /opt/node24/bin/node
# 2. a disposable PostgreSQL 16 with TLS (details: docs/F001-CLOSURE-REPORT.md section 7), then
npm i --no-save pg
psql -f deployment/freshness/postgres.sql                                         # as the owner role
psql -v executor_password=... -v namespace=f001-closure-ns -f deployment/freshness/provision-executor-login.sql
#    write $F001_PG_DIR/claim-config.json (host,port,database,user,namespace,passwordFile,caFile), ca.crt, execpw, ownerpw
# 3. run everything
F001_PG_DIR=<dir> node --no-warnings tests/f001-closure/closure.mjs               # results.json: every scenario PASS
F001_PG_DIR=<dir> node --no-warnings tests/f001-closure/closure.mjs W0 W0c        # whole-system rollback: W0 refused, W0c control executes
# 4. the vulnerabilities on the pre-remediation tree (control)
git worktree add --detach /var/tmp/base 3f0e3a5 && ln -s "$PWD/node_modules" /var/tmp/base/node_modules
F001_SRC=/var/tmp/base F001_PG_DIR=<dir> node --no-warnings tests/f001-closure/closure.mjs R1 G2   # R1: second push executes; G2: 12 write tokens
# 5. offline evidence verification, no network, no keys
node scripts/verify-git-push-evidence.mjs <evidence.signed.json> --authority-bundle <bundle> --root-fingerprint <fp> --expected-executor-id <id> --expected-environment-id <env>
```

`results.json` records `tree_head`, `tree_dirty_paths` (must be `[]`), Node and PostgreSQL versions. A result whose `tree_head` is not the commit under review, or whose
`tree_dirty_paths` is non-empty, does not describe that commit.

## What a reproduction cannot show

GitHub's behaviour (the GitHub-App scenarios use a local emulator), a real physical approval, real power loss (`F001-POWER-LOSS-RUNBOOK.md`), or administrative
independence (everything above runs on one machine). Those need the operator steps in `F001-LIVE-TEST-READINESS.md`.
