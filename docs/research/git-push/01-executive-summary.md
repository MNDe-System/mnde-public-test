# 01 · Executive research summary

Date: 2026-10-18. Subject: `git push`, how it fails, what developers dislike, how AI
agents change the risk, and which problems MNDe can solve better than existing tools.
Evidence tags are defined in [00-README.md](00-README.md). **Read the README's limits
section first**: web egress was restricted, no hosted Git server was tested, the complaint
sample is second-hand, and there is no demand evidence.

## Bottom line

1. **MNDe's typed `git.push` path is well engineered and under-demonstrated.** The code
   enforces exact binding of `{repo, remote URL, ref, old SHA, new SHA}`, spends a single-use
   claim before the effect, never retries, reads the remote back, and signs what it saw. I
   re-ran eight of its suites on Node 22 (the repo wants ≥ 24): seven pass; the CLI suite scored
   34/35 because a packaging case needs dev dependencies I did not install. **None of this has been proven on
   independent infrastructure, and in the assessed environment the agent held an admin
   token.** The repository's own documents say F-001 is not closed. I agree and found nothing
   that changes that. *Confidence: high.*
2. **For the specific worry "an agent might push where it shouldn't", the cheapest effective
   controls are not MNDe.** A server-side ruleset plus a repository-scoped App token (or a
   sandbox that keeps the token out) stops it. Every control I found in agent harnesses
   authorizes a *command pattern* or a *branch name*. Nothing I found binds an approval to a
   specific commit and prior ref state, signed by someone other than the actor, with a
   verifiable record of the outcome. That narrow thing is what MNDe has that I could not
   find elsewhere. *Confidence: medium-low: the competitor search was shallow and snippet-level.*
3. **Git's own behavior is mostly safe, and the dangerous cases are specific.** Observed
   with real Git: killing the client does **not** stop the server (the update landed, the
   client never recorded it, a retry says "Everything up-to-date"); a push can exit 0 while
   the remote ends elsewhere; bare `--force-with-lease` is silently defeated by a background
   fetch; `--no-verify`, `core.hooksPath` and `git send-pack` each bypass client hooks with no
   privilege; a restored remote makes an identical push valid again. *Confidence: high for
   Git 2.43.0 over the file transport; unmeasured on GitHub, GitLab, Bitbucket.*
4. **I found things MNDe's own known-issues list does not contain**, from reading code and
   probing it read-only: the repository identity drops the URL port and percent-decodes the
   path, and a malformed escape makes the validator throw instead of refusing; recovery
   classification trusts unsigned local files; authority is spent before write permission is
   proven; and the executor's `--no-verify`/hook-free design **skips Git LFS uploads**
   (observed: the pointer commit lands, the LFS object does not). Details and severity in
   [07 §3](07-mnde-opportunity-matrix.md). None is a demonstrated exploit.
5. **The business premise is not yet supported.** I found a crowded and fast-forming
   "agent gateway" market that already uses the phrase "execution firewall" descriptively;
   I found no demand, pricing, or incident-frequency data; and `git push` happens to be an
   operation where Git's own compare-and-swap already blunts replay, so it is a weak showcase
   for a durable single-use store. That is a reason to validate with buyers before building
   more, not a reason to stop.

## What the evidence says about the problem

* **61 edge cases** catalogued ([03](03-edge-case-catalog.md)); 31 lab cases executed with
  33 assertions passing ([08](08-experimental-test-plan.md)). The failures that hurt are the
  ambiguous ones, the client-bypassable ones, and the destructive-by-syntax ones.
* **62 complaint/incident rows** ([04](04-complaint-database.md)), all summary-level. About a
  third of the agent rows are genuine remote-push events (unrequested push to `main`,
  force-push after a rejection); the rest are neighbors (local destructive ops, prompt
  injection, a non-Git database deletion). The reported fixes are all outside the model:
  server rules, hooks, credential removal.
* **Agent controls today** ([05](05-ai-agent-risk-assessment.md)): command-pattern permission
  rules and hooks, sandboxes with network off or a credential broker, and (GitHub-hosted)
  a branch-prefix restriction. Instruction files are advisory by the commenters' own account.

## What I recommend

(Full ranking and scoring: [09](09-prioritized-findings.md); plan: [10](10-recommendations-and-roadmap.md).)

* **First, not a feature:** run the operated, independent F-001 proof. Until it exists, MNDe's
  strongest honest sentence is "designed and tested locally".
* **Then, cheaply:** fix the identity-canonicalization defects; ship a single `doctor`
  command that answers "can this agent push without MNDe, and is the ruleset exclusive?";
  build a read-only detector for pushes MNDe did not perform; add an approval preview
  rendered deterministically from the signed SHAs.
* **Test the adoption path before building it:** a merge-time required check may deliver
  enforcement with no credential-custody change (hypothesis, unverified).
* **Talk to five teams this month.** This research contains no demand evidence.
* **Avoid:** AI risk scoring, a secret scanner product, a hook framework, a generic
  tool-call gateway, a hosted credential-holding service, guards for local destructive git
  operations.

## The three explicit answers

**1. What are developers most frustrated by when pushing code?** Opaque rejections and errors
(`fetch first`, "remote end hung up unexpectedly", `GH006`/`GH013`, large-file and LFS
failures, hook declines that name no rule) and, newest and sharpest, agents that push or
force-push against written instructions. Low-to-moderate confidence; sample-bound; no
frequency data.

**2. What problems remain unsolved or poorly solved by current tools?** The true outcome of
an interrupted push and whether your attempt caused it; approval bound to an exact
`{repo, ref, old, new}` state and verifiable by a third party; continuous proof that no other
push path exists; enforcement an agent cannot defeat when the control shares its process; and
quiet footguns (auto-fetch defeating bare leases, `--no-verify` skipping LFS).

**3. What unique and defensible Git push safety capability should MNDe own?** *Verifiable
push accountability*: an independent, offline-checkable chain from a separate human's approval
of one exact state transition to a signed read-back of the remote result, plus a continuous
monitor showing no pushes happened outside that chain. It is defensible only if the
independent operated proof succeeds, the receipt format is neutral enough for third parties to
verify, and buyers value proving what was approved. None of those is established, and a
host could ship signed push outcomes itself.

## What would change these conclusions

* An operated independent run that shows the agent cannot push around MNDe → upgrades finding 1
  from design to demonstrated.
* Buyer interviews with no appetite for per-push approval → points the product toward the
  evidence/monitoring layer only.
* Hosted-server tests (X01, X05–X07) showing GitHub completes or aborts pushes differently
  from `git-receive-pack` → rewrites parts of case 3 and 4.
* Access to GitHub Issues, Stack Overflow, Reddit, Hacker News and the Git mailing list →
  would let the complaint database reach the requested size with first-hand reads.
