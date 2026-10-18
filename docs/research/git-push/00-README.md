# Git push deep research — index, method, limits

Research date: 2026-10-18. Repository state: branch `mnde/wonderful-mendel-ybwxox`,
merged `main` at `3f0e3a5`. Nothing under `src/`, `bin/`, `tests/` or any shipped
path was changed. This folder is documentation, one lab script and its captured output.

## Read this first: what this research can and cannot support

The research environment had a restricted egress policy. That shaped the evidence
and the reader should weight it accordingly.

| Source class | Reachable? | Consequence |
| --- | --- | --- |
| Git's own docs (`git/git` `Documentation/`, master at `c514088`, 2026-10-16) | **Yes**, via a sparse public clone | Protocol, hook, `git push` claims below are checked against primary text where marked `[P]` |
| A local Git 2.43.0 + git-lfs 3.4.1 | **Yes** | 31 lab cases actually executed (`[L]`). File transport only |
| This repository (code, docs, tests) | **Yes** | `[R]`. Test suites re-run on Node 22.22.0 (repo requires ≥24; see doc 07) |
| `git-scm.com`, `docs.github.com`, `docs.gitlab.com`, `github.blog`, `githubstatus.com`, `kernel.org`, `lore.kernel.org`, `stackoverflow.com`, `reddit.com`, `news.ycombinator.com`, GitHub issue pages (403), and every blog/incident page I tried | **No** (403 or DNS) | Host-behaviour claims (GitHub/GitLab/Bitbucket) are **not** verified against vendor docs. Complaint evidence is from search-result summaries only |
| Web search (summaries + URLs) | Yes | `[S]`: a URL and a one-paragraph summary written by the search tool. **I did not open these pages.** A summary can be wrong |

Consequences, stated plainly:

1. **No GitHub, GitLab or Bitbucket server behaviour was tested.** The lab uses
   `git-receive-pack` over the local file transport. HTTP smart protocol, SSH,
   credential flows, token expiry, rate limits, GitHub rulesets and GitHub's own
   hooks were not exercised.
2. **The complaint database has 62 entries, not 75.** The prompt asks for 75 "if
   sufficient credible examples exist". I could not reach Stack Overflow, Reddit,
   Hacker News, the Git mailing list or GitHub Issues, so I did not manufacture
   the difference. Every entry carries its evidence level. None carries a
   frequency count, because I have none.
3. **"2026 incidents" in the AI-agent section are mostly user-filed issues and
   blog posts relayed by search summaries.** They are reports, not confirmed
   defects. Vendor responses are largely unknown to me.
4. **No market, pricing or willingness-to-pay data was gathered.** Where the
   opportunity matrix scores "willingness to pay", it is a judgment with no
   customer evidence behind it, and says so.
5. **Nothing was pushed anywhere.** No production GitHub operation, credential,
   or permission was touched. The only remote operations were `git clone` of the
   public `git/git` repository and web searches.

## Evidence legend (used in every document)

| Tag | Meaning | Strength |
| --- | --- | --- |
| `[L<n>]` | Lab case `L<n>`, executed this session. Script: `lab/run-lab.sh`; verbatim output: `evidence/lab-output.md`. Git 2.43.0, file transport | Strong for *that* git version and transport; says nothing about hosted servers |
| `[P]` | Read in Git's own documentation (`git/git` master `c514088`) this session | Strong for upstream Git; hosts may differ |
| `[R]` | Read or ran in this repository this session | Strong for this commit |
| `[R-doc]` | A repository document records it and I did not reproduce it | Weak: a record is not a reproduction |
| `[S]` | Search-result summary naming a URL; page not opened | Weak: unverified second-hand |
| `[K]` | Author's prior knowledge of Git or a host; not re-checked | Medium for stable Git behaviour, weak for host behaviour or anything after mid-2026 |
| `[H]` | Hypothesis; not tested | Do not rely on it |

## Deliverables

| # | Deliverable | File |
| --- | --- | --- |
| 1 | Executive research summary | [01-executive-summary.md](01-executive-summary.md) |
| 2 | Complete Git push technical architecture (Part 1) | [02-git-push-architecture.md](02-git-push-architecture.md) |
| 3 | Edge-case catalog (Part 2) | [03-edge-case-catalog.md](03-edge-case-catalog.md) |
| 4 | Developer complaint database (Part 3) | [04-complaint-database.md](04-complaint-database.md) |
| 5 | AI agent Git push risk assessment (Parts 4, 5) | [05-ai-agent-risk-assessment.md](05-ai-agent-risk-assessment.md) |
| 6 | Competitive landscape (Part 6) | [06-competitive-landscape.md](06-competitive-landscape.md) |
| 7 | MNDe feature opportunity matrix (Part 7) | [07-mnde-opportunity-matrix.md](07-mnde-opportunity-matrix.md) |
| 8 | Reproducible experimental test plan (Part 8) | [08-experimental-test-plan.md](08-experimental-test-plan.md) |
| 9 | Prioritized findings (Part 9 lists A–D) | [09-prioritized-findings.md](09-prioritized-findings.md) |
| 10 | Top ten improvements and 30-day roadmap | [10-recommendations-and-roadmap.md](10-recommendations-and-roadmap.md) |

Supporting material: [`lab/run-lab.sh`](lab/run-lab.sh) (the laboratory),
[`lab/identity-probe.mjs`](lab/identity-probe.mjs) (read-only probe of
`canonicalRepositoryIdentity`), [`evidence/lab-output.md`](evidence/lab-output.md)
(verbatim lab output), [`evidence/repo-test-run-2026-10-18.txt`](evidence/repo-test-run-2026-10-18.txt)
(tail of each suite run).

## Reproducing the lab

```
bash docs/research/git-push/lab/run-lab.sh > out.md      # ~40 s, needs git; git-lfs optional
node  docs/research/git-push/lab/identity-probe.mjs      # read-only, needs Node
```

The lab builds every repository under `mktemp -d`, removes it on exit, uses
`GIT_CONFIG_GLOBAL=/dev/null`, and never opens a socket. Cases that depend on
timing (L12, L13, L14, L30) are not deterministic in general; each prints what it
observed rather than asserting a race outcome. L23 is inconclusive when run as root.
