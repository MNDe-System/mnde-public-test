# desktop/ — MNDe operational dashboard

The local, no-login operational view for MNDe. It answers exactly one question:

> **Is routed execution protected right now?**

MNDe is local execution infrastructure, not a SaaS product. The dashboard is built to feel like a firewall / runtime / OS component: you launch it and immediately see whether MNDe-routed execution is protected — **no login, no signup, no account, no email, no forced cloud**.

## How it runs

`dashboard.html` is a single static file with no front-end build step. The local sidecar serves it at the root:

```powershell
npm ci
npm start
# Then open http://127.0.0.1:8787/
```

It reads the sidecar's local status endpoints (`/readyz`, `/healthz`, `/receipts/recent`, `/policy/current`, `/capabilities`, `/identity`, `/hub/discovery`) over same-origin requests. The Windows sidecar performs local-network Hub discovery and pairing; the browser does not contact candidate Hubs directly. See the [installation instructions](../README.md) and [Hub physical pairing](../docs/HUB-PHYSICAL-PAIRING.md) for the protocol, security limits and Pi integration still required.

## Startup flow

1. Launch the application (start the local sidecar).
2. The sidecar starts / is connected to locally.
3. Runtime status is verified via local endpoints.
4. Routed protection status is displayed — within seconds, with no account.
5. On Windows, Hub discovery runs in the background and appears in its own status card.

## What it shows

| Panel | Source | Meaning |
| --- | --- | --- |
| Protection Status | `/readyz` + `/healthz` | PROTECTED / DEGRADED / FAIL-CLOSED / OFFLINE |
| Sidecar Status | `/healthz` | runtime health, worker, event-loop lag |
| Last Decision | `/receipts/recent` | most recent ALLOW/REFUSE, tool, reason |
| Receipt Count | `/receipts/recent` | signed receipts observed |
| Active Policy | `/policy/current` | active policy version + hash |
| Connected Tool Sources | `/receipts/recent` | distinct tools that have routed through MNDe |
| Trust Status | receipts + `/identity` | receipts signed & offline-verifiable |

## Navigation / copy

Infrastructure vocabulary only — no marketing or auth funnels:

`Authority` · `Protection Status` · `Infrastructure` · `Audit Record` · `Policy` · `Demonstration`

Removed entirely: Login, Sign In, Create Account, Welcome, Get Started.

## Enterprise identity is optional and OFF by default

Identity / team features — **Microsoft Entra ID, Okta, SSO, team management, centralized audit, policy distribution** — are reserved for future enterprise use and are **disabled by default**. MNDe enforces decisions and signs receipts with none of them. MNDe does not currently provide a public login or account system. Private beta uses local sidecar access or bearer-protected machine access; production sidecar mode requires `MNDE_SIDECAR_AUTH=bearer`. Enabling bearer auth never adds a login screen to this dashboard.

## Guarantees preserved

The dashboard reads local execution status and Hub discovery status. Pairing requests require a separate physical Hub decision, then a signed PC challenge. The current checkout does not contain the deployed Pi's button/display driver, so that last hardware connection must be integrated before pairing can complete on the Pi. Pairing does **not** change the decision engine, receipt system, replay verification, authority model, or policy enforcement.

See [docs/operational-dashboard.md](../docs/operational-dashboard.md) for the full repositioning notes.
