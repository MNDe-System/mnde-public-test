# Hub physical pairing protocol (checkout implementation)

This checkout contains the pairing protocol and the Windows browser dashboard
client. It does **not** contain the deployed Pi's button/display driver. The
deployed Pi source reported in October 2026 also has a discovery identity route
that is newer than this checkout's Hub source. Do not deploy this checkout to the
Pi until the physical driver and the deployed identity implementation are
reconciled and tested together. No Pi files or production credentials were
changed during this work.

The current deployed Pi contract supplied for the Windows verification has
public pairing and challenge routes on port 8790 and a **localhost-only**
physical button bridge. The Windows app uses only `/healthz`,
`/v1/hub/identity`, `/v1/pairing/requests` and `/v1/auth/*`; it never calls
`/internal/physical/*`. Its dashboard enters Waiting for physical approval only
after the pairing POST returns HTTP 201 with `ok: true` and `status: "PENDING"`.

## Trust boundaries

- mDNS and `GET /v1/hub/identity` locate a candidate and provide a claimed Hub
  ID. Plain LAN HTTP does not authenticate that claim.
- A new PC has a persistent Ed25519 key in its current Windows user's DPAPI
  store. `%LOCALAPPDATA%\MNDe\client-identity.json` contains only the client
  ID, name, creation time and public key. `client-private-key.dpapi` holds the
  encrypted private key. The private key is never sent to the Hub.
- A pending request is not a credential. Only the in-process physical approval
  interface can approve/refuse it. Approval durably records the public key in
  `<MNDE_HUB_DATA_DIR>/paired-clients.json` using the existing Hub state layer.
  The data directory must retain its existing owner-only permissions.
- A paired PC uses a new Ed25519 signed challenge for each authentication. The
  resulting session lasts five minutes and is recognized only by
  `GET /v1/auth/session`. It is **not** accepted by `/v1/actions`, lock/unlock,
  receipts or any execution endpoint. Existing operator/agent bearer auth,
  policy, approvals, claims, execution gate and receipts still apply.
- `%LOCALAPPDATA%\MNDe\paired-hubs.json` holds one record per Hub ID and its
  last authenticated address. A discovered IP does not create that record. If
  a Hub supplies the earlier signed identity proof, its public key is pinned
  after the user confirms the physical Hub's displayed fingerprint; reconnects
  must prove possession of that same key.

## Hub routes

Set `MNDE_HUB_ID` to the Pi's existing persistent ID before enabling pairing in
this checkout; it must match `hub-[A-Za-z0-9_-]+`. Do not generate a different
ID for a previously paired Hub. By default the checkout Hub still binds
`127.0.0.1:8790`; `MNDE_HUB_BIND_ADDRESS=0.0.0.0` is an explicit LAN bind and
must be reviewed against the Pi's network rules before use.

| Route | Request | Success response | Access |
| --- | --- | --- | --- |
| `GET /v1/hub/identity` | none | `{ "product":"MNDe Hub", "protocolVersion":1, "hubId":"hub-...", "status":"ready" }` | LAN read |
| `POST /v1/pairing/requests` | `{ "clientId":"pc-<16-32 lowercase hex>", "clientName":"PC", "publicKey":"<43 base64url characters>", "protocolVersion":1 }` | HTTP 201 `{ "ok":true, "pairingRequestId":"pair-...", "status":"PENDING", "expiresAt":"<ISO UTC>" }` | LAN create; rate limited |
| `GET /v1/pairing/requests/:id` | none | `{ "ok":true, "status":"PENDING|APPROVED|REFUSED|EXPIRED|COMPLETED" }` | possession of random ID |
| `POST /v1/auth/challenge` | `{ "clientId":"pc-..." }` | `{ "challengeId":"challenge-...", "nonce":"<43 base64url characters>", "expiresAt":"<ISO UTC>", "hubId":"hub-..." }` | paired client ID; rate limited |
| `POST /v1/auth/verify` | `{ "clientId":"pc-...", "challengeId":"challenge-...", "signature":"<86 base64url characters>" }` | `{ "ok":true, "sessionToken":"<43 base64url characters>", "expiresAt":"<ISO UTC>" }` | valid one-use signed challenge |
| `GET /v1/auth/session` | `Authorization: Bearer <sessionToken>` | `{ "ok":true, "clientId":"pc-...", "hubId":"hub-...", "expiresAt":"<ISO UTC>" }` | paired session only |
| `GET /v1/pairing/clients` | existing operator bearer | `{ "clients":[{ "hubId":"hub-...", "clientId":"pc-...", "clientName":"PC", "pairedAt":"<ISO UTC>", "revoked":false, "credentialVersion":1 }] }` | operator only |
| `POST /v1/pairing/clients/:clientId/revoke` | empty JSON `{}` and existing operator bearer | `{ "ok":true, "clientId":"pc-...", "revoked":true }` | operator only |

Malformed data, unsupported versions, duplicate active requests, excessive
pending requests and rate excess are rejected. Pending requests last three
minutes; challenges last one minute; sessions last five minutes. Requests,
challenges and sessions are memory only and disappear on restart. Paired clients
survive restart. Revocation durably marks a client revoked and immediately
invalidates its in-memory challenges and sessions.

The signature covers UTF-8 bytes of this exact compact JSON shape and field
order, with the challenge values returned by the Hub:

```json
{"purpose":"mnde.hub.client-auth.v1","hubId":"hub-...","clientId":"pc-...","challengeId":"challenge-...","nonce":"...","expiresAt":"..."}
```

The Hub consumes each challenge on the first verify attempt, including a bad
signature. This prevents replay and repeated guesses against one challenge.

The Windows dashboard keeps the Pi pairing POST's HTTP status and safe
`reason_code` in Connection details when a request fails. Pairing and auth
events are logged with status, request ID and reason code; no private key,
signature, session token or bearer credential is logged. Discovery events are
available in the same diagnostics panel; set `MNDE_HUB_DISCOVERY_DEBUG=1` to
also write them to the local sidecar's standard output.

## Physical driver integration required

`startHub()` returns `physicalPairing.pending()`,
`physicalPairing.approve(pairingRequestId)` and
`physicalPairing.refuse(pairingRequestId)` when `MNDE_HUB_ID` is configured.
`pending()` returns records with `actionType: "pairing.client"`, the request ID,
client ID/name and expiry. The Pi's actual button/display driver must consume
these methods **in the same trusted Hub process** or through an independently
reviewed local-only IPC channel. Show `PAIR COMPUTER`, the PC name and short
client ID, plus distinct `APPROVE` and `REFUSE` actions. Show the outcome.
Never map a generic execution approval event to these methods. No HTTP endpoint
can invoke `approve` or `refuse`. The current `bin/mnde-hub.mjs` does not
connect a driver, so physical approval on the deployed Pi is not implemented.

## Manual Pi integration procedure after driver connection

1. Back up every Pi file to be changed. Confirm the persistent Hub ID reported
   by `GET /v1/hub/identity` and configure this exact ID. Do not change
   production credentials or the execution service's authority bundle.
2. On a test LAN, verify the existing mDNS service, `/healthz` and identity
   responses. Confirm the desktop shows **Unpaired**, not Connected.
3. Start pairing in the Windows dashboard. The Pi display must show the same
   PC name and short client ID with an explicit pairing action. Wait without
   pressing a button; no credential should appear in `paired-clients.json`.
4. Press **REFUSE**. Confirm the desktop shows Pairing refused and auth fails.
   Repeat, let the request expire, and confirm the button cannot approve it.
5. Start a new request and press **APPROVE**. Confirm one owner-only trusted
   client record, a valid signed challenge, and Connected in the dashboard.
6. Restart the Hub; confirm the client record persists and a fresh challenge
   authenticates. Move the Hub to a different private IP; confirm the same Hub
   ID reconnects and the desktop's saved address updates.
7. Revoke the PC through the existing operator authentication. Confirm new
   challenges and its current session fail. Confirm its pairing session token
   receives HTTP 401 on `/v1/actions`, even with a syntactically valid action.

## Known security limits

LAN HTTP does not provide confidentiality or server authentication. A network
attacker can intercept short-lived session tokens and can spoof the Hub's
unsigned identity, status or auth responses. The session token has no execution
authority, but the dashboard's Connected state cannot prove it reached the
physical Hub against an active network attacker. A signed, pinned Hub identity
or TLS/mutual TLS must be added before relying on that state for stronger trust.
The older discovery prototype has optional signed identity proof, but the
reported deployed Pi identity endpoint currently returns only the plain fields
shown above. Physical approval alone does not solve the server-authentication
gap over active MITM.
