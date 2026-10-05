# MNDe app for Windows

This repository contains the MNDe operational dashboard, its local Node sidecar, Hub discovery and pairing client, assets, and relevant tests. The dashboard opens in a browser at `http://127.0.0.1:8787/`; this source does not include a Windows `.exe` or installer. It is an independent copy of the desktop-facing code and the runtime modules it imports. No files from the original checkout are needed to install or build it.

## Install on a home Windows PC

1. Install [Git for Windows](https://git-scm.com/download/win) and [Node.js 24 or newer](https://nodejs.org/en/download). Open a **new PowerShell** window and confirm `git --version` and `node --version` work.
2. Sign in to GitHub with access to the private `MNDe-System/mnde-app` repository. In PowerShell, run:

   ```powershell
   cd $HOME\Documents
   git clone https://github.com/MNDe-System/mnde-app.git
   cd mnde-app
   npm ci
   Copy-Item .env.example .env
   ```

3. If the Hub is on the same local network, leave `MNDE_HUB_IP` commented in `.env`. If the Hub is reached through Tailscale, install [Tailscale for Windows](https://tailscale.com/docs/install/windows), sign the PC and Hub into the same tailnet, get the Hub's IPv4 address with `tailscale ip -4` on the Hub, and set `MNDE_HUB_IP=<that 100.x IPv4 address>` in `.env`. The Hub must listen on its tailnet interface at TCP port 8790 and tailnet policy must allow the PC to reach it. A Tailscale IP can also be tested from PowerShell with `Test-NetConnection <Hub-IP> -Port 8790`.
4. Run `npm start`. Leave that PowerShell window open and visit `http://127.0.0.1:8787/` on the same PC. Stop with Ctrl+C. If port 8787 is in use, set another `MNDE_BIND_PORT` in `.env` and use that port in the browser URL.

The first launch creates local development authority keys and receipts under `%LOCALAPPDATA%\MNDe\app-runtime` by default. Windows client identity, Hub trust records and pairing metadata are stored separately under `%LOCALAPPDATA%\MNDe`. Back up these local files if you need to preserve pairing across a reinstall. Never copy them into this source repository. `.env` is ignored; keep credentials out of it and out of Git.

## Build and test

From the repository folder:

```powershell
npm ci
npm test
npm run build
npm run test:built
```

`npm run build` creates a portable source bundle in `dist`. It is not an `.exe`. To run that bundle on another Windows PC, copy `dist` to that PC, open PowerShell in the copied folder, run `npm ci --omit=dev`, then `npm start`. The launcher still stores writable keys and receipts in the current Windows user's local application data folder.

## Find and pair a Hub

The Windows sidecar browses `_mnde-hub._tcp.local` with mDNS and probes the advertised private address at TCP port 8790. The Hub must advertise that service and expose `/healthz` and `/v1/hub/identity` on a reachable interface. Allow local multicast DNS (UDP 5353) and Hub TCP 8790 through the relevant network and host firewalls. The browser itself talks only to the local sidecar. If a candidate appears, open **MNDe Hub → Connection details**, choose the Hub, and select **Pair selected Hub**. Check the PC name and short client ID on the physical Hub, then press its distinct approval button. A pairing request is pending until the Hub approves it; seeing a Hub in the list does not establish trust.

For a Tailscale connection, use `MNDE_HUB_IP` as described above. The client accepts Tailscale `100.64.0.0/10` IPv4 addresses and probes the configured address directly; mDNS across a tailnet is not assumed. It also retries a saved, previously paired address. A manual address must still pass the same health and identity checks before appearing as a candidate.

Automatic local-network discovery and physical pairing have **not** been verified here against a real Hub. The copied source includes the desktop client and protocol, but the original checkout does not include the deployed Raspberry Pi button/display driver. Before relying on pairing, verify the deployed Hub's discovery route, network binding, physical approval driver, signed identity behavior, reconnect and revocation on your actual hardware. The current plain HTTP Hub protocol has limits against an active network attacker; see [pairing protocol](docs/HUB-PHYSICAL-PAIRING.md).

## Configuration

`.env.example` shows local settings. `MNDE_HUB_DISCOVERY=0` disables discovery. `MNDE_HUB_IP` permits a direct private or Tailscale IP probe. `MNDE_HOME` optionally moves generated local authority data to another folder outside the checkout. The app does not start a Hub server and contains no GitHub push credential, token, private key, saved client identity or saved device credential.
