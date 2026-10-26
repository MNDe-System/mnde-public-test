# MNDe installation

No MSI, NSIS, EXE, DMG, PKG, or AppImage is available. No downloadable npm
tarball is currently published. The current evaluation path is a source
checkout with Node.js 24 or later:

```bash
git clone https://github.com/mndesystems-ship-it/mnde-public-test.git
cd mnde-public-test
npm install
npm run reviewer-kit
```

Start MNDe directly from the checkout with:

```bash
npm run sidecar
```

`npm run release` creates local release-candidate artifacts for release
verification and maintainer publication preparation. Those local artifacts are
not public downloads and are not desktop installers.

See [`docs/RELEASE.md`](../docs/RELEASE.md) for the build and packaged-install
contract.

## Windows desktop shortcut (one click)

This is a shortcut to the existing dashboard, not an installer or a new app.
From a checkout with Node.js 24 or later on `PATH`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File installer\windows\install-shortcut.ps1
```

This creates `MNDe.lnk` on your Desktop (OneDrive-redirected Desktops included) with
the MNDe mark. Double-clicking it runs `installer/windows/mnde-launch.mjs`, which:

1. opens `http://127.0.0.1:8787/` if the sidecar already answers `/readyz`;
2. otherwise starts the existing `scripts/start-sidecar.mjs` hidden, waits for
   `/readyz`, then opens the dashboard.

It never starts a second sidecar, resolves paths from its own location (so the
working directory does not matter), and changes no bind address, auth, or
settings. Startup output goes to `mnde-receipts/_sidecar-logs/launcher-sidecar.log`.
The sidecar keeps running after you close the browser; stop it from Task Manager
(`node.exe`) or by running `npm run sidecar` in a terminal and pressing Ctrl+C.
Re-run the install command if you move the repo or reinstall Node. Remove the
shortcut by deleting `MNDe.lnk`.
