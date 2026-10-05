# cosmetic/

A small, optional easter egg. **Purely cosmetic — delete this folder and nothing changes.**

When someone mashes the keyboard at a text-entry surface (long repeated-character runs, mashed patterns, or symbol gibberish — the "cat walked across the keyboard" shape), MNDe shows a small, self-dismissing message such as "Potential feline input detected."

## Isolation guarantees

This module has **no connection** to authority decisions, policy evaluation, receipts, signatures, replay, policy hashes, audit records, verification, or performance. Specifically:

- It never influences `ALLOW` / `REFUSE`.
- It never appears in receipts, signatures, replay data, policy hashes, audit exports, or verification results.
- It never stores, logs, or transmits the typed text or the event (no file, no receipt, no audit, no telemetry). Text is read transiently and discarded.
- Nothing in the authority path imports it. The sidecar runtime (`mnde-local-sidecar.mjs` and the engines it imports) does not depend on `cosmetic/`.
- Frequency is rate-limited so it cannot become annoying.

## Where it runs

- **Interactive terminal** (`npm run sidecar`): a dim one-line message at the prompt where you type `stop`. Only active for a real TTY — never under pipes, automation, or tests. Disable with `MNDE_FELINE=0`.
- **Browser (future desktop/dashboard UI):** opt-in via `enableFelineInputEasterEgg()`. Nothing happens until called; pasted input is ignored. Preview it by opening `cosmetic/demo.html`.

## Files

- `feline-input.mjs` — `looksLikeKeyboardSpam(text)` (pure), `createFelineWatcher(opts)` (rate-limited gate), `enableFelineInputEasterEgg(opts)` (browser DOM hook).
- `demo.html` — browser preview.
- Tests: `npm run test:feline`.
