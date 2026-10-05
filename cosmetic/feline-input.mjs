// Cosmetic UI easter egg: "feline input" detection.
//
// THIS IS PURELY COSMETIC. It has NO connection to authority decisions, policy
// evaluation, receipts, signatures, replay, policy hashes, audit records, or
// verification. It reads typed text transiently to decide whether to show a
// small message, then forgets it. It never stores, logs, transmits, or records
// the text or the event anywhere — not in receipts, audit logs, telemetry, or
// any file. Nothing in the authority path (the sidecar runtime and the engines
// it imports) imports this module.
//
// It is safe to delete this entire folder with no effect on any guarantee.

export const DEFAULT_MESSAGES = [
  "Potential feline input detected.",
  "Keyboard ownership under review.",
  "Unauthorized paw activity suspected.",
  "Authority unable to verify operator species.",
  "MNDe recommends additional keyboard supervision."
];

// Pure, dependency-free, environment-agnostic (works in Node and the browser).
// Conservative on purpose: real prose, file paths, URLs, and identifiers should
// not trip it. It looks at the tail of the input for clear keyboard-spam shapes.
export function looksLikeKeyboardSpam(text) {
  if (typeof text !== "string") return false;
  const tail = text.slice(-48).trim();
  if (tail.length < 8) return false;

  // 1) A long run of one repeated character: "aaaaaaaa", "................".
  if (/(\S)\1{7,}/.test(tail)) return true;

  // 2) A short pattern mashed repeatedly: "asdasdasdasd", "jkjkjkjkjk".
  if (/(\S{2,4})\1{3,}/.test(tail)) return true;

  // 3) A long unbroken blob with almost no vowels and lots of variety/symbols —
  //    the classic "cat walked across the keyboard" signature.
  if (!/\s/.test(tail) && tail.length >= 16) {
    const letters = tail.replace(/[^a-z]/gi, "");
    const vowels = (tail.match(/[aeiou]/gi) || []).length;
    const symbols = (tail.match(/[^a-z0-9]/gi) || []).length;
    const unique = new Set(tail.toLowerCase()).size;
    const vowelRatio = letters.length ? vowels / letters.length : 0;
    if (vowelRatio < 0.12 && (symbols >= 4 || unique >= 11)) return true;
  }
  return false;
}

// Shared rate-limited gate used by any surface (terminal or browser). Returns a
// message string to show, or null. Holds only counters in memory.
export function createFelineWatcher(options = {}) {
  const messages = options.messages ?? DEFAULT_MESSAGES;
  const minIntervalMs = options.minIntervalMs ?? 15_000;
  const maxPerSession = options.maxPerSession ?? 5;
  let lastShown = 0;
  let shownCount = 0;

  return {
    consider(text) {
      if (!looksLikeKeyboardSpam(text)) return null;
      const now = Date.now();
      if (shownCount >= maxPerSession) return null;
      if (now - lastShown < minIntervalMs) return null;
      lastShown = now;
      shownCount += 1;
      return messages[Math.floor(Math.random() * messages.length)];
    }
  };
}

// Browser drop-in for a future desktop/dashboard UI. Opt-in: nothing happens
// until this is called. Attaches one passive listener, shows a small toast that
// dismisses itself, and ignores pasted input (this is about typing, not paste).
export function enableFelineInputEasterEgg(options = {}) {
  if (typeof document === "undefined") return () => {};
  const selector = options.selector ?? 'input[type="text"], input[type="search"], input:not([type]), textarea';
  const watcher = createFelineWatcher(options);
  const durationMs = options.durationMs ?? 2600;

  function onInput(event) {
    const el = event.target;
    if (!el || typeof el.matches !== "function" || !el.matches(selector)) return;
    if (typeof event.inputType === "string" && event.inputType.startsWith("insertFromPaste")) return;
    const message = watcher.consider(el.value); // read transiently; never stored or sent
    if (message) showToast(message, durationMs);
  }

  document.addEventListener("input", onInput, true);
  return () => document.removeEventListener("input", onInput, true);
}

function showToast(message, durationMs) {
  if (typeof document === "undefined") return;
  const previous = document.getElementById("mnde-feline-toast");
  if (previous) previous.remove();

  const reduce = typeof window !== "undefined" && window.matchMedia
    && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const el = document.createElement("div");
  el.id = "mnde-feline-toast";
  el.setAttribute("role", "status");
  el.setAttribute("aria-live", "polite");
  el.textContent = message;
  Object.assign(el.style, {
    position: "fixed", right: "16px", bottom: "16px", zIndex: "2147483647",
    maxWidth: "260px", padding: "8px 12px", borderRadius: "8px",
    font: "12px/1.4 system-ui, -apple-system, sans-serif", color: "#e8e8ea",
    background: "rgba(28,28,32,0.92)", border: "1px solid rgba(255,255,255,0.08)",
    boxShadow: "0 4px 16px rgba(0,0,0,0.25)", pointerEvents: "none",
    opacity: reduce ? "1" : "0", transition: reduce ? "none" : "opacity 180ms ease"
  });
  document.body.appendChild(el);
  if (!reduce) requestAnimationFrame(() => { el.style.opacity = "1"; });
  setTimeout(() => {
    if (reduce) { el.remove(); return; }
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 220);
  }, durationMs);
}
