// Canonical MNDE_PROFILE parser. All callers must use this — never compare the
// raw env string directly so that a missing, mistyped, or wrongly-cased value
// fails explicitly rather than silently degrading to local/dev mode.
//
// Valid values (case-insensitive): "production", "local".
//
// F1 (no implicit trust profile): an unset / empty / whitespace-only MNDE_PROFILE
// is NOT treated as local. It returns ok:false with ERR_PROFILE_REQUIRED so the
// load-bearing caller (the sidecar trust-root pre-flight) fails closed at startup.
// The operator must choose a profile explicitly; development stays available by
// setting MNDE_PROFILE=local. An unknown value returns ok:false ERR_UNKNOWN_PROFILE.
// On failure `profile` is null — a failed parse never yields a usable profile.

const VALID_PROFILES = new Set(["production", "local"]);

export function parseRuntimeProfile(raw) {
  if (raw === undefined || raw === null || String(raw).trim() === "") {
    return {
      ok: false,
      profile: null,
      reason_code: "ERR_PROFILE_REQUIRED",
      detail:
        "MNDE_PROFILE is not set. Select a trust profile explicitly: 'production' for the production trust gate, or 'local' for development. There is no implicit default — a missing profile never selects local mode."
    };
  }
  const normalized = String(raw).toLowerCase().trim();
  if (!VALID_PROFILES.has(normalized)) {
    return {
      ok: false,
      profile: null,
      reason_code: "ERR_UNKNOWN_PROFILE",
      detail: `MNDE_PROFILE value '${raw}' is not recognized. Valid values: 'production', 'local' (case-insensitive). There is no implicit default.`
    };
  }
  return { ok: true, profile: normalized };
}
