import { canonicalRepositoryIdentity, validateGitPushParameters } from "../../../../src/effects/git-push/validate.mjs";
const cases = [
  "https://github.com/Org/Repo.git",
  "https://github.com/org/repo.git",
  "https://github.com:8443/org/repo.git",
  "https://github.com./org/repo.git",
  "https://GITHUB.com/org/repo",
  "https://github.com/org%2Frepo.git",
  "https://github.com/org/repo/../repo.git",
  "https://github.com/org/repo%00.git",
  "https://github.com/org/repo%E0%A4%A.git",
  "https://github.com//org/repo.git",
  "https://github.com/org/repo.git/",
  "ssh://git@github.com/org/repo.git",
  "git@github.com:org/repo.git",
  "https://gitıthub.com/org/repo.git",
  "https://github.com/org/repо.git",
];
for (const u of cases) {
  let r; try { r = canonicalRepositoryIdentity(u); } catch (e) { r = `THROWS ${e.name}: ${e.message}`; }
  console.log(JSON.stringify(u).padEnd(52), "->", r);
}
// does a malformed percent escape throw out of the validator rather than refuse?
const sha = "a".repeat(40), sha2 = "b".repeat(40);
try {
  const v = validateGitPushParameters({ repository: "x", remote: "origin", remote_url: "https://github.com/org/repo%E0%A4%A.git", source_commit: sha2, target_ref: "refs/heads/x", expected_old_sha: sha }, { allowedSchemes: ["https"] });
  console.log("validator returned", JSON.stringify(v));
} catch (e) { console.log("validator THREW", e.name, e.message); }
