import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { isRepoContainedPath, readSecureExecutorPrivateKey } from "../src/custody/executor-identity.mjs";

const root = mkdtempSync(join(tmpdir(), "mnde-key-path-"));
const repoRoot = join(root, "repo");
const externalRoot = join(root, "repository-other");
mkdirSync(repoRoot);
mkdirSync(externalRoot);

let passed = 0;
let failed = 0;
let skipped = 0;

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ok - ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  FAIL - ${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function skip(name, reason) {
  skipped += 1;
  console.log(`  skip - ${name}: ${reason}`);
}

function keyFile(dir, name = "executor key.pem") {
  const path = join(dir, name);
  writeFileSync(path, "test-private-key-material", { mode: 0o600 });
  return path;
}

console.log("Executor private-key path security\n");

try {
  const externalKey = keyFile(externalRoot);
  const inRepoKey = keyFile(repoRoot, "contained.pem");

  await test("normal external key path is accepted", async () => {
    const result = await readSecureExecutorPrivateKey(externalKey, repoRoot);
    assert.equal(result.ok, true, result.code);
    assert.equal(result.privatePem, "test-private-key-material");
  });

  await test("repository-contained key is rejected by canonical containment", async () => {
    const result = await readSecureExecutorPrivateKey(inRepoKey, repoRoot);
    assert.equal(result.ok, false);
    assert.equal(result.code, "ERR_EXECUTOR_KEY_REPOSITORY_CONTAINED");
  });

  await test("segment comparison does not confuse repo with repository-other", () => {
    assert.equal(isRepoContainedPath(resolve(externalKey), resolve(repoRoot)), false);
  });

  await test("key path containing spaces is accepted", async () => {
    const spacedDir = join(externalRoot, "directory with spaces");
    mkdirSync(spacedDir);
    const result = await readSecureExecutorPrivateKey(keyFile(spacedDir), repoRoot);
    assert.equal(result.ok, true, result.code);
  });

  await test("missing key file fails closed", async () => {
    const result = await readSecureExecutorPrivateKey(join(externalRoot, "missing.pem"), repoRoot);
    assert.equal(result.ok, false);
    assert.equal(result.code, "ERR_EXECUTOR_KEY_MISSING");
  });

  await test("missing parent directory fails closed", async () => {
    const result = await readSecureExecutorPrivateKey(join(externalRoot, "missing-parent", "key.pem"), repoRoot);
    assert.equal(result.ok, false);
    assert.equal(result.code, "ERR_EXECUTOR_KEY_MISSING");
  });

  await test("directory passed as key file is rejected", async () => {
    const result = await readSecureExecutorPrivateKey(externalRoot, repoRoot);
    assert.equal(result.ok, false);
    assert.equal(result.code, "ERR_EXECUTOR_KEY_UNSUPPORTED_TYPE");
  });

  const fileLink = join(externalRoot, "direct-link.pem");
  try {
    symlinkSync(inRepoKey, fileLink, "file");
    await test("direct key-file symlink is rejected", async () => {
      const result = await readSecureExecutorPrivateKey(fileLink, repoRoot);
      assert.equal(result.ok, false);
      assert.equal(result.code, "ERR_EXECUTOR_KEY_SYMLINK");
    });
  } catch (error) {
    skip("direct key-file symlink", `platform did not permit file symlink creation (${error.code ?? "unknown"})`);
  }

  const parentLink = join(root, "linked-parent");
  try {
    symlinkSync(externalRoot, parentLink, "dir");
    await test("parent-directory symlink is rejected", async () => {
      const result = await readSecureExecutorPrivateKey(join(parentLink, "executor key.pem"), repoRoot);
      assert.equal(result.ok, false);
      assert.equal(result.code, "ERR_EXECUTOR_KEY_SYMLINK");
    });
  } catch (error) {
    skip("parent-directory symlink", `platform did not permit directory symlink creation (${error.code ?? "unknown"})`);
  }

  if (process.platform === "win32") {
    const junction = join(root, "repo-junction");
    try {
      symlinkSync(repoRoot, junction, "junction");
      await test("Windows directory junction into repository is rejected", async () => {
        const result = await readSecureExecutorPrivateKey(join(junction, "contained.pem"), repoRoot);
        assert.equal(result.ok, false);
        assert.equal(result.code, "ERR_EXECUTOR_KEY_SYMLINK");
      });
    } catch (error) {
      skip("Windows directory junction", `junction creation unavailable (${error.code ?? "unknown"})`);
    }

    await test("mixed-case and mixed-slash repository paths remain contained", async () => {
      const mixed = inRepoKey.replaceAll("\\", "/").replace(/^([a-z]):/iu, (_, drive) => `${drive.toUpperCase()}:`);
      const result = await readSecureExecutorPrivateKey(mixed, repoRoot.toUpperCase());
      assert.equal(result.ok, false);
      assert.equal(result.code, "ERR_EXECUTOR_KEY_REPOSITORY_CONTAINED");
    });

    skip("UNC path", "no deterministic writable UNC share is available in the test environment");
    skip("read-permission denial", "POSIX mode bits are not a reliable Windows ACL test");
  } else {
    await test("broadly writable key file is rejected", async () => {
      const writable = keyFile(externalRoot, "writable.pem");
      chmodSync(writable, 0o666);
      const result = await readSecureExecutorPrivateKey(writable, repoRoot);
      assert.equal(result.ok, false);
      assert.equal(result.code, "ERR_EXECUTOR_KEY_PERMISSIONS");
    });
    skip("Windows directory junction", "junctions are a Windows-only filesystem feature");
    skip("UNC path", "UNC paths are a Windows-only filesystem feature");
  }

  skip("path replacement race", "a deterministic descriptor-swap race is not reproducible without a filesystem test hook; descriptor identity checks are unit-inspected instead");
} finally {
  rmSync(root, { recursive: true, force: true });
}

console.log(`\n${failed === 0 ? "PASS" : "FAIL"} executor key path security (${passed} passed, ${failed} failed, ${skipped} skipped)`);
process.exit(failed === 0 ? 0 : 1);
