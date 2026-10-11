import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CANDIDATE_NAME, DEPENDENCY_BYTES, DEPENDENCY_SHA256, EXPECTED_TEST_INVENTORY, IMAGE_BYTES, IMAGE_NAME, IMAGE_SHA256, MANIFEST_BYTES, MANIFEST_SHA256, _controlInventory, runRetainedVerificationWithSeams, validateRetainedCli, validateRetainedPhase, verifyAcceptedVerifierCustody } from "./verify-retained.mjs";

const state = { head: "1234567890abcdef1234567890abcdef12345678", index: { path: ".git/index", type: "file", mode: 0o100644, bytes: 80, sha256: "a".repeat(64) }, worktree: { count: 7, totalBytes: 1200, digest: "b".repeat(64) }, worktreeStatusSha256: "c".repeat(64) };
const manifest = {
  schema: "controller-transport-hotfix-candidate-v1", candidate: CANDIDATE_NAME, localOnly: true, releaseApproved: false, installedBinaryProvenance: false,
  baseline: { commit: "cf8d06ad71d5e840304a842ec700cbe4c9637002", tree: "a7707962963733e4753a664493f067e89c851138" },
  reviewedDelta: {}, inputTrust: {}, sourceFiles: Array.from({ length: 279 }, (_, i) => ({ path: `source/${i}`, bytes: 1, sha256: "d".repeat(64) })),
  closure: { embeddedAssets: Array.from({ length: 12 }, (_, i) => ({ path: `asset/${i}`, bytes: 1, sha256: "e".repeat(64) })) },
  build: {}, binary: { path: IMAGE_NAME, bytes: IMAGE_BYTES, sha256: IMAGE_SHA256 }, gitStateBefore: structuredClone(state), gitStateAfter: structuredClone(state),
};
const cases = [];
async function control(name, fn) { await fn(); cases.push(name); }

const dependencyPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "verify-stage.mjs");
const dependencyBytes = fs.readFileSync(dependencyPath);
assert.equal(dependencyBytes.length, DEPENDENCY_BYTES);
function fakeFilesystem(mutant = "") {
  const state = { changed: false, namedCalls: 0 };
  const stats = (overrides = {}) => ({ dev: 1, ino: 2, mode: 0o100600, nlink: 1, size: dependencyBytes.length, mtimeMs: 10, ctimeMs: 20, isFile: () => true, isDirectory: () => false, isSymbolicLink: () => false, ...overrides });
  return {
    constants: fs.constants,
    lstatSync(target) {
      if (target !== dependencyPath) return fs.lstatSync(target);
      if (mutant === "missing") throw new Error("missing");
      state.namedCalls++;
      const changes = {};
      if (mutant === "link") Object.assign(changes, { isSymbolicLink: () => true, isFile: () => false });
      if (mutant === "multilink") changes.nlink = 2;
      if (mutant === "wrongsize") changes.size++;
      if (mutant === "mutation-during-read" && state.namedCalls > 1) changes.ctimeMs++;
      if (state.changed) changes.mtimeMs++;
      return stats(changes);
    },
    openSync(target) { assert.equal(target, dependencyPath); return { offset: 0 }; },
    fstatSync(fd) {
      if (mutant === "open-vs-named") return stats({ ino: 99 });
      return stats();
    },
    readSync(fd, out, offset, length) {
      const data = Buffer.from(dependencyBytes);
      if (mutant === "wronghash") data[0] ^= 0xff;
      const count = Math.min(length, data.length - fd.offset);
      if (count <= 0) return 0;
      data.copy(out, offset, fd.offset, fd.offset + count); fd.offset += count; return count;
    },
    closeSync() {},
    markChanged() { state.changed = true; },
  };
}

await control("historical phase accepted without current equality", () => {
  const out = validateRetainedPhase(manifest);
  assert.equal(out.currentWorktreeCompared, false);
  assert.equal(out.historicalHead, state.head);
  assert.notEqual(out.historicalHead, manifest.baseline.commit);
  assert.equal(out.sourceFiles, 279);
  assert.equal(out.embeddedAssets, 12);
});
await control("unknown phase and CLI rejected", () => {
  assert.equal(validateRetainedCli(["--verify"]), true);
  for (const args of [[], ["--local"], ["--verify", "extra"]]) assert.throws(() => validateRetainedCli(args));
  assert.throws(() => _controlInventory([...EXPECTED_TEST_INVENTORY, "unknown"], EXPECTED_TEST_INVENTORY.length + 1));
  assert.throws(() => _controlInventory([], 0));
});
await control("historical schema and identity mutants rejected", () => {
  for (const change of [m => { m.gitStateAfter.worktree.count++; }, m => { m.gitStateBefore.head = "0".repeat(40); }, m => { delete m.gitStateAfter.index.sha256; }, m => { m.gitStateBefore.worktree.digest = "bad"; }]) { const m = structuredClone(manifest); change(m); assert.throws(() => validateRetainedPhase(m)); }
});
await control("changed acceptance flags rejected", () => {
  for (const [key, value] of [["localOnly", false], ["releaseApproved", true], ["installedBinaryProvenance", true]]) { const m = structuredClone(manifest); m[key] = value; assert.throws(() => validateRetainedPhase(m)); }
});
await control("candidate and asset identity mutants rejected", () => {
  for (const change of [m => { m.candidate = "other"; }, m => { m.binary.sha256 = "0".repeat(64); }, m => { m.sourceFiles.pop(); }, m => { m.closure.embeddedAssets.pop(); }, m => { m.baseline.tree = "0".repeat(40); }]) { const m = structuredClone(manifest); change(m); assert.throws(() => validateRetainedPhase(m)); }
});
await control("fixed verifier orchestration and dependency custody", async () => {
  assert.equal(verifyAcceptedVerifierCustody().sha256, DEPENDENCY_SHA256);
  const expectedRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..", ".cache", "controller-transport-hotfix", CANDIDATE_NAME);
  let loaderCalls = 0; let observerCalls = 0;
  const loader = async (url) => { loaderCalls++; assert.equal(url, new URL("./verify-stage.mjs", import.meta.url).href); return { verifyCandidateAt() {} }; };
  const observe = (verifyCandidateAt, candidatePath) => { observerCalls++; assert.equal(typeof verifyCandidateAt, "function"); assert.equal(candidatePath, expectedRoot); return { manifest: structuredClone(manifest) }; };
  const fake = fakeFilesystem();
  const result = await runRetainedVerificationWithSeams(["--verify"], { filesystem: fake, loader, observe });
  assert.equal(loaderCalls, 1); assert.equal(observerCalls, 1); assert.equal(result.manifestSha256, MANIFEST_SHA256); assert.equal(result.manifestBytes, MANIFEST_BYTES); assert.equal(result.imageBytes, IMAGE_BYTES); assert.equal(result.imageSha256, IMAGE_SHA256);
  for (const mutant of ["missing", "link", "multilink", "wrongsize", "wronghash", "open-vs-named", "mutation-during-read"]) {
    let loadCount = 0; let observeCount = 0;
    await assert.rejects(runRetainedVerificationWithSeams(["--verify"], { filesystem: fakeFilesystem(mutant), loader: async () => { loadCount++; return { verifyCandidateAt() {} }; }, observe: () => { observeCount++; return { manifest }; } }));
    assert.equal(loadCount, 0, `${mutant} must reject before module load`); assert.equal(observeCount, 0, `${mutant} must reject before observation`);
  }
  let invalidLoads = 0; let invalidObserves = 0;
  await assert.rejects(runRetainedVerificationWithSeams(["--local"], { filesystem: fakeFilesystem("missing"), loader: async () => { invalidLoads++; }, observe: () => { invalidObserves++; } }));
  assert.equal(invalidLoads, 0); assert.equal(invalidObserves, 0);
  const changedDuringLoad = fakeFilesystem(); let changedLoads = 0; let changedObserves = 0;
  await assert.rejects(runRetainedVerificationWithSeams(["--verify"], { filesystem: changedDuringLoad, loader: async () => { changedLoads++; changedDuringLoad.markChanged(); return { verifyCandidateAt() {} }; }, observe: () => { changedObserves++; return { manifest }; } }));
  assert.equal(changedLoads, 1); assert.equal(changedObserves, 0);
  const changedAfterObserve = fakeFilesystem(); let successfulMutationLoads = 0; let successfulMutationObserves = 0;
  await assert.rejects(runRetainedVerificationWithSeams(["--verify"], { filesystem: changedAfterObserve, loader: async () => { successfulMutationLoads++; return { verifyCandidateAt() {} }; }, observe: () => { successfulMutationObserves++; changedAfterObserve.markChanged(); return { manifest: structuredClone(manifest) }; } }));
  assert.equal(successfulMutationLoads, 1); assert.equal(successfulMutationObserves, 1);
  let failedObserverCalls = 0;
  await assert.rejects(runRetainedVerificationWithSeams(["--verify"], { filesystem: fakeFilesystem(), loader, observe: () => { failedObserverCalls++; throw new Error("controlled rejection"); } }));
  assert.equal(failedObserverCalls, 1);
});
await control("exact test inventory and success-only marker", () => {
  assert.deepEqual([...cases, "exact test inventory and success-only marker"], EXPECTED_TEST_INVENTORY);
  assert.equal(_controlInventory([...cases, "exact test inventory and success-only marker"], cases.length + 1), true);
  assert.throws(() => _controlInventory(cases.slice(0, -1), cases.length - 1));
  assert.throws(() => _controlInventory(cases, cases.length - 1));
});

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3 || process.argv[2] !== "--verify") throw new Error("invalid test mode");
    if (! _controlInventory(cases, cases.length)) throw new Error("controls incomplete");
    process.stdout.write("retained controller phase controls passed\n");
  } catch {
    process.stderr.write("retained controller phase controls failed closed\n");
    process.exitCode = 1;
  }
}
