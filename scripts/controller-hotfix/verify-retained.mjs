import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const CANDIDATE_NAME = "candidate-20261005061320-3038c0fb3451";
export const MANIFEST_SHA256 = "d94e61c723d62e6cdf675559298fb6dc3cf6311f7e24b28161f28f2c1ac53fe4";
export const MANIFEST_BYTES = 773362;
export const IMAGE_NAME = "vram-governor-controller-linux-amd64";
export const IMAGE_SHA256 = "c50f1a7a53ffbca3aa7835786eb1bae67fddfe69260381cd77ec6e7780bdb543";
export const IMAGE_BYTES = 12976280;
export const BASELINE_COMMIT = "cf8d06ad71d5e840304a842ec700cbe4c9637002";
export const BASELINE_TREE = "a7707962963733e4753a664493f067e89c851138";
export const DEPENDENCY_BYTES = 12262;
export const DEPENDENCY_SHA256 = "f0e75cecb70b5230839e87abc26664037ebb39a30924a8e5a2b57c706f6e6bf8";
export const EXPECTED_TEST_INVENTORY = Object.freeze([
  "historical phase accepted without current equality",
  "unknown phase and CLI rejected",
  "historical schema and identity mutants rejected",
  "changed acceptance flags rejected",
  "candidate and asset identity mutants rejected",
  "fixed verifier orchestration and dependency custody",
  "exact test inventory and success-only marker",
]);

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CANDIDATE_ROOT = path.join(ROOT, ".cache", "controller-transport-hotfix", CANDIDATE_NAME);
const DEPENDENCY_PATH = fileURLToPath(new URL("./verify-stage.mjs", import.meta.url));
const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;

function fail(message) { throw new Error(message); }
function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}
function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }

function validateHistoricalState(state) {
  if (!exactKeys(state, ["head", "index", "worktree", "worktreeStatusSha256"]) || typeof state.head !== "string" || !HEX40.test(state.head)) fail("historical build snapshot identity is invalid");
  if (!exactKeys(state.index, ["path", "type", "mode", "bytes", "sha256"]) || state.index.path !== ".git/index" || state.index.type !== "file" || !Number.isSafeInteger(state.index.mode) || state.index.mode < 0 || !Number.isSafeInteger(state.index.bytes) || state.index.bytes < 0 || !HEX64.test(state.index.sha256)) fail("historical index snapshot schema is invalid");
  if (!exactKeys(state.worktree, ["count", "totalBytes", "digest"]) || !Number.isSafeInteger(state.worktree.count) || state.worktree.count < 0 || !Number.isSafeInteger(state.worktree.totalBytes) || state.worktree.totalBytes < 0 || !HEX64.test(state.worktree.digest) || !HEX64.test(state.worktreeStatusSha256)) fail("historical worktree snapshot schema is invalid");
  return state;
}

/** Pure projection of the retained artifact's historical build phase. */
export function validateRetainedPhase(manifest) {
  const manifestKeys = ["schema", "candidate", "localOnly", "releaseApproved", "installedBinaryProvenance", "baseline", "reviewedDelta", "inputTrust", "sourceFiles", "closure", "build", "binary", "gitStateBefore", "gitStateAfter"];
  if (!exactKeys(manifest, manifestKeys) || manifest.schema !== "controller-transport-hotfix-candidate-v1" || manifest.candidate !== CANDIDATE_NAME) fail("retained candidate schema or identity differs");
  if (manifest.localOnly !== true || manifest.releaseApproved !== false || manifest.installedBinaryProvenance !== false) fail("retained candidate acceptance flags differ");
  if (!exactKeys(manifest.baseline, ["commit", "tree"]) || manifest.baseline.commit !== BASELINE_COMMIT || manifest.baseline.tree !== BASELINE_TREE) fail("retained candidate baseline identity differs");
  if (!Array.isArray(manifest.sourceFiles) || manifest.sourceFiles.length !== 279 || !isRecord(manifest.closure) || !Array.isArray(manifest.closure.embeddedAssets) || manifest.closure.embeddedAssets.length !== 12) fail("retained source or embedded asset inventory differs");
  if (!exactKeys(manifest.binary, ["path", "bytes", "sha256"]) || manifest.binary.path !== IMAGE_NAME || manifest.binary.bytes !== IMAGE_BYTES || manifest.binary.sha256 !== IMAGE_SHA256) fail("retained executable identity differs");
  const before = validateHistoricalState(manifest.gitStateBefore);
  const after = validateHistoricalState(manifest.gitStateAfter);
  if (JSON.stringify(before) !== JSON.stringify(after)) fail("historical build snapshots differ");
  return Object.freeze({ phase: "historical-build-and-current-retained-artifact", candidate: CANDIDATE_NAME, manifestSha256: MANIFEST_SHA256, manifestBytes: MANIFEST_BYTES, imageSha256: IMAGE_SHA256, imageBytes: IMAGE_BYTES, sourceFiles: 279, embeddedAssets: 12, historicalHead: before.head, historicalWorktreeCount: before.worktree.count, historicalWorktreeBytes: before.worktree.totalBytes, historicalWorktreeDigest: before.worktree.digest, currentWorktreeCompared: false });
}

export function validateRetainedCli(args) {
  if (!Array.isArray(args) || args.length !== 1 || args[0] !== "--verify") fail("invalid retained verification mode");
  return true;
}

function sameAuthority(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode && left.nlink === right.nlink && left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs && left.sha256 === right.sha256;
}

export function verifyAcceptedVerifierCustody(filesystem = fs) {
  let current = path.parse(DEPENDENCY_PATH).root;
  for (const part of DEPENDENCY_PATH.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const ancestor = filesystem.lstatSync(current);
    if (ancestor.isSymbolicLink() || (current !== DEPENDENCY_PATH && !ancestor.isDirectory())) fail("accepted verifier path custody differs");
  }
  const before = filesystem.lstatSync(DEPENDENCY_PATH);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size !== DEPENDENCY_BYTES) fail("accepted verifier custody differs");
  const flags = filesystem.constants.O_RDONLY | (filesystem.constants.O_NOFOLLOW ?? 0);
  const fd = filesystem.openSync(DEPENDENCY_PATH, flags);
  try {
    const opened = filesystem.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.size !== before.size || opened.dev !== before.dev || opened.ino !== before.ino || opened.mode !== before.mode || opened.mtimeMs !== before.mtimeMs || opened.ctimeMs !== before.ctimeMs) fail("accepted verifier identity changed before read");
    const hash = crypto.createHash("sha256"); let total = 0; const buffer = Buffer.alloc(8192);
    for (;;) { const n = filesystem.readSync(fd, buffer, 0, buffer.length, null); if (n === 0) break; total += n; if (total > DEPENDENCY_BYTES) fail("accepted verifier exceeds bound"); hash.update(buffer.subarray(0, n)); }
    const after = filesystem.fstatSync(fd); const named = filesystem.lstatSync(DEPENDENCY_PATH); const digest = hash.digest("hex");
    if (total !== DEPENDENCY_BYTES || after.size !== before.size || after.mode !== before.mode || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || named.isSymbolicLink() || named.nlink !== 1 || named.dev !== before.dev || named.ino !== before.ino || named.size !== before.size || named.mode !== before.mode || named.mtimeMs !== before.mtimeMs || named.ctimeMs !== before.ctimeMs || digest !== DEPENDENCY_SHA256) fail("accepted verifier digest or custody differs");
    return Object.freeze({ dev: before.dev, ino: before.ino, mode: before.mode, nlink: before.nlink, size: before.size, mtimeMs: before.mtimeMs, ctimeMs: before.ctimeMs, sha256: digest });
  } finally { filesystem.closeSync(fd); }
}

async function loadAcceptedVerifier() {
  return import(new URL("./verify-stage.mjs", import.meta.url).href);
}

// The fixed CLI is intended for a fresh trusted local process. Named-file pre/post hashing detects unchanged custody; it is not race-proof authentication of Node's module cache/evaluation or a sandbox.
/** Test seam accepts only injected effects; production always uses fixed local bindings. */
export async function runRetainedVerificationWithSeams(args, { filesystem = fs, loader = loadAcceptedVerifier, observe } = {}) {
  validateRetainedCli(args);
  if (typeof loader !== "function" || typeof observe !== "function") fail("accepted verifier unavailable");
  const initialAuthority = verifyAcceptedVerifierCustody(filesystem);
  try {
    const loaded = await loader(new URL("./verify-stage.mjs", import.meta.url).href);
    const loadedAuthority = verifyAcceptedVerifierCustody(filesystem);
    if (!sameAuthority(initialAuthority, loadedAuthority) || !loaded || typeof loaded.verifyCandidateAt !== "function") fail("accepted verifier loaded source authority differs");
    const observed = observe(loaded.verifyCandidateAt, CANDIDATE_ROOT);
    const projection = validateRetainedPhase(observed?.manifest);
    if (observed.manifest.sourceFiles.length !== 279 || observed.manifest.closure.embeddedAssets.length !== 12) fail("accepted verifier inventory differs");
    return projection;
  } finally {
    const finalAuthority = verifyAcceptedVerifierCustody(filesystem);
    if (!sameAuthority(initialAuthority, finalAuthority)) fail("accepted verifier changed during retained verification");
  }
}

async function runFixedRetainedVerification() {
  return runRetainedVerificationWithSeams(process.argv.slice(2), {
    loader: loadAcceptedVerifier,
    observe: (verifyCandidateAt, candidatePath) => verifyCandidateAt(candidatePath),
  });
}

function runPureControlInventory(inventory, passed) {
  if (!Array.isArray(inventory) || inventory.length !== EXPECTED_TEST_INVENTORY.length || EXPECTED_TEST_INVENTORY.some((name, index) => inventory[index] !== name) || passed !== inventory.length) fail("retained control inventory incomplete");
  return true;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    validateRetainedCli(process.argv.slice(2));
    const result = await runFixedRetainedVerification();
    process.stdout.write(`retained controller candidate phase verified: candidate=${result.candidate}; manifest_sha256=${result.manifestSha256}; source_files=${result.sourceFiles}; embedded_assets=${result.embeddedAssets}; historical_build_snapshots=equal; current_worktree_compared=false\n`);
  } catch {
    process.stderr.write("retained controller candidate phase verification failed closed\n");
    process.exitCode = 1;
  }
}

export const _controlInventory = runPureControlInventory;
