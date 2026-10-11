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
export const ORIGINAL_SHA256 = "ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c";
export const ORIGINAL_BYTES = 12976280;
export const CONFIG_PATH = "/etc/vram-governor/controller.yaml";
export const CONFIG_SHA256 = "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37";
export const CONFIG_BYTES = 6789;
export const CA_PATH = "/etc/vram-governor/tls/controller.crt";
export const CA_SHA256 = "ddc7359a3f730b1817c7adff7ede84439bdf31cc56ff7cf658142473042c1944";
export const STAGING_PARENT = "/var/lib/vram-governor-controller-staging";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const MAX_MANIFEST = 2 * 1024 * 1024;
const MAX_SOURCE_FILES = 1000;
const MAX_SOURCE_BYTES = 64 * 1024 * 1024;
const MAX_SOURCE_FILE = 16 * 1024 * 1024;
const MAX_TREE_ENTRIES = 4000;
const MAX_DEPTH = 32;

function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function safeRelative(name) {
  return typeof name === "string" && name.length > 0 && !name.includes("\\") && !name.includes(":") && !name.includes("\0") && !path.posix.isAbsolute(name) && name.split("/").every((part) => part && part !== "." && part !== "..");
}
function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}
function sameDirectory(before, after) {
  return after.isDirectory() && !after.isSymbolicLink() && before.dev === after.dev && before.ino === after.ino && before.mode === after.mode && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs;
}
function assertNoLinkedAncestors(target) {
  const absolute = path.resolve(target); const parsed = path.parse(absolute); let current = parsed.root;
  for (const part of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const info = fs.lstatSync(current);
    if (info.isSymbolicLink()) throw new Error("candidate path contains a linked ancestor");
    if (current !== absolute && !info.isDirectory()) throw new Error("candidate path ancestor is not a directory");
  }
}
function listDirectoryBounded(directory, maximum) {
  const before = fs.lstatSync(directory);
  if (!before.isDirectory() || before.isSymbolicLink()) throw new Error("candidate directory is not a stable directory");
  const names = []; const entries = fs.opendirSync(directory);
  try {
    let entry;
    while ((entry = entries.readSync()) !== null) {
      if (names.length >= maximum) throw new Error("candidate directory entry count exceeds bound");
      names.push(entry.name);
    }
  } finally { entries.closeSync(); }
  if (!sameDirectory(before, fs.lstatSync(directory))) throw new Error("candidate directory changed during enumeration");
  return names;
}
function stableRead(file, maxBytes) {
  const before = fs.lstatSync(file);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || !Number.isSafeInteger(before.size) || before.size > maxBytes) throw new Error("candidate file is not a bounded singly-linked regular file");
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  const fd = fs.openSync(file, fs.constants.O_RDONLY | noFollow);
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.size !== before.size || opened.dev !== before.dev || opened.ino !== before.ino) throw new Error("candidate file identity changed before read");
    const bytes = Buffer.alloc(before.size); let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, null);
      if (count <= 0) throw new Error("candidate file ended before its declared size");
      offset += count;
    }
    const extra = Buffer.alloc(1);
    if (fs.readSync(fd, extra, 0, 1, null) !== 0) throw new Error("candidate file grew beyond its preflight size");
    const after = fs.fstatSync(fd);
    const named = fs.lstatSync(file);
    if (bytes.length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || named.isSymbolicLink() || named.nlink !== 1 || named.dev !== before.dev || named.ino !== before.ino || named.size !== before.size || named.mtimeMs !== before.mtimeMs || named.ctimeMs !== before.ctimeMs) throw new Error("candidate file identity changed during read");
    return bytes;
  } finally { fs.closeSync(fd); }
}

export function readCandidateFiles(sourceRoot) {
  const files = new Map(); let entryCount = 0; let totalBytes = 0;
  function walk(directory, relative = "", depth = 0) {
    if (depth > MAX_DEPTH) throw new Error("candidate source tree depth exceeds bound");
    const directoryBefore = fs.lstatSync(directory);
    if (!directoryBefore.isDirectory() || directoryBefore.isSymbolicLink()) throw new Error("candidate source directory changed before enumeration");
    const entries = fs.opendirSync(directory); let child; let childCount = 0;
    try {
      while ((child = entries.readSync()) !== null) {
        childCount++; entryCount++;
        if (entryCount > MAX_TREE_ENTRIES) throw new Error("candidate source entry count exceeds bound");
        const name = relative ? `${relative}/${child.name}` : child.name;
        if (!safeRelative(name)) throw new Error("candidate source path is unsafe");
        const full = path.join(directory, child.name); const info = fs.lstatSync(full);
        if (info.isSymbolicLink()) throw new Error("candidate source contains a symbolic link");
        if (info.isDirectory()) { walk(full, name, depth + 1); continue; }
        if (!info.isFile() || files.has(name) || !Number.isSafeInteger(info.size) || info.size > MAX_SOURCE_FILE || files.size >= MAX_SOURCE_FILES || totalBytes + info.size > MAX_SOURCE_BYTES) throw new Error("candidate source file exceeds inventory bounds");
        const bytes = stableRead(full, MAX_SOURCE_FILE); totalBytes += bytes.length; files.set(name, bytes);
      }
    } finally { entries.closeSync(); }
    if (relative && childCount === 0) throw new Error("candidate source contains an empty directory");
    if (!sameDirectory(directoryBefore, fs.lstatSync(directory))) throw new Error("candidate source directory changed during enumeration");
  }
  const rootInfo = fs.lstatSync(sourceRoot);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error("candidate source root is invalid");
  walk(sourceRoot);
  return files;
}

export function verifyCandidateAt(candidateRoot) {
  const root = path.resolve(candidateRoot);
  assertNoLinkedAncestors(root);
  const rootInfo = fs.lstatSync(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error("accepted candidate root is invalid");
  const top = listDirectoryBounded(root, 3).sort();
  const expectedTop = ["manifest.json", "source", IMAGE_NAME].sort();
  if (JSON.stringify(top) !== JSON.stringify(expectedTop)) throw new Error("accepted candidate has an unknown or missing top-level entry");
  const manifestBytes = stableRead(path.join(root, "manifest.json"), MAX_MANIFEST);
  if (manifestBytes.length !== MANIFEST_BYTES || sha256(manifestBytes) !== MANIFEST_SHA256) throw new Error("accepted candidate manifest identity mismatch");
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  if (!Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8").equals(manifestBytes)) throw new Error("accepted candidate manifest is not canonical");
  if (manifest.schema !== "controller-transport-hotfix-candidate-v1" || manifest.candidate !== CANDIDATE_NAME || manifest.localOnly !== true || manifest.releaseApproved !== false || manifest.installedBinaryProvenance !== false || manifest.baseline?.commit !== "cf8d06ad71d5e840304a842ec700cbe4c9637002" || manifest.baseline?.tree !== "a7707962963733e4753a664493f067e89c851138") throw new Error("accepted candidate manifest boundary differs");
  if (!exactKeys(manifest.binary, ["path", "bytes", "sha256"]) || manifest.binary.path !== IMAGE_NAME || manifest.binary.bytes !== IMAGE_BYTES || manifest.binary.sha256 !== IMAGE_SHA256) throw new Error("accepted candidate binary manifest differs from fixed identity");
  if (!Array.isArray(manifest.sourceFiles) || manifest.sourceFiles.length < 1 || manifest.sourceFiles.length > MAX_SOURCE_FILES) throw new Error("accepted candidate source inventory exceeds bound");
  const expected = new Map(); let declaredBytes = 0; let previous = null;
  for (const entry of manifest.sourceFiles) {
    if (!exactKeys(entry, ["path", "bytes", "sha256"]) || !safeRelative(entry.path) || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || entry.bytes > MAX_SOURCE_FILE || !/^[0-9a-f]{64}$/.test(entry.sha256) || expected.has(entry.path)) throw new Error("accepted candidate source manifest entry is invalid");
    if (previous !== null && previous.localeCompare(entry.path) > 0) throw new Error("accepted candidate source manifest ordering is invalid");
    previous = entry.path; declaredBytes += entry.bytes;
    if (declaredBytes > MAX_SOURCE_BYTES) throw new Error("accepted candidate source manifest exceeds total bound");
    expected.set(entry.path, entry);
  }
  const actual = readCandidateFiles(path.join(root, "source"));
  if (actual.size !== expected.size) throw new Error("accepted candidate source file count differs");
  for (const [name, record] of expected) {
    const bytes = actual.get(name);
    if (!bytes || bytes.length !== record.bytes || sha256(bytes) !== record.sha256) throw new Error("accepted candidate source bytes differ from manifest");
  }
  if (!Array.isArray(manifest.closure?.embeddedAssets) || manifest.closure.embeddedAssets.length < 1 || manifest.closure.embeddedAssets.length > 100) throw new Error("accepted candidate embedded asset inventory is invalid");
  const binaryBytes = stableRead(path.join(root, IMAGE_NAME), IMAGE_BYTES);
  if (binaryBytes.length !== IMAGE_BYTES || sha256(binaryBytes) !== IMAGE_SHA256) throw new Error("accepted candidate executable identity mismatch");
  const seenAssets = new Set();
  for (const asset of manifest.closure.embeddedAssets) {
    if (!exactKeys(asset, ["path", "bytes", "sha256"]) || !safeRelative(asset.path) || seenAssets.has(asset.path)) throw new Error("accepted candidate embedded asset record is invalid");
    seenAssets.add(asset.path);
    const source = actual.get(asset.path); const declared = expected.get(asset.path);
    if (!source || !declared || asset.bytes !== source.length || asset.sha256 !== sha256(source) || asset.bytes !== declared.bytes || asset.sha256 !== declared.sha256 || !binaryBytes.includes(source)) throw new Error("accepted candidate embedded asset identity mismatch");
  }
  if (!sameDirectory(rootInfo, fs.lstatSync(root))) throw new Error("accepted candidate root changed during verification");
  return { manifest, binaryBytes };
}

export function validateLocalRoot(candidateRoot) {
  return verifyCandidateAt(candidateRoot);
}

function fixedCandidateRoot() { return path.join(ROOT, ".cache", "controller-transport-hotfix", CANDIDATE_NAME); }

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3 || process.argv[2] !== "--local") throw new Error("invalid local verification mode");
    const { manifest } = verifyCandidateAt(fixedCandidateRoot());
    process.stdout.write(`controller staging local identity verified: candidate=${manifest.candidate}; manifest_sha256=${MANIFEST_SHA256}; binary_sha256=${IMAGE_SHA256}\n`);
  } catch {
    process.stderr.write("controller staging local identity verification failed closed\n");
    process.exitCode = 1;
  }
}
