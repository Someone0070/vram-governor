import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { readSafeFailureDiagnostic, verifyCandidateDirectory } from "./verify.mjs";

export const BASE_COMMIT = "cf8d06ad71d5e840304a842ec700cbe4c9637002";
export const BASE_TREE = "a7707962963733e4753a664493f067e89c851138";
export const HELPER_PATH = "internal/nodetransport/limits.go";
export const HELPER_SHA256 = "0c7453ec051d7f69e34f65bc1c5fdf4e512287a709f75dd409574f24d0bf5a0b";
export const GO_SHA256 = "8e8356be1603abff526f52c0d5fe887fb4d77b000f310d298ad10cd33e7471e6";
export const GO_TOOLCHAIN_MODULE_H1 = "h1:uAs0v1Tbi8pAEvc6IkL/tazTmMBok9HxjXC9XLzlLss=";
export const WS_PATH = "internal/api/ws.go";
const MAX_ARCHIVE = 128 * 1024 * 1024;
const MAX_FILE = 32 * 1024 * 1024;
const MAX_STATE_FILE = 128 * 1024 * 1024;
const MAX_STATE_FILES = 600_000;
const MAX_STATE_TOTAL = 64 * 1024 * 1024 * 1024;
const MAX_STATE_SINGLE_FILE = 16 * 1024 * 1024 * 1024;
const MAX_STATE_PATH_LIST = 256 * 1024 * 1024;
const MAX_CANDIDATE_FILES = 30_000;
const MAX_CANDIDATE_TOTAL = 4 * 1024 * 1024 * 1024;
const MAX_CANDIDATE_ENTRIES = 120_000;
const COMMAND_TIMEOUT_MS = 30_000;
const FAILURE_STAGES = new Set(["baseline", "initial-preservation", "source", "closure-before", "compile", "closure-after", "postbuild-preservation", "manifest", "preverify-preservation", "independent-verifier", "final-preservation"]);
const FAILURE_OPERATIONS = new Set(["git", "go-list", "go-version", "go-build", "local"]);
const FAILURE_ERRNOS = new Set(["EACCES", "EBUSY", "EIO", "EMFILE", "ENOMEM", "ENOENT", "EPERM", "ETIMEDOUT", "ENOBUFS", "EINVAL"]);
const SAFE_FAILURE = Symbol("safeFailure");
const TOOLCHAIN_EXTRA_GO_MOD_COPIES = [
  "src/cmd/go.mod",
  "src/cmd/objdump/testdata/testfilenum/go.mod",
  "src/cmd/vet/testdata/rangeloop/go.mod",
  "src/cmd/vet/testdata/stdversion/go.mod",
  "src/crypto/internal/bigmod/_asm/go.mod",
  "src/crypto/internal/edwards25519/field/_asm/go.mod",
  "src/go.mod",
];
const TOOLCHAIN_NORMALIZED_FILE_COUNT = 9874;
const TOOLCHAIN_NORMALIZED_BYTES = 227759789;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
let activeFailureStage = "baseline";

export function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

export function safeRelative(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\\") || value.includes(":") || value.includes("\0") || path.posix.isAbsolute(value)) return false;
  const parts = value.split("/");
  return parts.every((part) => part !== "" && part !== "." && part !== "..");
}

export function missingTrackedWorktreeRecord(name, tracked, code) {
  if (!safeRelative(name) || tracked !== true || code !== "ENOENT") throw new Error("only a missing cached tracked path is recorded as absent");
  return { path: name, type: "absent", mode: 0, bytes: 0, sha256: sha256(Buffer.alloc(0)) };
}

export function assertCandidateFileBound(size, fileCount, totalBytes) {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_FILE || !Number.isInteger(fileCount) || fileCount < 0 || fileCount >= MAX_CANDIDATE_FILES || !Number.isSafeInteger(totalBytes) || totalBytes < 0 || totalBytes + size > MAX_CANDIDATE_TOTAL) throw new Error("candidate source exceeds pre-read bounds");
  return true;
}

export function transformWs(source) {
  const importNeedle = '\t"vram-governor/internal/domain"\n';
  const importReplacement = `${importNeedle}\t"vram-governor/internal/nodetransport"\n`;
  if (source.split(importNeedle).length !== 2) throw new Error("pinned WebSocket import anchor is not unique");
  let transformed = source.replace(importNeedle, importReplacement);
  const acceptBlock = [
    "\tconn, err := websocket.Accept(w, r, nil)\n",
    "\tif err != nil {\n",
    '\t\ts.log.Error("ws accept failed", "err", err)\n',
    "\t\treturn\n",
    "\t}\n",
  ].join("");
  if (transformed.split(acceptBlock).length !== 2) throw new Error("pinned WebSocket accept anchor is not unique");
  transformed = transformed.replace(acceptBlock, `${acceptBlock}\tnodetransport.ApplyControlMessageLimit(conn)\n`);
  const acceptAt = transformed.indexOf("conn, err := websocket.Accept");
  const limitAt = transformed.indexOf("nodetransport.ApplyControlMessageLimit(conn)");
  const firstReadAt = transformed.indexOf("wsjson.Read(ctx, conn", acceptAt);
  if (!(acceptAt >= 0 && limitAt > acceptAt && firstReadAt > limitAt) || transformed.indexOf("nodetransport.ApplyControlMessageLimit(conn)", limitAt + 1) !== -1) {
    throw new Error("finite limit placement is invalid");
  }
  return transformed;
}

function command(binary, args, options = {}) {
  const result = spawnSync(binary, args, { cwd: options.cwd ?? ROOT, env: options.env, input: options.input, encoding: options.encoding ?? "buffer", maxBuffer: options.maxBuffer ?? MAX_ARCHIVE, timeout: options.timeout ?? COMMAND_TIMEOUT_MS, windowsHide: true });
  if (result.error || result.status !== 0) throw makeSafeCommandFailure(safeOperation(binary, args), result.error?.code, result.status);
  return result.stdout;
}

function safeOperation(binary, args) {
  if (binary === "git") return "git";
  if (path.basename(binary).toLowerCase() === "go.exe" || binary === "go") {
    if (args[0] === "list") return "go-list";
    if (args[0] === "version") return "go-version";
    if (args[0] === "build") return "go-build";
  }
  return "local";
}

function makeSafeCommandFailure(operation, errorCode, status) {
  let code = "terminated";
  if (errorCode === "ETIMEDOUT") code = "timeout";
  else if (errorCode === "ENOBUFS" || errorCode === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") code = "buffer";
  else if (FAILURE_ERRNOS.has(errorCode)) code = errorCode;
  else if (Number.isInteger(status) && status >= 0 && status <= 255) code = `exit-${status}`;
  const error = new Error("local command failed");
  Object.defineProperty(error, SAFE_FAILURE, { value: { operation: FAILURE_OPERATIONS.has(operation) ? operation : "local", code } });
  return error;
}

export function formatFailureDiagnostic(stage, error) {
  const safeStage = FAILURE_STAGES.has(stage) ? stage : "source";
  const detail = error instanceof Error ? (Object.getOwnPropertyDescriptor(error, SAFE_FAILURE)?.value ?? readSafeFailureDiagnostic(error)) : null;
  if (!detail) return `stage=${safeStage} operation=assertion code=assertion`;
  const operation = FAILURE_OPERATIONS.has(detail.operation) ? detail.operation : "local";
  const exitMatch = typeof detail.code === "string" ? /^exit-(0|[1-9][0-9]*)$/.exec(detail.code) : null;
  const validExit = Boolean(exitMatch && Number(exitMatch[1]) <= 255);
  const safeCode = detail.code === "timeout" || detail.code === "buffer" || detail.code === "terminated" || detail.code === "assertion" || FAILURE_ERRNOS.has(detail.code) || validExit ? detail.code : "assertion";
  return `stage=${safeStage} operation=${operation} code=${safeCode}`;
}

function gitText(args) {
  return command("git", ["--no-replace-objects", "--no-optional-locks", ...args], { env: gitEnvironment(), encoding: "utf8", maxBuffer: 4 * 1024 * 1024, failure: "pinned Git source inspection failed" }).trimEnd();
}

function hostEnvironment() {
  const allowed = ["SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "PATHEXT", "COMSPEC"];
  const result = {};
  for (const wanted of allowed) {
    const key = Object.keys(process.env).find((name) => name.toLowerCase() === wanted.toLowerCase());
    if (key && process.env[key]) result[wanted] = process.env[key];
  }
  if (!result.SystemRoot && result.WINDIR) result.SystemRoot = result.WINDIR;
  if (!result.WINDIR && result.SystemRoot) result.WINDIR = result.SystemRoot;
  return result;
}

function gitEnvironment() { return { ...hostEnvironment(), GIT_OPTIONAL_LOCKS: "0", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "" }; }

function goEnvironment(goRoot, goCache) {
  return {
    ...hostEnvironment(), GOOS: "linux", GOARCH: "amd64", GOAMD64: "v1", CGO_ENABLED: "0", GOTOOLCHAIN: "local",
    GOROOT: goRoot, GOCACHE: goCache, GOMODCACHE: path.join(ROOT, ".cache", "gopath", "pkg", "mod"),
    GOENV: "off", GOWORK: "off", GOFLAGS: "", GOEXPERIMENT: "", GODEBUG: "", GOFIPS140: "", GOAUTH: "",
    GOPROXY: "off", GOSUMDB: "off", GOPRIVATE: "", GONOPROXY: "", GONOSUMDB: "", GOINSECURE: "", GOVCS: "*:off",
  };
}

function recordedGoEnvironment() {
  return { GOOS: "linux", GOARCH: "amd64", GOAMD64: "v1", CGO_ENABLED: "0", GOTOOLCHAIN: "local", GOROOT: "pinned-go1.23.4-toolchain", GOCACHE: "candidate-private", GOMODCACHE: "repo-offline-cache", GOENV: "off", GOWORK: "off", GOFLAGS: "", GOEXPERIMENT: "", GODEBUG: "", GOFIPS140: "", GOAUTH: "", GOPROXY: "off", GOSUMDB: "off", GOPRIVATE: "", GONOPROXY: "", GONOSUMDB: "", GOINSECURE: "", GOVCS: "*:off" };
}

function stableRead(fullPath, maxBytes = MAX_STATE_FILE) {
  const before = fs.lstatSync(fullPath);
  if (!before.isFile() || before.isSymbolicLink() || before.size > maxBytes) throw new Error("preservation input is not a bounded regular file");
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  const fd = fs.openSync(fullPath, fs.constants.O_RDONLY | noFollow);
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.size !== before.size || opened.mode !== before.mode || opened.dev !== before.dev || opened.ino !== before.ino) throw new Error("preservation input changed before read");
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd); const finalPath = fs.lstatSync(fullPath);
    if (bytes.length !== before.size || after.size !== before.size || after.mode !== before.mode || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || finalPath.isSymbolicLink() || finalPath.dev !== before.dev || finalPath.ino !== before.ino || finalPath.mode !== before.mode || finalPath.size !== before.size || finalPath.mtimeMs !== before.mtimeMs || finalPath.ctimeMs !== before.ctimeMs) throw new Error("preservation input changed during read");
    return { bytes, stat: before };
  } finally { fs.closeSync(fd); }
}

function stableHashFile(fullPath, maxBytes = MAX_STATE_SINGLE_FILE) {
  const before = fs.lstatSync(fullPath);
  if (!before.isFile() || before.isSymbolicLink() || !Number.isSafeInteger(before.size) || before.size > maxBytes) throw new Error("preservation input is not a bounded regular file");
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  const fd = fs.openSync(fullPath, fs.constants.O_RDONLY | noFollow);
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.size !== before.size || opened.mode !== before.mode || opened.dev !== before.dev || opened.ino !== before.ino) throw new Error("preservation input changed before hash");
    const digest = crypto.createHash("sha256"); const chunk = Buffer.allocUnsafe(1024 * 1024); let bytes = 0;
    while (true) {
      const count = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (count === 0) break;
      bytes += count;
      if (bytes > maxBytes || bytes > before.size) throw new Error("preservation input exceeded its preflight bound");
      digest.update(chunk.subarray(0, count));
    }
    const after = fs.fstatSync(fd); const finalPath = fs.lstatSync(fullPath);
    if (bytes !== before.size || after.size !== before.size || after.mode !== before.mode || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || finalPath.isSymbolicLink() || finalPath.dev !== before.dev || finalPath.ino !== before.ino || finalPath.mode !== before.mode || finalPath.size !== before.size || finalPath.mtimeMs !== before.mtimeMs || finalPath.ctimeMs !== before.ctimeMs) throw new Error("preservation input changed during hash");
    return { bytes, sha256: digest.digest("hex"), stat: before };
  } finally { fs.closeSync(fd); }
}

export function hash1Entries(entries, prefix = "") {
  if (!Array.isArray(entries) || typeof prefix !== "string" || (prefix && !safeRelative(prefix)) || prefix.includes("\n") || prefix.includes("\\")) throw new Error("module hash input is invalid");
  const normalized = entries.map((entry) => {
    if (!entry || typeof entry.path !== "string" || !safeRelative(entry.path) || entry.path.includes("\n") || !Buffer.isBuffer(entry.bytes)) throw new Error("module hash entry is invalid");
    return { path: prefix ? `${prefix}/${entry.path}` : entry.path, sha256: sha256(entry.bytes) };
  });
  normalized.sort((a, b) => Buffer.compare(Buffer.from(a.path, "utf8"), Buffer.from(b.path, "utf8")));
  const h = crypto.createHash("sha256");
  for (const entry of normalized) h.update(`${entry.sha256}  ${entry.path}\n`, "utf8");
  return `h1:${h.digest("base64")}`;
}

export function assertModuleChecksumIdentity({ modulePath, version, treeH1, moduleSum, moduleGoMod, cacheGoMod, goModSum }) {
  if (typeof modulePath !== "string" || !safeRelative(modulePath) || typeof version !== "string" || !/^v[0-9][A-Za-z0-9.+-]*$/.test(version) || !Buffer.isBuffer(moduleGoMod) || !Buffer.isBuffer(cacheGoMod)) throw new Error("module checksum identity input is malformed");
  if (!moduleSum || treeH1 !== moduleSum || hash1Entries([{ path: "go.mod", bytes: moduleGoMod }]) !== goModSum || hash1Entries([{ path: "go.mod", bytes: cacheGoMod }]) !== goModSum || !moduleGoMod.equals(cacheGoMod)) throw new Error("module bytes differ from pinned go.sum h1");
  return true;
}

export function assertToolchainIdentity({ h1, fileCount, totalBytes, version, goToolSha256 }) {
  if (h1 !== GO_TOOLCHAIN_MODULE_H1 || fileCount !== TOOLCHAIN_NORMALIZED_FILE_COUNT || totalBytes !== TOOLCHAIN_NORMALIZED_BYTES || version !== "go version go1.23.4 windows/amd64" || goToolSha256 !== GO_SHA256) throw new Error("Go toolchain differs from official normalized module identity");
  return true;
}

function assertGeneratedGoModCopies(goRoot) {
  return assertGeneratedGoModPairs(TOOLCHAIN_EXTRA_GO_MOD_COPIES.map((copyPath) => {
    const parts = copyPath.split("/");
    return { path: copyPath, copied: stableRead(path.join(goRoot, ...parts)).bytes, original: stableRead(path.join(goRoot, ...parts.slice(0, -1), "_go.mod")).bytes };
  }));
}

export function assertGeneratedGoModPairs(pairs) {
  if (!Array.isArray(pairs) || pairs.length !== TOOLCHAIN_EXTRA_GO_MOD_COPIES.length || pairs.some((pair, index) => !pair || pair.path !== TOOLCHAIN_EXTRA_GO_MOD_COPIES[index] || !Buffer.isBuffer(pair.copied) || !Buffer.isBuffer(pair.original) || !pair.copied.equals(pair.original))) throw new Error("Go toolchain generated go.mod copy differs from its pinned _go.mod source");
  return true;
}

export function directoryH1(root, excluded = [], prefix = "") {
  const excludedSet = new Set(excluded);
  const records = []; let totalBytes = 0;
  function walk(dir, relative = "") {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      if (!safeRelative(name) || name.includes("\n")) throw new Error("module input contains an unsafe filename");
      const full = path.join(dir, entry.name); const st = fs.lstatSync(full);
      if (st.isSymbolicLink()) throw new Error("module input contains a symlink");
      if (st.isDirectory()) walk(full, name);
      else if (st.isFile()) {
        if (excludedSet.has(name)) continue;
        if (!Number.isSafeInteger(st.size) || st.size > MAX_STATE_FILE || records.length >= 100_000 || totalBytes + st.size > 512 * 1024 * 1024) throw new Error("module input tree exceeds pre-read bounds");
        const measured = stableHashFile(full, MAX_STATE_FILE); totalBytes += measured.bytes;
        records.push({ path: name, bytes: measured.bytes, sha256: measured.sha256 });
      } else throw new Error("module input contains a special file");
    }
  }
  walk(root);
  const normalized = records.map((entry) => ({ path: prefix ? `${prefix}/${entry.path}` : entry.path, sha256: entry.sha256 }));
  normalized.sort((a, b) => Buffer.compare(Buffer.from(a.path, "utf8"), Buffer.from(b.path, "utf8")));
  const h = crypto.createHash("sha256"); for (const entry of normalized) h.update(`${entry.sha256}  ${entry.path}\n`, "utf8");
  const h1 = `h1:${h.digest("base64")}`;
  return { h1, fileCount: records.length, totalBytes, files: records.map(({ path: name, bytes, sha256: hash }) => ({ path: name, bytes, sha256: hash })) };
}

function gitPathBytes(args, maxBytes = MAX_STATE_PATH_LIST) {
  const raw = command("git", ["--no-replace-objects", "--no-optional-locks", ...args], { env: gitEnvironment(), maxBuffer: maxBytes });
  const values = [];
  for (let start = 0; start < raw.length;) { const end = raw.indexOf(0, start); if (end < 0) throw new Error("Git path inventory is truncated"); const name = raw.subarray(start, end).toString("utf8"); if (!Buffer.from(name, "utf8").equals(raw.subarray(start, end)) || !safeRelative(name)) throw new Error("Git path inventory contains unsafe path"); values.push(name); start = end + 1; }
  if (values.length > MAX_STATE_FILES) throw new Error("Git path inventory exceeds count bound");
  return values;
}

function pathInsideRoot(full) {
  const relative = path.relative(ROOT, path.resolve(full));
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("preservation path escaped repository");
  return relative.split(path.sep).join("/");
}

function snapshotWorktreeFiles() {
  const tracked = gitPathBytes(["ls-files", "--cached", "-z"]);
  const trackedSet = new Set(tracked);
  const untracked = gitPathBytes(["ls-files", "--others", "--exclude-standard", "-z"]);
  const names = [...new Set([...tracked, ...untracked])].sort((a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")));
  if (names.length > MAX_STATE_FILES) throw new Error("worktree preservation path count exceeds measured bound");
  const digest = crypto.createHash("sha256"); let count = 0; let totalBytes = 0;
  const add = (entry) => { validateWorktreeRecord(entry); count++; totalBytes += entry.bytes; if (totalBytes > MAX_STATE_TOTAL) throw new Error("worktree preservation snapshot exceeds total-byte bound"); digest.update(`${JSON.stringify(entry)}\n`, "utf8"); };
  for (const name of names) {
    const full = path.resolve(ROOT, ...name.split("/"));
    if (pathInsideRoot(full) !== name) throw new Error("worktree path identity changed");
    let st;
    try { st = fs.lstatSync(full); }
    catch (error) {
      add(missingTrackedWorktreeRecord(name, trackedSet.has(name), error.code));
      continue;
    }
    const mode = st.mode & 0o7777;
    if (st.isSymbolicLink()) {
      const target = fs.readlinkSync(full, { encoding: "buffer" });
      const after = fs.lstatSync(full);
      if (!after.isSymbolicLink() || after.dev !== st.dev || after.ino !== st.ino || after.mode !== st.mode || after.mtimeMs !== st.mtimeMs || after.ctimeMs !== st.ctimeMs) throw new Error("worktree symlink changed during snapshot");
      if (target.length > 4096) throw new Error("worktree symlink target exceeds bound");
      add({ path: name, type: "symlink", mode, bytes: target.length, sha256: sha256(target) });
    } else if (st.isFile()) {
      if (!Number.isSafeInteger(st.size) || st.size > MAX_STATE_SINGLE_FILE || totalBytes + st.size > MAX_STATE_TOTAL) throw new Error("worktree file exceeds pre-read preservation bounds");
      const measured = stableHashFile(full);
      add({ path: name, type: "file", mode, bytes: measured.bytes, sha256: measured.sha256 });
    } else throw new Error("worktree inventory contains a non-file entry");
  }
  return { count, totalBytes, digest: digest.digest("hex") };
}

export function summarizeWorktreeRecords(entries) {
  if (!Array.isArray(entries) || entries.length > MAX_STATE_FILES) throw new Error("worktree preservation entry count exceeds bound");
  const ordered = [...entries].sort((a, b) => Buffer.compare(Buffer.from(a.path, "utf8"), Buffer.from(b.path, "utf8")));
  const seen = new Set(); let totalBytes = 0; const digest = crypto.createHash("sha256");
  for (const entry of ordered) {
    validateWorktreeRecord(entry);
    if (seen.has(entry.path)) throw new Error("worktree preservation record path is duplicated");
    seen.add(entry.path); totalBytes += entry.bytes;
    if (totalBytes > MAX_STATE_TOTAL) throw new Error("worktree preservation records exceed total-byte bound");
    digest.update(`${JSON.stringify(entry)}\n`, "utf8");
  }
  return { count: ordered.length, totalBytes, digest: digest.digest("hex") };
}

function validateWorktreeRecord(entry) {
  if (!entry || !safeRelative(entry.path) || !["file", "symlink", "absent"].includes(entry.type) || !Number.isInteger(entry.mode) || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || !/^[0-9a-f]{64}$/.test(entry.sha256)) throw new Error("worktree preservation record is malformed");
  if (entry.type === "absent" && (entry.mode !== 0 || entry.bytes !== 0 || entry.sha256 !== sha256(Buffer.alloc(0)))) throw new Error("tracked absence record is not canonical");
  if (entry.type !== "absent" && entry.bytes > MAX_STATE_SINGLE_FILE) throw new Error("worktree preservation record exceeds file bound");
}

function parseTreeListing(raw) {
  if (!Buffer.isBuffer(raw) || raw.length > MAX_ARCHIVE) throw new Error("pinned Git tree listing exceeds bound");
  const entries = [];
  for (let start = 0; start < raw.length;) {
    const end = raw.indexOf(0, start);
    if (end < 0) throw new Error("pinned Git tree listing is truncated");
    const record = raw.subarray(start, end);
    const tab = record.indexOf(9);
    if (tab < 0) throw new Error("pinned Git tree record is malformed");
    const fields = record.subarray(0, tab).toString("ascii").split(" ");
    const rawName = record.subarray(tab + 1);
    const name = rawName.toString("utf8");
    if (!Buffer.from(name, "utf8").equals(rawName) || fields.length !== 3 || !/^100(644|755)$/.test(fields[0]) || fields[1] !== "blob" || !/^[0-9a-f]{40}$/.test(fields[2]) || !safeRelative(name)) throw new Error("pinned tree contains a link, special, or unsafe entry");
    entries.push({ mode: fields[0], type: fields[1], oid: fields[2], name });
    start = end + 1;
  }
  if (!entries.length) throw new Error("pinned Git tree is empty");
  return entries;
}

function parseCatFileBatch(raw, entries) {
  if (!Buffer.isBuffer(raw) || raw.length > MAX_ARCHIVE) throw new Error("pinned blob batch exceeds bound");
  const files = new Map();
  let offset = 0;
  for (const entry of entries) {
    const end = raw.indexOf(10, offset);
    if (end < 0) throw new Error("pinned blob header is truncated");
    const fields = raw.subarray(offset, end).toString("ascii").split(" ");
    if (fields.length !== 3 || fields[0] !== entry.oid || fields[1] !== "blob" || !/^(0|[1-9][0-9]*)$/.test(fields[2])) throw new Error("pinned blob identity differs from tree");
    const size = Number(fields[2]);
    if (!Number.isSafeInteger(size) || size > MAX_FILE || end + 1 + size >= raw.length || raw[end + 1 + size] !== 10 || files.has(entry.name)) throw new Error("pinned blob size or path is invalid");
    files.set(entry.name, Buffer.from(raw.subarray(end + 1, end + 1 + size)));
    offset = end + 1 + size + 1;
  }
  if (offset !== raw.length) throw new Error("pinned blob batch contains unlisted data");
  return files;
}

export function readPinnedGitEntries() {
  if (gitText(["rev-parse", `${BASE_COMMIT}^{tree}`]) !== BASE_TREE) throw new Error("pinned commit does not resolve to the reviewed tree");
  const listing = parseTreeListing(command("git", ["--no-replace-objects", "--no-optional-locks", "ls-tree", "-r", "-z", "--full-tree", BASE_COMMIT], { env: gitEnvironment(), maxBuffer: MAX_ARCHIVE, failure: "pinned Git tree inventory failed" }));
  const batchInput = Buffer.from(`${listing.map((entry) => entry.oid).join("\n")}\n`, "ascii");
  const blobs = command("git", ["--no-replace-objects", "--no-optional-locks", "cat-file", "--batch"], { env: gitEnvironment(), input: batchInput, maxBuffer: MAX_ARCHIVE, failure: "pinned Git blob verification failed" });
  return parseCatFileBatch(blobs, listing);
}

function snapshotState() {
  const indexPathRaw = gitText(["rev-parse", "--git-path", "index"]);
  const indexPath = path.isAbsolute(indexPathRaw) ? indexPathRaw : path.resolve(ROOT, indexPathRaw);
  const indexName = pathInsideRoot(indexPath);
  const indexRead = stableRead(indexPath, MAX_STATE_FILE);
  const index = { path: indexName, type: "file", mode: indexRead.stat.mode & 0o7777, bytes: indexRead.bytes.length, sha256: sha256(indexRead.bytes) };
  return {
    head: gitText(["rev-parse", "HEAD"]),
    index,
    worktree: snapshotWorktreeFiles(),
    worktreeStatusSha256: sha256(command("git", ["--no-optional-locks", "status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignore-submodules=all"], { env: gitEnvironment(), maxBuffer: MAX_STATE_PATH_LIST, failure: "worktree preservation snapshot failed" })),
  };
}

function assertSameState(before) {
  const after = snapshotState();
  if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error("real Git HEAD, index, or worktree status changed during candidate assembly");
}

function assertDirectoryChain(target, stopAt) {
  const rel = path.relative(stopAt, target);
  if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("cache path escaped repository");
  let current = stopAt;
  for (const part of rel.split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    if (!fs.existsSync(current)) fs.mkdirSync(current);
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("cache path contains a non-directory or link");
  }
}

function writeTree(root, entries) {
  for (const [name, bytes] of entries) {
    if (!safeRelative(name)) throw new Error("refusing unsafe source path");
    const target = path.resolve(root, ...name.split("/"));
    const rel = path.relative(root, target);
    if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("source path escaped candidate root");
    const parent = path.dirname(target);
    fs.mkdirSync(parent, { recursive: true });
    fs.writeFileSync(target, bytes, { flag: "wx", mode: 0o644 });
  }
}

export function assertSameEntries(expected, actual) {
  if (!(expected instanceof Map) || !(actual instanceof Map) || expected.size !== actual.size) throw new Error("candidate inventory size differs");
  for (const [name, bytes] of expected) {
    const got = actual.get(name);
    if (!safeRelative(name) || !Buffer.isBuffer(bytes) || !Buffer.isBuffer(got) || !bytes.equals(got)) throw new Error(`candidate bytes differ: ${name}`);
  }
  return true;
}

function readTree(root) {
  const files = new Map(); let fileCount = 0; let entryCount = 0; let totalBytes = 0;
  function walk(dir, relative = "") {
    const children = fs.readdirSync(dir, { withFileTypes: true });
    if (relative && children.length === 0) throw new Error("candidate tree contains an empty directory");
    for (const entry of children) {
      entryCount++;
      if (entryCount > MAX_CANDIDATE_ENTRIES) throw new Error("candidate tree entry count exceeds bound");
      const rel = relative ? `${relative}/${entry.name}` : entry.name;
      const full = path.join(dir, entry.name); const stat = fs.lstatSync(full);
      if (!safeRelative(rel) || stat.isSymbolicLink()) throw new Error("candidate tree contains unsafe entry");
      if (stat.isDirectory()) walk(full, rel);
      else if (stat.isFile()) {
        assertCandidateFileBound(stat.size, fileCount, totalBytes);
        const { bytes } = stableRead(full, MAX_FILE); fileCount++; totalBytes += bytes.length; files.set(rel, bytes);
      }
      else throw new Error("candidate tree contains special entry");
    }
  }
  walk(root); return files;
}

function hashFiles(sourceRoot, names, displayPrefix = "") {
  return hashNamedFiles(names, (name) => path.resolve(sourceRoot, ...name.split("/")), (name) => `${displayPrefix}${name}`);
}

function hashNamedFiles(names, resolve, displayPath = (name) => name) {
  if (!Array.isArray(names) || names.length > 100_000) throw new Error("closure file inventory exceeds count bound");
  const seen = new Set(); let totalBytes = 0;
  return names.map((name) => {
    if (!safeRelative(name) || seen.has(name)) throw new Error("closure file inventory has an unsafe or duplicate path");
    seen.add(name); const full = resolve(name); const stat = fs.lstatSync(full);
    if (!stat.isFile() || stat.isSymbolicLink() || !Number.isSafeInteger(stat.size) || stat.size > MAX_STATE_FILE || totalBytes + stat.size > MAX_STATE_TOTAL) throw new Error("closure file exceeds pre-read bounds");
    const measured = stableHashFile(full, MAX_STATE_FILE); totalBytes += measured.bytes;
    return { path: displayPath(name), bytes: measured.bytes, sha256: measured.sha256 };
  });
}

function parseJsonStream(text) {
  const values = [];
  let start = -1;
  let depth = 0;
  let quote = false;
  let escape = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (start < 0) {
      if (/\s/.test(char)) continue;
      if (char !== "{") throw new Error("Go package inventory is malformed");
      start = i; depth = 1; quote = false; escape = false; continue;
    }
    if (quote) {
      if (escape) escape = false;
      else if (char === "\\") escape = true;
      else if (char === '"') quote = false;
      continue;
    }
    if (char === '"') quote = true;
    else if (char === "{") depth++;
    else if (char === "}") {
      depth--;
      if (depth === 0) { values.push(JSON.parse(text.slice(start, i + 1))); start = -1; }
    }
  }
  if (start >= 0 || values.length === 0) throw new Error("Go package inventory is truncated or empty");
  return values;
}

function collectGoClosure(sourceRoot, goPath, goCache) {
  const goRoot = path.dirname(path.dirname(goPath));
  const env = goEnvironment(goRoot, goCache);
  const raw = command(goPath, ["list", "-deps", "-json", "-mod=readonly", "./cmd/controller"], { cwd: sourceRoot, env, encoding: "utf8", maxBuffer: 32 * 1024 * 1024, timeout: 120_000, failure: "offline controller dependency inspection failed" });
  const packages = parseJsonStream(raw);
  const local = [];
  const standard = [];
  const moduleFiles = [];
  const modules = new Map();
  const assets = new Set();
  const sums = new Map();
  const goSumPath = path.join(sourceRoot, "go.sum");
  for (const line of fs.readFileSync(goSumPath, "utf8").split(/\r?\n/).filter(Boolean)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length === 3) sums.set(`${fields[0]}@${fields[1]}`, fields[2]);
  }
  for (const pkg of packages) {
    if (typeof pkg.ImportPath !== "string") throw new Error("Go package inventory omits import path");
    if (/internal\/(nodeagent|checkpointgpuobserver)|cmd\/(checkpoint|node-agent)/.test(pkg.ImportPath)) throw new Error("controller dependency closure unexpectedly reaches agent or observer");
    if (pkg.Module && pkg.Module.Path && pkg.Module.Version) {
      const key = `${pkg.Module.Path}@${pkg.Module.Version}`;
      const moduleKey = `${pkg.Module.Path}@${pkg.Module.Version}`;
      const prior = modules.get(moduleKey);
      if (prior && prior.dir !== pkg.Module.Dir) throw new Error("same module identity resolves to multiple cache directories");
      modules.set(moduleKey, { path: pkg.Module.Path, version: pkg.Module.Version, dir: pkg.Module.Dir, goMod: pkg.Module.GoMod, sum: pkg.Module.Sum || sums.get(key) || "", goModSum: pkg.Module.GoModSum || sums.get(`${key}/go.mod`) || "" });
    }
    if (typeof pkg.Dir !== "string") throw new Error("nonstandard Go package has no source directory");
    const dir = path.resolve(pkg.Dir);
    const relDir = path.relative(sourceRoot, dir);
    const localPackage = !relDir.startsWith("..") && !path.isAbsolute(relDir);
    const standardPackage = Boolean(pkg.Standard);
    const moduleCache = env.GOMODCACHE;
    const moduleRel = path.relative(moduleCache, dir);
    const goRootRel = path.relative(goRoot, dir);
    if (standardPackage ? (goRootRel.startsWith("..") || path.isAbsolute(goRootRel)) : (!localPackage && (moduleRel.startsWith("..") || path.isAbsolute(moduleRel) || !pkg.Module))) throw new Error("controller package source escaped pinned source/module/toolchain root");
    const files = [...(pkg.GoFiles ?? []), ...(pkg.CgoFiles ?? []), ...(pkg.SFiles ?? []), ...(pkg.CFiles ?? []), ...(pkg.CXXFiles ?? []), ...(pkg.HFiles ?? []), ...(pkg.FFiles ?? []), ...(pkg.MFiles ?? []), ...(pkg.SysoFiles ?? []), ...(pkg.EmbedFiles ?? [])];
    for (const file of files) {
      const full = path.resolve(dir, file);
      const rel = path.relative(localPackage ? sourceRoot : (standardPackage ? goRoot : moduleCache), full).split(path.sep).join("/");
      const stat = fs.lstatSync(full);
      if (!safeRelative(rel) || !stat.isFile() || stat.isSymbolicLink()) throw new Error("controller source closure contains an unsafe file");
      if (file.endsWith("_test.go")) throw new Error("test source entered production closure");
      if (pkg.EmbedFiles?.includes(file) && localPackage) assets.add(rel);
      (localPackage ? local : (standardPackage ? standard : moduleFiles)).push(standardPackage ? `@goroot/${rel}` : rel);
    }
    if (!localPackage && pkg.Module?.GoMod) {
      const goMod = path.resolve(pkg.Module.GoMod);
      const relativeGoMod = path.relative(moduleCache, goMod).split(path.sep).join("/");
      const stat = fs.lstatSync(goMod);
      if (!safeRelative(relativeGoMod) || !stat.isFile() || stat.isSymbolicLink()) throw new Error("module go.mod source identity is unsafe");
      moduleFiles.push(relativeGoMod);
    }
  }
  const unique = [...new Set(local)].sort();
  if (!unique.includes("internal/api/ws.go") || !unique.includes(HELPER_PATH) || !unique.includes("cmd/controller/main.go") || assets.size === 0) throw new Error("production source or embedded asset closure is incomplete");
  const sortedModules = [...modules.values()].sort((a, b) => `${a.path}@${a.version}`.localeCompare(`${b.path}@${b.version}`)).map((module) => {
    if (!module.sum || !module.goModSum || typeof module.dir !== "string" || typeof module.goMod !== "string") throw new Error("offline module identity or go.sum checksum is missing");
    const moduleDir = path.resolve(module.dir); const moduleRel = path.relative(env.GOMODCACHE, moduleDir);
    if (moduleRel.startsWith("..") || path.isAbsolute(moduleRel)) throw new Error("module directory escaped pinned offline module cache");
    const modulePrefix = `${module.path}@${module.version}`;
    const content = directoryH1(moduleDir, [], modulePrefix);
    const dirGoMod = stableRead(path.join(moduleDir, "go.mod"));
    const cacheGoMod = stableRead(module.goMod);
    assertModuleChecksumIdentity({ modulePath: module.path, version: module.version, treeH1: content.h1, moduleSum: module.sum, moduleGoMod: dirGoMod.bytes, cacheGoMod: cacheGoMod.bytes, goModSum: module.goModSum });
    return { path: module.path, version: module.version, sum: module.sum, goModSum: module.goModSum, treeH1: content.h1, fileCount: content.fileCount, totalBytes: content.totalBytes, files: content.files };
  });
  const uniqueModules = [...new Set(moduleFiles)].sort();
  const standardNames = [...new Set(standard)].sort();
  const standardFiles = hashNamedFiles(standardNames.map((name) => name.slice("@goroot/".length)), (name) => path.resolve(goRoot, ...name.split("/")), (name) => `@goroot/${name}`);
  const toolNames = ["go.exe", "pkg/tool/windows_amd64/asm.exe", "pkg/tool/windows_amd64/compile.exe", "pkg/tool/windows_amd64/link.exe", "pkg/tool/windows_amd64/pack.exe"];
  const toolchainFiles = hashNamedFiles(toolNames, (name) => name === "go.exe" ? goPath : path.join(goRoot, ...name.split("/")));
  const includeRoot = path.join(goRoot, "pkg", "include");
  const includeNames = [];
  function walkInclude(dir, rel = "") { for (const entry of fs.readdirSync(dir, { withFileTypes: true })) { const name = rel ? `${rel}/${entry.name}` : entry.name; const full = path.join(dir, entry.name); const stat = fs.lstatSync(full); if (stat.isSymbolicLink()) throw new Error("Go asm include tree contains a link"); if (stat.isDirectory()) walkInclude(full, name); else if (stat.isFile()) { if (includeNames.length >= 100_000 || !Number.isSafeInteger(stat.size) || stat.size > MAX_STATE_FILE) throw new Error("Go asm include tree exceeds pre-read bounds"); includeNames.push(name); } else throw new Error("Go asm include tree contains a special entry"); } }
  walkInclude(includeRoot);
  const includeFiles = hashFiles(path.join(goRoot, "pkg", "include"), includeNames.sort(), "pkg/include/");
  assertGeneratedGoModCopies(goRoot);
  const toolchainTree = directoryH1(goRoot, TOOLCHAIN_EXTRA_GO_MOD_COPIES, "golang.org/toolchain@v0.0.1-go1.23.4.windows-amd64");
  const toolchainVersion = command(goPath, ["version"], { cwd: sourceRoot, env, encoding: "utf8", timeout: 30_000 }).trim();
  const goToolSha256 = stableHashFile(goPath, MAX_STATE_FILE).sha256;
  assertToolchainIdentity({ ...toolchainTree, version: toolchainVersion, goToolSha256 });
  return { packages: packages.map((pkg) => ({ importPath: pkg.ImportPath, standard: Boolean(pkg.Standard), module: pkg.Module ? `${pkg.Module.Path}@${pkg.Module.Version}` : null })).sort((a, b) => a.importPath.localeCompare(b.importPath)), modules: sortedModules, sourceFiles: hashFiles(sourceRoot, unique), standardFiles, moduleFiles: hashFiles(env.GOMODCACHE, uniqueModules), embeddedAssets: hashFiles(sourceRoot, [...assets].sort()), toolchain: { goRoot: "pinned-go1.23.4-toolchain", moduleH1: GO_TOOLCHAIN_MODULE_H1, tree: { h1: toolchainTree.h1, fileCount: toolchainTree.fileCount, totalBytes: toolchainTree.totalBytes }, version: toolchainVersion, files: toolchainFiles, stdlibFiles: standardFiles, asmIncludeFiles: includeFiles } };
}

function checkBaseline() {
  if (gitText(["rev-parse", `${BASE_COMMIT}^{tree}`]) !== BASE_TREE) throw new Error("pinned baseline tree mismatch");
}

function ensureCandidateRoot() {
  const cache = path.join(ROOT, ".cache");
  assertDirectoryChain(cache, ROOT);
  const parent = path.join(cache, "controller-transport-hotfix");
  assertDirectoryChain(parent, ROOT);
  command("git", ["--no-optional-locks", "check-ignore", "--quiet", ".cache/controller-transport-hotfix"], { env: gitEnvironment(), timeout: 30_000, failure: "owned candidate cache must be ignored by Git" });
  return parent;
}

function assemble() {
  activeFailureStage = "baseline";
  checkBaseline();
  activeFailureStage = "initial-preservation";
  const state = snapshotState();
  activeFailureStage = "source";
  const helperPath = path.join(ROOT, ...HELPER_PATH.split("/"));
  const helperStat = fs.lstatSync(helperPath);
  if (!helperStat.isFile() || helperStat.isSymbolicLink()) throw new Error("reviewed transport helper is not a regular file");
  const helper = fs.readFileSync(helperPath);
  if (sha256(helper) !== HELPER_SHA256) throw new Error("reviewed transport helper digest mismatch");
  const entries = readPinnedGitEntries();
  const baseWs = entries.get(WS_PATH);
  if (!baseWs) throw new Error("pinned controller WebSocket source is missing");
  entries.set(WS_PATH, Buffer.from(transformWs(baseWs.toString("utf8")), "utf8"));
  if (entries.has(HELPER_PATH)) throw new Error("transport helper unexpectedly exists in pinned baseline");
  entries.set(HELPER_PATH, helper);

  const cacheRoot = ensureCandidateRoot();
  const now = new Date();
  const timestamp = `${now.getUTCFullYear()}${String(now.getUTCMonth() + 1).padStart(2, "0")}${String(now.getUTCDate()).padStart(2, "0")}${String(now.getUTCHours()).padStart(2, "0")}${String(now.getUTCMinutes()).padStart(2, "0")}${String(now.getUTCSeconds()).padStart(2, "0")}`;
  const id = `candidate-${timestamp}-${crypto.randomBytes(6).toString("hex")}`;
  const candidate = path.join(cacheRoot, id);
  const goCache = path.join(cacheRoot, `gocache-${id}`);
  fs.mkdirSync(candidate);
  fs.mkdirSync(goCache);
  const sourceRoot = path.join(candidate, "source");
  fs.mkdirSync(sourceRoot);
  writeTree(sourceRoot, entries);
  assertSameEntries(entries, readTree(sourceRoot));

  const goPath = path.join(ROOT, ".cache", "gopath", "pkg", "mod", "golang.org", "toolchain@v0.0.1-go1.23.4.windows-amd64", "bin", "go.exe");
  const goStat = fs.lstatSync(goPath);
  if (!goStat.isFile() || goStat.isSymbolicLink()) throw new Error("pinned cached Go toolchain is unavailable");
  if (sha256(fs.readFileSync(goPath)) !== GO_SHA256) throw new Error("cached Go toolchain digest differs from reviewed identity");
  activeFailureStage = "closure-before";
  const closureBefore = collectGoClosure(sourceRoot, goPath, goCache);
  const binary = path.join(candidate, "vram-governor-controller-linux-amd64");
  const env = goEnvironment(path.dirname(path.dirname(goPath)), goCache);
  activeFailureStage = "compile";
  command(goPath, ["build", "-mod=readonly", "-buildvcs=false", "-trimpath", "-ldflags", "-s -w", "-o", binary, "./cmd/controller"], { cwd: sourceRoot, env, encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 600_000, failure: "offline controller-only build failed" });
  activeFailureStage = "closure-after";
  const closureAfter = collectGoClosure(sourceRoot, goPath, goCache);
  if (JSON.stringify(closureBefore) !== JSON.stringify(closureAfter)) throw new Error("production source/toolchain/module closure changed during build");
  const binaryBytes = fs.readFileSync(binary);
  activeFailureStage = "postbuild-preservation";
  const stateAfterBuild = snapshotState();
  activeFailureStage = "manifest";
  const manifest = {
    schema: "controller-transport-hotfix-candidate-v1",
    candidate: id,
    localOnly: true,
    releaseApproved: false,
    installedBinaryProvenance: false,
    baseline: { commit: BASE_COMMIT, tree: BASE_TREE },
    reviewedDelta: { wsPath: WS_PATH, helperPath: HELPER_PATH, helperSha256: HELPER_SHA256, insertion: "ApplyControlMessageLimit after successful websocket.Accept and before first wsjson.Read" },
    inputTrust: { schema: "controller-input-trust-v1", source: "pinned-baseline-go.sum plus official-go-toolchain-module-h1", modulesVerifiedAgainstGoSum: true, toolchainModuleH1: GO_TOOLCHAIN_MODULE_H1 },
    sourceFiles: [...entries.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([name, bytes]) => ({ path: name, bytes: bytes.length, sha256: sha256(bytes) })),
    closure: closureAfter,
    build: { goVersion: "go1.23.4", goToolSha256: GO_SHA256, environment: recordedGoEnvironment(), goos: "linux", goarch: "amd64", goamd64: "v1", cgo: false, workspace: "off", goenv: "off", goflags: "", network: "disabled", command: "go build -mod=readonly -buildvcs=false -trimpath -ldflags=-s -w ./cmd/controller" },
    binary: { path: "vram-governor-controller-linux-amd64", bytes: binaryBytes.length, sha256: sha256(binaryBytes) },
    gitStateBefore: state,
    gitStateAfter: stateAfterBuild,
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  fs.writeFileSync(path.join(candidate, "manifest.json"), manifestBytes, { flag: "wx", mode: 0o600 });
  activeFailureStage = "preverify-preservation";
  assertSameState(state);
  if (JSON.stringify(manifest.gitStateBefore) !== JSON.stringify(manifest.gitStateAfter)) throw new Error("Git preservation snapshots differ");
  activeFailureStage = "independent-verifier";
  verifyCandidateDirectory(candidate);
  activeFailureStage = "final-preservation";
  assertSameState(state);
  return { candidate, manifest };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3 || process.argv[2] !== "--mode=build") throw new Error("usage: node scripts/controller-hotfix/build.mjs --mode=build");
    const result = assemble();
    process.stdout.write(`controller transport hotfix candidate built and verified: ${path.basename(result.candidate)}\n`);
  } catch (error) {
    process.stderr.write(`controller hotfix assembly failed closed; ${formatFailureDiagnostic(activeFailureStage, error)}\n`);
    process.exitCode = 1;
  }
}

export const testSurface = Object.freeze({ parseTreeListing, parseCatFileBatch, readPinnedGitEntries, parseJsonStream, transformWs, safeRelative, sha256, hash1Entries, directoryH1, summarizeWorktreeRecords, missingTrackedWorktreeRecord, assertCandidateFileBound, readTree, assertModuleChecksumIdentity, assertToolchainIdentity, assertGeneratedGoModPairs, makeSafeCommandFailure, formatFailureDiagnostic });
