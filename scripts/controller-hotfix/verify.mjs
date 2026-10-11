import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const BASE_COMMIT = "cf8d06ad71d5e840304a842ec700cbe4c9637002";
const BASE_TREE = "a7707962963733e4753a664493f067e89c851138";
const HELPER_PATH = "internal/nodetransport/limits.go";
const HELPER_SHA256 = "0c7453ec051d7f69e34f65bc1c5fdf4e512287a709f75dd409574f24d0bf5a0b";
const GO_SHA256 = "8e8356be1603abff526f52c0d5fe887fb4d77b000f310d298ad10cd33e7471e6";
const GO_TOOLCHAIN_MODULE_H1 = "h1:uAs0v1Tbi8pAEvc6IkL/tazTmMBok9HxjXC9XLzlLss=";
const TOOLCHAIN_EXTRA_GO_MOD_COPIES = ["src/cmd/go.mod", "src/cmd/objdump/testdata/testfilenum/go.mod", "src/cmd/vet/testdata/rangeloop/go.mod", "src/cmd/vet/testdata/stdversion/go.mod", "src/crypto/internal/bigmod/_asm/go.mod", "src/crypto/internal/edwards25519/field/_asm/go.mod", "src/go.mod"];
const TOOLCHAIN_NORMALIZED_FILE_COUNT = 9874;
const TOOLCHAIN_NORMALIZED_BYTES = 227759789;
const WS_PATH = "internal/api/ws.go";
const REVIEWED_DELTA = { wsPath: WS_PATH, helperPath: HELPER_PATH, helperSha256: HELPER_SHA256, insertion: "ApplyControlMessageLimit after successful websocket.Accept and before first wsjson.Read" };
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
const SAFE_FAILURE = Symbol("safeFailure");
const SAFE_OPERATIONS = new Set(["git", "go-list", "go-version", "local"]);
const SAFE_ERRNOS = new Set(["EACCES", "EBUSY", "EIO", "EMFILE", "ENOMEM", "ENOENT", "EPERM", "ETIMEDOUT", "ENOBUFS", "EINVAL"]);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function safeRelative(value) {
  if (typeof value !== "string" || !value || value.includes("\\") || value.includes(":") || value.includes("\0") || path.posix.isAbsolute(value)) return false;
  return value.split("/").every((part) => part && part !== "." && part !== "..");
}
export function missingTrackedWorktreeRecord(name, tracked, code) { if (!safeRelative(name) || tracked !== true || code !== "ENOENT") throw new Error("only a missing cached tracked path is recorded as absent"); return { path: name, type: "absent", mode: 0, bytes: 0, sha256: sha256(Buffer.alloc(0)) }; }
export function assertCandidateFileBound(size, fileCount, totalBytes) { if (!Number.isSafeInteger(size) || size < 0 || size > MAX_FILE || !Number.isInteger(fileCount) || fileCount < 0 || fileCount >= MAX_CANDIDATE_FILES || !Number.isSafeInteger(totalBytes) || totalBytes < 0 || totalBytes + size > MAX_CANDIDATE_TOTAL) throw new Error("candidate source exceeds pre-read bounds"); return true; }
function run(binary, args, options = {}) {
  const result = spawnSync(binary, args, { cwd: options.cwd ?? ROOT, env: options.env, input: options.input, encoding: options.encoding ?? "buffer", maxBuffer: options.maxBuffer ?? MAX_ARCHIVE, timeout: options.timeout ?? COMMAND_TIMEOUT_MS, windowsHide: true });
  if (result.error || result.status !== 0) throw makeSafeCommandFailure(safeOperation(binary, args), result.error?.code, result.status);
  return result.stdout;
}

function safeOperation(binary, args) {
  if (binary === "git") return "git";
  if (path.basename(binary).toLowerCase() === "go.exe") {
    if (args[0] === "list") return "go-list";
    if (args[0] === "version") return "go-version";
  }
  return "local";
}

function makeSafeCommandFailure(operation, errorCode, status) {
  let code = "terminated";
  if (errorCode === "ETIMEDOUT") code = "timeout";
  else if (errorCode === "ENOBUFS" || errorCode === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") code = "buffer";
  else if (SAFE_ERRNOS.has(errorCode)) code = errorCode;
  else if (Number.isInteger(status) && status >= 0 && status <= 255) code = `exit-${status}`;
  const error = new Error("local command failed");
  Object.defineProperty(error, SAFE_FAILURE, { value: { operation: SAFE_OPERATIONS.has(operation) ? operation : "local", code } });
  return error;
}

export function readSafeFailureDiagnostic(error) {
  if (!(error instanceof Error)) return null;
  return Object.getOwnPropertyDescriptor(error, SAFE_FAILURE)?.value ?? null;
}
function gitText(args) { return run("git", ["--no-replace-objects", "--no-optional-locks", ...args], { env: gitEnvironment(), encoding: "utf8", maxBuffer: 4 * 1024 * 1024 }).trimEnd(); }
function hostEnvironment() {
  const allowed = ["SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "PATHEXT", "COMSPEC"]; const result = {};
  for (const wanted of allowed) { const key = Object.keys(process.env).find((name) => name.toLowerCase() === wanted.toLowerCase()); if (key && process.env[key]) result[wanted] = process.env[key]; }
  if (!result.SystemRoot && result.WINDIR) result.SystemRoot = result.WINDIR;
  if (!result.WINDIR && result.SystemRoot) result.WINDIR = result.SystemRoot;
  return result;
}
function gitEnvironment() { return { ...hostEnvironment(), GIT_OPTIONAL_LOCKS: "0", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "" }; }
function goEnvironment(goRoot, goCache) {
  return { ...hostEnvironment(), GOOS: "linux", GOARCH: "amd64", GOAMD64: "v1", CGO_ENABLED: "0", GOTOOLCHAIN: "local", GOROOT: goRoot, GOCACHE: goCache, GOMODCACHE: path.join(ROOT, ".cache", "gopath", "pkg", "mod"), GOENV: "off", GOWORK: "off", GOFLAGS: "", GOEXPERIMENT: "", GODEBUG: "", GOFIPS140: "", GOAUTH: "", GOPROXY: "off", GOSUMDB: "off", GOPRIVATE: "", GONOPROXY: "", GONOSUMDB: "", GOINSECURE: "", GOVCS: "*:off" };
}
function recordedGoEnvironment() {
  return { GOOS: "linux", GOARCH: "amd64", GOAMD64: "v1", CGO_ENABLED: "0", GOTOOLCHAIN: "local", GOROOT: "pinned-go1.23.4-toolchain", GOCACHE: "candidate-private", GOMODCACHE: "repo-offline-cache", GOENV: "off", GOWORK: "off", GOFLAGS: "", GOEXPERIMENT: "", GODEBUG: "", GOFIPS140: "", GOAUTH: "", GOPROXY: "off", GOSUMDB: "off", GOPRIVATE: "", GONOPROXY: "", GONOSUMDB: "", GOINSECURE: "", GOVCS: "*:off" };
}
function currentGitState() {
  const indexPathRaw = gitText(["rev-parse", "--git-path", "index"]);
  const indexPath = path.isAbsolute(indexPathRaw) ? indexPathRaw : path.resolve(ROOT, indexPathRaw);
  const indexName = relativeToRoot(indexPath);
  const indexRead = stableRead(indexPath, MAX_STATE_FILE);
  return {
    head: gitText(["rev-parse", "HEAD"]),
    index: { path: indexName, type: "file", mode: indexRead.stat.mode & 0o7777, bytes: indexRead.bytes.length, sha256: sha256(indexRead.bytes) },
    worktree: snapshotWorktreeFiles(),
    worktreeStatusSha256: sha256(run("git", ["--no-optional-locks", "status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignore-submodules=all"], { env: gitEnvironment(), maxBuffer: MAX_STATE_PATH_LIST })),
  };
}
function stableRead(fullPath, maxBytes = MAX_STATE_FILE) {
  const before = fs.lstatSync(fullPath);
  if (!before.isFile() || before.isSymbolicLink() || before.size > maxBytes) throw new Error("preservation input is not a bounded regular file");
  const fd = fs.openSync(fullPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.size !== before.size || opened.mode !== before.mode || opened.dev !== before.dev || opened.ino !== before.ino) throw new Error("preservation input changed before read");
    const bytes = fs.readFileSync(fd); const after = fs.fstatSync(fd); const finalPath = fs.lstatSync(fullPath);
    if (bytes.length !== before.size || after.size !== before.size || after.mode !== before.mode || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || finalPath.isSymbolicLink() || finalPath.dev !== before.dev || finalPath.ino !== before.ino || finalPath.mode !== before.mode || finalPath.size !== before.size || finalPath.mtimeMs !== before.mtimeMs || finalPath.ctimeMs !== before.ctimeMs) throw new Error("preservation input changed during read");
    return { bytes, stat: before };
  } finally { fs.closeSync(fd); }
}
function stableHashFile(fullPath, maxBytes = MAX_STATE_SINGLE_FILE) {
  const before = fs.lstatSync(fullPath);
  if (!before.isFile() || before.isSymbolicLink() || !Number.isSafeInteger(before.size) || before.size > maxBytes) throw new Error("preservation input is not a bounded regular file");
  const noFollow = fs.constants.O_NOFOLLOW ?? 0; const fd = fs.openSync(fullPath, fs.constants.O_RDONLY | noFollow);
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.size !== before.size || opened.mode !== before.mode || opened.dev !== before.dev || opened.ino !== before.ino) throw new Error("preservation input changed before hash");
    const digest = crypto.createHash("sha256"); const chunk = Buffer.allocUnsafe(1024 * 1024); let bytes = 0;
    while (true) { const count = fs.readSync(fd, chunk, 0, chunk.length, null); if (count === 0) break; bytes += count; if (bytes > maxBytes || bytes > before.size) throw new Error("preservation input exceeded its preflight bound"); digest.update(chunk.subarray(0, count)); }
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
  const h = crypto.createHash("sha256"); for (const entry of normalized) h.update(`${entry.sha256}  ${entry.path}\n`, "utf8");
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
  return assertGeneratedGoModPairs(TOOLCHAIN_EXTRA_GO_MOD_COPIES.map((copyPath) => { const parts = copyPath.split("/"); return { path: copyPath, copied: stableRead(path.join(goRoot, ...parts)).bytes, original: stableRead(path.join(goRoot, ...parts.slice(0, -1), "_go.mod")).bytes }; }));
}
export function assertGeneratedGoModPairs(pairs) {
  if (!Array.isArray(pairs) || pairs.length !== TOOLCHAIN_EXTRA_GO_MOD_COPIES.length || pairs.some((pair, index) => !pair || pair.path !== TOOLCHAIN_EXTRA_GO_MOD_COPIES[index] || !Buffer.isBuffer(pair.copied) || !Buffer.isBuffer(pair.original) || !pair.copied.equals(pair.original))) throw new Error("toolchain generated go.mod copy differs from pinned _go.mod source");
  return true;
}
export function directoryH1(root, excluded = [], prefix = "") {
  const excludedSet = new Set(excluded); const records = []; let totalBytes = 0;
  function walk(dir, relative = "") {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      if (!safeRelative(name) || name.includes("\n")) throw new Error("module tree filename is unsafe");
      const full = path.join(dir, entry.name); const st = fs.lstatSync(full);
      if (st.isSymbolicLink()) throw new Error("module tree contains a symlink");
      if (st.isDirectory()) walk(full, name);
      else if (st.isFile()) { if (excludedSet.has(name)) continue; if (!Number.isSafeInteger(st.size) || st.size > MAX_STATE_FILE || records.length >= 100_000 || totalBytes + st.size > 512 * 1024 * 1024) throw new Error("module tree exceeds pre-read bounds"); const measured = stableHashFile(full, MAX_STATE_FILE); totalBytes += measured.bytes; records.push({ path: name, bytes: measured.bytes, sha256: measured.sha256 }); }
      else throw new Error("module tree contains a special file");
    }
  }
  walk(root);
  const normalized = records.map((entry) => ({ path: prefix ? `${prefix}/${entry.path}` : entry.path, sha256: entry.sha256 }));
  normalized.sort((a, b) => Buffer.compare(Buffer.from(a.path, "utf8"), Buffer.from(b.path, "utf8")));
  const h = crypto.createHash("sha256"); for (const entry of normalized) h.update(`${entry.sha256}  ${entry.path}\n`, "utf8");
  const h1 = `h1:${h.digest("base64")}`;
  return { h1, fileCount: records.length, totalBytes, files: records.map(({ path: name, bytes, sha256: hash }) => ({ path: name, bytes, sha256: hash })) };
}
function relativeToRoot(full) {
  const rel = path.relative(ROOT, path.resolve(full));
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("preservation path escaped repository");
  return rel.split(path.sep).join("/");
}
function gitPathList() {
  const trackedRaw = run("git", ["--no-replace-objects", "--no-optional-locks", "ls-files", "--cached", "-z"], { env: gitEnvironment(), maxBuffer: MAX_STATE_PATH_LIST });
  const untrackedRaw = run("git", ["--no-replace-objects", "--no-optional-locks", "ls-files", "--others", "--exclude-standard", "-z"], { env: gitEnvironment(), maxBuffer: MAX_STATE_PATH_LIST });
  const parse = (raw) => {
  const names = [];
  for (let start = 0; start < raw.length;) { const end = raw.indexOf(0, start); if (end < 0) throw new Error("Git worktree path list truncated"); const segment = raw.subarray(start, end); const name = segment.toString("utf8"); if (!Buffer.from(name, "utf8").equals(segment) || !safeRelative(name)) throw new Error("Git worktree path list unsafe"); names.push(name); start = end + 1; }
  if (names.length > MAX_STATE_FILES) throw new Error("Git worktree path count exceeds bound"); return names;
  };
  const tracked = parse(trackedRaw); const untracked = parse(untrackedRaw);
  return { tracked, names: [...new Set([...tracked, ...untracked])].sort((a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"))) };
}
function snapshotWorktreeFiles() {
  const inventory = gitPathList(); const tracked = new Set(inventory.tracked); const names = inventory.names;
  if (names.length > MAX_STATE_FILES) throw new Error("worktree preservation path count exceeds measured bound");
  const digest = crypto.createHash("sha256"); let count = 0; let totalBytes = 0;
  const add = (entry) => { validateWorktreeRecord(entry); count++; totalBytes += entry.bytes; if (totalBytes > MAX_STATE_TOTAL) throw new Error("worktree preservation snapshot exceeds byte bound"); digest.update(`${JSON.stringify(entry)}\n`, "utf8"); };
  for (const name of names) {
    const full = path.resolve(ROOT, ...name.split("/")); if (relativeToRoot(full) !== name) throw new Error("worktree path identity changed");
    let st;
    try { st = fs.lstatSync(full); }
    catch (error) { add(missingTrackedWorktreeRecord(name, tracked.has(name), error.code)); continue; }
    const mode = st.mode & 0o7777;
    if (st.isSymbolicLink()) { const target = fs.readlinkSync(full, { encoding: "buffer" }); const after = fs.lstatSync(full); if (!after.isSymbolicLink() || after.dev !== st.dev || after.ino !== st.ino || after.mode !== st.mode || after.mtimeMs !== st.mtimeMs || after.ctimeMs !== st.ctimeMs) throw new Error("worktree symlink changed during snapshot"); if (target.length > 4096) throw new Error("worktree symlink exceeds bound"); add({ path: name, type: "symlink", mode, bytes: target.length, sha256: sha256(target) }); }
    else if (st.isFile()) { if (!Number.isSafeInteger(st.size) || st.size > MAX_STATE_SINGLE_FILE || totalBytes + st.size > MAX_STATE_TOTAL) throw new Error("worktree file exceeds pre-read preservation bounds"); const measured = stableHashFile(full); add({ path: name, type: "file", mode, bytes: measured.bytes, sha256: measured.sha256 }); }
    else throw new Error("worktree contains a non-file entry");
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
    seen.add(entry.path); totalBytes += entry.bytes; if (totalBytes > MAX_STATE_TOTAL) throw new Error("worktree preservation records exceed total-byte bound");
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
    const end = raw.indexOf(0, start); if (end < 0) throw new Error("pinned Git tree listing is truncated");
    const record = raw.subarray(start, end); const tab = record.indexOf(9); if (tab < 0) throw new Error("pinned Git tree record malformed");
    const fields = record.subarray(0, tab).toString("ascii").split(" "); const rawName = record.subarray(tab + 1); const name = rawName.toString("utf8");
    if (!Buffer.from(name, "utf8").equals(rawName) || fields.length !== 3 || !/^100(644|755)$/.test(fields[0]) || fields[1] !== "blob" || !/^[0-9a-f]{40}$/.test(fields[2]) || !safeRelative(name)) throw new Error("pinned tree contains nonregular or unsafe entry");
    entries.push({ mode: fields[0], type: fields[1], oid: fields[2], name }); start = end + 1;
  }
  if (!entries.length) throw new Error("pinned Git tree is empty"); return entries;
}
function parseCatFileBatch(raw, entries) {
  if (!Buffer.isBuffer(raw) || raw.length > MAX_ARCHIVE) throw new Error("pinned blob batch exceeds bound");
  const files = new Map(); let offset = 0;
  for (const entry of entries) {
    const end = raw.indexOf(10, offset); if (end < 0) throw new Error("pinned blob header truncated");
    const fields = raw.subarray(offset, end).toString("ascii").split(" ");
    if (fields.length !== 3 || fields[0] !== entry.oid || fields[1] !== "blob" || !/^(0|[1-9][0-9]*)$/.test(fields[2])) throw new Error("pinned blob identity mismatch");
    const size = Number(fields[2]);
    if (!Number.isSafeInteger(size) || size > 32 * 1024 * 1024 || end + 1 + size >= raw.length || raw[end + 1 + size] !== 10 || files.has(entry.name)) throw new Error("pinned blob size/path invalid");
    files.set(entry.name, Buffer.from(raw.subarray(end + 1, end + 1 + size))); offset = end + 1 + size + 1;
  }
  if (offset !== raw.length) throw new Error("pinned blob batch contains trailing data"); return files;
}
function readPinnedGitEntries() {
  if (gitText(["rev-parse", `${BASE_COMMIT}^{tree}`]) !== BASE_TREE) throw new Error("pinned commit/tree identity mismatch");
  const listing = parseTreeListing(run("git", ["--no-replace-objects", "--no-optional-locks", "ls-tree", "-r", "-z", "--full-tree", BASE_COMMIT], { env: gitEnvironment(), maxBuffer: MAX_ARCHIVE }));
  const input = Buffer.from(`${listing.map((entry) => entry.oid).join("\n")}\n`, "ascii");
  return parseCatFileBatch(run("git", ["--no-replace-objects", "--no-optional-locks", "cat-file", "--batch"], { env: gitEnvironment(), input, maxBuffer: MAX_ARCHIVE }), listing);
}
function expectedWs(source) {
  const importNeedle = '\t"vram-governor/internal/domain"\n';
  if (source.split(importNeedle).length !== 2) throw new Error("base import anchor not unique");
  source = source.replace(importNeedle, `${importNeedle}\t"vram-governor/internal/nodetransport"\n`);
  const block = ["\tconn, err := websocket.Accept(w, r, nil)\n", "\tif err != nil {\n", '\t\ts.log.Error("ws accept failed", "err", err)\n', "\t\treturn\n", "\t}\n"].join("");
  if (source.split(block).length !== 2) throw new Error("base accept anchor not unique");
  return source.replace(block, `${block}\tnodetransport.ApplyControlMessageLimit(conn)\n`);
}
function parseJSONStream(text) {
  const out = []; let start = -1; let depth = 0; let quoted = false; let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (start < 0) { if (/\s/.test(c)) continue; if (c !== "{") throw new Error("package inventory malformed"); start = i; depth = 1; continue; }
    if (quoted) { if (escaped) escaped = false; else if (c === "\\") escaped = true; else if (c === '"') quoted = false; continue; }
    if (c === '"') quoted = true; else if (c === "{") depth++; else if (c === "}" && --depth === 0) { out.push(JSON.parse(text.slice(start, i + 1))); start = -1; }
  }
  if (start >= 0 || !out.length) throw new Error("package inventory truncated");
  return out;
}
function currentGoClosure(sourceRoot, goPath, candidate) {
  const goCache = path.join(path.dirname(candidate), `gocache-${path.basename(candidate)}`);
  const cacheStat = fs.lstatSync(goCache);
  if (!cacheStat.isDirectory() || cacheStat.isSymbolicLink()) throw new Error("candidate Go cache directory invalid");
  const goRoot = path.dirname(path.dirname(goPath));
  const env = goEnvironment(goRoot, goCache);
  const raw = run(goPath, ["list", "-deps", "-json", "-mod=readonly", "./cmd/controller"], { cwd: sourceRoot, env, encoding: "utf8", maxBuffer: 32 * 1024 * 1024, timeout: 120_000 });
  const hashNamedFiles = (names, resolve, displayPath = (name) => name) => {
    if (!Array.isArray(names) || names.length > 100_000) throw new Error("closure file inventory exceeds count bound");
    const seen = new Set(); let totalBytes = 0;
    return names.map((name) => {
      if (!safeRelative(name) || seen.has(name)) throw new Error("closure file inventory has an unsafe or duplicate path");
      seen.add(name); const full = resolve(name); const st = fs.lstatSync(full);
      if (!st.isFile() || st.isSymbolicLink() || !Number.isSafeInteger(st.size) || st.size > MAX_STATE_FILE || totalBytes + st.size > MAX_STATE_TOTAL) throw new Error("closure file exceeds pre-read bounds");
      const measured = stableHashFile(full, MAX_STATE_FILE); totalBytes += measured.bytes;
      return { path: displayPath(name), bytes: measured.bytes, sha256: measured.sha256 };
    });
  };
  const pkgs = parseJSONStream(raw); const local = new Set(); const standard = new Set(); const moduleFiles = new Set(); const assets = new Set(); const modules = new Map();
  const sums = new Map();
  for (const line of fs.readFileSync(path.join(sourceRoot, "go.sum"), "utf8").split(/\r?\n/).filter(Boolean)) { const f = line.trim().split(/\s+/); if (f.length === 3) sums.set(`${f[0]}@${f[1]}`, f[2]); }
  const escapedPath = (value) => value.replace(/[A-Z]/g, (letter) => `!${letter.toLowerCase()}`);
  for (const pkg of pkgs) {
    if (typeof pkg.ImportPath !== "string" || /internal\/(nodeagent|checkpointgpuobserver)|cmd\/(checkpoint|node-agent)/.test(pkg.ImportPath)) throw new Error("forbidden production dependency closure");
    if (pkg.Module?.Path && pkg.Module?.Version) { const key = `${pkg.Module.Path}@${pkg.Module.Version}`; const previous = modules.get(key); if (previous && previous.dir !== pkg.Module.Dir) throw new Error("module identity resolves to multiple directories"); modules.set(key, { path: pkg.Module.Path, version: pkg.Module.Version, dir: pkg.Module.Dir, goMod: pkg.Module.GoMod, sum: pkg.Module.Sum || sums.get(key) || "", goModSum: pkg.Module.GoModSum || sums.get(`${key}/go.mod`) || "" }); }
    if (typeof pkg.Dir !== "string") throw new Error("package inventory omits source directory");
    const dir = path.resolve(pkg.Dir); const relDir = path.relative(sourceRoot, dir); const standardPackage = Boolean(pkg.Standard);
    const localPackage = !relDir.startsWith("..") && !path.isAbsolute(relDir);
    const moduleCache = env.GOMODCACHE; const moduleRel = path.relative(moduleCache, dir);
    const goRootRel = path.relative(goRoot, dir);
    if (standardPackage ? (goRootRel.startsWith("..") || path.isAbsolute(goRootRel)) : (!localPackage && (moduleRel.startsWith("..") || path.isAbsolute(moduleRel) || !pkg.Module))) throw new Error("package source escaped candidate/module/toolchain root");
    for (const file of [...(pkg.GoFiles ?? []), ...(pkg.CgoFiles ?? []), ...(pkg.SFiles ?? []), ...(pkg.CFiles ?? []), ...(pkg.CXXFiles ?? []), ...(pkg.HFiles ?? []), ...(pkg.FFiles ?? []), ...(pkg.MFiles ?? []), ...(pkg.SysoFiles ?? []), ...(pkg.EmbedFiles ?? [])]) {
      const full = path.resolve(dir, file); const rel = path.relative(localPackage ? sourceRoot : (standardPackage ? goRoot : moduleCache), full).split(path.sep).join("/");
      const st = fs.lstatSync(full);
      if (!safeRelative(rel) || !st.isFile() || st.isSymbolicLink() || (file.endsWith("_test.go"))) throw new Error("unsafe/test source in production closure");
      (localPackage ? local : (standardPackage ? standard : moduleFiles)).add(standardPackage ? `@goroot/${rel}` : rel); if (pkg.EmbedFiles?.includes(file) && localPackage) assets.add(rel);
    }
    if (!localPackage && pkg.Module?.GoMod) {
      const goMod = path.resolve(pkg.Module.GoMod); const rel = path.relative(moduleCache, goMod).split(path.sep).join("/");
      const st = fs.lstatSync(goMod); if (!safeRelative(rel) || !st.isFile() || st.isSymbolicLink()) throw new Error("module go.mod source is unsafe"); moduleFiles.add(rel);
    }
  }
  const moduleList = [...modules.values()].sort((a, b) => `${a.path}@${a.version}`.localeCompare(`${b.path}@${b.version}`)).map((module) => {
    if (!module.sum || !module.goModSum || typeof module.dir !== "string" || typeof module.goMod !== "string") throw new Error("module or pinned go.sum checksum missing");
    const moduleDir = path.resolve(module.dir); const moduleRel = path.relative(env.GOMODCACHE, moduleDir);
    if (moduleRel.startsWith("..") || path.isAbsolute(moduleRel)) throw new Error("module tree escaped offline cache");
    const modulePrefix = `${module.path}@${module.version}`;
    const content = directoryH1(moduleDir, [], modulePrefix);
    if (content.h1 !== module.sum) throw new Error("module tree does not match pinned go.sum h1");
    const moduleGoMod = stableRead(path.join(moduleDir, "go.mod")).bytes; const cacheGoMod = stableRead(module.goMod).bytes;
    assertModuleChecksumIdentity({ modulePath: module.path, version: module.version, treeH1: content.h1, moduleSum: module.sum, moduleGoMod, cacheGoMod, goModSum: module.goModSum });
    return { path: module.path, version: module.version, sum: module.sum, goModSum: module.goModSum, treeH1: content.h1, fileCount: content.fileCount, totalBytes: content.totalBytes, files: content.files };
  });
  const files = hashNamedFiles([...local].sort(), (name) => path.resolve(sourceRoot, ...name.split("/")));
  const embeddedAssets = hashNamedFiles([...assets].sort(), (name) => path.resolve(sourceRoot, ...name.split("/")));
  const packages = pkgs.map((p) => ({ importPath: p.ImportPath, standard: Boolean(p.Standard), module: p.Module ? `${p.Module.Path}@${p.Module.Version}` : null })).sort((a, b) => a.importPath.localeCompare(b.importPath));
  const moduleSourceFiles = hashNamedFiles([...moduleFiles].sort(), (name) => path.resolve(env.GOMODCACHE, ...name.split("/")));
  const standardNames = [...standard].sort();
  const standardFiles = hashNamedFiles(standardNames.map((name) => name.slice("@goroot/".length)), (name) => path.resolve(goRoot, ...name.split("/")), (name) => `@goroot/${name}`);
  const toolNames = ["go.exe", "pkg/tool/windows_amd64/asm.exe", "pkg/tool/windows_amd64/compile.exe", "pkg/tool/windows_amd64/link.exe", "pkg/tool/windows_amd64/pack.exe"];
  const toolchainFiles = hashNamedFiles(toolNames, (name) => name === "go.exe" ? goPath : path.join(goRoot, ...name.split("/")));
  const includeRoot = path.join(goRoot, "pkg", "include"); const includeNames = [];
  function walkInclude(dir, rel = "") { for (const entry of fs.readdirSync(dir, { withFileTypes: true })) { const name = rel ? `${rel}/${entry.name}` : entry.name; const full = path.join(dir, entry.name); const st = fs.lstatSync(full); if (st.isSymbolicLink()) throw new Error("Go asm include tree contains link"); if (st.isDirectory()) walkInclude(full, name); else if (st.isFile()) includeNames.push(name); else throw new Error("Go asm include tree contains special entry"); } }
  walkInclude(includeRoot);
  const includeFiles = hashNamedFiles(includeNames.sort(), (name) => path.join(includeRoot, ...name.split("/")), (name) => `pkg/include/${name}`);
  assertGeneratedGoModCopies(goRoot);
  const toolchainTree = directoryH1(goRoot, TOOLCHAIN_EXTRA_GO_MOD_COPIES, "golang.org/toolchain@v0.0.1-go1.23.4.windows-amd64");
  const toolchainVersion = run(goPath, ["version"], { cwd: sourceRoot, env, encoding: "utf8", timeout: 30_000 }).trim();
  const goToolSha256 = stableHashFile(goPath, MAX_STATE_FILE).sha256;
  assertToolchainIdentity({ ...toolchainTree, version: toolchainVersion, goToolSha256 });
  return { packages, modules: moduleList, sourceFiles: files, standardFiles, moduleFiles: moduleSourceFiles, embeddedAssets, toolchain: { goRoot: "pinned-go1.23.4-toolchain", moduleH1: GO_TOOLCHAIN_MODULE_H1, tree: { h1: toolchainTree.h1, fileCount: toolchainTree.fileCount, totalBytes: toolchainTree.totalBytes }, version: toolchainVersion, files: toolchainFiles, stdlibFiles: standardFiles, asmIncludeFiles: includeFiles } };
}
function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}
export function assertFileManifest(manifestFiles, expectedEntries) {
  if (!Array.isArray(manifestFiles) || !(expectedEntries instanceof Map) || manifestFiles.length !== expectedEntries.size) throw new Error("file manifest count differs");
  const seen = new Set();
  for (const entry of manifestFiles) {
    if (!exactKeys(entry, ["path", "bytes", "sha256"]) || !safeRelative(entry.path) || seen.has(entry.path)) throw new Error("file manifest entry invalid");
    const bytes = expectedEntries.get(entry.path);
    if (!bytes || entry.bytes !== bytes.length || entry.sha256 !== sha256(bytes)) throw new Error(`file manifest bytes mismatch: ${entry.path}`);
    seen.add(entry.path);
  }
  return true;
}
export function assertEmbeddedAssets(binary, assets, expectedEntries) {
  if (!Buffer.isBuffer(binary) || !Array.isArray(assets) || !assets.length) throw new Error("embedded asset inventory invalid");
  for (const asset of assets) {
    if (!exactKeys(asset, ["path", "bytes", "sha256"]) || !safeRelative(asset.path)) throw new Error("embedded asset entry invalid");
    const bytes = expectedEntries.get(asset.path);
    if (!bytes || bytes.length !== asset.bytes || sha256(bytes) !== asset.sha256 || !binary.includes(bytes)) throw new Error(`embedded baseline asset is absent or changed: ${asset.path}`);
  }
  return true;
}
export function assertExactNames(expected, actual) {
  if (!Array.isArray(expected) || !Array.isArray(actual) || expected.some((name) => typeof name !== "string") || actual.some((name) => typeof name !== "string")) throw new Error("candidate entry inventory is invalid");
  const left = [...expected].sort(); const right = [...actual].sort();
  if (new Set(left).size !== left.length || new Set(right).size !== right.length || JSON.stringify(left) !== JSON.stringify(right)) throw new Error("candidate entry inventory differs");
  return true;
}
export function validateCandidateBytes({ candidateName, candidateEntries, manifestBytes, sourceEntries, expectedEntries, closure, binaryBytes, currentState }) {
  if (typeof candidateName !== "string" || !/^candidate-[0-9]{14}-[0-9a-f]{12}$/.test(candidateName) || !Buffer.isBuffer(manifestBytes) || manifestBytes.length > 8 * 1024 * 1024 || !(sourceEntries instanceof Map) || !(expectedEntries instanceof Map) || !Buffer.isBuffer(binaryBytes)) throw new Error("candidate byte-validation inputs invalid");
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  assertExactNames(["manifest.json", "source", "vram-governor-controller-linux-amd64"], candidateEntries);
  if (!Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8").equals(manifestBytes)) throw new Error("manifest is not canonical or has duplicate fields");
  if (!exactKeys(manifest, ["schema", "candidate", "localOnly", "releaseApproved", "installedBinaryProvenance", "baseline", "reviewedDelta", "inputTrust", "sourceFiles", "closure", "build", "binary", "gitStateBefore", "gitStateAfter"])) throw new Error("manifest fields differ from byte validator schema");
  if (manifest.schema !== "controller-transport-hotfix-candidate-v1" || manifest.candidate !== candidateName || manifest.localOnly !== true || manifest.releaseApproved !== false || manifest.installedBinaryProvenance !== false || manifest.baseline?.commit !== BASE_COMMIT || manifest.baseline?.tree !== BASE_TREE) throw new Error("candidate identity or release boundary invalid");
  if (JSON.stringify(manifest.reviewedDelta) !== JSON.stringify(REVIEWED_DELTA)) throw new Error("candidate reviewed delta differs");
  const expectedTrust = { schema: "controller-input-trust-v1", source: "pinned-baseline-go.sum plus official-go-toolchain-module-h1", modulesVerifiedAgainstGoSum: true, toolchainModuleH1: GO_TOOLCHAIN_MODULE_H1 };
  if (JSON.stringify(manifest.inputTrust) !== JSON.stringify(expectedTrust)) throw new Error("candidate input trust provenance is not pinned");
  const expectedFiles = [...expectedEntries.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([name, bytes]) => ({ path: name, bytes: bytes.length, sha256: sha256(bytes) }));
  if (sourceEntries.size !== expectedEntries.size) throw new Error("candidate source entry count differs");
  for (const [name, bytes] of expectedEntries) if (!sourceEntries.has(name) || !sourceEntries.get(name).equals(bytes)) throw new Error(`candidate source bytes differ: ${name}`);
  assertFileManifest(manifest.sourceFiles, expectedEntries);
  if (JSON.stringify(manifest.sourceFiles) !== JSON.stringify(expectedFiles)) throw new Error("candidate source manifest is not exact");
  if (!closure || JSON.stringify(manifest.closure) !== JSON.stringify(closure)) throw new Error("candidate dependency closure differs from fresh independent measurement");
  const goSum = expectedEntries.get("go.sum");
  if (!Buffer.isBuffer(goSum)) throw new Error("pinned baseline go.sum missing");
  const checksums = new Map(goSum.toString("utf8").split(/\r?\n/).filter(Boolean).map((line) => { const fields = line.trim().split(/\s+/); return fields.length === 3 ? [`${fields[0]}@${fields[1]}`, fields[2]] : ["", ""]; }).filter(([key]) => key));
  if (!Array.isArray(closure.modules) || closure.modules.some((module) => checksums.get(`${module.path}@${module.version}`) !== module.sum || checksums.get(`${module.path}@${module.version}/go.mod`) !== module.goModSum || module.treeH1 !== module.sum)) throw new Error("dependency module content identity is not bound to pinned go.sum");
  if (closure.toolchain?.moduleH1 !== GO_TOOLCHAIN_MODULE_H1 || closure.toolchain?.tree?.h1 !== GO_TOOLCHAIN_MODULE_H1) throw new Error("compiler/stdlib toolchain tree is not bound to official module checksum");
  const expectedEnvironment = { GOOS: "linux", GOARCH: "amd64", GOAMD64: "v1", CGO_ENABLED: "0", GOTOOLCHAIN: "local", GOROOT: "pinned-go1.23.4-toolchain", GOCACHE: "candidate-private", GOMODCACHE: "repo-offline-cache", GOENV: "off", GOWORK: "off", GOFLAGS: "", GOEXPERIMENT: "", GODEBUG: "", GOFIPS140: "", GOAUTH: "", GOPROXY: "off", GOSUMDB: "off", GOPRIVATE: "", GONOPROXY: "", GONOSUMDB: "", GOINSECURE: "", GOVCS: "*:off" };
  const expectedBuild = { goVersion: "go1.23.4", goToolSha256: GO_SHA256, environment: expectedEnvironment, goos: "linux", goarch: "amd64", goamd64: "v1", cgo: false, workspace: "off", goenv: "off", goflags: "", network: "disabled", command: "go build -mod=readonly -buildvcs=false -trimpath -ldflags=-s -w ./cmd/controller" };
  if (JSON.stringify(manifest.build) !== JSON.stringify(expectedBuild)) throw new Error("candidate build settings differ from fixed no-inherited-knob envelope");
  if (!exactKeys(manifest.binary, ["path", "bytes", "sha256"]) || manifest.binary.path !== "vram-governor-controller-linux-amd64" || manifest.binary.bytes !== binaryBytes.length || manifest.binary.sha256 !== sha256(binaryBytes)) throw new Error("candidate binary identity differs");
  assertEmbeddedAssets(binaryBytes, closure.embeddedAssets, expectedEntries);
  for (const state of [manifest.gitStateBefore, manifest.gitStateAfter, currentState]) {
    if (!exactKeys(state, ["head", "index", "worktree", "worktreeStatusSha256"]) || typeof state.head !== "string" || !exactKeys(state.index, ["path", "type", "mode", "bytes", "sha256"]) || state.index.type !== "file" || !Number.isInteger(state.index.mode) || !Number.isInteger(state.index.bytes) || !/^[0-9a-f]{64}$/.test(state.index.sha256) || !exactKeys(state.worktree, ["count", "totalBytes", "digest"]) || !Number.isInteger(state.worktree.count) || state.worktree.count < 0 || state.worktree.count > MAX_STATE_FILES || !Number.isSafeInteger(state.worktree.totalBytes) || state.worktree.totalBytes < 0 || state.worktree.totalBytes > MAX_STATE_TOTAL || !/^[0-9a-f]{64}$/.test(state.worktree.digest) || !/^[0-9a-f]{64}$/.test(state.worktreeStatusSha256)) throw new Error("candidate Git preservation state schema invalid");
  }
  if (!currentState || JSON.stringify(manifest.gitStateBefore) !== JSON.stringify(manifest.gitStateAfter) || JSON.stringify(manifest.gitStateAfter) !== JSON.stringify(currentState)) throw new Error("candidate Git/index/worktree preservation snapshot differs");
  return manifest;
}
function readFileMap(root) {
  const files = new Map(); let fileCount = 0; let entryCount = 0; let totalBytes = 0;
  function walk(dir, relative = "") {
    const children = fs.readdirSync(dir, { withFileTypes: true });
    if (relative && children.length === 0) throw new Error("candidate source contains an empty directory");
    for (const entry of children) {
      entryCount++;
      if (entryCount > MAX_CANDIDATE_ENTRIES) throw new Error("candidate source entry count exceeds bound");
      const rel = relative ? `${relative}/${entry.name}` : entry.name;
      if (!safeRelative(rel)) throw new Error("candidate has unsafe path");
      const full = path.join(dir, entry.name); const st = fs.lstatSync(full);
      if (st.isSymbolicLink()) throw new Error("candidate contains symlink");
      if (st.isDirectory()) walk(full, rel);
      else if (st.isFile()) {
        assertCandidateFileBound(st.size, fileCount, totalBytes);
        const { bytes } = stableRead(full, MAX_FILE); fileCount++; totalBytes += bytes.length; files.set(rel, bytes);
      }
      else throw new Error("candidate contains special file");
    }
  }
  walk(root); return files;
}
export function verifyCandidateDirectory(candidate) {
  const outputRoot = path.join(ROOT, ".cache", "controller-transport-hotfix");
  const cacheStat = fs.lstatSync(path.join(ROOT, ".cache")); const outputStat = fs.lstatSync(outputRoot);
  const candidateResolved = path.resolve(candidate); const relativeCandidate = path.relative(outputRoot, candidateResolved);
  if (!cacheStat.isDirectory() || cacheStat.isSymbolicLink() || !outputStat.isDirectory() || outputStat.isSymbolicLink() || relativeCandidate.startsWith("..") || path.isAbsolute(relativeCandidate) || !/^candidate-[0-9]{14}-[0-9a-f]{12}$/.test(path.basename(candidateResolved))) throw new Error("candidate path is outside the fixed owned cache");
  const baseTree = gitText(["rev-parse", `${BASE_COMMIT}^{tree}`]);
  if (baseTree !== BASE_TREE) throw new Error("baseline tree identity mismatch");
  const baseline = readPinnedGitEntries();
  const ws = baseline.get(WS_PATH); const helperPath = path.join(ROOT, ...HELPER_PATH.split("/")); const helperStat = fs.lstatSync(helperPath);
  if (!helperStat.isFile() || helperStat.isSymbolicLink()) throw new Error("pinned helper path is not regular");
  const helper = fs.readFileSync(helperPath);
  if (sha256(helper) !== HELPER_SHA256 || baseline.has(HELPER_PATH)) throw new Error("helper delta identity mismatch");
  baseline.set(WS_PATH, Buffer.from(expectedWs(ws.toString("utf8")), "utf8")); baseline.set(HELPER_PATH, helper);

  const sourceRoot = path.join(candidate, "source"); const sourceStat = fs.lstatSync(sourceRoot);
  if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink()) throw new Error("candidate source root invalid");
  const actual = readFileMap(sourceRoot);
  if (actual.size !== baseline.size) throw new Error("candidate source inventory differs from pinned baseline plus exact delta");
  for (const [name, bytes] of baseline) {
    const got = actual.get(name);
    if (!got || got.length !== bytes.length || !got.equals(bytes)) throw new Error(`candidate source differs from pinned bytes: ${name}`);
  }

  const manifestPath = path.join(candidate, "manifest.json"); const manifestStat = fs.lstatSync(manifestPath);
  if (!manifestStat.isFile() || manifestStat.isSymbolicLink() || manifestStat.size > 8 * 1024 * 1024) throw new Error("candidate manifest file invalid");
  const manifestBytes = fs.readFileSync(manifestPath); const manifest = JSON.parse(manifestBytes.toString("utf8"));
  if (!Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8").equals(manifestBytes)) throw new Error("manifest is not canonical or has duplicate fields");
  if (!exactKeys(manifest, ["schema", "candidate", "localOnly", "releaseApproved", "installedBinaryProvenance", "baseline", "reviewedDelta", "inputTrust", "sourceFiles", "closure", "build", "binary", "gitStateBefore", "gitStateAfter"])) throw new Error("manifest fields differ from schema");
  if (manifest.schema !== "controller-transport-hotfix-candidate-v1" || manifest.localOnly !== true || manifest.releaseApproved !== false || manifest.installedBinaryProvenance !== false || manifest.baseline?.commit !== BASE_COMMIT || manifest.baseline?.tree !== BASE_TREE || manifest.candidate !== path.basename(candidate)) throw new Error("manifest candidate identity or release boundary invalid");
  if (!exactKeys(manifest.reviewedDelta, ["wsPath", "helperPath", "helperSha256", "insertion"]) || JSON.stringify(manifest.reviewedDelta) !== JSON.stringify({ wsPath: WS_PATH, helperPath: HELPER_PATH, helperSha256: HELPER_SHA256, insertion: "ApplyControlMessageLimit after successful websocket.Accept and before first wsjson.Read" })) throw new Error("reviewed delta declaration differs");
  const expectedFiles = [...baseline.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([name, bytes]) => ({ path: name, bytes: bytes.length, sha256: sha256(bytes) }));
  assertFileManifest(manifest.sourceFiles, baseline);
  if (JSON.stringify(manifest.sourceFiles) !== JSON.stringify(expectedFiles)) throw new Error("source manifest differs from independently reconstructed pinned tree");

  const goPath = path.join(ROOT, ".cache", "gopath", "pkg", "mod", "golang.org", "toolchain@v0.0.1-go1.23.4.windows-amd64", "bin", "go.exe");
  const goStat = fs.lstatSync(goPath); if (!goStat.isFile() || goStat.isSymbolicLink() || stableHashFile(goPath, MAX_STATE_FILE).sha256 !== GO_SHA256) throw new Error("cached Go toolchain identity path invalid");
  const closure = currentGoClosure(sourceRoot, goPath, candidate);
  if (JSON.stringify(manifest.closure) !== JSON.stringify(closure)) throw new Error("transitive controller closure differs from manifest");
  if (!exactKeys(manifest.build, ["goVersion", "goToolSha256", "environment", "goos", "goarch", "goamd64", "cgo", "workspace", "goenv", "goflags", "network", "command"])) throw new Error("build settings fields differ from reviewed envelope");
  if (!exactKeys(manifest.binary, ["path", "bytes", "sha256"]) || manifest.binary.path !== "vram-governor-controller-linux-amd64") throw new Error("binary manifest invalid");
  const expectedTop = ["manifest.json", "source", manifest.binary.path];
  const actualTop = fs.readdirSync(candidateResolved);
  assertExactNames(expectedTop, actualTop);
  const sourceTop = fs.lstatSync(sourceRoot);
  if (!sourceTop.isDirectory() || sourceTop.isSymbolicLink()) throw new Error("candidate source entry is not a directory");
  const binaryPath = path.join(candidate, manifest.binary.path); const binaryStat = fs.lstatSync(binaryPath);
  if (!binaryStat.isFile() || binaryStat.isSymbolicLink() || binaryStat.size !== manifest.binary.bytes || binaryStat.size > 512 * 1024 * 1024) throw new Error("candidate binary metadata mismatch");
  const binary = fs.readFileSync(binaryPath);
  if (sha256(binary) !== manifest.binary.sha256) throw new Error("candidate binary digest mismatch");
  return validateCandidateBytes({ candidateName: path.basename(candidateResolved), candidateEntries: actualTop, manifestBytes, sourceEntries: actual, expectedEntries: baseline, closure, binaryBytes: binary, currentState: currentGitState() });
}

function latestCandidate() {
  const root = path.join(ROOT, ".cache", "controller-transport-hotfix"); const stat = fs.lstatSync(root);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("owned candidate root invalid");
  const names = fs.readdirSync(root).filter((name) => /^candidate-[0-9]{14}-[0-9a-f]{12}$/.test(name)).sort();
  if (!names.length) throw new Error("no retained controller candidate");
  const candidate = path.join(root, names.at(-1)); const candidateStat = fs.lstatSync(candidate);
  if (!candidateStat.isDirectory() || candidateStat.isSymbolicLink()) throw new Error("candidate path invalid");
  return candidate;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3 || process.argv[2] !== "--latest") throw new Error("usage: node scripts/controller-hotfix/verify.mjs --latest");
    const manifest = verifyCandidateDirectory(latestCandidate());
    process.stdout.write(`controller transport hotfix local closure verified: ${manifest.candidate}; local_only=true; release_approved=false\n`);
  } catch {
    process.stderr.write("controller hotfix candidate verification failed closed\n");
    process.exitCode = 1;
  }
}

export const testSurface = Object.freeze({ safeRelative, expectedWs, parseTreeListing, parseCatFileBatch, readPinnedGitEntries, exactKeys, assertExactNames, assertFileManifest, assertEmbeddedAssets, validateCandidateBytes, hash1Entries, directoryH1, summarizeWorktreeRecords, missingTrackedWorktreeRecord, assertCandidateFileBound, readFileMap, assertModuleChecksumIdentity, assertToolchainIdentity, assertGeneratedGoModPairs, makeSafeCommandFailure });
