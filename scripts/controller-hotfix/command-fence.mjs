import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export const HOST = "10.0.0.115";
export const RECEIVER_BYTES = 35368;
export const RECEIVER_SHA256 = "96e0c5afe0ba463fe42cbc2700a486322a02f844e8a3f4118ef2373a2e67d496";
export const ORIGINAL_CONFIG_SHA256 = "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37";
export const ORIGINAL_IMAGE_SHA256 = "ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const RECEIVER_PATH = path.join(HERE, "command-fence.py");
const SSH = "C:/Windows/System32/OpenSSH/ssh.exe";
const SSH_WINSXS = "C:/Windows/WinSxS/amd64_openssh-client-components-onecore_31bf3856ad364e35_10.0.26100.9549_none_9bb78eedccaa8631/ssh.exe";
export const FIXED_SSH_TOOL_BYTES = 1257984;
export const FIXED_SSH_TOOL_SHA256 = "0b8b5653141c6e02e8afc043d1703dcd6410f1606422ff3ba5eb52dc56a5cce9";
export const FIXED_SSH_HARDLINKS = Object.freeze([SSH, SSH_WINSXS]);
const SSH_KEY = "C:/Users/Sasha/.ssh/lb_proxy_deploy";
const KNOWN_HOSTS = "C:/Users/Sasha/.ssh/known_hosts";
const MAX_FRAME = 4096;
const MAX_OUTPUT = 64 * 1024;
const MAX_STDERR = 8 * 1024;
const SESSION_MS = 180000;
const ACTION_MS = 15000;
const CLOSE_MS = 6000;
export const SCHEMA = "controller-command-fence-v1";
const RECEIVER_FAILURE_CATEGORIES = Object.freeze(["original_service_config_custody", "database_connection_identity", "lock_ownership", "protocol_deadline", "cleanup", "unknown"]);
const FAILURE_STAGES = Object.freeze(["cli", "local_custody", "ssh_spawn", "ssh_early_exit", "receiver_acquisition", "receiver_snapshot", "receiver_rollback", "receiver_service_config", "receiver_database", "receiver_lock", "receiver_protocol", "receiver_cleanup", "receiver_unknown", "unknown"]);

// This is for a fresh, fixed trusted-local CLI process. Named-file pre/post
// hashing detects ordinary changes; it is not race-proof Node module-cache or
// evaluation authentication, nor a sandbox boundary.

function fail(code) { throw new Error(code); }
class FenceStageFailure extends Error {
  constructor(stage) { super("fixed controller command fence failed closed"); this.name = "FenceStageFailure"; this.fenceStage = FAILURE_STAGES.includes(stage) ? stage : "unknown"; }
}
function stageFailure(stage) { return new FenceStageFailure(stage); }
function safeFailureStage(error) { return error instanceof FenceStageFailure && FAILURE_STAGES.includes(error.fenceStage) ? error.fenceStage : "unknown"; }
function formatFailureDiagnostic(error) { return `fixed controller command fence failed closed: stage=${safeFailureStage(error)}\n`; }
function receiverFailureStage(category) {
  return ({ original_service_config_custody: "receiver_service_config", database_connection_identity: "receiver_database", lock_ownership: "receiver_lock", protocol_deadline: "receiver_protocol", cleanup: "receiver_cleanup", unknown: "receiver_unknown" })[category] ?? "receiver_unknown";
}
function sha(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}
function validNonce(value) { return typeof value === "string" && /^[a-f0-9]{32}$/.test(value); }

function noLinkedAncestors(filename, fsOps = fs) {
  const absolute = path.resolve(filename); const parsed = path.parse(absolute); let cursor = parsed.root;
  for (const part of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    const info = fsOps.lstatSync(cursor, { bigint: true });
    if (info.isSymbolicLink() || (cursor !== absolute && !info.isDirectory())) fail("local custody failed");
  }
}

function fixedLocalFile(filename) {
  noLinkedAncestors(filename);
  const info = fs.lstatSync(filename);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) fail("fixed local tool custody failed");
}

function sameSshMetadata(a, b) {
  return ["dev", "ino", "mode", "nlink", "uid", "gid", "size", "mtimeNs", "ctimeNs"].every((key) => a[key] === b[key]);
}

function fixedSshTool(fsOps = fs, pin = { bytes: FIXED_SSH_TOOL_BYTES, digest: FIXED_SSH_TOOL_SHA256 }) {
  const before = FIXED_SSH_HARDLINKS.map((filename) => {
    noLinkedAncestors(filename, fsOps);
    const info = fsOps.lstatSync(filename, { bigint: true });
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 2n || info.size !== BigInt(pin.bytes)) fail("fixed SSH tool custody failed");
    return info;
  });
  if (before[0].dev !== before[1].dev || before[0].ino !== before[1].ino) fail("fixed SSH hardlink identity failed");
  const flags = fsOps.constants.O_RDONLY | (fsOps.constants.O_NOFOLLOW ?? 0);
  const fds = [];
  try {
    for (let index = 0; index < FIXED_SSH_HARDLINKS.length; index++) {
      const fd = fsOps.openSync(FIXED_SSH_HARDLINKS[index], flags); fds.push(fd);
      const opened = fsOps.fstatSync(fd, { bigint: true });
      if (!opened.isFile() || opened.nlink !== 2n || !sameSshMetadata(before[index], opened)) fail("fixed SSH opened custody failed");
    }
    const chunks = []; let total = 0;
    while (total < pin.bytes) {
      const buffer = Buffer.alloc(Math.min(65536, pin.bytes - total));
      const count = fsOps.readSync(fds[0], buffer, 0, buffer.length, null);
      if (count <= 0) fail("fixed SSH short read");
      chunks.push(buffer.subarray(0, count)); total += count;
    }
    const extra = Buffer.alloc(1);
    if (fsOps.readSync(fds[0], extra, 0, 1, null) !== 0) fail("fixed SSH grew");
    for (let index = 0; index < FIXED_SSH_HARDLINKS.length; index++) {
      const opened = fsOps.fstatSync(fds[index], { bigint: true });
      noLinkedAncestors(FIXED_SSH_HARDLINKS[index], fsOps);
      const named = fsOps.lstatSync(FIXED_SSH_HARDLINKS[index], { bigint: true });
      if (!sameSshMetadata(before[index], opened) || !sameSshMetadata(before[index], named)) fail("fixed SSH changed");
    }
    const bytes = Buffer.concat(chunks);
    if (total !== pin.bytes || sha(bytes) !== pin.digest) fail("fixed SSH digest failed");
    return bytes;
  } finally {
    let closeFailed = false;
    for (const fd of fds) { try { fsOps.closeSync(fd); } catch { closeFailed = true; } }
    if (closeFailed) fail("fixed SSH handle close failed");
  }
}

/** Test seam accepts a filesystem facade only; the two fixed executable names cannot be replaced. */
export function _fixedSshToolForTest(fsFacade, fixtureBytes) {
  if (!Buffer.isBuffer(fixtureBytes)) fail("fixed SSH test fixture invalid");
  return fixedSshTool(fsFacade, { bytes: fixtureBytes.length, digest: sha(fixtureBytes) });
}

export function stableReceiver() {
  noLinkedAncestors(RECEIVER_PATH);
  const before = fs.lstatSync(RECEIVER_PATH);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size !== RECEIVER_BYTES) fail("receiver pin failed");
  const fd = fs.openSync(RECEIVER_PATH, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.size !== before.size || opened.dev !== before.dev || opened.ino !== before.ino || opened.mode !== before.mode || opened.mtimeMs !== before.mtimeMs || opened.ctimeMs !== before.ctimeMs) fail("receiver custody failed");
    const chunks = []; let total = 0;
    while (total < RECEIVER_BYTES) {
      const buffer = Buffer.alloc(Math.min(16384, RECEIVER_BYTES - total));
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (count <= 0) fail("receiver short read");
      chunks.push(buffer.subarray(0, count)); total += count;
    }
    const extra = Buffer.alloc(1);
    if (fs.readSync(fd, extra, 0, 1, null) !== 0) fail("receiver grew");
    const after = fs.fstatSync(fd); const named = fs.lstatSync(RECEIVER_PATH);
    for (const key of ["dev", "ino", "mode", "nlink", "size", "mtimeMs", "ctimeMs"]) if (before[key] !== after[key] || before[key] !== named[key]) fail("receiver changed");
    const bytes = Buffer.concat(chunks);
    if (total !== RECEIVER_BYTES || sha(bytes) !== RECEIVER_SHA256) fail("receiver digest failed");
    return bytes;
  } finally { fs.closeSync(fd); }
}

function fixedSshArgs() {
  return [
    "-F", "none", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
    "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + KNOWN_HOSTS, "-o", "HostName=" + HOST,
    "-o", "PermitLocalCommand=no", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
    "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "CanonicalizeHostname=no", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
    "-i", SSH_KEY, "root@" + HOST,
    "/usr/bin/python3 -I -B -c 'import sys,hashlib,re,os\ndef read_exact(n):\n b=bytearray()\n while len(b)<n:\n  c=os.read(0,n-len(b))\n  if not c: break\n  b.extend(c)\n return bytes(b)\ndef read_line(n):\n b=bytearray()\n while len(b)<n:\n  c=os.read(0,1)\n  if not c: break\n  b.extend(c)\n  if c==b\"\\n\": break\n return bytes(b)\nn=read_line(16)\nif not re.fullmatch(b\"(?:[1-9][0-9]{0,6})\\n\",n): raise SystemExit(91)\ns=int(n)\nh=read_line(66)\nif s!=" + RECEIVER_BYTES + " or s>131072 or not re.fullmatch(b\"[0-9a-f]{64}\\n\",h): raise SystemExit(92)\nr=read_exact(s)\nif len(r)!=s or hashlib.sha256(r).hexdigest().encode(\"ascii\")!=h.rstrip(b\"\\n\") or h!=b\"" + RECEIVER_SHA256 + "\\n\": raise SystemExit(93)\nexec(compile(r,\"<fixed-command-fence>\",\"exec\"),{\"__name__\":\"__main__\"})'",
  ];
}

export function _fixedBootstrapForTest() {
  const command = fixedSshArgs().at(-1);
  const prefix = "/usr/bin/python3 -I -B -c '";
  if (!command.startsWith(prefix) || !command.endsWith("'")) fail("fixed bootstrap shape");
  return command.slice(prefix.length, -1);
}

function fixedSpawnOptions() {
  return {
    cwd: HERE,
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
    env: { SystemRoot: "C:/Windows", WINDIR: "C:/Windows", ProgramData: "C:/ProgramData", PATH: "C:/Windows/System32;C:/Windows", LANG: "C" },
  };
}

function spawnFixed(executable, args, options) {
  return spawn(executable, args, options);
}

function monotonicMs() { return Number(process.hrtime.bigint() / 1000000n); }
function remaining(deadline, now, code) {
  const value = deadline - now();
  if (!Number.isFinite(value) || value <= 0) fail(code);
  return value;
}
function withinUntil(promise, deadline, now, code) {
  const budget = remaining(deadline, now, code);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(code)), budget);
    Promise.resolve(promise).then(resolve, reject).finally(() => clearTimeout(timer));
  });
}

export class ResponseReader {
  constructor(stream, child) {
    this.stream = stream; this.child = child; this.buffer = Buffer.alloc(0); this.queue = []; this.waiter = null; this.total = 0; this.lines = 0; this.ended = false; this.error = null;
    stream.on("data", (chunk) => this._data(chunk));
    stream.on("end", () => { this.ended = true; this._wake(); });
    stream.on("error", () => this._fail("ssh output failed"));
    child.once("error", () => this._fail("ssh child failed"));
    child.once("close", () => { if (!this.ended) this._fail("ssh closed early"); });
  }
  _fail(code) {
    if (this.error) return;
    this.error = new Error(code);
    try { this.child.kill(); } catch {}
    this._wake();
  }
  _wake() {
    if (this.waiter) { const wake = this.waiter; this.waiter = null; wake(); }
  }
  _data(chunk) {
    this.total += chunk.length;
    if (this.total > MAX_OUTPUT) return this._fail("ssh output bound");
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (this.buffer.length > MAX_FRAME && !this.buffer.includes(10)) return this._fail("ssh frame bound");
    while (true) {
      const end = this.buffer.indexOf(10);
      if (end < 0) break;
      if (end > MAX_FRAME) return this._fail("ssh frame bound");
      const line = this.buffer.subarray(0, end);
      this.buffer = this.buffer.subarray(end + 1);
      if (line.some((byte) => byte > 0x7f)) return this._fail("ssh frame encoding");
      this.lines++;
      if (this.lines > 62) return this._fail("ssh response count");
      this.queue.push(line.toString("ascii"));
    }
    this._wake();
  }
  async next(deadline, now) {
    remaining(deadline, now, "ssh response deadline");
    if (this.error) throw this.error;
    if (this.queue.length) return { done: false, value: this.queue.shift() };
    if (this.ended) {
      if (this.buffer.length) throw new Error("ssh truncated frame");
      return { done: true };
    }
    await withinUntil(new Promise((resolve) => { this.waiter = resolve; }), deadline, now, "ssh response timeout");
    remaining(deadline, now, "ssh response expired");
    return this.next(deadline, now);
  }
}

export function validateFenceResponse(line, operation, nonce) {
  let value;
  try { value = JSON.parse(line); } catch { fail("invalid receiver response"); }
  if (!value || typeof value !== "object" || Array.isArray(value) || value.schema !== SCHEMA || value.operation !== operation || value.nonce !== nonce || value.ok !== true) fail("receiver refused or response differed");
  if (operation === "begin") {
    if (!exactKeys(value, ["ok", "schema", "operation", "nonce", "held"]) || value.held !== true) fail("lock acquisition uncertain");
    return true;
  }
  if (operation === "snapshot") {
    const fields = ["total", "terminal", "expired", "nonterminal", "uncertain", "malformed"];
    if (!exactKeys(value, ["ok", "schema", "operation", "nonce", ...fields, "command_clear"]) || fields.some((key) => !Number.isSafeInteger(value[key]) || value[key] < 0 || value[key] > 1000000000)) fail("snapshot projection invalid");
    if (value.terminal + value.nonterminal !== value.total || value.terminal > value.total || ["expired", "uncertain", "malformed"].some((key) => value[key] > value.total)) fail("snapshot counts invalid");
    const clear = value.expired === 0 && value.nonterminal === 0 && value.uncertain === 0 && value.malformed === 0;
    if (value.command_clear !== clear) fail("snapshot clearance invalid");
    return Object.freeze(Object.fromEntries(fields.map((key) => [key, value[key]]).concat([["command_clear", clear]])));
  }
  if (operation === "close") {
    if (!exactKeys(value, ["ok", "schema", "operation", "nonce", "released"]) || value.released !== true) fail("rollback unverified");
    return true;
  }
  fail("unknown operation");
}

function validateOperationResponse(line, operation, nonce) {
  let value;
  try { value = JSON.parse(line); } catch { fail("invalid receiver response"); }
  if (value && typeof value === "object" && !Array.isArray(value) && value.ok === false) {
    const keys = ["ok", "schema", "operation", "nonce", "category"];
    if (exactKeys(value, keys) && value.schema === SCHEMA && value.operation === "failed" && value.nonce === nonce && RECEIVER_FAILURE_CATEGORIES.includes(value.category)) {
      throw stageFailure(receiverFailureStage(value.category));
    }
    throw stageFailure("receiver_unknown");
  }
  return validateFenceResponse(line, operation, nonce);
}

export function _failureDiagnosticForTest(error) { return formatFailureDiagnostic(error); }
export function _stageDiagnosticForTest(stage) { return `fixed controller command fence failed closed: stage=${FAILURE_STAGES.includes(stage) ? stage : "unknown"}\n`; }

function request(operation, nonce) {
  return Buffer.from(JSON.stringify({ schema: SCHEMA, operation, nonce }) + "\n", "ascii");
}

async function write(stream, bytes, deadline, now) {
  remaining(deadline, now, "ssh input deadline");
  if (stream.destroyed || stream.writableEnded) fail("ssh input closed");
  if (stream.write(bytes)) return;
  if (stream.destroyed || stream.writableEnded) fail("ssh input closed");
  await withinUntil(new Promise((resolve, reject) => {
    const cleanup = () => { stream.removeListener("drain", onDrain); stream.removeListener("error", onError); stream.removeListener("close", onClose); };
    const finish = (error) => { cleanup(); if (error) reject(error); else resolve(); };
    const onDrain = () => finish(); const onError = () => finish(new Error("ssh input failed"));
    const onClose = () => finish(new Error("ssh input closed"));
    stream.once("drain", onDrain); stream.once("error", onError); stream.once("close", onClose);
    if (stream.destroyed || stream.writableEnded) onClose();
  }), deadline, now, "ssh input timeout");
  remaining(deadline, now, "ssh input expired");
}

function watchStderr(stream, child, reader) {
  let bytes = 0;
  stream.on("data", (chunk) => { bytes += chunk.length; if (bytes > MAX_STDERR) reader._fail("ssh stderr bound"); });
}

function waitChild(child, deadline, now) {
  return withinUntil(child._fenceTerminal, deadline, now, "ssh close timeout").then((result) => {
    remaining(deadline, now, "ssh close expired");
    return result;
  });
}

function ensureChildAlive(child, reader, lifecycle) {
  if (child.exitCode !== null || child.signalCode !== null || reader.ended || lifecycle.closed) throw stageFailure("ssh_early_exit");
}

async function openWith(spawnChild, receiverBytes, nonce, now = monotonicMs) {
  if (!Buffer.isBuffer(receiverBytes) || receiverBytes.length !== RECEIVER_BYTES || sha(receiverBytes) !== RECEIVER_SHA256 || !validNonce(nonce)) throw stageFailure("local_custody");
  let child;
  try { child = spawnChild(SSH, fixedSshArgs(), fixedSpawnOptions()); }
  catch { throw stageFailure("ssh_spawn"); }
  const lifecycle = { spawned: false, spawnFailed: false, closed: false, earlyExit: false, abortRequested: false, expectedTerminal: false };
  let terminalResolve; let terminalReject;
  child._fenceTerminal = new Promise((resolve, reject) => { terminalResolve = resolve; terminalReject = reject; });
  child.once("spawn", () => { lifecycle.spawned = true; });
  child.once("error", () => { lifecycle.spawnFailed = !lifecycle.spawned; terminalReject(new Error("ssh child failed")); });
  child.once("close", (code, signal) => { lifecycle.closed = true; if (!lifecycle.abortRequested && !lifecycle.expectedTerminal) lifecycle.earlyExit = true; terminalResolve({ code, signal }); });
  const reader = new ResponseReader(child.stdout, child);
  watchStderr(child.stderr, child, reader);
  const deadline = now() + SESSION_MS;
  const actionDeadline = () => Math.min(deadline, now() + ACTION_MS);
  const abort = async () => {
    if (reader.ended || child.exitCode !== null || child.signalCode !== null) lifecycle.earlyExit = true;
    lifecycle.abortRequested = true;
    try { child.stdin.destroy(); } catch {}
    try { child.kill(); } catch {}
    try { await waitChild(child, now() + 2000, now); } catch {}
  };
  const phaseFailure = (fallback) => {
    if (lifecycle.spawnFailed && !lifecycle.spawned) return "ssh_spawn";
    if (lifecycle.earlyExit || lifecycle.closed || reader.ended || child.exitCode !== null || child.signalCode !== null) return "ssh_early_exit";
    return fallback;
  };
  try {
    const header = Buffer.from(`${receiverBytes.length}\n${RECEIVER_SHA256}\n`, "ascii");
    const acquisitionDeadline = actionDeadline();
    await write(child.stdin, Buffer.concat([header, receiverBytes]), acquisitionDeadline, now);
    await write(child.stdin, request("begin", nonce), acquisitionDeadline, now);
    const line = await reader.next(acquisitionDeadline, now);
    remaining(acquisitionDeadline, now, "fence acquisition expired");
    {
      if (line.done) throw stageFailure("ssh_early_exit");
      validateOperationResponse(line.value, "begin", nonce);
    }
    ensureChildAlive(child, reader, lifecycle);
  } catch (error) {
    const stage = error instanceof FenceStageFailure ? safeFailureStage(error) : phaseFailure("receiver_acquisition");
    await abort();
    throw stageFailure(stage);
  }
  let state = "held"; let actions = 0; let busy = false;
  const ensure = () => {
    if (state !== "held" || busy || now() >= deadline || actions >= 59) fail("fixed command fence session unavailable");
    actions++;
  };
  const perform = async (operation) => {
    ensure(); busy = true;
    try {
      const operationDeadline = actionDeadline();
      await write(child.stdin, request(operation, nonce), operationDeadline, now);
      const line = await reader.next(operationDeadline, now);
      remaining(operationDeadline, now, "fence action expired");
      if (line.done) fail("receiver closed during action");
      const value = validateOperationResponse(line.value, operation, nonce);
      remaining(operationDeadline, now, "fence response expired");
      ensureChildAlive(child, reader, lifecycle);
      return value;
    } catch (error) {
      const stage = error instanceof FenceStageFailure ? safeFailureStage(error) : phaseFailure(operation === "snapshot" ? "receiver_snapshot" : "receiver_unknown");
      state = "failed"; await abort(); throw stageFailure(stage);
    } finally { busy = false; }
  };
  const session = {
    nonce,
    async snapshot() { return perform("snapshot"); },
    async close() {
      if (state !== "held" || busy || now() >= deadline || actions >= 60) fail("fixed command fence session unavailable");
      actions++;
      busy = true;
      let closeResponseReceived = false;
      try {
        const closeDeadline = actionDeadline();
        await write(child.stdin, request("close", nonce), closeDeadline, now);
        child.stdin.end();
        const line = await reader.next(closeDeadline, now);
        remaining(closeDeadline, now, "rollback response expired");
        if (line.done) fail("rollback response missing");
        validateOperationResponse(line.value, "close", nonce);
        closeResponseReceived = true;
        lifecycle.expectedTerminal = true;
        state = "closing";
        const settledDeadline = Math.min(deadline, now() + CLOSE_MS);
        const ended = await waitChild(child, settledDeadline, now);
        remaining(settledDeadline, now, "rollback settlement expired");
        if (ended.code !== 0) fail("receiver close failed");
        remaining(deadline, now, "rollback terminal expired");
        const eofDeadline = Math.min(deadline, now() + 100);
        const extra = await reader.next(eofDeadline, now);
        remaining(eofDeadline, now, "rollback EOF action expired");
        remaining(deadline, now, "rollback EOF expired");
        if (!extra.done) fail("unexpected receiver output");
        remaining(deadline, now, "rollback confirmation expired");
        state = "closed";
        return true;
      } catch (error) {
        const stage = error instanceof FenceStageFailure ? safeFailureStage(error) : (lifecycle.spawnFailed && !lifecycle.spawned ? "ssh_spawn" : lifecycle.earlyExit || (lifecycle.closed && !closeResponseReceived) ? "ssh_early_exit" : "receiver_rollback");
        state = "failed"; await abort(); throw stageFailure(stage);
      } finally { busy = false; }
    },
    async abort() {
      if (state === "closed") return;
      state = "failed"; await abort();
    },
  };
  return Object.freeze(session);
}

/** Fixed LB115 client. The caller can only hold, snapshot, and explicitly close its own fence. */
export async function openCommandFenceSession() {
  let receiver;
  try {
    fixedSshTool();
    fixedLocalFile(SSH_KEY);
    fixedLocalFile(KNOWN_HOSTS);
    receiver = stableReceiver();
  } catch {
    throw stageFailure("local_custody");
  }
  const nonce = crypto.randomBytes(16).toString("hex");
  return openWith(spawnFixed, receiver, nonce);
}

/** Test-only injection point for finite local controls; it accepts no target, path, URL, SQL, or environment. */
export async function _openWithTestSeams(spawnChild, nonce, now = monotonicMs) {
  return openWith(spawnChild, stableReceiver(), nonce, now);
}

export function validateProbeCli(args) {
  if (!Array.isArray(args) || args.length !== 1 || args[0] !== "--probe") throw stageFailure("cli");
  return true;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    validateProbeCli(process.argv.slice(2));
    const session = await openCommandFenceSession();
    let summary;
    try { summary = await session.snapshot(); await session.close(); }
    catch (error) { await session.abort(); throw error; }
    process.stdout.write(`fixed controller command fence roundtrip completed: total=${summary.total}; terminal=${summary.terminal}; expired=${summary.expired}; nonterminal=${summary.nonterminal}; uncertain=${summary.uncertain}; malformed=${summary.malformed}; command_clear=${summary.command_clear}; source_route=postgres_node_commands_only\n`);
  } catch (error) {
    process.stderr.write(formatFailureDiagnostic(error));
    process.exitCode = 1;
  }
}
