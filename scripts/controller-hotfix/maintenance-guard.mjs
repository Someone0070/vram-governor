import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildCombinedInstallPlan, buildCombinedRemovalPlan } from "./maintenance-guard-plan.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SSH = "C:/Windows/System32/OpenSSH/ssh.exe";
const SSH_KEY_LB = "C:/Users/Sasha/.ssh/lb_proxy_deploy";
const SSH_KEY_PVE = "C:/Users/Sasha/.ssh/cmp170_proxmox";
const KNOWN_HOSTS = "C:/Users/Sasha/.ssh/known_hosts";
const MAX_RECEIVER = 128 * 1024;
const MAX_SESSION_INPUT = 1024 * 1024;
const MAX_STDOUT = 256 * 1024;
const MAX_STDERR = 8 * 1024;
const CHILD_TIMEOUT_MS = 120000;
const SESSION_ACTION_LIMIT = 63;
const SESSION_TIMEOUT_MS = 115000;
const ACTION_TIMEOUT_MS = 30000;
const RECEIVER_BYTES = 74449;
const RECEIVER_SHA256 = "13b128018636587aac8f419df8ac79ffe6ae50789e2a0accfb49b1a717fd42a5";
const SAFE_CODES = new Set([
  "request_invalid", "role_invalid", "nonce_invalid", "plan_invalid", "identity_changed",
  "lock_custody", "lock_busy", "socket_conflict", "socket_inventory", "ephemeral_conflict",
  "nft_tool_custody", "nft_read_failed", "nft_json_invalid", "nft_schema_unknown",
  "owned_table_present", "owned_table_absent", "owned_table_mismatch", "foreign_rules_changed",
  "install_uncertain", "install_verified", "release_not_verified", "release_uncertain",
  "receipt_custody", "deadline", "action_limit", "diagnostic_failed", "phase_invalid",
]);
const ROLES = Object.freeze({ LB115: "10.0.0.115", CT200: "10.0.0.3" });
const SESSION_OPS = new Set(["get", "inspect", "install", "release"]);

function sha(data) { return crypto.createHash("sha256").update(data).digest("hex"); }
function exactKeys(value, keys) { return value && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0"); }
function error(code) { throw new Error(code); }
function safeRole(role) { return typeof role === "string" && Object.hasOwn(ROLES, role); }
function validNonce(nonce) { return typeof nonce === "string" && /^[a-f0-9]{32}$/.test(nonce); }

function noLinkedAncestors(filename) {
  const absolute = path.resolve(filename); const parsed = path.parse(absolute); let cursor = parsed.root;
  for (const part of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    const info = fs.lstatSync(cursor);
    if (info.isSymbolicLink() || (cursor !== absolute && !info.isDirectory())) error("receiver_source_custody");
  }
}

function stableReceiver() {
  const filename = path.join(HERE, "maintenance-guard.py");
  noLinkedAncestors(filename);
  const before = fs.lstatSync(filename);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size !== RECEIVER_BYTES) error("receiver_source_bound");
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.size !== RECEIVER_BYTES || opened.dev !== before.dev || opened.ino !== before.ino) error("receiver_source_identity");
    const chunks = []; let total = 0;
    while (total < RECEIVER_BYTES) {
      const chunk = Buffer.alloc(Math.min(16384, RECEIVER_BYTES - total));
      const count = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (count <= 0) error("receiver_source_short");
      chunks.push(chunk.subarray(0, count)); total += count;
    }
    const extra = Buffer.alloc(1);
    if (fs.readSync(fd, extra, 0, 1, null) !== 0) error("receiver_source_grew");
    const after = fs.fstatSync(fd); const named = fs.lstatSync(filename);
    for (const key of ["dev", "ino", "mode", "size", "mtimeMs", "ctimeMs"]) if (before[key] !== after[key] || before[key] !== named[key]) error("receiver_source_identity");
    const bytes = Buffer.concat(chunks);
    if (sha(bytes) !== RECEIVER_SHA256) error("receiver_source_identity");
    return bytes;
  } finally { fs.closeSync(fd); }
}

function shellQuote(value) { return "'" + value.replaceAll("'", "'\\''") + "'"; }
function fixedCommand(role, bootstrap) {
  const py = "/usr/bin/python3 -I -B -c " + shellQuote(bootstrap);
  if (role === "LB115") return py;
  return "exec /usr/sbin/pct exec 200 -- " + py;
}
function fixedSshArgs(role) {
  const host = ROLES[role]; const key = role === "LB115" ? SSH_KEY_LB : SSH_KEY_PVE;
  return [
    "-F", "none", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
    "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + KNOWN_HOSTS,
    "-o", "HostName=" + host, "-o", "PermitLocalCommand=no", "-o", "ClearAllForwardings=yes",
    "-o", "ForwardAgent=no", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
    "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "CanonicalizeHostname=no",
    "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", key,
    "root@" + host,
  ];
}
function receiverBootstrap() {
  return "import sys,hashlib,re\nn=sys.stdin.buffer.readline(16)\nif not n.endswith(b'\\n') or not re.fullmatch(b'(?:[1-9][0-9]{0,6})\\n',n): raise SystemExit(91)\nsize=int(n)\nhl=sys.stdin.buffer.readline(66)\nif not re.fullmatch(b'[0-9a-f]{64}\\n',hl): raise SystemExit(92)\nh=hl[:-1]\nif size!=" + RECEIVER_BYTES + " or size>" + MAX_RECEIVER + ": raise SystemExit(91)\ns=sys.stdin.buffer.read(size)\nif len(s)!=size or hashlib.sha256(s).hexdigest().encode('ascii')!=h or h!=b'" + RECEIVER_SHA256 + "': raise SystemExit(92)\nexec(compile(s,'<fixed-maintenance-guardian>','exec'),{'__name__':'__main__'})\n";
}

function parseRemoteLine(line) {
  let value;
  try { value = JSON.parse(line); } catch { error("receiver_response_invalid"); }
  if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.ok !== "boolean") error("receiver_response_invalid");
  if (value.ok === false) {
    if (!exactKeys(value, ["ok", "code", "state"]) || typeof value.code !== "string" || !SAFE_CODES.has(value.code) || !["uncertain", false, "attempting", "verified", "released"].includes(value.state)) error("receiver_response_invalid");
    error("receiver_" + value.code);
  }
  if (!exactKeys(value, ["ok", "result", "receipt_sha256"]) || !value.result || typeof value.result !== "object" || Array.isArray(value.result) || !(value.receipt_sha256 === null || (typeof value.receipt_sha256 === "string" && /^[a-f0-9]{64}$/.test(value.receipt_sha256)))) error("receiver_response_invalid");
  return value;
}

function normalizeSessionInput(input, role, nonce) {
  if (!Buffer.isBuffer(input) || input.length > MAX_SESSION_INPUT || (input.length && input[input.length - 1] !== 10)) error("session_input_invalid");
  const lines = input.length ? input.toString("ascii").split("\n").slice(0, -1) : [];
  if (lines.length > 63) error("session_action_limit");
  const requests = [];
  for (const line of lines) {
    if (line.length === 0 || line.length > 16384) error("session_input_invalid");
    let value;
    try { value = JSON.parse(line); } catch { error("session_input_invalid"); }
    if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.operation !== "string" || !SESSION_OPS.has(value.operation)) error("session_input_invalid");
    if (value.operation === "get") {
      if (!exactKeys(value, ["operation", "plane"]) || typeof value.plane !== "string" || !["lb_current", "lb_candidate", "lb_rollback", "ct_node_agent", "ct_comfy_queue"].includes(value.plane)) error("session_input_invalid");
      if ((role === "LB115" && !value.plane.startsWith("lb_")) || (role === "CT200" && !value.plane.startsWith("ct_"))) error("session_input_invalid");
      requests.push({ schema: "maintenance-guard-request-v1", role, operation: "get", nonce, plane: value.plane });
    }
    if (value.operation === "inspect") {
      if (!exactKeys(value, ["operation"])) error("session_input_invalid");
      requests.push({ schema: "maintenance-guard-request-v1", role, operation: "inspect", nonce });
    }
    if (value.operation === "install") {
      if (!exactKeys(value, ["operation"])) error("session_input_invalid");
      const plan = buildCombinedInstallPlan({ role, ownershipNonce: nonce });
      requests.push({ schema: "maintenance-guard-request-v1", role, operation: "install", nonce, batch_sha256: plan.batchSha256, batch_bytes: plan.batchBytes, transaction: plan.transaction });
    }
    if (value.operation === "release") {
      if (!exactKeys(value, ["operation", "receipt_sha256"]) || typeof value.receipt_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(value.receipt_sha256)) error("session_input_invalid");
      requests.push({ schema: "maintenance-guard-request-v1", role, operation: "release", nonce, verification: { schema: "maintenance-guard-success-v1", nonce, disposition: "successfully_verified", receipt_sha256: value.receipt_sha256 } });
    }
  }
  return requests;
}

function requestFrames(requests) { return Buffer.from(requests.map((request) => JSON.stringify(request) + "\n").join(""), "ascii"); }

function spawnBounded(role, receiver, requests) {
  const prelude = Buffer.from(receiver.length + "\n" + RECEIVER_SHA256 + "\n", "ascii");
  const payload = Buffer.concat([prelude, receiver, requestFrames(requests)]);
  if (payload.length > MAX_SESSION_INPUT + MAX_RECEIVER + 65536) error("session_input_bound");
  const args = [...fixedSshArgs(role), fixedCommand(role, receiverBootstrap())];
  return new Promise((resolve, reject) => {
    const child = spawn(SSH, args, { windowsHide: true, cwd: HERE, stdio: ["pipe", "pipe", "pipe"] });
    const stdout = []; let stdoutBytes = 0; let stderrBytes = 0; let settled = false;
    const stop = (code) => { if (settled) return; settled = true; clearTimeout(timer); try { child.kill(); } catch {} reject(new Error(code)); };
    const timer = setTimeout(() => stop("ssh_timeout"), CHILD_TIMEOUT_MS);
    child.stdout.on("data", (chunk) => { stdoutBytes += chunk.length; if (stdoutBytes > MAX_STDOUT) return stop("ssh_stdout_bound"); stdout.push(chunk); });
    child.stderr.on("data", (chunk) => { stderrBytes += chunk.length; if (stderrBytes > MAX_STDERR) return stop("ssh_stderr_bound"); });
    child.on("error", () => stop("ssh_spawn"));
    child.on("close", (code) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (code !== 0) return reject(new Error("ssh_exit_" + (Number.isInteger(code) ? code : "unknown")));
      const lines = Buffer.concat(stdout).toString("ascii").trimEnd().split("\n");
      if (lines.length !== requests.length) return reject(new Error("receiver_response_count"));
      try { resolve(lines.map(parseRemoteLine)); } catch (failure) { reject(failure); }
    });
    child.stdin.on("error", () => {});
    child.stdin.end(payload);
  });
}

export function parseCli(argv) {
  if (!Array.isArray(argv)) error("invalid_cli");
  if (argv.length === 0 || (argv.length === 1 && argv[0] === "--preflight")) return { mode: "preflight", roles: ["LB115", "CT200"] };
  if (argv.length === 2 && argv[0] === "--preflight" && safeRole(argv[1])) return { mode: "preflight", roles: [argv[1]] };
  if (argv.length === 4 && argv[0] === "--preflight" && argv[1] === "CT200" && argv[2] === "--phase" && argv[3] === "agent_paused") return { mode: "preflight", roles: ["CT200"], phase: "agent_paused" };
  if (argv.length === 3 && argv[0] === "--session" && safeRole(argv[1]) && validNonce(argv[2])) return { mode: "session", role: argv[1], nonce: argv[2] };
  error("invalid_cli");
}

export async function runPreflight(role, phase) {
  if (!safeRole(role)) error("role_invalid");
  if (phase !== undefined && (phase !== "agent_paused" || role !== "CT200")) error("phase_invalid");
  const receiver = stableReceiver();
  const nonce = crypto.randomBytes(16).toString("hex");
  const request = { schema: "maintenance-guard-request-v1", role, operation: "preflight", nonce };
  if (phase !== undefined) request.phase = phase;
  const requests = [request];
  const responses = await spawnBounded(role, receiver, requests);
  validatePreflightResult(role, nonce, responses[0]?.result, phase);
  return responses;
}

function validateUnitProjection(unit) {
  if (!exactKeys(unit, ["LoadState", "ActiveState", "SubState", "MainPID", "InvocationID", "ExecMainStartTimestampMonotonic"]) ||
      unit.LoadState !== "loaded" || unit.ActiveState !== "active" || unit.SubState !== "running" ||
      typeof unit.MainPID !== "string" || !/^[0-9]+$/.test(unit.MainPID) || !Number.isSafeInteger(Number(unit.MainPID)) || Number(unit.MainPID) < 2 ||
      typeof unit.InvocationID !== "string" || !/^[a-f0-9]{32}$/.test(unit.InvocationID) ||
      typeof unit.ExecMainStartTimestampMonotonic !== "string" || !/^[0-9]+$/.test(unit.ExecMainStartTimestampMonotonic)) error("receiver_response_invalid");
}

function validatePausedUnitProjection(unit) {
  if (!exactKeys(unit, ["LoadState", "ActiveState", "SubState", "MainPID", "InvocationID", "ExecMainStartTimestampMonotonic"]) ||
      unit.LoadState !== "loaded" || unit.ActiveState !== "inactive" || unit.SubState !== "dead" || unit.MainPID !== "0" ||
      !(unit.InvocationID === "" || (typeof unit.InvocationID === "string" && /^[a-f0-9]{32}$/.test(unit.InvocationID))) ||
      !(unit.ExecMainStartTimestampMonotonic === "" || (typeof unit.ExecMainStartTimestampMonotonic === "string" && /^[0-9]+$/.test(unit.ExecMainStartTimestampMonotonic)))) error("receiver_response_invalid");
}

export function validatePreflightResult(role, nonce, result, phase) {
  if (phase !== undefined && (phase !== "agent_paused" || role !== "CT200")) error("receiver_response_invalid");
  const rootKeys = ["role", "nonce", "identity", "foreign_ruleset_sha256", "held_source_ports", "source_sockets", "protected_listener_counts", "owned_table_absent", "applying", "diagnostics"];
  if (!safeRole(role) || !validNonce(nonce) || !exactKeys(result, rootKeys) || result.role !== role || result.nonce !== nonce ||
      !/^[a-f0-9]{64}$/.test(result.foreign_ruleset_sha256) || !Array.isArray(result.held_source_ports) ||
      result.held_source_ports.join(",") !== "443,444,445" || result.source_sockets !== "bound_exclusive_noninheritable" ||
      result.owned_table_absent !== true || result.applying !== false || result.diagnostics !== "not_performed") error("receiver_response_invalid");
  const protectedPorts = role === "LB115" ? [4000, 8443, 18082, 9444, 9445] : [8080, 8188, 8190];
  const counts = result.protected_listener_counts;
  if (!exactKeys(counts, protectedPorts.map(String)) || protectedPorts.some((port) => !Number.isSafeInteger(counts[String(port)]) || counts[String(port)] < 0)) error("receiver_response_invalid");
  const identity = result.identity;
  if (role === "LB115") {
    if (!exactKeys(identity, ["role", "image", "config_sha256", "ca_sha256", "unit", "process"]) || identity.role !== role || identity.image !== "pinned" || identity.config_sha256 !== "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37" || identity.ca_sha256 !== "ddc7359a3f730b1817c7adff7ede84439bdf31cc56ff7cf658142473042c1944") error("receiver_response_invalid");
    validateUnitProjection(identity.unit);
    if (!exactKeys(identity.process, ["pid", "executable_matches_installed", "fixed_config_argument", "service_cgroup"]) || !Number.isSafeInteger(identity.process.pid) || identity.process.pid < 2 || identity.process.executable_matches_installed !== true || identity.process.fixed_config_argument !== true || identity.process.service_cgroup !== true) error("receiver_response_invalid");
  } else if (phase === "agent_paused") {
    const nativeNames = ["llama-server.service", "comfyui.service", "comfy-harness.service", "vram-governor-runtime-tunnel.service"];
    if (role !== "CT200" || !exactKeys(identity, ["role", "phase", "container_ip", "net_namespace_matches_pid1", "agent", "native_units", "config_or_image_read"]) ||
        identity.role !== role || identity.phase !== "agent_paused" || identity.container_ip !== "10.0.0.58" || identity.net_namespace_matches_pid1 !== true ||
        identity.config_or_image_read !== true || !exactKeys(identity.agent, ["image", "unit_artifact", "config", "unit", "pending_job", "dropins_absent", "cgroup_state"]) ||
        identity.agent.image !== "pinned" || identity.agent.unit_artifact !== "pinned" || identity.agent.config !== "pinned" ||
        identity.agent.pending_job !== false || identity.agent.dropins_absent !== true || !["empty", "absent"].includes(identity.agent.cgroup_state) ||
        !exactKeys(identity.native_units, nativeNames)) error("receiver_response_invalid");
    validatePausedUnitProjection(identity.agent.unit);
    for (const name of nativeNames) validateUnitProjection(identity.native_units[name]);
  } else {
    const unitNames = ["vram-governor-node-agent.service", "llama-server.service", "comfyui.service", "comfy-harness.service", "vram-governor-runtime-tunnel.service"];
    if (!exactKeys(identity, ["role", "container_ip", "net_namespace_matches_pid1", "units", "config_or_image_read"]) || identity.role !== role || identity.container_ip !== "10.0.0.58" || identity.net_namespace_matches_pid1 !== true || identity.config_or_image_read !== false || !exactKeys(identity.units, unitNames)) error("receiver_response_invalid");
    for (const name of unitNames) validateUnitProjection(identity.units[name]);
  }
  return true;
}

export async function runSession(role, nonce, input) {
  if (!safeRole(role) || !validNonce(nonce)) error("session_input_invalid");
  const requests = normalizeSessionInput(input, role, nonce);
  if (requests.length === 0) error("session_input_invalid");
  return spawnBounded(role, stableReceiver(), requests);
}

export async function runInteractiveSession(role, nonce, inputStream = process.stdin, outputStream = process.stdout) {
  if (!safeRole(role) || !validNonce(nonce)) error("session_input_invalid");
  const receiver = stableReceiver();
  const args = [...fixedSshArgs(role), fixedCommand(role, receiverBootstrap())];
  const child = spawn(SSH, args, { windowsHide: true, cwd: HERE, stdio: ["pipe", "pipe", "pipe"] });
  return runInteractiveProtocol({ child, inputStream, outputStream, role, nonce, receiver });
}

function sessionFailure(code) { const failure = new Error(code); failure.code = code; return failure; }

function terminalEvent(child) {
  return new Promise((resolve) => {
    child.once("error", () => resolve({ kind: "error" }));
    child.once("close", (code, signal) => resolve({ kind: "close", code, signal }));
  });
}

async function within(promise, ms, code) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(sessionFailure(code)), ms); }),
    ]);
  } finally { clearTimeout(timer); }
}

async function* boundedLines(stream, { maxLine, maxTotal, maxLines, code }) {
  let pending = Buffer.alloc(0); let total = 0; let count = 0;
  for await (const raw of stream) {
    const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
    total += chunk.length;
    if (total > maxTotal) throw sessionFailure(code + "_total_bound");
    pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
    if (pending.length > maxLine && pending.indexOf(10) < 0) throw sessionFailure(code + "_line_bound");
    let at;
    while ((at = pending.indexOf(10)) >= 0) {
      if (at > maxLine) throw sessionFailure(code + "_line_bound");
      let line = pending.subarray(0, at);
      if (line.length && line[line.length - 1] === 13) line = line.subarray(0, line.length - 1);
      count += 1;
      if (count > maxLines) throw sessionFailure(code + "_count_bound");
      yield line.toString("ascii");
      pending = pending.subarray(at + 1);
    }
    if (pending.length > maxLine) throw sessionFailure(code + "_line_bound");
  }
  if (pending.length !== 0) throw sessionFailure(code + "_unterminated");
}

export function validatePublicResult(operation, value) {
  const obj = (keys) => exactKeys(value, keys);
  const hash = (item) => typeof item === "string" && /^[a-f0-9]{64}$/.test(item);
  if (operation === "get") {
    if (!obj(["port", "path", "status", "body_bytes", "source_port", "retained_fd"]) &&
        !obj(["port", "path", "status", "body_bytes", "source_port", "retained_fd", "running_count", "pending_count"]) &&
        !obj(["port", "path", "status", "body_bytes", "source_port", "retained_fd", "reports_ok"])) error("receiver_response_invalid");
    const validTarget = (value.port === 8443 && value.path === "/healthz") || (value.port === 8080 && value.path === "/health") || (value.port === 8188 && value.path === "/queue");
    if (!validTarget || value.status !== 200 || !Number.isSafeInteger(value.body_bytes) || value.body_bytes < 0 || value.body_bytes > 1024 * 1024 || ![443, 444, 445].includes(value.source_port) || value.retained_fd !== true) error("receiver_response_invalid");
    if (Object.hasOwn(value, "running_count") && (!Number.isSafeInteger(value.running_count) || value.running_count < 0 || !Number.isSafeInteger(value.pending_count) || value.pending_count < 0)) error("receiver_response_invalid");
    if (Object.hasOwn(value, "pending_count") && !Object.hasOwn(value, "running_count")) error("receiver_response_invalid");
    if (Object.hasOwn(value, "reports_ok") && value.reports_ok !== true) error("receiver_response_invalid");
    return value;
  }
  if (operation === "install") {
    if (!obj(["install_state", "owned", "foreign_ruleset_sha256"]) || value.install_state !== "verified" || !hash(value.foreign_ruleset_sha256)) error("receiver_response_invalid");
    validateOwnedProjection(value.owned); return value;
  }
  if (operation === "release") {
    if (!obj(["release_state", "prior_owned_handle"]) || value.release_state !== "verified_absent" || !Number.isSafeInteger(value.prior_owned_handle) || value.prior_owned_handle < 1) error("receiver_response_invalid");
    return value;
  }
  if (operation === "inspect") {
    if (obj(["owned_table_absent", "foreign_ruleset_sha256"])) {
      if (value.owned_table_absent !== true || !hash(value.foreign_ruleset_sha256)) error("receiver_response_invalid");
      return value;
    }
    validateOwnedProjection(value); return value;
  }
  error("receiver_response_invalid");
}

function validateOwnedProjection(value) {
  if (!exactKeys(value, ["table_handle", "chain_handles", "rule_handles", "ownership_nonce", "rules_sha256"]) ||
      !Number.isSafeInteger(value.table_handle) || value.table_handle < 1 ||
      !exactKeys(value.chain_handles, ["input", "output"]) || !Number.isSafeInteger(value.chain_handles.input) || value.chain_handles.input < 1 ||
      !Number.isSafeInteger(value.chain_handles.output) || value.chain_handles.output < 1 ||
      !Array.isArray(value.rule_handles) || value.rule_handles.length < 1 || value.rule_handles.length > 512 ||
      value.rule_handles.some((handle) => !Number.isSafeInteger(handle) || handle < 1) ||
      new Set(value.rule_handles).size !== value.rule_handles.length || !validNonce(value.ownership_nonce) ||
      !/^[a-f0-9]{64}$/.test(value.rules_sha256)) error("receiver_response_invalid");
}

export async function runInteractiveProtocol({ child, inputStream, outputStream, role, nonce, receiver, timeouts = {} }) {
  if (!child?.stdin || !child.stdout || !child.stderr || !inputStream || !outputStream || !safeRole(role) || !validNonce(nonce) || !Buffer.isBuffer(receiver) || receiver.length === 0 || receiver.length > MAX_RECEIVER) error("session_input_invalid");
  if (!timeouts || !exactKeys(timeouts, Object.keys(timeouts)) || Object.keys(timeouts).some((key) => !["sessionMs", "actionMs", "closeGraceMs"].includes(key))) error("session_input_invalid");
  const sessionMs = timeouts.sessionMs ?? SESSION_TIMEOUT_MS;
  const actionMs = timeouts.actionMs ?? ACTION_TIMEOUT_MS;
  const closeGraceMs = timeouts.closeGraceMs ?? 1000;
  if (![sessionMs, actionMs, closeGraceMs].every((value) => Number.isSafeInteger(value) && value > 0) || sessionMs > SESSION_TIMEOUT_MS || actionMs > ACTION_TIMEOUT_MS || closeGraceMs > 1000) error("session_input_invalid");
  let terminalResolve;
  const terminal = new Promise((resolve) => { terminalResolve = resolve; });
  child.once("error", () => terminalResolve({ kind: "error" }));
  child.once("close", (code, signal) => terminalResolve({ kind: "close", code, signal }));
  child.stdin.once("error", () => terminalResolve({ kind: "error" }));
  child.stdout.once("error", () => terminalResolve({ kind: "error" }));
  child.stderr.once("error", () => terminalResolve({ kind: "error" }));
  inputStream.once?.("error", () => terminalResolve({ kind: "error" }));
  outputStream.once?.("error", () => terminalResolve({ kind: "error" }));
  let stderrBytes = 0; let inputBytes = 0; let actions = 0;
  let stderrOverflow = false;
  child.stderr.on("data", (chunk) => { stderrBytes += chunk.length; if (stderrBytes > MAX_STDERR) { stderrOverflow = true; terminalResolve({ kind: "stderr_overflow" }); try { child.kill(); } catch {} } });
  const responses = boundedLines(child.stdout, { maxLine: 16384, maxTotal: MAX_STDOUT, maxLines: SESSION_ACTION_LIMIT, code: "receiver_response" })[Symbol.asyncIterator]();
  const nextResponse = () => { const pending = responses.next(); pending.catch(() => {}); return pending; };
  let pendingResponse = nextResponse();
  const inputs = boundedLines(inputStream, { maxLine: 16384, maxTotal: MAX_SESSION_INPUT, maxLines: SESSION_ACTION_LIMIT, code: "session_input" })[Symbol.asyncIterator]();
  const deadline = Date.now() + sessionMs;
  const ensureLive = async (ms = ACTION_TIMEOUT_MS) => {
    const left = Math.min(ms, deadline - Date.now());
    if (left <= 0) throw sessionFailure("session_deadline");
    const event = await Promise.race([
      terminal,
      new Promise((resolve) => setTimeout(() => resolve({ kind: "alive" }), Math.min(1, left))),
    ]);
    if (stderrOverflow) throw sessionFailure("ssh_stderr_bound");
    if (event.kind === "error") throw sessionFailure("ssh_child_error");
    if (event.kind === "stderr_overflow") throw sessionFailure("ssh_stderr_bound");
    if (event.kind === "close") throw sessionFailure("ssh_closed_early");
  };
  const writeBounded = async (stream, bytes) => {
    const left = deadline - Date.now(); if (left <= 0) throw sessionFailure("session_deadline");
    if (!stream.write(bytes)) await within(Promise.race([new Promise((resolve, reject) => {
      stream.once("drain", resolve); stream.once("error", () => reject(sessionFailure("ssh_stdin_error")));
    }), terminal.then((event) => { if (event.kind === "stderr_overflow") throw sessionFailure("ssh_stderr_bound"); throw sessionFailure("ssh_stdin_error"); })]), Math.min(actionMs, left), "ssh_drain_timeout");
  };
  try {
    const preamble = Buffer.from(receiver.length + "\n" + RECEIVER_SHA256 + "\n", "ascii");
    await writeBounded(child.stdin, preamble);
    await writeBounded(child.stdin, receiver);
    for (;;) {
      const left = deadline - Date.now(); if (left <= 0) throw sessionFailure("session_deadline");
      let next;
      try { next = await within(Promise.race([inputs.next(), terminal.then((event) => {
        if (event.kind === "error") throw sessionFailure("ssh_child_error");
        if (event.kind === "stderr_overflow") throw sessionFailure("ssh_stderr_bound");
        throw sessionFailure("ssh_closed_early");
      }), pendingResponse.then((item) => {
        if (item.done) throw sessionFailure("ssh_closed_early");
        throw sessionFailure("receiver_unsolicited_response");
      })]), left, "session_input_timeout"); }
      catch (failure) { throw failure; }
      if (next.done) break;
      actions += 1; inputBytes += Buffer.byteLength(next.value, "ascii") + 1;
      if (actions > SESSION_ACTION_LIMIT || inputBytes > MAX_SESSION_INPUT) throw sessionFailure("session_action_limit");
      let action;
      try { action = JSON.parse(next.value); } catch { throw sessionFailure("session_input_invalid"); }
      const requests = normalizeSessionInput(Buffer.from(JSON.stringify(action) + "\n", "ascii"), role, nonce);
      if (requests.length !== 1) throw sessionFailure("session_input_invalid");
      const request = requests[0];
      const unsolicited = await Promise.race([
        pendingResponse.then((item) => ({ item })),
        new Promise((resolve) => setTimeout(() => resolve({ idle: true }), 5)),
      ]);
      if (unsolicited.item) throw sessionFailure(unsolicited.item.done ? "receiver_response_missing" : "receiver_unsolicited_response");
      const frame = requestFrames(requests);
      await writeBounded(child.stdin, frame);
      let response;
      try { response = await within(Promise.race([pendingResponse, terminal.then((event) => {
        if (event.kind === "error") throw sessionFailure("ssh_child_error");
        if (event.kind === "stderr_overflow") throw sessionFailure("ssh_stderr_bound");
        return { terminal: event };
      })]), Math.min(actionMs, Math.max(1, deadline - Date.now())), "receiver_response_timeout"); }
      catch (failure) { throw failure; }
      if (response?.terminal) throw sessionFailure("receiver_response_missing");
      if (response.done || typeof response.value !== "string") throw sessionFailure("receiver_response_missing");
      const parsed = parseRemoteLine(response.value);
      pendingResponse = nextResponse();
      validatePublicResult(request.operation, parsed.result);
      if (request.operation === "get") {
        const expected = {
          lb_current: [8443, "/healthz", 443], lb_candidate: [8443, "/healthz", 444], lb_rollback: [8443, "/healthz", 445],
          ct_node_agent: [8080, "/health", 443], ct_comfy_queue: [8188, "/queue", 444],
        }[action.plane];
        if (!expected || parsed.result.port !== expected[0] || parsed.result.path !== expected[1] || parsed.result.source_port !== expected[2]) throw sessionFailure("receiver_response_invalid");
      }
      if (request.operation === "install" && parsed.receipt_sha256 === null) throw sessionFailure("receiver_response_invalid");
      if (request.operation === "release" && parsed.receipt_sha256 === null) throw sessionFailure("receiver_response_invalid");
      if (request.operation !== "install" && request.operation !== "release" && parsed.receipt_sha256 !== null && !/^[a-f0-9]{64}$/.test(parsed.receipt_sha256)) throw sessionFailure("receiver_response_invalid");
      const publicResult = JSON.stringify({ ok: true, operation: request.operation, result: parsed.result, receipt_sha256: parsed.receipt_sha256 }) + "\n";
      if (Buffer.byteLength(publicResult, "ascii") > 16384) throw sessionFailure("receiver_response_bound");
      if (!outputStream.write(publicResult)) await within(new Promise((resolve, reject) => {
        outputStream.once("drain", resolve); outputStream.once("error", () => reject(sessionFailure("session_output_error")));
      }), Math.min(actionMs, Math.max(1, deadline - Date.now())), "session_output_timeout");
      await ensureLive();
    }
    child.stdin.end();
    const ended = await within(terminal, Math.max(1, deadline - Date.now()), "session_close_timeout");
    if (ended.kind === "error" || ended.code !== 0) throw sessionFailure("ssh_exit_" + (Number.isInteger(ended.code) ? ended.code : "unknown"));
    const extra = await within(pendingResponse, closeGraceMs, "receiver_close_timeout");
    if (!extra.done) throw sessionFailure("receiver_unsolicited_response");
    return true;
  } catch (failure) {
    try { child.stdin.destroy(); } catch {}
    try { child.kill(); } catch {}
    throw failure;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const command = parseCli(process.argv.slice(2));
    if (command.mode === "preflight") {
      for (const role of command.roles) {
        const results = await runPreflight(role, command.phase);
        const result = results[0].result;
        process.stdout.write("fixed maintenance preflight observed role=" + role + " applying=false held_ports=443,444,445 owned_table_absent=" + String(result.owned_table_absent) + "\n");
      }
    } else {
      await runInteractiveSession(command.role, command.nonce);
    }
  } catch {
    process.stderr.write("fixed maintenance guardian failed closed\n");
    process.exitCode = 1;
  }
}
