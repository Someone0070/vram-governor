import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  FIXED_SSH_HARDLINKS,
  FIXED_SSH_TOOL_BYTES,
  FIXED_SSH_TOOL_SHA256,
  HOST as LB_HOST,
  RECEIVER_BYTES,
  RECEIVER_SHA256,
  _fixedSshToolForTest,
  stableReceiver,
} from "./command-fence.mjs";

export const WIRE_SCHEMA = "fixed-expired-command-evidence-v1";
const OUTPUT_SCHEMA = "expired-command-evidence-readonly-v1";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PYTHON_PATH = path.join(HERE, "expired-command-evidence.py");
const SSH = "C:/Windows/System32/OpenSSH/ssh.exe";
const LB_KEY = "C:/Users/Sasha/.ssh/lb_proxy_deploy";
const PVE_KEY = "C:/Users/Sasha/.ssh/cmp170_proxmox";
const KNOWN_HOSTS = "C:/Users/Sasha/.ssh/known_hosts";
const PVE_HOST = "10.0.0.3";
const CT_ID = "200";
const MAX_SOURCE = 32768;
const HELPER_SOURCE_BYTES = 32653;
const HELPER_SOURCE_SHA256 = "3a8a3a526fc7b1ec467493e48fc804cbf9b1cfcb89966c06a5e7bb262dfa88cf";
const MAX_WIRE = 65536;
const MAX_STDOUT = 65536;
const CHILD_TIMEOUT_MS = 25000;
const SESSION_TIMEOUT_MS = 45000;
const FIXED_ENV = Object.freeze({
  SystemRoot: "C:/Windows",
  WINDIR: "C:/Windows",
  ProgramData: "C:/ProgramData",
  PATH: "C:/Windows/System32;C:/Windows",
  LANG: "C",
});
const ROW_KEYS = Object.freeze([
  "id", "node_id", "idempotency_key", "status", "command", "target_id", "model",
  "created_at", "expires_at", "sent_at", "last_sent_at", "completed_at",
  "body_id", "body_node_id", "body_idempotency_key", "body_status", "body_created_at",
  "body_expires_at", "body_sent_at", "body_last_sent_at", "body_completed_at",
  "args_type", "target_type", "model_type", "body_result_present",
]);
const COUNT_KEYS = Object.freeze([
  "selected", "matched_pairs", "missing", "mismatched", "malformed", "time_binding_unknown",
  "completed_before_expiry", "completed_at_expiry", "completed_after_expiry", "ok_true",
  "ok_false", "validation_refusal", "catalog_refusal", "lifecycle_unsupported", "unknown_failure",
  "outcome_unknown", "result_mismatch", "cache_invalid_entries",
]);
const LB_FAILURES = new Set([
  "original_custody", "readonly_connection", "readonly_transaction", "selected_projection", "readonly_rollback",
  "original_custody_after", "unsupported_rows", "too_many_rows", "row_projection", "database_readonly",
  "database_rollback", "database_resolution", "protocol", "unknown",
]);
const CT_FAILURES = new Set([
  "original_custody", "cache_custody", "cache_malformed", "unsupported_rows", "too_many_rows", "protocol",
  "cleanup", "unknown",
]);

class EvidenceFailure extends Error {
  constructor(stage) {
    super("fixed expired command evidence failed closed");
    this.stage = stage;
  }
}

function fail(stage) { throw new EvidenceFailure(stage); }
function sha(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function exactObject(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null) &&
    Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}
function safeStage(value, known) { return typeof value === "string" && known.has(value) ? value : "unknown"; }

function parseStrictJson(source, maxChars = MAX_STDOUT) {
  if (typeof source !== "string" || source.length === 0 || source.length > maxChars) fail("protocol");
  let offset = 0;
  let nodes = 0;
  const whitespace = () => { while (offset < source.length && /[\t\n\r ]/.test(source[offset])) offset++; };
  const string = () => {
    const start = offset;
    if (source[offset++] !== '"') fail("protocol");
    let escaped = false;
    while (offset < source.length) {
      const char = source[offset++];
      if (escaped) { escaped = false; continue; }
      if (char === "\\") { escaped = true; continue; }
      if (char === '"') {
        try { return JSON.parse(source.slice(start, offset)); } catch { fail("protocol"); }
      }
      if (char < " ") fail("protocol");
    }
    fail("protocol");
  };
  const value = (depth) => {
    if (depth > 20 || ++nodes > 20000) fail("protocol");
    whitespace();
    const char = source[offset];
    if (char === '"') return string();
    if (char === "{") {
      offset++; whitespace(); const object = Object.create(null); const keys = new Set();
      if (source[offset] === "}") { offset++; return object; }
      while (true) {
        whitespace(); const key = string(); whitespace();
        if (source[offset++] !== ":" || keys.has(key)) fail("protocol");
        keys.add(key); object[key] = value(depth + 1); whitespace();
        const next = source[offset++];
        if (next === "}") return object;
        if (next !== ",") fail("protocol");
      }
    }
    if (char === "[") {
      offset++; whitespace(); const array = [];
      if (source[offset] === "]") { offset++; return array; }
      while (true) {
        array.push(value(depth + 1)); whitespace();
        const next = source[offset++];
        if (next === "]") return array;
        if (next !== ",") fail("protocol");
      }
    }
    for (const [literal, parsed] of [["true", true], ["false", false], ["null", null]]) {
      if (source.startsWith(literal, offset)) { offset += literal.length; return parsed; }
    }
    const match = source.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (match) {
      offset += match[0].length;
      const number = Number(match[0]);
      if (!Number.isFinite(number)) fail("protocol");
      return number;
    }
    fail("protocol");
  };
  const parsed = value(0); whitespace();
  if (offset !== source.length) fail("protocol");
  return parsed;
}

function noLinkedAncestors(filename) {
  const absolute = path.resolve(filename);
  const parsed = path.parse(absolute);
  let cursor = parsed.root;
  for (const part of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    const info = fs.lstatSync(cursor, { bigint: true });
    if (info.isSymbolicLink() || (cursor !== absolute && !info.isDirectory())) fail("local_custody");
  }
}

function metadataTuple(info) {
  return [info.dev, info.ino, info.mode, info.nlink, info.size, info.mtimeNs, info.ctimeNs];
}

function fixedPrivateFile(filename) {
  noLinkedAncestors(filename);
  const info = fs.lstatSync(filename, { bigint: true });
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n) fail("local_custody");
  return metadataTuple(info);
}

function fixedSource(filename, maximum) {
  noLinkedAncestors(filename);
  const before = fs.lstatSync(filename, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size > BigInt(maximum)) fail("local_custody");
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || metadataTuple(opened).some((part, i) => part !== metadataTuple(before)[i])) fail("local_custody");
    const chunks = []; let total = 0;
    while (total < Number(before.size)) {
      const buffer = Buffer.alloc(Math.min(16384, Number(before.size) - total));
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (count <= 0) fail("local_custody");
      chunks.push(buffer.subarray(0, count)); total += count;
    }
    const extra = Buffer.alloc(1);
    if (fs.readSync(fd, extra, 0, 1, null) !== 0) fail("local_custody");
    const after = fs.fstatSync(fd, { bigint: true });
    noLinkedAncestors(filename);
    const named = fs.lstatSync(filename, { bigint: true });
    for (const candidate of [after, named]) {
      if (metadataTuple(candidate).some((part, i) => part !== metadataTuple(before)[i])) fail("local_custody");
    }
    return Buffer.concat(chunks);
  } finally { fs.closeSync(fd); }
}

function verifiedHelperSource() {
  const bytes = fixedSource(PYTHON_PATH, MAX_SOURCE);
  if (bytes.length !== HELPER_SOURCE_BYTES || sha(bytes) !== HELPER_SOURCE_SHA256) fail("local_custody");
  return bytes;
}

function fixedLbCommand(nonce) {
  validateNonce(nonce);
  const bindings = ["_probe_service_and_config", "_connection_environment", "_yaml_database_url", "PsqlChannel",
    "_validate_identity", "IDENTITY_SQL", "RESOLUTION_SQL", "_same_original"];
  const bootstrap = `import hashlib,sys\ndef _read_fixed(_n):\n _b=bytearray()\n while len(_b)<_n:\n  _p=sys.stdin.buffer.read(_n-len(_b))\n  if not _p: raise SystemExit(2)\n  _b.extend(_p)\n return bytes(_b)\n_rbytes=_read_fixed(${RECEIVER_BYTES})\n_hbytes=_read_fixed(${HELPER_SOURCE_BYTES})\nif hashlib.sha256(_rbytes).hexdigest()!=\"${RECEIVER_SHA256}\" or hashlib.sha256(_hbytes).hexdigest()!=\"${HELPER_SOURCE_SHA256}\": raise SystemExit(3)\n_rns={\"__name__\":\"_fixed_controller_receiver\"}\nexec(compile(_rbytes,\"<fixed-controller-receiver>\",\"exec\"),_rns)\n_hns={\"__name__\":\"diagnostic\"}\nexec(compile(_hbytes,\"<fixed-expired-command-helper>\",\"exec\"),_hns)\nfor _key in ${JSON.stringify(bindings)}: _hns[_key]=_rns[_key]\nraise SystemExit(_hns[\"_lb_main\"](\"${nonce}\"))`;
  return `/usr/bin/python3 -I -B -c '${bootstrap}'`;
}

function verifyFixedToolAndCredentials() {
  const toolBytes = fs.readFileSync(SSH);
  if (toolBytes.length !== FIXED_SSH_TOOL_BYTES || sha(toolBytes) !== FIXED_SSH_TOOL_SHA256) fail("local_custody");
  try { _fixedSshToolForTest(fs, toolBytes); } catch { fail("local_custody"); }
  const lbKey = fixedPrivateFile(LB_KEY);
  const pveKey = fixedPrivateFile(PVE_KEY);
  const knownHosts = fixedPrivateFile(KNOWN_HOSTS);
  return () => {
    try {
      _fixedSshToolForTest(fs, toolBytes);
      if (fixedPrivateFile(LB_KEY).some((part, i) => part !== lbKey[i]) ||
          fixedPrivateFile(PVE_KEY).some((part, i) => part !== pveKey[i]) ||
          fixedPrivateFile(KNOWN_HOSTS).some((part, i) => part !== knownHosts[i])) fail("local_custody");
      const receiver = stableReceiver();
      if (receiver.length !== RECEIVER_BYTES || sha(receiver) !== RECEIVER_SHA256) fail("local_custody");
    } catch { fail("local_custody"); }
  };
}

function fixedSshArgs(host, key, remoteCommand) {
  return [
    "-F", "none", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
    "-o", "StrictHostKeyChecking=yes", "-o", `UserKnownHostsFile=${KNOWN_HOSTS}`, "-o", `HostName=${host}`,
    "-o", "PermitLocalCommand=no", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
    "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "CanonicalizeHostname=no", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
    "-i", key, `root@${host}`, remoteCommand,
  ];
}

function spawnFixed(host, key, remoteCommand, input, deadline) {
  const remaining = Number((deadline - process.hrtime.bigint()) / 1000000n);
  if (remaining <= 0) fail("timeout");
  if (!Buffer.isBuffer(input) || input.length > MAX_WIRE * 2) fail("protocol");
  let result;
  try {
    result = spawnSync(SSH, fixedSshArgs(host, key, remoteCommand), {
      input,
      cwd: HERE,
      windowsHide: true,
      timeout: Math.min(CHILD_TIMEOUT_MS, remaining),
      maxBuffer: MAX_STDOUT,
      encoding: "utf8",
      env: { ...FIXED_ENV },
      stdio: ["pipe", "pipe", "ignore"],
    });
  } catch { fail("ssh_transport"); }
  if (result.error) {
    const code = result.error.code;
    if (code === "ETIMEDOUT") fail("timeout");
    fail("ssh_transport");
  }
  if (typeof result.stdout !== "string" || Buffer.byteLength(result.stdout, "utf8") > MAX_STDOUT) fail("protocol");
  return { status: result.status, stdout: result.stdout };
}

function pythonRemoteCommand() {
  const bootstrap = `import hashlib,os,sys\ndef _read_source(_n):\n _b=bytearray()\n while len(_b)<_n:\n  _p=os.read(0,_n-len(_b))\n  if not _p: raise SystemExit(2)\n  _b.extend(_p)\n return bytes(_b)\n_source=_read_source(${HELPER_SOURCE_BYTES})\nif hashlib.sha256(_source).hexdigest()!=\"${HELPER_SOURCE_SHA256}\": raise SystemExit(3)\nexec(compile(_source,\"<fixed-expired-command-evidence>\",\"exec\"),{\"__name__\":\"__main__\"})`;
  return `exec /usr/sbin/pct exec ${CT_ID} -- /usr/bin/python3 -I -B -c '${bootstrap}'`;
}

function buildCtInput(nonce, rows) {
  validateNonce(nonce);
  const wire = Buffer.from(JSON.stringify({ schema: WIRE_SCHEMA, nonce, rows }), "utf8");
  if (wire.length > MAX_WIRE) fail("protocol");
  return wire;
}

function validateNonce(nonce) {
  if (typeof nonce !== "string" || !/^[a-f0-9]{32}$/.test(nonce)) fail("protocol");
}

function validateRowsEnvelope(line, nonce) {
  validateNonce(nonce);
  const value = parseStrictJson(line);
  if (!value || value.schema !== WIRE_SCHEMA || value.nonce !== nonce || value.authoritative_outcome !== false ||
      value.permission_to_restart !== false || value.command_history_changed !== false) fail("protocol");
  if (value.stage !== "ok") {
    if (!exactObject(value, ["schema", "nonce", "stage", "authoritative_outcome", "permission_to_restart", "command_history_changed"])) fail("protocol");
    fail(safeStage(value.stage, LB_FAILURES));
  }
  const keys = ["schema", "nonce", "stage", "expired_total", "unsupported_expired", "load_model_total", "rows", "read_only", "original_custody_unchanged", "database_timestamp_precision_limited", "authoritative_outcome", "permission_to_restart", "command_history_changed"];
  if (!exactObject(value, keys) || value.database_timestamp_precision_limited !== true || value.read_only !== true || value.original_custody_unchanged !== true ||
      !Number.isSafeInteger(value.expired_total) || value.expired_total < 0 ||
      !Number.isSafeInteger(value.unsupported_expired) || value.unsupported_expired !== 0 ||
      !Number.isSafeInteger(value.load_model_total) || value.load_model_total < 0 || value.load_model_total > 32 ||
      !Array.isArray(value.rows) || value.rows.length !== value.load_model_total || value.expired_total !== value.load_model_total) fail("protocol");
  const ids = new Set(); const keysSeen = new Set();
  for (const row of value.rows) {
    if (!exactObject(row, ROW_KEYS)) fail("protocol");
    if (row.status !== "expired" || row.command !== "load_model" || row.args_type !== "object" || row.target_type !== "string" || row.model_type !== "string") fail("protocol");
    if (typeof row.id !== "string" || !/^cmd-[0-9a-f]{24}$/.test(row.id) || typeof row.idempotency_key !== "string" || row.idempotency_key.length < 1 || row.idempotency_key.length > 512) fail("protocol");
    if (typeof row.node_id !== "string" || row.node_id.length < 1 || row.node_id.length > 128 || /[\u0000-\u001f]/.test(row.node_id)) fail("protocol");
    if (typeof row.target_id !== "string" || row.target_id.length < 1 || row.target_id.length > 512 || typeof row.model !== "string" || row.model.length < 1 || row.model.length > 512) fail("protocol");
    for (const key of ["created_at", "expires_at", "body_created_at", "body_expires_at", "completed_at"]) if (typeof row[key] !== "string" || row[key].length > 64) fail("protocol");
    for (const key of ["sent_at", "last_sent_at", "body_sent_at", "body_last_sent_at", "body_completed_at"]) if (row[key] !== null && (typeof row[key] !== "string" || row[key].length > 64)) fail("protocol");
    for (const key of ["body_id", "body_node_id", "body_idempotency_key", "body_status"]) if (typeof row[key] !== "string") fail("protocol");
    if (typeof row.body_result_present !== "boolean") fail("protocol");
    if (row.id !== row.body_id || row.node_id !== row.body_node_id || row.idempotency_key !== row.body_idempotency_key || row.status !== row.body_status) fail("protocol");
    if (ids.has(row.id) || keysSeen.has(row.idempotency_key)) fail("protocol");
    ids.add(row.id); keysSeen.add(row.idempotency_key);
  }
  return Object.freeze({
    nonce,
    expiredTotal: value.expired_total,
    selected: value.load_model_total,
    rows: value.rows,
  });
}

function projectAggregate(line, nonce, expiredTotal, selected) {
  validateNonce(nonce);
  if (!Number.isSafeInteger(expiredTotal) || expiredTotal < 0 || expiredTotal !== selected) fail("protocol");
  const value = parseStrictJson(line);
  if (!value || value.schema !== WIRE_SCHEMA || value.nonce !== nonce || value.authoritative_outcome !== false ||
      value.permission_to_restart !== false || value.command_history_changed !== false) fail("protocol");
  if (value.stage !== "ok") {
    const failureKeys = ["schema", "nonce", "stage", "authoritative_outcome", "permission_to_restart", "command_history_changed"];
    if (!exactObject(value, failureKeys)) fail("protocol");
    fail(safeStage(value.stage, CT_FAILURES));
  }
  const keys = ["schema", "nonce", "stage", "counts", "cache_custody_unchanged", "original_custody_unchanged", "database_timestamp_precision_limited", "authoritative_outcome", "permission_to_restart", "command_history_changed"];
  if (!exactObject(value, keys) || value.database_timestamp_precision_limited !== true || value.cache_custody_unchanged !== true || value.original_custody_unchanged !== true || !exactObject(value.counts, COUNT_KEYS)) fail("protocol");
  const counts = {};
  for (const key of COUNT_KEYS) {
    const n = value.counts[key];
    const maximum = key === "cache_invalid_entries" ? 100000 : 32;
    if (!Number.isSafeInteger(n) || n < 0 || n > maximum) fail("protocol");
    counts[key] = n;
  }
  if (counts.selected !== selected) fail("protocol");
  const failureTotal = counts.validation_refusal + counts.catalog_refusal + counts.lifecycle_unsupported + counts.unknown_failure;
  const temporalTotal = counts.time_binding_unknown + counts.completed_before_expiry + counts.completed_at_expiry + counts.completed_after_expiry;
  const unmatched = counts.missing + counts.mismatched + counts.malformed;
  const residual = counts.selected - unmatched - counts.matched_pairs;
  if (counts.ok_true + counts.ok_false !== counts.matched_pairs || failureTotal !== counts.ok_false ||
      temporalTotal !== counts.matched_pairs || residual < 0 || residual > counts.outcome_unknown ||
      counts.outcome_unknown > residual + counts.matched_pairs || counts.result_mismatch > counts.ok_true ||
      counts.result_mismatch > counts.matched_pairs - counts.time_binding_unknown) fail("protocol");
  return Object.freeze({
    schema: OUTPUT_SCHEMA,
    scope: "expired_command_cache_linkage_readonly",
    counts: Object.freeze({ expired_total: expiredTotal, ...counts }),
    read_only: true,
    original_custody_unchanged: true,
    cache_custody_unchanged: true,
    database_timestamp_precision_limited: true,
    authoritative_outcome: false,
    permission_to_restart: false,
    command_history_changed: false,
  });
}

/** Narrow pure seams: no path, target, environment, command, or operation injection. */
export function _validateRowsForTest(line, nonce) { return validateRowsEnvelope(line, nonce); }
export function _projectAggregateForTest(line, nonce, expiredTotal, selected) { return projectAggregate(line, nonce, expiredTotal, selected); }
export function _parseStrictJsonForTest(line) { return parseStrictJson(line); }
export function _lbCompositionFixtureForTest() {
  const receiver = stableReceiver();
  const helper = verifiedHelperSource();
  return Object.freeze({ nonce: "0123456789abcdef0123456789abcdef", command: fixedLbCommand("0123456789abcdef0123456789abcdef"),
    input: Buffer.concat([receiver, helper]) });
}
export function _ctCompositionFixtureForTest() {
  const helper = verifiedHelperSource();
  const nonce = "0123456789abcdef0123456789abcdef";
  const wire = buildCtInput(nonce, [{ id: "cmd-111111111111111111111111", node_id: "fixture-ct-node" }]);
  const command = pythonRemoteCommand();
  return Object.freeze({ nonce, command, args: fixedSshArgs(PVE_HOST, PVE_KEY, command),
    helperBytes: helper.length, wire: Buffer.from(wire), input: Buffer.concat([helper, wire]) });
}
export function validateProbeCli(args) {
  if (!Array.isArray(args) || args.length !== 1 || args[0] !== "--probe") fail("cli");
  return true;
}

async function runProbe() {
  const deadline = process.hrtime.bigint() + BigInt(SESSION_TIMEOUT_MS) * 1000000n;
  let custodyCheck;
  try {
    custodyCheck = verifyFixedToolAndCredentials();
    const receiver = stableReceiver();
    if (receiver.length !== RECEIVER_BYTES || sha(receiver) !== RECEIVER_SHA256) fail("local_custody");
    const helper = verifiedHelperSource();
    const nonce = crypto.randomBytes(16).toString("hex");
    const invocation = Buffer.concat([receiver, helper]);
    if (invocation.length > MAX_WIRE * 2) fail("local_custody");
    const lbCommand = fixedLbCommand(nonce);
    let lb;
    try { lb = spawnFixed(LB_HOST, LB_KEY, lbCommand, invocation, deadline); }
    finally { custodyCheck(); }
    const selected = validateRowsEnvelope(lb.stdout, nonce);
    if (lb.status !== 0) fail("protocol");
    const ctProgram = verifiedHelperSource();
    const ctCommand = pythonRemoteCommand();
    const ctWire = buildCtInput(nonce, selected.rows);
    const ctInput = Buffer.concat([ctProgram, ctWire]);
    let ct;
    try { ct = spawnFixed(PVE_HOST, PVE_KEY, ctCommand, ctInput, deadline); }
    finally { custodyCheck(); }
    const output = projectAggregate(ct.stdout, nonce, selected.expiredTotal, selected.selected);
    if (ct.status !== 0) fail("protocol");
    custodyCheck();
    return output;
  } catch (error) {
    if (error instanceof EvidenceFailure) throw error;
    throw new EvidenceFailure("unknown");
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    validateProbeCli(process.argv.slice(2));
    const result = await runProbe();
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch (error) {
    const stage = error instanceof EvidenceFailure ? error.stage : "unknown";
    process.stderr.write(`fixed expired command evidence failed closed: stage=${stage}\n`);
    process.exitCode = 1;
  }
}
