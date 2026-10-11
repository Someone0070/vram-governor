import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SSH_HOST = "10.0.0.115";
const SSH_KEY = "C:/Users/Sasha/.ssh/lb_proxy_deploy";
const SSH_EXE = "C:/Windows/System32/OpenSSH/ssh.exe";
const KNOWN_HOSTS = "C:/Users/Sasha/.ssh/known_hosts";
const SSH_TIMEOUT_MS = 120000;
const MAX_STDOUT = 64 * 1024;
const MAX_STDERR = 16 * 1024;
const STAGE_BYTES = 37531;
const STAGE_SHA256 = "9284118f8c6f9723e09cc36219defd11a74710bf91685fcede84e6bf2d3af220";
const RECEIVER_BYTES = 37660;
const RECEIVER_SHA256 = "d09f05e09cecf0b31fcc447cc38ef374fe2448d8b3ed3fa255e979507f0af21f";
const CONFIG_BYTES = 6758;
const CONFIG_SHA256 = "22307f4535286ac56d6ee08b62b5febd8f2e1c6af6e525cbaa8a8b47852ddda0";
const NEW_CONFIG_BYTES = 6789;
const NEW_CONFIG_SHA256 = "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37";
const ORIGINAL_BYTES = 12976280;
const ORIGINAL_SHA256 = "ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c";
const CA_BYTES = 1484;
const CA_SHA256 = "ddc7359a3f730b1817c7adff7ede84439bdf31cc56ff7cf658142473042c1944";
const RECEIPT_KEYS = ["activationApproved", "config_gid", "config_mode", "config_uid", "image_dev", "image_ino", "invocation", "new_bytes", "new_config_dev", "new_config_ino", "new_sha256", "nonce", "old_backup_dev", "old_backup_ino", "old_bytes", "old_config_dev", "old_config_ino", "old_sha256", "pid", "process_dev", "process_ino", "runtimeConfigReloaded", "schema", "start_ticks"];
const RECEIVER_CODES = new Set(["request_frame", "request_json", "request_schema", "request_operation", "request_nonce", "request_fields", "deadline", "config_identity", "config_yaml", "target_missing", "target_ambiguous", "target_binding", "target_capacity_present", "config_transform", "path_custody", "file_custody", "file_size", "file_digest", "file_open", "file_identity", "file_changed", "service_identity", "service_changed", "image_identity", "ca_identity", "backup_parent", "backup_quota", "backup_exists", "backup_receipt", "backup_content", "backup_directory", "lock_exists", "lock_create", "config_changed", "temp_create", "temp_write", "temp_custody", "replace_failed", "post_replace_identity", "inspect_nonce", "inspect_missing", "inspect_service", "inspect_current", "inspect_original_service", "inspect_backup", "inspect_shape", "inspect_directory", "inspect_lock", "live_custody_changed", "operation_failed"]);
const LOCAL_ERROR_CODES = new Set(["source_custody", "source_bound", "source_identity", "source_short", "source_grew", "response_invalid", "receipt_invalid", "ssh_timeout", "ssh_stdout_bound", "ssh_stderr_bound", "ssh_spawn", "ssh_exit_unknown", "invalid_cli", "nonce_invalid", "operation_failed"]);
const BOOTSTRAP = `import sys,hashlib,json,types
def read_exact(n):
 if type(n) is not int or n<0 or n>1048576: raise SystemExit(91)
 out=[]
 while n:
  b=sys.stdin.buffer.read(min(n,65536))
  if not b: raise SystemExit(91)
  out.append(b); n-=len(b)
 return b''.join(out)
line=sys.stdin.buffer.readline(4097)
try: h=json.loads(line.decode('ascii'))
except Exception: raise SystemExit(91)
if type(h) is not dict or set(h)!={'stage_bytes','stage_sha256','receiver_bytes','receiver_sha256'}: raise SystemExit(91)
if json.dumps(h,sort_keys=True,separators=(',',':')).encode('ascii')+b'\\n'!=line: raise SystemExit(91)
if h['stage_bytes']!=${STAGE_BYTES} or h['stage_sha256']!='${STAGE_SHA256}' or h['receiver_bytes']!=${RECEIVER_BYTES} or h['receiver_sha256']!='${RECEIVER_SHA256}': raise SystemExit(92)
stage=read_exact(h['stage_bytes']); receiver=read_exact(h['receiver_bytes'])
if hashlib.sha256(stage).hexdigest()!=h['stage_sha256'] or hashlib.sha256(receiver).hexdigest()!=h['receiver_sha256']: raise SystemExit(92)
m=types.ModuleType('capacity_config_stage'); m.__file__='<pinned-controller-stage-helper>'
exec(compile(stage,m.__file__,'exec'),m.__dict__); sys.modules[m.__name__]=m
g={'__name__':'__main__','capacity_config_stage':m}
exec(compile(receiver,'<fixed-capacity-config-receiver>','exec'),g)
`;

function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function shellQuote(value) { return `'${String(value).replaceAll("'", "'\\''")}'`; }
function sourcePath(name) { return path.join(HERE, name); }
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

function stableSource(name, expectedBytes, expectedHash) {
  const filename = path.resolve(sourcePath(name));
  const parsed = path.parse(filename); let cursor = parsed.root;
  for (const part of filename.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    const info = fs.lstatSync(cursor);
    if (info.isSymbolicLink() || (cursor !== filename && !info.isDirectory())) throw new Error("source_custody");
  }
  const before = fs.lstatSync(filename);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size !== expectedBytes) throw new Error("source_bound");
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.size !== expectedBytes || opened.dev !== before.dev || opened.ino !== before.ino) throw new Error("source_identity");
    const bytes = Buffer.alloc(expectedBytes); let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, null);
      if (count <= 0) throw new Error("source_short");
      offset += count;
    }
    const extra = Buffer.alloc(1);
    if (fs.readSync(fd, extra, 0, 1, null) !== 0) throw new Error("source_grew");
    const after = fs.fstatSync(fd); const named = fs.lstatSync(filename);
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || named.isSymbolicLink() || named.nlink !== 1 || named.dev !== before.dev || named.ino !== before.ino || named.size !== before.size || named.mtimeMs !== before.mtimeMs || named.ctimeMs !== before.ctimeMs || sha256(bytes) !== expectedHash) throw new Error("source_identity");
    return bytes;
  } finally { fs.closeSync(fd); }
}

export function parseSafeResponse(bytes, nonce, operation) {
  let value;
  try {
    const text = bytes.toString("ascii");
    value = JSON.parse(text);
    if (!text.endsWith("\n") || Buffer.from(`${canonicalJson(value)}\n`, "ascii").compare(bytes) !== 0) throw new Error("response_invalid");
  } catch { throw new Error("response_invalid"); }
  if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.ok !== "boolean") throw new Error("response_invalid");
  if (!value.ok) {
    if (Object.keys(value).sort().join(",") !== "code,ok,replacement" || typeof value.code !== "string" || !RECEIVER_CODES.has(value.code) || !["not_applied", "unknown", "confirmed"].includes(value.replacement)) throw new Error("response_invalid");
    throw new Error(`receiver_${value.code}_${value.replacement}`);
  }
  if (Object.keys(value).sort().join(",") !== "ok,receipt" || !value.receipt || typeof value.receipt !== "object" || Array.isArray(value.receipt)) throw new Error("response_invalid");
  const receipt = value.receipt;
  if (Object.keys(receipt).sort().join(",") !== [...RECEIPT_KEYS].sort().join(",") || receipt.schema !== "controller-capacity-config-receipt-v1" || receipt.nonce !== nonce || receipt.activationApproved !== false || receipt.runtimeConfigReloaded !== false || receipt.old_sha256 !== CONFIG_SHA256 || receipt.old_bytes !== CONFIG_BYTES || receipt.new_sha256 !== NEW_CONFIG_SHA256 || receipt.new_bytes !== NEW_CONFIG_BYTES || !/^[a-f0-9]{32}$/.test(receipt.invocation || "") || !/^\d+$/.test(receipt.start_ticks || "")) throw new Error("receipt_invalid");
  if (![receipt.pid, receipt.old_config_dev, receipt.old_config_ino, receipt.config_uid, receipt.config_gid, receipt.config_mode, receipt.old_backup_dev, receipt.old_backup_ino, receipt.new_config_dev, receipt.new_config_ino, receipt.process_dev, receipt.process_ino, receipt.image_dev, receipt.image_ino].every((item) => Number.isSafeInteger(item) && item >= 0) || receipt.pid <= 1 || receipt.config_uid !== 0 || receipt.config_gid !== 990 || receipt.config_mode !== 0o640) throw new Error("receipt_invalid");
  if (operation === "apply" && receipt.new_sha256 !== NEW_CONFIG_SHA256) throw new Error("receipt_invalid");
  return receipt;
}

export function safeErrorCode(error) {
  const code = error instanceof Error ? error.message : "";
  for (const receiverCode of RECEIVER_CODES) {
    for (const state of ["not_applied", "unknown", "confirmed"]) {
      if (code === `receiver_${receiverCode}_${state}`) return code;
    }
  }
  return LOCAL_ERROR_CODES.has(code) || /^ssh_exit_(?:[0-9]{1,3}|unknown)$/.test(code) ? code : "operation_failed";
}

function invokeRemote(operation, nonce) {
  const stageSource = stableSource("stage.py", STAGE_BYTES, STAGE_SHA256);
  const receiverSource = stableSource("capacity-config.py", RECEIVER_BYTES, RECEIVER_SHA256);
  const header = Buffer.from(`{"receiver_bytes":${RECEIVER_BYTES},"receiver_sha256":"${RECEIVER_SHA256}","stage_bytes":${STAGE_BYTES},"stage_sha256":"${STAGE_SHA256}"}\n`, "ascii");
  const request = Buffer.from(`${JSON.stringify({ schema: "controller-capacity-config-request-v1", operation, nonce })}\n`, "ascii");
  const remote = `exec /usr/bin/python3 -I -B -c ${shellQuote(BOOTSTRAP)}`;
  const args = ["-F", "none", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=yes", "-o", `UserKnownHostsFile=${KNOWN_HOSTS}`, "-o", `HostName=${SSH_HOST}`, "-o", "PermitLocalCommand=no", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "CanonicalizeHostname=no", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", SSH_KEY, `root@${SSH_HOST}`, remote];
  return new Promise((resolve, reject) => {
    const child = spawn(SSH_EXE, args, { windowsHide: true, cwd: "C:/Windows/System32", stdio: ["pipe", "pipe", "pipe"] });
    const stdout = []; let outBytes = 0; let errBytes = 0; let settled = false;
    const stop = (code) => { if (settled) return; settled = true; clearTimeout(timer); try { child.kill(); } catch {} reject(new Error(code)); };
    const timer = setTimeout(() => stop("ssh_timeout"), SSH_TIMEOUT_MS);
    child.stdout.on("data", (chunk) => { outBytes += chunk.length; if (outBytes > MAX_STDOUT) return stop("ssh_stdout_bound"); stdout.push(chunk); });
    child.stderr.on("data", (chunk) => { errBytes += chunk.length; if (errBytes > MAX_STDERR) return stop("ssh_stderr_bound"); });
    child.on("error", () => stop("ssh_spawn"));
    child.on("close", (code) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (code !== 0) return reject(new Error(`ssh_exit_${Number.isInteger(code) ? code : "unknown"}`));
      try { resolve(parseSafeResponse(Buffer.concat(stdout), nonce, operation)); } catch (error) { reject(error); }
    });
    child.stdin.on("error", () => {});
    child.stdin.write(header); child.stdin.write(stageSource); child.stdin.write(receiverSource); child.stdin.write(request); child.stdin.end();
  });
}

export function parseCli(argv) {
  if (argv.length === 1 && argv[0] === "--apply") return { operation: "apply" };
  if (argv.length === 2 && argv[0] === "--inspect" && /^[a-f0-9]{32}$/.test(argv[1])) return { operation: "inspect", nonce: argv[1] };
  throw new Error("invalid_cli");
}

export async function run(operation, suppliedNonce) {
  const nonce = operation === "apply" ? crypto.randomBytes(16).toString("hex") : suppliedNonce;
  if (!/^[a-f0-9]{32}$/.test(nonce)) throw new Error("nonce_invalid");
  if (operation === "apply") process.stdout.write(`capacity config repair nonce=${nonce}; replacement not yet confirmed\n`);
  const receipt = await invokeRemote(operation, nonce);
  process.stdout.write(`capacity config ${operation === "apply" ? "applied" : "inspected"}: nonce=${nonce}; old_sha256=${CONFIG_SHA256}; new_sha256=${NEW_CONFIG_SHA256}; new_bytes=${NEW_CONFIG_BYTES}; activationApproved=false; runtimeConfigReloaded=false\n`);
  return receipt;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const command = parseCli(process.argv.slice(2));
    await run(command.operation, command.nonce);
  } catch (error) {
    const code = safeErrorCode(error);
    process.stderr.write(`capacity config operation failed closed: ${code}\n`);
    process.exitCode = 1;
  }
}
