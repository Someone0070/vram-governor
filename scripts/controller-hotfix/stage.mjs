import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  CA_SHA256, CONFIG_BYTES, CONFIG_SHA256, IMAGE_BYTES,
  IMAGE_SHA256, MANIFEST_SHA256, ORIGINAL_SHA256, ORIGINAL_BYTES,
  validateLocalRoot,
} from "./verify-stage.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SSH_HOST = "10.0.0.115";
const SSH_KEY = "C:/Users/Sasha/.ssh/lb_proxy_deploy";
const SSH_EXE = "C:/Windows/System32/OpenSSH/ssh.exe";
const KNOWN_HOSTS = "C:/Users/Sasha/.ssh/known_hosts";
const SSH_TIMEOUT_MS = 120000;
const MAX_STDOUT = 128 * 1024;
const MAX_STDERR = 16 * 1024;
const RECEIVER_BYTES = 37531;
const RECEIVER_SHA256 = "06de3473816e380fb8bf2c019ec452bdcf3739ee383546d1011d27aa7053d355";
const BOOTSTRAP = `import sys,hashlib,re\nnl=sys.stdin.buffer.readline(33)\nif not nl.endswith(b'\\n') or len(nl)>32: raise SystemExit(91)\nnraw=nl[:-1]\nif not nraw or not nraw.isdigit() or (len(nraw)>1 and nraw.startswith(b'0')): raise SystemExit(91)\nn=int(nraw)\nif n!=${RECEIVER_BYTES} or n>1048576: raise SystemExit(91)\nhl=sys.stdin.buffer.readline(66)\nif re.fullmatch(b'[0-9a-f]{64}\\n',hl) is None: raise SystemExit(92)\nh=hl[:-1].decode('ascii')\ns=sys.stdin.buffer.read(n)\nif len(s)!=n or hashlib.sha256(s).hexdigest()!=h: raise SystemExit(92)\nif h!='${RECEIVER_SHA256}': raise SystemExit(93)\nexec(compile(s,'<fixed-controller-stage-receiver>','exec'),{'__name__':'__main__'})\n`;

function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function shellQuote(value) { return `'${String(value).replaceAll("'", "'\\''")}'`; }
function fixedCandidateRoot() { return path.join(ROOT, ".cache", "controller-transport-hotfix", "candidate-20261005061320-3038c0fb3451"); }
function receiverPath() { return path.join(path.dirname(fileURLToPath(import.meta.url)), "stage.py"); }

function stableReceiverSource() {
  const filename = path.resolve(receiverPath());
  const parsed = path.parse(filename); let cursor = parsed.root;
  for (const part of filename.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    const ancestor = fs.lstatSync(cursor);
    if (ancestor.isSymbolicLink() || (cursor !== filename && !ancestor.isDirectory())) throw new Error("receiver_source_custody");
  }
  const before = fs.lstatSync(filename);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size !== RECEIVER_BYTES) throw new Error("receiver_source_bound");
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.size !== RECEIVER_BYTES || opened.dev !== before.dev || opened.ino !== before.ino) throw new Error("receiver_source_identity");
    const bytes = Buffer.alloc(RECEIVER_BYTES); let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, null);
      if (count <= 0) throw new Error("receiver_source_short");
      offset += count;
    }
    const extra = Buffer.alloc(1);
    if (fs.readSync(fd, extra, 0, 1, null) !== 0) throw new Error("receiver_source_grew");
    const after = fs.fstatSync(fd); const named = fs.lstatSync(filename);
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || named.isSymbolicLink() || named.nlink !== 1 || named.dev !== before.dev || named.ino !== before.ino || named.size !== before.size || named.mtimeMs !== before.mtimeMs || named.ctimeMs !== before.ctimeMs || sha256(bytes) !== RECEIVER_SHA256) throw new Error("receiver_source_identity");
    return bytes;
  } finally { fs.closeSync(fd); }
}

function makeRequest(operation, nonce) {
  const value = operation === "stage"
    ? { schema: "controller-stage-request-v1", operation, nonce, manifest_sha256: MANIFEST_SHA256, image_sha256: IMAGE_SHA256, image_bytes: IMAGE_BYTES }
    : { schema: "controller-stage-request-v1", operation, nonce };
  return Buffer.from(`${JSON.stringify(value)}\n`, "ascii");
}

export function parseSafeResponse(bytes) {
  let value;
  try { value = JSON.parse(bytes.toString("ascii")); } catch { throw new Error("receiver_response_invalid"); }
  if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.ok !== "boolean") throw new Error("receiver_response_invalid");
  if (value.ok === false) {
    if (Object.keys(value).sort().join(",") !== "code,ok" || typeof value.code !== "string" || !/^[a-z_]{1,48}$/.test(value.code)) throw new Error("receiver_response_invalid");
    throw new Error(`receiver_${value.code}`);
  }
  if (Object.keys(value).sort().join(",") !== "ok,receipt" || !value.receipt || typeof value.receipt !== "object") throw new Error("receiver_response_invalid");
  const receipt = value.receipt;
  if (receipt.activationApproved !== false || !/^[a-f0-9]{32}$/.test(receipt.nonce || "") || receipt.candidate_sha256 !== IMAGE_SHA256 || receipt.original_sha256 !== ORIGINAL_SHA256 || receipt.manifest_sha256 !== MANIFEST_SHA256 || receipt.config_sha256 !== CONFIG_SHA256 || receipt.ca_sha256 !== CA_SHA256 || receipt.check_config_success !== true || receipt.check_config_exit !== 0) throw new Error("receiver_receipt_invalid");
  return receipt;
}

function invokeRemote(operation, nonce, image) {
  const receiver = stableReceiverSource();
  const request = makeRequest(operation, nonce);
  const prelude = Buffer.from(`${receiver.length}\n${RECEIVER_SHA256}\n`, "ascii");
  const command = `exec /usr/bin/python3 -I -B -c ${shellQuote(BOOTSTRAP)}`;
  const args = ["-F", "none", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=yes", "-o", `UserKnownHostsFile=${KNOWN_HOSTS}`, "-o", `HostName=${SSH_HOST}`, "-o", "PermitLocalCommand=no", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "CanonicalizeHostname=no", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", SSH_KEY, `root@${SSH_HOST}`, command];
  return new Promise((resolve, reject) => {
    const child = spawn(SSH_EXE, args, { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    const stdout = []; const stderr = []; let outBytes = 0; let errBytes = 0; let settled = false;
    const stop = (error) => { if (settled) return; settled = true; clearTimeout(timer); try { child.kill(); } catch {} reject(error); };
    const timer = setTimeout(() => stop(new Error("ssh_timeout")), SSH_TIMEOUT_MS);
    child.stdout.on("data", (chunk) => { outBytes += chunk.length; if (outBytes > MAX_STDOUT) return stop(new Error("ssh_stdout_bound")); stdout.push(chunk); });
    child.stderr.on("data", (chunk) => { errBytes += chunk.length; if (errBytes > MAX_STDERR) return stop(new Error("ssh_stderr_bound")); stderr.push(chunk); });
    child.on("error", () => stop(new Error("ssh_spawn")));
    child.on("close", (code) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (code !== 0) return reject(new Error(`ssh_exit_${Number.isInteger(code) ? code : "unknown"}`));
      try { resolve(parseSafeResponse(Buffer.concat(stdout))); } catch (error) { reject(error); }
    });
    child.stdin.on("error", () => { /* A close/error is classified by the child exit path. */ });
    child.stdin.write(prelude);
    child.stdin.write(receiver);
    child.stdin.write(request);
    if (image) child.stdin.write(image);
    child.stdin.end();
  });
}

function validateReceipt(receipt, nonce) {
  if (receipt.nonce !== nonce || receipt.candidate_bytes !== IMAGE_BYTES || receipt.original_bytes !== ORIGINAL_BYTES || receipt.config_bytes !== CONFIG_BYTES || receipt.ca_bytes !== 1484 || receipt.activationApproved !== false || !Number.isInteger(receipt.pid) || receipt.pid < 2 || typeof receipt.invocation !== "string" || !/^[0-9a-f]{32}$/.test(receipt.invocation) || typeof receipt.start_ticks !== "string" || !/^\d+$/.test(receipt.start_ticks)) throw new Error("receipt_fields_invalid");
  const keys = Object.keys(receipt).sort().join(",");
  const expected = ["activationApproved", "ca_bytes", "ca_sha256", "candidate_bytes", "candidate_sha256", "check_config_exit", "check_config_success", "config_bytes", "config_sha256", "dropins", "image_dev", "image_ino", "invocation", "manifest_sha256", "nonce", "original_bytes", "original_sha256", "pid", "process_dev", "process_ino", "schema", "start_ticks", "unit_sha256"].sort().join(",");
  if (keys !== expected || receipt.schema !== "controller-stage-receipt-v1" || !receipt.dropins || typeof receipt.dropins !== "object" || Array.isArray(receipt.dropins)) throw new Error("receipt_fields_invalid");
  if (![receipt.process_dev, receipt.process_ino, receipt.image_dev, receipt.image_ino].every((value) => Number.isSafeInteger(value) && value >= 0) || !/^[a-f0-9]{64}$/.test(receipt.unit_sha256)) throw new Error("receipt_fields_invalid");
  if (Object.keys(receipt.dropins).join(",") !== "artifact-store.conf") throw new Error("receipt_fields_invalid");
  const dropin = receipt.dropins["artifact-store.conf"];
  if (!dropin || Object.keys(dropin).sort().join(",") !== "bytes,sha256" || !Number.isInteger(dropin.bytes) || dropin.bytes < 0 || dropin.bytes > 256 * 1024 || !/^[a-f0-9]{64}$/.test(dropin.sha256)) throw new Error("receipt_fields_invalid");
  return receipt;
}

export async function stageCandidate() {
  const candidate = validateLocalRoot(fixedCandidateRoot());
  const nonce = crypto.randomBytes(16).toString("hex");
  const receipt = validateReceipt(await invokeRemote("stage", nonce, candidate.binaryBytes), nonce);
  process.stdout.write(`private controller staging recorded: nonce=${nonce}; candidate_sha256=${IMAGE_SHA256}; original_sha256=${ORIGINAL_SHA256}; activationApproved=false\n`);
  return receipt;
}

export async function inspectStage(nonce) {
  if (!/^[a-f0-9]{32}$/.test(nonce)) throw new Error("inspect_nonce_invalid");
  const receipt = validateReceipt(await invokeRemote("inspect", nonce, null), nonce);
  process.stdout.write(`private controller staging inspected: nonce=${nonce}; candidate_sha256=${IMAGE_SHA256}; original_sha256=${ORIGINAL_SHA256}; activationApproved=false\n`);
  return receipt;
}

export function parseCli(argv) {
  if (argv.length === 1 && argv[0] === "--stage") return { operation: "stage" };
  if (argv.length === 2 && argv[0] === "--inspect" && /^[a-f0-9]{32}$/.test(argv[1])) return { operation: "inspect", nonce: argv[1] };
  throw new Error("invalid_cli");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const command = parseCli(process.argv.slice(2));
    if (command.operation === "stage") await stageCandidate();
    else await inspectStage(command.nonce);
  } catch {
    process.stderr.write("controller staging operation failed closed\n");
    process.exitCode = 1;
  }
}
