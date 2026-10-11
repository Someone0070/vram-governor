import crypto from "node:crypto";
import fs from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  FIXED_SSH_TOOL_BYTES,
  FIXED_SSH_TOOL_SHA256,
  _fixedSshToolForTest,
} from "../controller-hotfix/command-fence.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RECEIVER_PATH = path.join(HERE, "prepare-tools.py");
export const RECEIVER_BYTES = 21812;
export const RECEIVER_SHA256 = "599cbf8435dbe30a9df85ecd406a4552bceab5e4769b2bc7eecca283c57e573d";
const SESSION_MS = 225_000;
const MAX_STDOUT = 4096;
const MAX_STDERR = 8192;
const SSH = "C:/Windows/System32/OpenSSH/ssh.exe";
const SSH_WINSXS = "C:/Windows/WinSxS/amd64_openssh-client-components-onecore_31bf3856ad364e35_10.0.26100.9549_none_9bb78eedccaa8631/ssh.exe";
const SSH_PATHS = Object.freeze([SSH, SSH_WINSXS]);
const SSH_KEY = "C:/Users/Sasha/.ssh/cmp170_proxmox";
const KNOWN_HOSTS = "C:/Users/Sasha/.ssh/known_hosts";
const HOST = "10.0.0.3";
const PYTHON = "/usr/bin/python3";
const TERMINAL = "CT200_TOOLS_STAGED";
const FAILURE_TERMINAL = "CT200_TOOLS_FAILED";

function fail(code) { throw new Error(code); }
function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}
function positiveInteger(value, max) { return Number.isSafeInteger(value) && value > 0 && value <= max; }

export function verifyFixedSshBytes(bytes, expected = { bytes: FIXED_SSH_TOOL_BYTES, sha256: FIXED_SSH_TOOL_SHA256 }) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== expected.bytes || sha256(bytes) !== expected.sha256) fail("fixed SSH bytes differ");
  return bytes;
}

export function posixQuote(value) {
  if (typeof value !== "string" || value.length > 128 * 1024 || value.includes("\0")) fail("fixed command invalid");
  return "'" + value.replace(/'/g, "'\\''") + "'";
}

export function buildBootstrap(sourceBytes) {
  if (!Buffer.isBuffer(sourceBytes) || sourceBytes.length !== RECEIVER_BYTES || sha256(sourceBytes) !== RECEIVER_SHA256) fail("receiver source pin failed");
  const sourceHash = RECEIVER_SHA256;
  return [
    "import sys,os,hashlib,re,time",
    "import signal",
    "deadline=time.monotonic()+215",
    "signal.setitimer(signal.ITIMER_REAL,215)",
    "def exact(n):",
    " b=bytearray()",
    " while len(b)<n:",
    "  x=os.read(0,n-len(b))",
    "  if not x: break",
    "  b.extend(x)",
    " return bytes(b)",
    "def line(limit):",
    " b=bytearray()",
    " while len(b)<limit:",
    "  x=os.read(0,1)",
    "  if not x: break",
    "  b.extend(x)",
    "  if x==b'\\n': break",
    " return bytes(b)",
    "n=line(16)",
    "h=line(66)",
    `if not re.fullmatch(b'(?:[1-9][0-9]{0,6})\\n',n) or int(n)!=${RECEIVER_BYTES}: raise SystemExit(91)`,
    `if h!=b'${sourceHash}\\n': raise SystemExit(92)`,
    `s=exact(${RECEIVER_BYTES})`,
    `if len(s)!=${RECEIVER_BYTES} or hashlib.sha256(s).hexdigest()!= '${sourceHash}': raise SystemExit(93)`,
    `exec(compile(s,'<ct200-private-tool-stager>','exec'),{'__name__':'__main__','_bootstrap_deadline':deadline})`,
  ].join("\n");
}

function fixedSshArgs(remoteCommand) {
  return [
    "-F", "none", "-T",
    "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
    "-o", "StrictHostKeyChecking=yes", "-o", `UserKnownHostsFile=${KNOWN_HOSTS}`, "-o", "GlobalKnownHostsFile=none", "-o", `HostName=${HOST}`,
    "-o", "PermitLocalCommand=no", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no", "-o", "ForwardX11Trusted=no", "-o", "Tunnel=no", "-o", "UpdateHostKeys=no",
    "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ControlMaster=no", "-o", "ControlPath=none",
    "-o", "CanonicalizeHostname=no", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
    "-i", SSH_KEY, `root@${HOST}`, remoteCommand,
  ];
}

function checkLocalCustody(filename) {
  const absolute = path.resolve(filename);
  let cursor = path.parse(absolute).root;
  for (const part of absolute.slice(cursor.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    const stat = fs.lstatSync(cursor, { bigint: true });
    if (stat.isSymbolicLink() || (cursor !== absolute && !stat.isDirectory())) fail("local SSH path custody failed");
  }
}

function fixedLocalRegular(filename, label) {
  checkLocalCustody(filename);
  const info = fs.lstatSync(filename, { bigint: true });
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n) fail(`${label} custody failed`);
}

function readFixedSsh() {
  const snapshots = SSH_PATHS.map((name) => {
    checkLocalCustody(name);
    const stat = fs.lstatSync(name, { bigint: true });
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 2n || stat.size !== BigInt(FIXED_SSH_TOOL_BYTES)) fail("fixed SSH metadata differs");
    return stat;
  });
  if (snapshots[0].dev !== snapshots[1].dev || snapshots[0].ino !== snapshots[1].ino) fail("fixed SSH hardlink differs");
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  const fds = [];
  try {
    for (let i = 0; i < SSH_PATHS.length; i++) {
      const fd = fs.openSync(SSH_PATHS[i], flags); fds.push(fd);
      const opened = fs.fstatSync(fd, { bigint: true });
      for (const key of ["dev", "ino", "mode", "nlink", "uid", "gid", "size", "mtimeNs", "ctimeNs"]) if (opened[key] !== snapshots[i][key]) fail("fixed SSH open metadata differs");
    }
    const chunks = []; let total = 0;
    while (total < FIXED_SSH_TOOL_BYTES) {
      const buffer = Buffer.alloc(Math.min(65536, FIXED_SSH_TOOL_BYTES - total));
      const n = fs.readSync(fds[0], buffer, 0, buffer.length, null);
      if (n <= 0) fail("fixed SSH short read");
      chunks.push(buffer.subarray(0, n)); total += n;
    }
    const extra = Buffer.alloc(1);
    if (fs.readSync(fds[0], extra, 0, 1, null) !== 0) fail("fixed SSH grew");
    for (let i = 0; i < SSH_PATHS.length; i++) {
      const opened = fs.fstatSync(fds[i], { bigint: true });
      checkLocalCustody(SSH_PATHS[i]);
      const named = fs.lstatSync(SSH_PATHS[i], { bigint: true });
      for (const key of ["dev", "ino", "mode", "nlink", "uid", "gid", "size", "mtimeNs", "ctimeNs"]) if (opened[key] !== snapshots[i][key] || named[key] !== snapshots[i][key]) fail("fixed SSH changed during read");
    }
    const bytes = Buffer.concat(chunks);
    verifyFixedSshBytes(bytes);
    const fencedBytes = _fixedSshToolForTest(fs, bytes);
    if (!fencedBytes.equals(bytes)) fail("fixed SSH fence bytes differ");
    return bytes;
  } finally {
    for (const fd of fds) fs.closeSync(fd);
  }
}

function nowMs() { return Number(process.hrtime.bigint() / 1_000_000n); }
function remaining(deadline) { const n = deadline - nowMs(); if (n <= 0) fail("preparation deadline expired"); return n; }

function runFixedSsh(sshBytes, sourceBytes, deadline) {
  verifyFixedSshBytes(sshBytes);
  const bootstrap = buildBootstrap(sourceBytes);
  const remote = `/usr/sbin/pct exec 200 -- ${PYTHON} -I -B -c ${posixQuote(bootstrap)}`;
  const child = spawn(SSH, fixedSshArgs(remote), {
    cwd: HERE,
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
    env: { SystemRoot: "C:/Windows", WINDIR: "C:/Windows", ProgramData: "C:/ProgramData", PATH: "C:/Windows/System32;C:/Windows", LANG: "C" },
  });
  return new Promise((resolve, reject) => {
    let stdout = Buffer.alloc(0); let stderrBytes = 0; let ended = false; let spawnFailed = false;
    const timer = setTimeout(() => { try { child.kill(); } catch {} finish(new Error("fixed SSH deadline expired")); }, remaining(deadline));
    function finish(error, result) {
      if (ended) return;
      ended = true; clearTimeout(timer);
      if (error) reject(error); else resolve(result);
    }
    child.once("error", () => { spawnFailed = true; finish(new Error("fixed SSH launch failed")); });
    child.stdout.on("data", (chunk) => {
      stdout = Buffer.concat([stdout, chunk]);
      if (stdout.length > MAX_STDOUT) { try { child.kill(); } catch {} finish(new Error("fixed SSH receipt bound")); }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > MAX_STDERR) { try { child.kill(); } catch {} finish(new Error("fixed SSH diagnostic bound")); }
    });
    child.once("close", (code) => {
      if (spawnFailed) return finish(new Error("fixed SSH failed"));
      if (code !== 0) {
        try {
          const failure = parseFailure(bytesFrom(stdout));
          const error = new Error("fixed receiver reported a bounded failure");
          error.safePath = failure.path;
          error.safeCategory = failure.category;
          return finish(error);
        } catch { return finish(new Error("fixed SSH failed")); }
      }
      try { finish(null, parseReceipt(stdout)); } catch { finish(new Error("fixed SSH returned invalid receipt")); }
    });
    child.stdin.on("error", () => { try { child.kill(); } catch {} finish(new Error("fixed SSH input failed")); });
    const header = Buffer.from(`${sourceBytes.length}\n${RECEIVER_SHA256}\n`, "ascii");
    child.stdin.end(Buffer.concat([header, sourceBytes]));
  });
}

function bytesFrom(value) { return Buffer.from(value); }

function parseFailure(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > MAX_STDOUT) fail("failure frame length invalid");
  const text = bytes.toString("ascii");
  if (!Buffer.from(text, "ascii").equals(bytes)) fail("failure frame encoding invalid");
  const lines = text.split("\n");
  if (lines.length !== 3 || lines[2] !== "" || lines[1] !== FAILURE_TERMINAL) fail("failure frame terminal invalid");
  let value;
  try { value = JSON.parse(lines[0]); } catch { fail("failure frame invalid"); }
  const categories = ["deadline", "observation", "redirect", "url", "download", "download_timeout", "download_size", "download_hash", "disk", "disk_reserve", "scratch_custody", "archive", "archive_path", "archive_type", "archive_data", "archive_entries", "archive_expanded_bound", "archive_total", "node_member", "node_missing", "node_file", "node_changed", "tree_bound", "tree_mode", "tree_type", "tree_changed", "archive_empty", "units_changed", "receipt_bound", "unknown"];
  if (!exactKeys(value, ["status", "category", "path"]) || value.status !== "failed" || !categories.includes(value.category) ||
      !(value.path === null || (typeof value.path === "string" && /^\/var\/tmp\/lb-verification-tools-[a-z0-9_]{8,32}$/.test(value.path)))) fail("failure frame fields invalid");
  return value;
}

export function parseReceipt(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > MAX_STDOUT) fail("receipt length invalid");
  const text = bytes.toString("ascii");
  if (!Buffer.from(text, "ascii").equals(bytes) || !text.endsWith(`\n${TERMINAL}\n`)) fail("receipt terminal missing");
  const lines = text.split("\n");
  if (lines.length !== 3 || lines[2] !== "") fail("receipt frame count invalid");
  let value;
  try { value = JSON.parse(lines[0]); } catch { fail("receipt JSON invalid"); }
  const keys = ["schema", "status", "path", "go_archive_sha256", "node_archive_sha256", "go_tree_entries", "go_files_bytes", "go_tree_sha256", "node_bytes", "node_file_sha256", "units_before_sha256", "units_after_sha256", "downloaded_tools_executed", "production_units_unchanged"];
  const digestKeys = ["go_archive_sha256", "node_archive_sha256", "go_tree_sha256", "node_file_sha256", "units_before_sha256", "units_after_sha256"];
  if (!exactKeys(value, keys) || value.schema !== "ct200-private-tools-v1" || value.status !== "staged" ||
      digestKeys.some((key) => typeof value[key] !== "string" || !/^[a-f0-9]{64}$/.test(value[key])) ||
      typeof value.path !== "string" || !/^\/var\/tmp\/lb-verification-tools-[a-z0-9_]{8,32}$/.test(value.path) ||
      value.go_archive_sha256 !== "6924efde5de86fe277676e929dc9917d466efa02fb934197bc2eba35d5680971" ||
      value.node_archive_sha256 !== "9d942932535988091034dc94cc5f42b6dc8784d6366df3a36c4c9ccb3996f0c2" ||
      !positiveInteger(value.go_tree_entries, 100_000) || !positiveInteger(value.go_files_bytes, 2_000_000_000) ||
      !positiveInteger(value.node_bytes, 128 * 1024 * 1024) || !/^[a-f0-9]{64}$/.test(value.go_tree_sha256) ||
      !/^[a-f0-9]{64}$/.test(value.node_file_sha256) || !/^[a-f0-9]{64}$/.test(value.units_before_sha256) ||
      value.units_before_sha256 !== value.units_after_sha256 || value.downloaded_tools_executed !== false ||
      value.production_units_unchanged !== true) fail("receipt schema or evidence invalid");
  return Object.freeze(value);
}

function readReceiver() {
  checkLocalCustody(RECEIVER_PATH);
  const before = fs.lstatSync(RECEIVER_PATH, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size !== BigInt(RECEIVER_BYTES)) fail("receiver local metadata differs");
  const fd = fs.openSync(RECEIVER_PATH, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    for (const key of ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]) if (opened[key] !== before[key]) fail("receiver open metadata differs");
    const chunks = []; let total = 0;
    while (total < RECEIVER_BYTES) {
      const chunk = Buffer.alloc(Math.min(16384, RECEIVER_BYTES - total));
      const n = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (n <= 0) fail("receiver short read");
      chunks.push(chunk.subarray(0, n)); total += n;
    }
    const extra = Buffer.alloc(1);
    if (fs.readSync(fd, extra, 0, 1, null) !== 0) fail("receiver grew");
    const after = fs.fstatSync(fd, { bigint: true });
    const named = fs.lstatSync(RECEIVER_PATH, { bigint: true });
    checkLocalCustody(RECEIVER_PATH);
    for (const key of ["dev", "ino", "mode", "nlink", "size", "mtimeNs", "ctimeNs"]) if (after[key] !== before[key] || named[key] !== before[key]) fail("receiver changed during read");
    const bytes = Buffer.concat(chunks);
    if (total !== RECEIVER_BYTES || sha256(bytes) !== RECEIVER_SHA256) fail("receiver local digest differs");
    return bytes;
  } finally { fs.closeSync(fd); }
}

async function prepare() {
  const deadline = nowMs() + SESSION_MS;
  const sourceBytes = readReceiver();
  fixedLocalRegular(SSH_KEY, "SSH key");
  fixedLocalRegular(KNOWN_HOSTS, "known-hosts");
  const sshBytes = readFixedSsh();
  const receipt = await runFixedSsh(sshBytes, sourceBytes, deadline);
  process.stdout.write(JSON.stringify(receipt) + "\nCT200 private tools staged without execution\n");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== "--prepare") {
    process.stderr.write("usage: node prepare-tools.mjs --prepare\n"); process.exitCode = 2;
  } else {
    prepare().catch((error) => {
      const safePath = error && typeof error.safePath === "string" && /^\/var\/tmp\/lb-verification-tools-[a-z0-9_]{8,32}$/.test(error.safePath) ? ` path=${error.safePath}` : "";
      const category = error && typeof error.safeCategory === "string" && /^[a-z_]{1,32}$/.test(error.safeCategory) ? ` category=${error.safeCategory}` : "";
      process.stderr.write(`CT200 private staging failed${category}${safePath}; any created scratch data was preserved\n`);
      process.exitCode = 1;
    });
  }
}
