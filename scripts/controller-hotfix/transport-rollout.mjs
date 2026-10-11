import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { openCommandFenceSession, stableReceiver, FIXED_SSH_HARDLINKS, FIXED_SSH_TOOL_BYTES, FIXED_SSH_TOOL_SHA256, RECEIVER_BYTES, RECEIVER_SHA256, _fixedSshToolForTest } from "./command-fence.mjs";
import { verifyCandidateAt } from "./verify-stage.mjs";
import { runRetainedVerificationWithSeams } from "./verify-retained.mjs";
import { _projectAggregateForTest, _parseStrictJsonForTest } from "./expired-command-evidence.mjs";
import { PIN, validateCli, validatePreflight } from "./transport-rollout-plan.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const EVIDENCE_SCRIPT = path.join(HERE, "expired-command-evidence.mjs");
const STAGE_SCRIPT = path.join(HERE, "stage.mjs");
const PY_SOURCE = path.join(HERE, "transport-rollout.py");
const NONCE = "d771b06efb5715b296d04d891f3d854d";
const MAX_CHILD = 65536;
const SESSION_MS = 180000;
const LB_HOST = "10.0.0.115";
const LB_KEY = "C:/Users/Sasha/.ssh/lb_proxy_deploy";
const BRIDGE_SCHEMA = "controller-transport-rollout-bridge-v1";
const BRIDGE_FRAME_MAX = 32768;
const BRIDGE_TOTAL_MAX = 128 * 1024;
const BRIDGE_MAX_EXCHANGES = 4;
const PROTECTED_OBSERVATION_MS = 10000;
const CT_STAT_U64_MAX = 18446744073709551615n;
const PVE_HOST = "10.0.0.3";
const PVE_KEY = "C:/Users/Sasha/.ssh/cmp170_proxmox";
const KNOWN_HOSTS = "C:/Users/Sasha/.ssh/known_hosts";
const SSH = "C:/Windows/System32/OpenSSH/ssh.exe";
const ROLLOUT_PY_SOURCE_BYTES = 99386;
const ROLLOUT_PY_SOURCE_SHA256 = "80af780f3e12f1667a9514aa949fdb4a02eddce24bb9b6f0d57f5f94e8fff3b4";
const PY_SOURCE_BYTES = 99386;
const PY_SOURCE_SHA256 = "80af780f3e12f1667a9514aa949fdb4a02eddce24bb9b6f0d57f5f94e8fff3b4";
const COUNT_KEYS = ["selected", "matched_pairs", "missing", "mismatched", "malformed", "time_binding_unknown", "completed_before_expiry", "completed_at_expiry", "completed_after_expiry", "ok_true", "ok_false", "validation_refusal", "catalog_refusal", "lifecycle_unsupported", "unknown_failure", "outcome_unknown", "result_mismatch", "cache_invalid_entries"];

function fail() { throw new Error("fixed transport rollout preflight failed closed"); }
function sha(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function monoMs() { return Number(process.hrtime.bigint() / 1000000n); }
function noLinkedAncestors(filename) {
  const absolute = path.resolve(filename); let current = path.parse(absolute).root;
  for (const part of absolute.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const info = fs.lstatSync(current, { bigint: true });
    if (info.isSymbolicLink() || (current !== absolute && !info.isDirectory())) fail();
  }
}
function stablePrivateFile(filename) {
  noLinkedAncestors(filename);
  const info = fs.lstatSync(filename, { bigint: true });
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1n) fail();
  return [info.dev, info.ino, info.mode, info.nlink, info.uid, info.gid, info.size, info.mtimeNs, info.ctimeNs];
}
function stablePythonSource() {
  noLinkedAncestors(PY_SOURCE);
  const before = fs.lstatSync(PY_SOURCE, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size !== BigInt(PY_SOURCE_BYTES)) fail();
  const fd = fs.openSync(PY_SOURCE, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if ([opened.dev,opened.ino,opened.mode,opened.nlink,opened.size,opened.mtimeNs,opened.ctimeNs].some((v,i)=>v!==[before.dev,before.ino,before.mode,before.nlink,before.size,before.mtimeNs,before.ctimeNs][i])) fail();
    const chunks=[]; let total=0;
    while (total < PY_SOURCE_BYTES) { const b=Buffer.alloc(Math.min(16384,PY_SOURCE_BYTES-total)); const n=fs.readSync(fd,b,0,b.length,null); if(n<=0) fail(); chunks.push(b.subarray(0,n)); total+=n; }
    const extra=Buffer.alloc(1); if(fs.readSync(fd,extra,0,1,null)!==0) fail();
    const after=fs.fstatSync(fd,{bigint:true}); noLinkedAncestors(PY_SOURCE); const named=fs.lstatSync(PY_SOURCE,{bigint:true}); const bytes=Buffer.concat(chunks);
    for(const candidate of [after,named]) if([candidate.dev,candidate.ino,candidate.mode,candidate.nlink,candidate.size,candidate.mtimeNs,candidate.ctimeNs].some((v,i)=>v!==[before.dev,before.ino,before.mode,before.nlink,before.size,before.mtimeNs,before.ctimeNs][i])) fail();
    if(total!==PY_SOURCE_BYTES || sha(bytes)!==PY_SOURCE_SHA256) fail();
    return bytes;
  } finally { fs.closeSync(fd); }
}
function fixedSshCustody() {
  const data=fs.readFileSync(SSH);
  if(data.length!==FIXED_SSH_TOOL_BYTES || sha(data)!==FIXED_SSH_TOOL_SHA256) fail();
  try { _fixedSshToolForTest(fs,data); } catch { fail(); }
  return data;
}
function fixedPveArgs(command) {
  return ["-F","none","-T","-o","BatchMode=yes","-o","ConnectTimeout=8","-o","ServerAliveInterval=5","-o","ServerAliveCountMax=1","-o","StrictHostKeyChecking=yes","-o",`UserKnownHostsFile=${KNOWN_HOSTS}`,"-o",`HostName=${PVE_HOST}`,"-o","PermitLocalCommand=no","-o","ClearAllForwardings=yes","-o","ForwardAgent=no","-o","ProxyCommand=none","-o","ProxyJump=none","-o","ControlMaster=no","-o","ControlPath=none","-o","CanonicalizeHostname=no","-o","IdentitiesOnly=yes","-o","IdentityAgent=none","-i",PVE_KEY,`root@${PVE_HOST}`,command];
}
function posixShellQuote(value) {
  if (typeof value !== "string" || value.includes("\0")) fail();
  return "'" + value.replace(/'/g, "'\"'\"'") + "'";
}
function ctRemoteCommand(sourceBytes) {
  const bootstrap = `import hashlib,os,sys\ndef r(n):\n b=bytearray()\n while len(b)<n:\n  c=os.read(0,n-len(b))\n  if not c: raise SystemExit(2)\n  b.extend(c)\n return bytes(b)\ndef line(n):\n b=bytearray()\n while len(b)<n:\n  c=os.read(0,1)\n  if not c: break\n  b.extend(c)\n  if c==b'\\n': break\n return bytes(b)\nn=line(16)\nif n!=b'${PY_SOURCE_BYTES}\\n': raise SystemExit(3)\nh=line(66)\nif h!=b'${PY_SOURCE_SHA256}\\n': raise SystemExit(3)\ns=r(${PY_SOURCE_BYTES})\nif hashlib.sha256(s).hexdigest()!=h[:-1].decode('ascii'): raise SystemExit(3)\nexec(compile(s,'<fixed-controller-transport-observer>','exec'),{'__name__':'__main__'})`;
  return `/usr/sbin/pct exec 200 -- /usr/bin/python3 -I -B -c ${posixShellQuote(bootstrap)}`;
}
function observerCloseWithinDeadline(code, signal, deadline, now = monoMs()) {
  return now < deadline && signal == null && code === 0;
}
function verifyCustodyWithinDeadline(deadline, verify, now = monoMs) {
  if (!Number.isSafeInteger(deadline) || typeof verify !== "function" || typeof now !== "function" || now() >= deadline) fail();
  verify();
  if (now() >= deadline) fail();
  return true;
}
function observeCtFixed() {
  const deadline=monoMs()+9000;
  const sshBefore=fixedSshCustody(), keyBefore=stablePrivateFile(PVE_KEY), hostsBefore=stablePrivateFile(KNOWN_HOSTS), source=stablePythonSource();
  if(monoMs()>=deadline-1000) fail();
  const nonce=crypto.randomBytes(16).toString("hex");
  const frame=Buffer.from(JSON.stringify({schema:"controller-transport-ct-observation-v1",nonce,operation:"observe"})+"\n","ascii");
  const input=Buffer.concat([Buffer.from(`${source.length}\n${PY_SOURCE_SHA256}\n`),source,frame]);
  const child=spawn(SSH,fixedPveArgs(ctRemoteCommand(source)),{cwd:HERE,windowsHide:true,stdio:["pipe","pipe","pipe"],env:{SystemRoot:"C:/Windows",WINDIR:"C:/Windows",ProgramData:"C:/ProgramData",PATH:"C:/Windows/System32;C:/Windows",LANG:"C"}});
  return observeCtChild(child,input,deadline,(code,signal,out,errBytes)=>{
    if(!observerCloseWithinDeadline(code,signal,deadline) || errBytes!==0) fail();
    const raw=Buffer.concat(out).toString("ascii");
    if(!raw.endsWith("\n") || raw.indexOf("\n")!==raw.length-1) fail();
    const observation=parseCtObservationResponse(raw.trimEnd(),nonce);
    if(sha(fixedSshCustody())!==sha(sshBefore) || stablePrivateFile(PVE_KEY).some((v,i)=>v!==keyBefore[i]) || stablePrivateFile(KNOWN_HOSTS).some((v,i)=>v!==hostsBefore[i]) || !stablePythonSource().equals(source)) fail();
    return observation;
  });
}
function observeCtChild(child,input,deadline,validateClose,now=monoMs,cleanupReserveMs=1000){
  if(!Number.isSafeInteger(deadline)||typeof validateClose!=="function"||typeof now!=="function"||!Number.isSafeInteger(cleanupReserveMs)||cleanupReserveMs<1) fail();
  return new Promise((resolve,reject)=>{
    const out=[];let outBytes=0,errBytes=0,settled=false,aborting=false,stopPromise=null,timer;
    const closed=new Promise(resolveClose=>child.once("close",(code,signal)=>resolveClose({code,signal})));
    const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);if(error)reject(error);else resolve(value);};
    const abort=()=>{
      if(aborting||stopPromise||settled)return;
      aborting=true;
      clearTimeout(timer);
      stopPromise=settleChildCloseWithinDeadline(child,closed,deadline,now).then(observed=>finish(new Error(observed?"fixed observation failed closed":"fixed observation cleanup uncertain")),()=>finish(new Error("fixed observation cleanup uncertain")));
    };
    timer=setTimeout(abort,Math.max(0,deadline-cleanupReserveMs-now()));
    child.stdout.on("data",b=>{outBytes+=b.length;if(outBytes>8192)abort();else out.push(b);});
    child.stderr.on("data",b=>{errBytes+=b.length;if(errBytes>4096)abort();});
    child.once("error",()=>abort());
    child.once("close",(code,signal)=>{
      if(aborting||stopPromise||settled)return;
      try{
        const closedAt=now();
        if(closedAt>=deadline){finish(new Error("fixed observation cleanup uncertain"));return;}
        if(!observerCloseWithinDeadline(code,signal,deadline,closedAt)) fail();
        const value=validateClose(code,signal,out,errBytes);
        if(now()>=deadline) fail();
        finish(null,value);
      }catch{finish(new Error("fixed observation failed closed"));}
    });
    child.stdin.on("error",()=>{});
    if(now()>=deadline-cleanupReserveMs) abort(); else child.stdin.end(input);
  });
}
function parseChild(script, args, timeout) {
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: HERE, windowsHide: true, timeout, maxBuffer: MAX_CHILD, encoding: "utf8",
    env: { SystemRoot: "C:/Windows", WINDIR: "C:/Windows", ProgramData: "C:/ProgramData", PATH: "C:/Windows/System32;C:/Windows" },
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.error || result.status !== 0 || typeof result.stdout !== "string" || Buffer.byteLength(result.stdout) > MAX_CHILD) fail();
  return _parseStrictJsonForTest(result.stdout.trim());
}
function readFixedStage() {
  const result = spawnSync(process.execPath, [STAGE_SCRIPT, "--inspect", NONCE], {
    cwd: HERE, windowsHide: true, timeout: 30000, maxBuffer: 4096, encoding: "utf8",
    env: { SystemRoot: "C:/Windows", WINDIR: "C:/Windows", ProgramData: "C:/ProgramData", PATH: "C:/Windows/System32;C:/Windows" },
    stdio: ["ignore", "pipe", "ignore"],
  });
  const expected = `private controller staging inspected: nonce=${NONCE}; candidate_sha256=${PIN.imageSha256}; original_sha256=${PIN.originalSha256}; activationApproved=false\n`;
  if (result.error || result.status !== 0 || result.stdout !== expected) fail();
  return { nonce: NONCE, candidate_sha256: PIN.imageSha256, original_sha256: PIN.originalSha256, config_sha256: PIN.configSha256, activationApproved: false };
}

function fixedLbArgs(remoteCommand) {
  return ["-F", "none", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
    "-o", "StrictHostKeyChecking=yes", "-o", `UserKnownHostsFile=${KNOWN_HOSTS}`, "-o", `HostName=${LB_HOST}`,
    "-o", "PermitLocalCommand=no", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
    "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "CanonicalizeHostname=no", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
    "-i", LB_KEY, `root@${LB_HOST}`, remoteCommand];
}

function rolloutRemoteCommand(fenceBytes, rolloutBytes) {
  if (!Buffer.isBuffer(fenceBytes) || fenceBytes.length !== RECEIVER_BYTES || sha(fenceBytes) !== RECEIVER_SHA256 ||
      !Buffer.isBuffer(rolloutBytes) || rolloutBytes.length !== ROLLOUT_PY_SOURCE_BYTES || sha(rolloutBytes) !== ROLLOUT_PY_SOURCE_SHA256) fail();
  const bootstrap = `import hashlib,os,sys\ndef _read_exact(_n):\n _b=bytearray()\n while len(_b)<_n:\n  _p=os.read(0,_n-len(_b))\n  if not _p: raise SystemExit(2)\n  _b.extend(_p)\n return bytes(_b)\n_fence=_read_exact(${RECEIVER_BYTES})\n_rollout=_read_exact(${ROLLOUT_PY_SOURCE_BYTES})\nif hashlib.sha256(_fence).hexdigest()!=\"${RECEIVER_SHA256}\" or hashlib.sha256(_rollout).hexdigest()!=\"${ROLLOUT_PY_SOURCE_SHA256}\": raise SystemExit(3)\n_fns={\"__name__\":\"_fixed_fence_library\"}\nexec(compile(_fence,\"<fixed-command-fence-library>\",\"exec\"),_fns)\n_tns={\"__name__\":\"_fixed-transport-rollout-library\"}\nexec(compile(_rollout,\"<fixed-transport-rollout-library>\",\"exec\"),_tns)\nraise SystemExit(_tns[\"serve_rollout_bridge\"](_fns))`;
  return `/usr/bin/python3 -I -B -c '${bootstrap}'`;
}

class BridgeResponseReader {
  constructor(stream) {
    this.stream = stream; this.buffer = Buffer.alloc(0); this.queue = []; this.waiter = null; this.bytes = 0; this.frames = 0; this.ended = false; this.error = null;
    stream.on("data", (chunk) => this._data(chunk));
    stream.on("end", () => { this.ended = true; this._wake(); });
    stream.on("error", () => this._fail());
  }
  _fail() { if (this.error) return; this.error = new Error("fixed bridge protocol failed"); this._wake(); }
  _wake() { if (this.waiter) { const wake = this.waiter; this.waiter = null; wake(); } }
  _data(chunk) {
    this.bytes += chunk.length;
    if (this.bytes > BRIDGE_TOTAL_MAX) return this._fail();
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (true) {
      const end = this.buffer.indexOf(10);
      if (end < 0) break;
      if (end > BRIDGE_FRAME_MAX || this.buffer.subarray(0, end).some((byte) => byte > 0x7f)) return this._fail();
      this.frames++;
      if (this.frames > 12) return this._fail();
      this.queue.push(this.buffer.subarray(0, end).toString("ascii"));
      this.buffer = this.buffer.subarray(end + 1);
    }
    if (this.buffer.length > BRIDGE_FRAME_MAX) return this._fail();
    this._wake();
  }
  async next(timeoutMs) {
    const deadline = monoMs() + timeoutMs;
    if (this.error) throw this.error;
    if (this.queue.length) return this.queue.shift();
    if (this.ended) { if (this.buffer.length) throw new Error("fixed bridge truncated"); return null; }
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { cleanup(); reject(new Error("fixed bridge deadline")); }, timeoutMs);
      const cleanup = () => { clearTimeout(timer); if (this.waiter === wake) this.waiter = null; };
      const wake = () => { cleanup(); resolve(); };
      this.waiter = wake;
    });
    const left = deadline - monoMs();
    if (left <= 0) throw new Error("fixed bridge deadline");
    return this.next(left);
  }
}

function parseBridgeLine(line) {
  if (typeof line !== "string" || Buffer.byteLength(line, "ascii") > BRIDGE_FRAME_MAX || line.includes("\r")) fail();
  const value = _parseStrictJsonForTest(line);
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  return value;
}

function bridgeFrame(value) {
  const raw = Buffer.from(JSON.stringify(value) + "\n", "ascii");
  if (raw.length > BRIDGE_FRAME_MAX) fail();
  return raw;
}

async function writeBridge(stream, bytes, timeoutMs) {
  if (stream.destroyed || stream.writableEnded) fail();
  if (stream.write(bytes)) return;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error("fixed bridge write deadline")), timeoutMs);
    const cleanup = () => { clearTimeout(timer); stream.removeListener("drain", onDrain); stream.removeListener("error", onError); stream.removeListener("close", onClose); };
    const finish = (error) => { cleanup(); if (error) reject(error); else resolve(); };
    const onDrain = () => finish(); const onError = () => finish(new Error("fixed bridge write failed")); const onClose = () => finish(new Error("fixed bridge closed"));
    stream.once("drain", onDrain); stream.once("error", onError); stream.once("close", onClose);
  });
}

async function boundedProtectedObservation(responder, timeoutMs) {
  if (typeof responder !== "function" || !Number.isInteger(timeoutMs) || timeoutMs <= 0) fail();
  let timer; const deadline = monoMs() + timeoutMs;
  try {
    const value = await Promise.race([
      Promise.resolve().then(responder),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("protected observation deadline")), timeoutMs); }),
    ]);
    if (monoMs() >= deadline) fail();
    return value;
  } finally { clearTimeout(timer); }
}

function validBridgeReady(value, nonce) {
  return value && Object.keys(value).sort().join(",") === "held,kind,nonce,schema,seq" && value.schema === BRIDGE_SCHEMA && value.nonce === nonce && value.seq === 0 && value.kind === "ready" && value.held === true;
}

async function driveBridge(child, nonce, candidate, responders, deadline, closed, now = monoMs) {
  const reader = new BridgeResponseReader(child.stdout); let nextSeq = 0; let exchanges = 0; let ctBefore = null; let stderrBytes = 0; const transcript = [];
  child.stderr.on("data", (chunk) => { stderrBytes += chunk.length; if (stderrBytes > 4096) { try { child.kill(); } catch {} } });
  child.once("error", () => reader._fail());
  const frame = bridgeFrame({ schema: BRIDGE_SCHEMA, operation: "begin", nonce });
  try {
    if (deadline - now() <= 0) fail();
    const fenceSource = stableReceiver();
    const rolloutSource = stablePythonSource();
    if (fenceSource.length !== RECEIVER_BYTES || sha(fenceSource) !== RECEIVER_SHA256 || rolloutSource.length !== ROLLOUT_PY_SOURCE_BYTES || sha(rolloutSource) !== ROLLOUT_PY_SOURCE_SHA256) fail();
    const bootstrapInput = Buffer.concat([fenceSource, rolloutSource, frame]);
    if (bootstrapInput.length > BRIDGE_TOTAL_MAX * 2) fail();
    let remaining = deadline - now(); if (remaining <= 0) fail();
    await writeBridge(child.stdin, bootstrapInput, Math.min(15000, remaining));
    remaining = deadline - now(); if (remaining <= 0) fail();
    const readyLine = await reader.next(Math.min(12000, remaining));
    const ready = parseBridgeLine(readyLine);
    if (!validBridgeReady(ready, nonce)) fail();
    while (true) {
      const left = deadline - now(); if (left <= 0) fail();
      const line = await reader.next(left);
      if (line === null) fail();
      const request = parseBridgeLine(line);
      if (request.kind === "complete") {
        const status = validateBridgeTerminal(request, nonce, nextSeq);
        validateBridgeTranscript(status, transcript);
        if (reader.queue.length || reader.buffer.length) fail();
        child.stdin.end();
        const closeTimeout = Math.min(6000, Math.max(1, deadline - now()));
        let closeTimer;
        const terminal = await Promise.race([closed, new Promise((_, reject) => { closeTimer = setTimeout(() => reject(new Error("fixed bridge close deadline")), closeTimeout); })]).finally(() => clearTimeout(closeTimer));
        if (now() >= deadline) fail();
        if (terminal.signal || terminal.code !== (status === "handoff" ? 1 : 0) || stderrBytes !== 0 || reader.queue.length || reader.buffer.length) fail();
        if (status === "handoff") fail();
        return status;
      }
      if (request.kind === "failed") fail();
      nextSeq++;
      exchanges++;
      if (exchanges > BRIDGE_MAX_EXCHANGES || Object.keys(request).sort().join(",") !== "kind,nonce,operation,payload,schema,seq" || request.schema !== BRIDGE_SCHEMA || request.nonce !== nonce || request.seq !== nextSeq || request.kind !== "request" || !request.payload || typeof request.payload !== "object" || Array.isArray(request.payload)) fail();
      const expectedOperation = exchanges === 1 ? "preflight_evidence" : "protected_identity";
      if (exchanges > BRIDGE_MAX_EXCHANGES || request.operation !== expectedOperation) fail();
      let payload;
      let responseDeadline = deadline;
      if (request.operation === "preflight_evidence" && exchanges === 1) {
        if (Object.keys(request.payload).sort().join(",") !== "snapshot") fail();
        const snapshot = snapshotCounts(request.payload.snapshot);
        const diagnostic = await responders.readExpiry();
        let responseLeft = deadline - now(); if (responseLeft <= 0) fail();
        const stageReceipt = await responders.readStage();
        responseLeft = deadline - now(); if (responseLeft <= 0) fail();
        buildProjection(candidate, snapshot, diagnostic, stageReceipt);
        payload = { diagnostic, stage: stageReceipt };
      } else if (request.operation === "protected_identity" && Object.keys(request.payload).length === 0) {
        const observationBudget = Math.min(PROTECTED_OBSERVATION_MS, deadline - now());
        responseDeadline = now() + observationBudget;
        const observation = validateCtObservation(await boundedProtectedObservation(() => responders.observeCt(), observationBudget));
        if (now() >= responseDeadline) fail();
        if (ctBefore === null) ctBefore = observation;
        else if (!samePrivateObservation(ctBefore, observation)) fail();
        payload = { observation };
      } else fail();
      const responseLeft = Math.min(deadline, responseDeadline) - now(); if (responseLeft <= 0) fail();
      await writeBridge(child.stdin, bridgeFrame({ schema: BRIDGE_SCHEMA, nonce, seq: nextSeq, kind: "response", operation: request.operation, payload }), Math.min(15000, responseLeft));
      transcript.push(request.operation);
      if (request.operation === "preflight_evidence") continue;
    }
  } finally {
    if (!child.stdin.destroyed) child.stdin.end();
  }
}

function validateBridgeTerminal(value, nonce, seq) {
  const keys = "effects,kind,native_preserved,nonce,rollback,schema,seq,startup_admission_proven,status";
  if (!value || Object.keys(value).sort().join(",") !== keys || value.schema !== BRIDGE_SCHEMA || value.nonce !== nonce || value.seq !== seq || value.kind !== "complete" || !["candidate_verified", "original_restored", "handoff"].includes(value.status) || typeof value.effects !== "boolean" || typeof value.rollback !== "boolean" || typeof value.native_preserved !== "boolean" || value.startup_admission_proven !== false) fail();
  if (value.status === "candidate_verified" && (!value.effects || value.rollback || !value.native_preserved)) fail();
  if (value.status === "original_restored" && (!value.effects || !value.rollback || !value.native_preserved)) fail();
  if (value.status === "handoff" && value.native_preserved !== false) fail();
  return value.status;
}

function validateBridgeTranscript(status, transcript) {
  if (!Array.isArray(transcript) || transcript.length < 2 || transcript.length > BRIDGE_MAX_EXCHANGES || transcript[0] !== "preflight_evidence" || transcript[1] !== "protected_identity" || transcript.slice(2).some(operation => operation !== "protected_identity")) fail();
  if (status === "candidate_verified" && (transcript.length !== 3 || transcript[2] !== "protected_identity")) fail();
  if (status === "original_restored" && (transcript.length !== 3 && transcript.length !== 4)) fail();
  return true;
}

export function _rolloutRemoteCommandForTest(fenceBytes, rolloutBytes) { return rolloutRemoteCommand(fenceBytes, rolloutBytes); }
export function _stablePythonSourceForTest() { return stablePythonSource(); }
export function _ctRemoteCommandForTest() { return ctRemoteCommand(stablePythonSource()); }
export function _bridgeSourcePinsForTest() { return Object.freeze({ fenceBytes: RECEIVER_BYTES, fenceSha256: RECEIVER_SHA256, rolloutBytes: ROLLOUT_PY_SOURCE_BYTES, rolloutSha256: ROLLOUT_PY_SOURCE_SHA256 }); }
export function _boundedProtectedObservationForTest(responder, timeoutMs) { return boundedProtectedObservation(responder, timeoutMs); }
export function _validateCtObservationForTest(value) { return validateCtObservation(value); }
export function _parseCtObservationResponseForTest(raw,nonce) { return parseCtObservationResponse(raw,nonce); }
export function _observerCloseWithinDeadlineForTest(code, signal, deadline, now) { return observerCloseWithinDeadline(code, signal, deadline, now); }
export function _observeCtChildForTest(child, input, deadline, validateClose, now, cleanupReserveMs) { return observeCtChild(child, input, deadline, validateClose, now, cleanupReserveMs); }
export function _verifyCustodyWithinDeadlineForTest(deadline, verify, now) { return verifyCustodyWithinDeadline(deadline, verify, now); }
export function _validateBridgeTerminalForTest(value, nonce, seq) { return validateBridgeTerminal(value, nonce, seq); }

async function runFixedRolloutBridge(candidate, responders = {}) {
  const deadline = monoMs() + SESSION_MS;
  const sshBefore = fixedSshCustody();
  const keyBefore = stablePrivateFile(LB_KEY); const pveKeyBefore = stablePrivateFile(PVE_KEY); const hostsBefore = stablePrivateFile(KNOWN_HOSTS);
  const fenceSource = stableReceiver(); const rolloutSource = stablePythonSource();
  const remote = rolloutRemoteCommand(fenceSource, rolloutSource);
  let child;
  try {
    child = spawn(SSH, fixedLbArgs(remote), { cwd: HERE, windowsHide: true, stdio: ["pipe", "pipe", "pipe"],
      env: { SystemRoot: "C:/Windows", WINDIR: "C:/Windows", ProgramData: "C:/ProgramData", PATH: "C:/Windows/System32;C:/Windows", LANG: "C" } });
  } catch { fail(); }
  const closed = new Promise((resolve) => child.once("close", (code, signal) => resolve({ code, signal })));
  try {
    const status = await driveBridge(child, crypto.randomBytes(16).toString("hex"), candidate, {
      readExpiry: responders.readExpiry ?? (() => parseChild(EVIDENCE_SCRIPT, ["--probe"], 50000)),
      readStage: responders.readStage ?? readFixedStage,
      observeCt: responders.observeCt ?? observeCtFixed,
    }, deadline, closed);
    verifyCustodyWithinDeadline(deadline, () => {
      if (sha(fixedSshCustody()) !== sha(sshBefore) || stablePrivateFile(LB_KEY).some((v, i) => v !== keyBefore[i]) ||
          stablePrivateFile(PVE_KEY).some((v, i) => v !== pveKeyBefore[i]) || stablePrivateFile(KNOWN_HOSTS).some((v, i) => v !== hostsBefore[i]) ||
          !stableReceiver().equals(fenceSource) || !stablePythonSource().equals(rolloutSource)) fail();
    });
    return status;
  } catch {
    const settled = await settleChildCloseWithinDeadline(child, closed, deadline);
    throw new Error(settled ? "fixed transport rollout bridge failed closed" : "fixed transport rollout bridge cleanup uncertain");
  }
}

async function settleChildClose(child, closed, timeoutMs) {
  try { if (!child.stdin.destroyed) child.stdin.end(); } catch {}
  try { child.kill(); } catch {}
  let timer;
  try {
    const result = timeoutMs <= 0
      ? await Promise.race([closed, Promise.resolve(null)])
      : await Promise.race([closed, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("fixed child close deadline")), timeoutMs); })]);
    return result && (Number.isInteger(result.code) || typeof result.signal === "string");
  } catch { return false; }
  finally { clearTimeout(timer); }
}
async function stopObserverChild(child, closed, deadline) {
  return settleChildCloseWithinDeadline(child, closed, deadline);
}
async function settleChildCloseWithinDeadline(child, closed, deadline) {
  const observed = await settleChildClose(child, closed, Math.max(0, deadline - monoMs()));
  return observed && monoMs() < deadline;
}

export function _driveBridgeForTest(child, nonce, candidate, responders, deadline, closed, now = monoMs) {
  return driveBridge(child, nonce, candidate, responders, deadline, closed, now);
}
export function _settleChildCloseForTest(child, closed, timeoutMs) {
  return settleChildClose(child, closed, timeoutMs);
}
export function _stopObserverChildForTest(child, closed, deadline) { return stopObserverChild(child, closed, deadline); }
export function _settleChildCloseWithinDeadlineForTest(child, closed, deadline) { return settleChildCloseWithinDeadline(child, closed, deadline); }

function snapshotCounts(snapshot) {
  if (!snapshot || Object.keys(snapshot).sort().join(",") !== ["command_clear", "expired", "malformed", "nonterminal", "terminal", "total", "uncertain"].sort().join(",") || [snapshot.total,snapshot.terminal,snapshot.expired,snapshot.nonterminal,snapshot.uncertain,snapshot.malformed].some(n=>!Number.isSafeInteger(n)||n<0||n>1000000000) || snapshot.command_clear !== false || snapshot.terminal + snapshot.nonterminal !== snapshot.total || snapshot.terminal>snapshot.total || snapshot.nonterminal>snapshot.total || snapshot.expired>snapshot.total || snapshot.uncertain>snapshot.total || snapshot.malformed>snapshot.total) fail();
  return snapshot;
}

function validateCtObservation(value) {
  const record = (x, keys) => x && typeof x === "object" && !Array.isArray(x) && Object.keys(x).sort().join(",") === [...keys].sort().join(",");
  const wireU64 = x => typeof x === "string" && /^(?:0|[1-9][0-9]{0,19})$/.test(x) && BigInt(x) <= CT_STAT_U64_MAX;
  const tuple = x => Array.isArray(x) && x.length === 4 && x.every(wireU64);
  const agentKeys = ["pid","node_id","proc_dev","proc_ino","exe_dev","exe_ino","config","unit_file","image","command_sha256","service"];
  if (!record(value, ["agent","native"]) || !record(value.agent, agentKeys) || value.agent.pid !== 315 || typeof value.agent.node_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.agent.node_id) || !tuple(value.agent.config) || !tuple(value.agent.unit_file) || !tuple(value.agent.image) || typeof value.agent.command_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(value.agent.command_sha256)) fail();
  const unitKeys=["unit","pid","invocation","start","proc_dev","proc_ino","cgroup","cgroup_dev","cgroup_ino","cgroup_procs_sha256","command_sha256"];
  if (!record(value.agent.service, unitKeys) || value.agent.service.unit !== "vram-governor-node-agent.service" || value.agent.service.pid !== 315) fail();
  if (!Array.isArray(value.native) || value.native.length !== 4) fail();
  const expected = ["llama-server.service","comfyui.service","comfy-harness.service","vram-governor-runtime-tunnel.service"];
  for (let i=0;i<expected.length;i++) {
    const row=value.native[i];
    if (!record(row,unitKeys) || row.unit!==expected[i] || !Number.isSafeInteger(row.pid) || row.pid<=1 || typeof row.invocation!=="string" || !/^[a-f0-9]{32}$/.test(row.invocation) || typeof row.start!=="string" || !/^\d+$/.test(row.start) || !Number.isSafeInteger(row.proc_dev) || row.proc_dev<0 || !Number.isSafeInteger(row.proc_ino) || row.proc_ino<=0 || typeof row.cgroup!=="string" || !row.cgroup.startsWith("/system.slice/") || !Number.isSafeInteger(row.cgroup_dev) || row.cgroup_dev<0 || !Number.isSafeInteger(row.cgroup_ino) || row.cgroup_ino<=0 || typeof row.cgroup_procs_sha256!=="string" || !/^[a-f0-9]{64}$/.test(row.cgroup_procs_sha256) || typeof row.command_sha256!=="string" || !/^[a-f0-9]{64}$/.test(row.command_sha256)) fail();
  }
  const s=value.agent.service;
  if (!Number.isSafeInteger(s.pid) || typeof s.invocation!=="string" || !/^[a-f0-9]{32}$/.test(s.invocation) || typeof s.start!=="string" || !/^\d+$/.test(s.start) || !Number.isSafeInteger(s.proc_dev) || s.proc_dev<0 || !Number.isSafeInteger(s.proc_ino) || s.proc_ino<=0 || typeof s.cgroup!=="string" || !s.cgroup.startsWith("/system.slice/") || !Number.isSafeInteger(s.cgroup_dev) || s.cgroup_dev<0 || !Number.isSafeInteger(s.cgroup_ino) || s.cgroup_ino<=0 || typeof s.cgroup_procs_sha256!=="string" || !/^[a-f0-9]{64}$/.test(s.cgroup_procs_sha256) || typeof s.command_sha256!=="string" || !/^[a-f0-9]{64}$/.test(s.command_sha256)) fail();
  for (const key of ["proc_dev","proc_ino","exe_dev","exe_ino"]) if (!Number.isSafeInteger(value.agent[key]) || value.agent[key]<0) fail();
  return value;
}

function parseCtObservationResponse(raw,nonce) {
  const value=_parseStrictJsonForTest(raw);
  if(!value || Object.keys(value).sort().join(",")!=="nonce,observation,ok,schema" || value.schema!=="controller-transport-ct-observation-v1" || value.nonce!==nonce || value.ok!==true) fail();
  return validateCtObservation(value.observation);
}

function samePrivateObservation(a,b) { return JSON.stringify(a) === JSON.stringify(b); }

function buildProjection(candidate, snapshot, diagnostic, stageReceipt) {
  if (!candidate || candidate.manifest.candidate !== PIN.candidate || candidate.manifest.releaseApproved !== false || candidate.manifest.installedBinaryProvenance !== false) fail();
  if (!stageReceipt || stageReceipt.activationApproved !== false || stageReceipt.nonce !== NONCE || stageReceipt.candidate_sha256 !== PIN.imageSha256 || stageReceipt.original_sha256 !== PIN.originalSha256 || stageReceipt.config_sha256 !== PIN.configSha256) fail();
  const counts = diagnostic?.counts;
  if (!diagnostic || Object.keys(diagnostic).sort().join(",") !== ["schema", "scope", "counts", "read_only", "original_custody_unchanged", "cache_custody_unchanged", "database_timestamp_precision_limited", "authoritative_outcome", "permission_to_restart", "command_history_changed"].sort().join(",") || diagnostic.schema !== "expired-command-evidence-readonly-v1" || diagnostic.scope !== "expired_command_cache_linkage_readonly" || diagnostic.authoritative_outcome !== false || diagnostic.permission_to_restart !== false || diagnostic.command_history_changed !== false || diagnostic.read_only !== true || diagnostic.original_custody_unchanged !== true || diagnostic.cache_custody_unchanged !== true || diagnostic.database_timestamp_precision_limited !== true || !counts || Object.keys(counts).sort().join(",") !== ["expired_total", ...COUNT_KEYS].sort().join(",")) fail();
  for (const key of COUNT_KEYS) if (!Number.isSafeInteger(counts[key]) || counts[key] < 0 || counts[key] > (key === "cache_invalid_entries" ? 100000 : 32)) fail();
  const failClasses = counts.validation_refusal + counts.catalog_refusal + counts.lifecycle_unsupported + counts.unknown_failure;
  const temporal = counts.time_binding_unknown + counts.completed_before_expiry + counts.completed_at_expiry + counts.completed_after_expiry;
  const residual=counts.selected-counts.missing-counts.mismatched-counts.malformed-counts.matched_pairs;
  if (failClasses !== counts.ok_false || counts.ok_true + counts.ok_false !== counts.matched_pairs || temporal !== counts.matched_pairs || counts.selected !== counts.expired_total || counts.cache_invalid_entries > 100000 || residual<0 || residual>counts.outcome_unknown || counts.outcome_unknown>residual+counts.matched_pairs || counts.result_mismatch>counts.ok_true || counts.result_mismatch>counts.matched_pairs-counts.time_binding_unknown) fail();
  const cacheUnknown = counts.selected - counts.matched_pairs;
  const transportOnly = snapshot.total === snapshot.terminal && snapshot.nonterminal === 0 && snapshot.uncertain === 0 && snapshot.malformed === 0 && snapshot.expired === counts.expired_total && cacheUnknown === 0 && counts.outcome_unknown === 0;
  const projection = {
    schema: "controller-transport-preflight-v1", stage: "observed", nonce: NONCE,
    candidate: PIN.candidate, manifest_sha256: PIN.manifestSha256,
    image_sha256: PIN.imageSha256, original_sha256: PIN.originalSha256, config_sha256: PIN.configSha256,
    command: {
      total: snapshot.total, terminal: snapshot.terminal, expired: snapshot.expired,
      nonterminal: snapshot.nonterminal, uncertain: snapshot.uncertain, malformed: snapshot.malformed,
      expired_rows: counts.expired_total, cache_matched_pairs: counts.matched_pairs,
      cache_unknown: cacheUnknown, transport_only_candidate: transportOnly, command_clear: false,
    },
    native: { leaf14_within_probe_unchanged: diagnostic.original_custody_unchanged, cross_operation_identity_joined: true },
    ct: { agent_within_probe_unchanged: true, cross_operation_identity_joined: true },
    startup_admission_proven: false,
    effects: { controller_stop: false, image_write: false, controller_start: false, history_write: false, native_action: false },
  };
  return validatePreflight(projection);
}

export async function runPreflightWithSeams(seams = {}) {
  const verifyCandidate = seams.verifyCandidate ?? (async () => {
    const retained = await runRetainedVerificationWithSeams(["--verify"], {
      observe: (verify, fixedPath) => verify(fixedPath),
    });
    const current = verifyCandidateAt(path.join(ROOT, ".cache", "controller-transport-hotfix", PIN.candidate));
    return Object.freeze({ manifest: current.manifest, retained });
  });
  const openFence = seams.openFence ?? openCommandFenceSession;
  const readExpiry = seams.readExpiry ?? (() => parseChild(EVIDENCE_SCRIPT, ["--probe"], 50000));
  const readStage = seams.readStage ?? readFixedStage;
  const observeCt = seams.observeCt ?? observeCtFixed;
  const now = seams.monotonicNs ?? (() => process.hrtime.bigint());
  const started = now(); let session;
  const withinBudget = () => { if (now() - started >= BigInt(SESSION_MS) * 1000000n) fail(); };
  const ctBefore = validateCtObservation(await observeCt());
  withinBudget();
  const candidate = await verifyCandidate();
  withinBudget();
  session = await openFence();
  try {
    const snapshot = snapshotCounts(await session.snapshot());
    withinBudget();
    const diagnostic = readExpiry();
    withinBudget();
    const stageReceipt = await readStage();
    withinBudget();
    const ctAfter = validateCtObservation(await observeCt());
    if (!samePrivateObservation(ctBefore, ctAfter)) fail();
    const after = snapshotCounts(await session.snapshot());
    if (JSON.stringify(snapshot) !== JSON.stringify(after)) fail();
    withinBudget();
    const projection = buildProjection(candidate, snapshot, diagnostic, stageReceipt);
    await session.close(); session = null; withinBudget();
    return projection;
  } finally {
    if (session) { try { await session.abort(); } catch { fail(); } }
  }
}

export function _validateSnapshotForTest(value) { return snapshotCounts(value); }
export function _buildProjectionForTest(candidate, snapshot, diagnostic, stageReceipt) { return buildProjection(candidate, snapshot, diagnostic, stageReceipt); }

async function cliProjection(args, preflight) {
  const operation = validateCli(args);
  if (operation === "apply") fail(); // Permanently disabled absent a separate root activation contract.
  return preflight();
}

export function _cliProjectionForTest(args, preflight) {
  if (typeof preflight !== "function") fail();
  return cliProjection(args, preflight);
}

async function main(args) {
  const result = await cliProjection(args, runPreflightWithSeams);
  process.stdout.write(JSON.stringify(result) + "\n");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await main(process.argv.slice(2)); }
  catch { process.stderr.write("fixed controller transport rollout failed closed\n"); process.exitCode = 1; }
}
