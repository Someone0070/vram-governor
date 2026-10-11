import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough, Readable, Writable } from "node:stream";
import { spawnSync } from "node:child_process";
import { deflateSync } from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { buildCombinedInstallPlan, parseNftRuleset, inspectForeignSnapshot, inspectOwnedTable } from "./maintenance-guard-plan.mjs";
import { parseCli, runInteractiveProtocol, validatePreflightResult, validatePublicResult } from "./maintenance-guard.mjs";
import { buildInstallPlan } from "./maintenance-fence.mjs";

const NONCE = "0123456789abcdef0123456789abcdef";
const HASH = "a".repeat(64);
const TEST_RECEIVER = Buffer.from("fixture-only receiver source\n");
const PYTHON = "C:/Program Files/Python38/python.exe";
const VERIFY_MODE = process.argv[2] === "--verify";
const PYTHON_STATE_GROUPS = Object.freeze([
  "root-namespace-custody",
  "install-inspect-release",
  "stale-kernel-identity-refusal",
  "fresh-session-no-adoption",
  "uncertain-apply-no-release",
  "held-fd-and-identity-refusal",
  "eof-and-deadline-retain",
  "nested-deadline-terminal",
  "first-read-deadline-terminal",
  "fixed-file-mode-and-link-custody",
  "lock-descriptor-custody",
  "receipt-held-inode-update",
  "receipt-update-failure-terminal",
  "installed-inspection-custody",
  "fixed-get-all-lb-lanes",
  "get-inspect-release-held-reverse-tuple",
  "protected-client-tuple-classification",
  "paused-phase-request-boundaries",
  "paused-agent-production-preflight-positive",
  "paused-agent-production-preflight-drift-refusals",
  "paused-preflight-failure-terminal-loop",
  "paused-agent-cgroup-custody",
]);
const PYTHON_PARSER_GROUPS = Object.freeze(["strict-json-and-numeric-bool-rejection"]);
const SAFE_TEST_FAILURES = new Set(["receiver_response_missing", "receiver_response_invalid", "receiver_unsolicited_response", "receiver_response_line_bound", "receiver_response_unterminated", "ssh_child_error", "ssh_stderr_bound", "session_input_count_bound", "receiver_response_timeout", "session_input_timeout", "session_deadline", "session_output_error", "session_input_invalid", "python_control_spawn_ENOENT", "python_control_spawn_EACCES", "python_control_spawn_ETIMEDOUT", "python_control_spawn_other"]);
const TEST_NAMES = Object.freeze([
  "combined guard plans are fixed and order validation lanes before protected-port drops",
  "libnftables JSON parser pins version and schema and rejects unknown structures",
  "session input and public result projection reject unsupported fields",
  "interactive guardian streams actions and completes a bounded EOF handshake",
  "interactive guardian fails closed on oversized input, early exit, duplicate output, and unsafe output",
  "receiver production transitions require retained identity and preserve uncertain ownership",
  "test runner validator requires the exact successful inventory",
  "paused CT preflight is explicit and bounded",
]);

function throwsCode(fn, code) { assert.throws(fn, (failure) => failure instanceof Error && failure.message === code); }

function nftFixture(version = "1.0.9", schema = 1) {
  return Buffer.from(JSON.stringify({ nftables: [
    { metainfo: { version, release_name: "nftables", json_schema_version: schema } },
    { table: { family: "inet", name: "example", handle: 1 } },
  ] }));
}

function independentFixtureLines(role, nonce) {
  const table = role === "LB115" ? "vg_controller_maintenance" : "vg_native_maintenance";
  const lanes = role === "LB115" ? [8443] : [8080, 8188, 8190];
  const protectedPorts = role === "LB115" ? [4000, 8443, 18082, 9444, 9445] : [8080, 8188, 8190];
  const lines = [`create table inet ${table} { comment "vg-maintenance-owner-nonce-${nonce}"; }`, `add chain inet ${table} input { type filter hook input priority -150; policy accept; }`, `add chain inet ${table} output { type filter hook output priority -150; policy accept; }`];
  for (const source of [443, 444, 445]) for (const port of lanes) {
    lines.push(`add rule inet ${table} input iifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport ${source} tcp dport ${port} accept`);
    lines.push(`add rule inet ${table} output oifname "lo" meta skuid 0 ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport ${source} tcp dport ${port} accept`);
    lines.push(`add rule inet ${table} output oifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport ${source} tcp dport ${port} drop`);
  }
  for (const port of protectedPorts) lines.push(`add rule inet ${table} input tcp dport ${port} drop`);
  return lines;
}

function ownedNftFixture(plan, mutate = null) {
  const objects = [
    { kind: "metainfo", value: { version: "1.0.9", release_name: "fixture", json_schema_version: 1 } },
    { kind: "table", value: { family: "inet", name: plan.table, handle: 40, comment: `vg-maintenance-owner-nonce-${plan.ownershipNonce}` } },
    ...["input", "output"].map((hook, index) => ({ kind: "chain", value: { family: "inet", table: plan.table, name: hook, handle: 41 + index, type: "filter", hook, prio: -150, policy: "accept" } })),
  ];
  let handle = 50;
  const fixtureLines = plan.fixtureTransaction ? plan.fixtureTransaction.trimEnd().split("\n") : independentFixtureLines(plan.role, plan.ownershipNonce);
  for (const line of fixtureLines.slice(3)) {
    const match = line.match(/^add rule inet \S+ (input|output) (.*) (accept|drop)$/);
    assert.ok(match, "fixture requires canonical generated transaction");
    const tokens = (match[2].match(/"[^"]*"|\S+/g) || []).map((token) => token.startsWith('"') ? token.slice(1, -1) : token);
    const expr = [];
    for (let index = 0; index < tokens.length;) {
      const kind = tokens[index++]; let left; let right;
      if (kind === "iifname" || kind === "oifname") { left = { meta: { key: kind } }; right = tokens[index++]; }
      else { const field = tokens[index++]; const raw = tokens[index++]; left = kind === "meta" ? { meta: { key: field } } : { payload: { protocol: kind, field } }; right = /^\d+$/.test(raw) ? Number(raw) : raw; }
      expr.push({ match: { op: "==", left, right } });
    }
    expr.push({ [match[3]]: null });
    objects.push({ kind: "rule", value: { family: "inet", table: plan.table, chain: match[1], expr, handle: handle++ } });
  }
  mutate?.(objects);
  return Buffer.from(JSON.stringify({ nftables: objects.map(({ kind, value }) => ({ [kind]: value })) }));
}

function validInspect() { return { owned_table_absent: true, foreign_ruleset_sha256: HASH }; }

function decision(plan, chain, packet) {
  const prefix = `add rule inet ${plan.table} ${chain} `;
  for (const line of plan.transaction.split("\n").filter((entry) => entry.startsWith(prefix))) {
    const tokens = (line.slice(prefix.length).match(/"[^\"]*"|\S+/g) || []).map((token) => token.startsWith('"') ? token.slice(1, -1) : token);
    const action = tokens.pop(); let matched = true;
    for (let index = 0; index < tokens.length;) {
      const key = tokens[index++];
      if (key === "iifname" || key === "oifname") { const expected = tokens[index++]; if (packet[key] !== expected) matched = false; }
      else if (key === "meta" && tokens[index] === "skuid") { index++; const expected = Number(tokens[index++]); if (packet.uid !== expected) matched = false; }
      else if (["ip", "tcp"].includes(key)) {
        const field = tokens[index++]; const value = tokens[index++];
        const property = key === "ip" ? `ip_${field}` : `tcp_${field}`;
        if (packet[property] !== (/^\d+$/.test(value) ? Number(value) : value)) matched = false;
      } else throw new Error("fixture_expression_unknown");
    }
    if (matched) return action;
  }
  return "accept";
}

function packetDecision(plan, packet) {
  const output = decision(plan, "output", packet);
  return output === "accept" ? decision(plan, "input", packet) : output;
}

function knownBadInterleavedPlan(plan) {
  const singles = plan.sourcePorts.map((sourcePort) => buildInstallPlan({ role: plan.role, sourcePort, ownershipNonce: plan.ownershipNonce }));
  const common = singles[0].transaction.trimEnd().split("\n").slice(0, 3);
  const interleaved = singles.flatMap((single) => single.transaction.trimEnd().split("\n").slice(3));
  return { ...plan, transaction: [...common, ...interleaved].join("\n") + "\n" };
}

function knownBadBroadOutputPlan(plan) {
  const additions = plan.protectedPorts.map((port) => `add rule inet ${plan.table} output tcp dport ${port} drop`);
  return { ...plan, transaction: plan.transaction.trimEnd() + "\n" + additions.join("\n") + "\n" };
}

function fakeChild({ response = validInspect(), duplicate = false, closeOnRequest = false, errorOnRequest = false, unsafe = false, partial = false, silent = false, oversized = false, stderrOverflow = false, responseFactory = null } = {}) {
  const child = new EventEmitter();
  child.stdout = new PassThrough(); child.stderr = new PassThrough();
  let writes = 0; let killed = false;
  child.stdin = new Writable({
    write(chunk, _encoding, callback) {
      writes += 1;
      if (writes >= 3) {
        if (closeOnRequest) {
          setImmediate(() => { child.stdout.end(); child.emit("close", 0, null); });
        } else if (errorOnRequest) {
          setImmediate(() => { child.stdout.end(); child.emit("error", new Error("fixture-only secret")); });
        } else if (!silent) {
          if (stderrOverflow) child.stderr.write("x".repeat(8193));
          const request = JSON.parse(chunk.toString("ascii").trim());
          let envelope = responseFactory ? responseFactory(request) : { result: response, receipt_sha256: null };
          if (!responseFactory && request.operation === "install") envelope = { result: { install_state: "verified", owned: { table_handle: 1, chain_handles: { input: 2, output: 3 }, rule_handles: [4], ownership_nonce: NONCE, rules_sha256: HASH }, foreign_ruleset_sha256: HASH }, receipt_sha256: HASH };
          if (!responseFactory && request.operation === "release") envelope = { result: { release_state: "verified_absent", prior_owned_handle: 1 }, receipt_sha256: HASH };
          if (unsafe) envelope = { result: { ...validInspect(), secret: "must-not-escape" }, receipt_sha256: null };
          const line = JSON.stringify({ ok: true, ...envelope }) + "\n";
          child.stdout.write(oversized ? "x".repeat(16385) + "\n" : partial ? line.slice(0, -1) : line);
          if (partial) setImmediate(() => { child.stdout.end(); child.emit("close", 0, null); });
          if (duplicate) child.stdout.write(line);
        }
      }
      callback();
    },
    final(callback) { child.stdout.end(); setImmediate(() => child.emit("close", 0, null)); callback(); },
  });
  child.kill = () => { killed = true; child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy(); };
  Object.defineProperty(child, "wasKilled", { get: () => killed });
  return child;
}

function runFake(options = {}, input = '{"operation":"inspect"}\n', timeouts = {}) {
  const child = fakeChild(options); const output = new PassThrough(); const chunks = [];
  output.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
  const promise = runInteractiveProtocol({ child, inputStream: Readable.from([Buffer.from(input)]), outputStream: output, role: "LB115", nonce: NONCE, receiver: TEST_RECEIVER, timeouts });
  return { child, promise, output: () => Buffer.concat(chunks).toString("utf8") };
}

function validateTapRun(status, output) {
  if (status !== 0 || typeof output !== "string" || output.length > 1024 * 1024) throw new Error("test_run_failed");
  const lines = output.split(/\r?\n/);
  const terminals = lines.filter((line) => /^(?:ok|not ok)\s+\d+\s+-/.test(line));
  if (terminals.some((line) => /(?:^|\s)#\s*(?:SKIP|TODO)\b/i.test(line))) throw new Error("test_directive_forbidden");
  if (terminals.length !== TEST_NAMES.length || terminals.some((line, index) => line !== `ok ${index + 1} - ${TEST_NAMES[index]}`)) throw new Error("test_inventory_mismatch");
  const plans = lines.filter((line) => /^1\.\.\d+$/.test(line));
  if (plans.length !== 1 || plans[0] !== `1..${TEST_NAMES.length}`) throw new Error("test_plan_mismatch");
  for (const [key, expected] of [["tests", TEST_NAMES.length], ["pass", TEST_NAMES.length], ["fail", 0], ["cancelled", 0], ["skipped", 0], ["todo", 0]]) {
    const summaries = lines.filter((line) => line.startsWith(`# ${key} `));
    if (summaries.length !== 1 || summaries[0] !== `# ${key} ${expected}`) throw new Error("test_summary_mismatch");
  }
  return true;
}

function runPythonControl(source, receiverPath, groups) {
  const packed = deflateSync(Buffer.from(source, "utf8")).toString("base64");
  const bootstrap = "import base64,zlib;exec('try:\\n exec(zlib.decompress(base64.b64decode(\"" + packed + "\")))\\nexcept BaseException as failure:\\n tb=failure.__traceback__\\n while tb.tb_next: tb=tb.tb_next\\n detail=getattr(failure,\"code\",\"unknown\")\\n if not isinstance(detail,str) or not detail or not all(c.isalnum() or c==\"_\" for c in detail): detail=\"unknown\"\\n line=getattr(failure,\"lineno\",0)\\n if not isinstance(line,int) or line<=0: line=tb.tb_lineno\\n print(\"python-control-exception:\"+type(failure).__name__+\":\"+tb.tb_frame.f_code.co_name+\":\"+detail+\":\"+str(line))\\n raise',{'base64':base64,'zlib':zlib})";
  const result = spawnSync(PYTHON, ["-I", "-S", "-B", "-c", bootstrap, receiverPath], { encoding: "utf8", timeout: 20000, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
  if (result.error) {
    const code = typeof result.error.code === "string" && /^[A-Z0-9_]{1,24}$/.test(result.error.code) ? result.error.code : "unknown";
    const errno = Number.isSafeInteger(result.error.errno) ? String(Math.abs(result.error.errno)) : "none";
    throw new Error(("python_control_spawn_" + code + "_" + errno).toLowerCase());
  }
  if (result.status !== 0) {
    const marker = String(result.stdout).match(/python-control-exception:([A-Za-z]{1,32}):([A-Za-z_<>]{1,64}):([a-z0-9_]{1,64}):([0-9]{1,5})/);
    const kind = marker?.[1]?.toLowerCase() || "unknown";
    const line = marker?.[2]?.replace(/[^a-z0-9]/gi, "_").toLowerCase() || "unknown";
    const detail = marker?.[3] || "unknown";
    const observed = String(result.stdout).split(/\r?\n/).filter((line) => groups.some((name) => line === "python-control:" + name)).at(-1);
    const stage = observed ? observed.slice("python-control:".length).replace(/[^a-z0-9_]/g, "_") : "before_inventory";
    const lineNumber = marker?.[4] || "0";
    throw new Error("python_control_exit_" + kind + "_" + detail + "_" + line + "_line_" + lineNumber + "_" + stage);
  }
  if (String(result.stdout).replace(/\r\n/g, "\n") !== [...groups.map((name) => `python-control:${name}`), "python guardian controls passed", ""].join("\n")) throw new Error("python_control_inventory");
}

const RECEIVER_STATE_CONTROL = String.raw`import hashlib, importlib.machinery, io, json, posixpath, shlex, signal, stat, sys, types
from types import SimpleNamespace
from unittest import mock
fake=types.ModuleType('fcntl'); fake.LOCK_EX=2; fake.LOCK_NB=4; fake.flock=lambda *args: (_ for _ in ()).throw(AssertionError('unexpected fcntl call')); sys.modules['fcntl']=fake
if sys.flags.optimize != 0: raise RuntimeError('optimized Python forbidden')
m=importlib.machinery.SourceFileLoader('guard_state_fixture',sys.argv[1]).load_module()
NONCE='0123456789abcdef0123456789abcdef'
def code(call):
    try: call()
    except m.GuardError as exc: return exc.code
    raise AssertionError('expected GuardError')
def fixture_lines(role,nonce):
    table={'LB115':'vg_controller_maintenance','CT200':'vg_native_maintenance'}[role]
    lanes={'LB115':[8443],'CT200':[8080,8188,8190]}[role]
    protected={'LB115':[4000,8443,18082,9444,9445],'CT200':[8080,8188,8190]}[role]
    lines=[f'create table inet {table} {{ comment "vg-maintenance-owner-nonce-{nonce}"; }}',f'add chain inet {table} input {{ type filter hook input priority -150; policy accept; }}',f'add chain inet {table} output {{ type filter hook output priority -150; policy accept; }}']
    for source in (443,444,445):
        for port in lanes:
            lines += [f'add rule inet {table} input iifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport {source} tcp dport {port} accept',f'add rule inet {table} output oifname "lo" meta skuid 0 ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport {source} tcp dport {port} accept',f'add rule inet {table} output oifname "lo" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport {source} tcp dport {port} drop']
    lines += [f'add rule inet {table} input tcp dport {port} drop' for port in protected]
    return lines
def rows(role, nonce):
    table=m.ROLES[role]['table']; result=[{'metainfo':{'version':'1.0.9','release_name':'fixture','json_schema_version':1}}, {'table':{'family':'inet','name':'foreign_fixture','handle':1}}]
    result += [{'table':{'family':'inet','name':table,'handle':10,'comment':'vg-maintenance-owner-nonce-'+nonce}}]
    result += [{'chain':{'family':'inet','table':table,'name':name,'handle':handle,'type':'filter','hook':name,'prio':-150,'policy':'accept'}} for name,handle in [('input',11),('output',12)]]
    handle=20
    for line in fixture_lines(role,nonce)[3:]:
        if not line.startswith('add rule '): continue
        tokens=shlex.split(line); chain=tokens[4]; body=tokens[5:-1]; verdict=tokens[-1]; expr=[]; i=0
        while i < len(body):
            token=body[i]; i+=1
            if token in ('iifname','oifname'):
                key=token; right=body[i]; i+=1; left={'meta':{'key':key}}
            elif token in ('meta','ip','tcp'):
                field=body[i]; right=body[i+1]; i+=2
                if token=='meta': left={'meta':{'key':field}}
                else: left={'payload':{'protocol':token,'field':field}}
                right=int(right) if right.isdigit() else right
            else: raise AssertionError('unexpected plan token')
            expr.append({'match':{'op':'==','left':left,'right':right}})
        expr.append({verdict:None}); result.append({'rule':{'family':'inet','table':table,'chain':chain,'expr':expr,'handle':handle}}); handle+=1
    return result
def env(apply_code=0,selected_role='CT200'):
    role=selected_role; nonce=NONCE; foreign=[{'metainfo':{'version':'1.0.9','release_name':'fixture','json_schema_version':1}}, {'table':{'family':'inet','name':'foreign_fixture','handle':1}}]
    current=list(foreign); installed=rows(role,nonce); calls=[]; receipts=[]
    digest=m.sha(m.canonical(foreign).encode('utf-8'))
    def apply(data):
        calls.append(data)
        if data.startswith(b'create table'): current[:]=installed
        elif data.startswith(b'delete table'): current[:]=foreign
        return apply_code,b''
    lockinfo=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_dev=2,st_ino=71)
    receiptinfo=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_dev=3,st_ino=72)
    class CustodyFS:
        SEEK_SET=0; SEEK_CUR=1
        def __init__(self): self.data=b''; self.offset=0; self.named_lock=lockinfo; self.named_receipt=receiptinfo
        def fstat(self,fd): return lockinfo if fd==71 else receiptinfo if fd==72 else (_ for _ in ()).throw(AssertionError('unknown custody fd'))
        def stat(self,path,follow_symlinks=False): return self.named_lock if path==m.LOCK_PATH else self.named_receipt if path==m.receipt_path(nonce) else (_ for _ in ()).throw(AssertionError('unknown custody path'))
        def lseek(self,fd,offset,whence):
            old=self.offset; self.offset=offset if whence==self.SEEK_SET else self.offset+offset; return old if whence==self.SEEK_CUR else self.offset
        def read(self,fd,size): result=self.data[self.offset:self.offset+size]; self.offset+=len(result); return result
    custody=CustodyFS()
    def receipt_write(data): receipts.append(data); custody.data=data
    def receipt_update(data): receipts.append(data); custody.data=data
    hooks={'ruleset':lambda:list(current),'nft_apply':apply,'receipt_writer':receipt_write,'receipt_update':receipt_update,'receipt_fd':72,'receipt_path':m.receipt_path(nonce),'custody_fs':custody}
    return role,nonce,foreign,current,installed,calls,receipts,digest,hooks
def install_request(role,nonce):
    batch=m.expected_batch(role,nonce)
    return {'role':role,'nonce':nonce,'operation':'install','batch_bytes':len(batch),'batch_sha256':m.sha(batch),'transaction':batch.decode('ascii')}
def release_request(role,nonce,digest):
    return {'role':role,'nonce':nonce,'operation':'release','verification':{'schema':'maintenance-guard-success-v1','nonce':nonce,'disposition':'successfully_verified','receipt_sha256':digest}}
originals={name:getattr(m,name) for name in ('fixed_preflight','verify_held_sockets','check_fixed_identity','ephemeral_range','process_protected_client_tuples','safe_child','stable_tool','inspect_agent_cgroup')}
try:
    m.fixed_preflight=lambda role,nonce,held:{'foreign_ruleset_sha256':m.sha(m.canonical([{'metainfo':{'version':'1.0.9','release_name':'fixture','json_schema_version':1}},{'table':{'family':'inet','name':'foreign_fixture','handle':1}}]).encode('utf-8'))}
    m.verify_held_sockets=lambda held:None; m.check_fixed_identity=lambda role:None; m.ephemeral_range=lambda role:None; m.process_protected_client_tuples=lambda role,**kwargs:None
    def forbidden(*args,**kwargs): raise AssertionError('unexpected operational call')
    m.safe_child=forbidden; m.subprocess.Popen=forbidden; m.socket.socket=forbidden
    for name in ('open','mkdir','write','unlink','remove','rename','replace','ftruncate','fsync','lseek','fstat','stat','close'):
        setattr(m.os,name,forbidden)
    class LaneSocket:
        def __init__(self,index): self.index=index; self.address=None; self.inheritable=True; self.options={}; self.closed=False
        def setsockopt(self,level,option,value): self.options[(level,option)]=value
        def set_inheritable(self,value): self.inheritable=value
        def get_inheritable(self): return self.inheritable
        def bind(self,address): self.address=address
        def getsockname(self): return self.address
        def fileno(self): return -1 if self.closed else self.index+20
        def getsockopt(self,level,option): return self.options.get((level,option),0)
        def close(self): self.closed=True
    lanes=[]
    actual_lanes=m.acquire_lane_sockets('CT200',socket_factory=lambda *args:lanes.append(LaneSocket(len(lanes))) or lanes[-1],proc_reader=lambda:[],range_reader=lambda role:None,tuple_reader=lambda role:None)
    assert [sock.address for sock in actual_lanes]==[('127.0.0.1',443),('127.0.0.1',444),('127.0.0.1',445)]
    assert all(not sock.inheritable and sock.options[(m.socket.SOL_SOCKET,m.socket.SO_REUSEADDR)]==0 for sock in actual_lanes)
    with mock.patch.object(m.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFSOCK|0o600,st_uid=0)):
        originals['verify_held_sockets'](actual_lanes)
    actual_lanes[1].inheritable=True
    with mock.patch.object(m.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFSOCK|0o600,st_uid=0)):
        assert code(lambda:originals['verify_held_sockets'](actual_lanes))=='socket_inventory'
    actual_lanes[1].inheritable=False
    with mock.patch.object(m.os,'geteuid',return_value=0,create=True), mock.patch.object(m.os,'stat',side_effect=lambda path:SimpleNamespace(st_ino=41)):
        assert m.validate_guardian_context()=={'euid':0,'net_namespace_matches_pid1':True}
    with mock.patch.object(m.os,'geteuid',return_value=1000,create=True), mock.patch.object(m.os,'stat',side_effect=lambda path:SimpleNamespace(st_ino=41)):
        assert code(m.validate_guardian_context)=='identity_changed'
    with mock.patch.object(m.os,'geteuid',return_value=0,create=True), mock.patch.object(m.os,'stat',side_effect=lambda path:SimpleNamespace(st_ino=41 if path=='/proc/self/ns/net' else 42)):
        assert code(m.validate_guardian_context)=='identity_changed'
    valid_ancestor=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)
    with mock.patch.object(m.os,'stat',return_value=valid_ancestor):
        assert m.assert_fixed_ancestors('/fixture/image') is None
    for unsafe_ancestor in (SimpleNamespace(st_mode=stat.S_IFDIR|0o777,st_uid=0),SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=1000),SimpleNamespace(st_mode=stat.S_IFREG|0o755,st_uid=0)):
        with mock.patch.object(m.os,'stat',return_value=unsafe_ancestor):
            assert code(lambda:m.assert_fixed_ancestors('/fixture/image'))=='identity_changed'
    print('python-control:root-namespace-custody')
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env()
    state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    result=m.handle_action(install_request(role,nonce),[],state,hooks)
    assert result['result']['install_state']=='verified' and result['receipt_sha256']==state['receipt_sha256'] and len(receipts)==2
    inspected=m.handle_action({'role':role,'nonce':nonce,'operation':'inspect'},[],state,hooks)
    assert inspected['result']==state['receipt']['owned']
    released=m.handle_action(release_request(role,nonce,state['receipt_sha256']),[],state,hooks)
    assert released['result']['release_state']=='verified_absent' and state['installed']=='released' and len(calls)==2
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(selected_role='LB115'); state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    assert m.handle_action(install_request(role,nonce),[],state,hooks)['result']['install_state']=='verified'
    assert m.handle_action({'role':role,'nonce':nonce,'operation':'inspect'},[],state,hooks)['result']==state['receipt']['owned']
    assert m.handle_action(release_request(role,nonce,state['receipt_sha256']),[],state,hooks)['result']['release_state']=='verified_absent'
    print('python-control:install-inspect-release')
    for mutation,expected in [('handle','release_not_verified'),('nonce','owned_table_mismatch'),('foreign','release_not_verified'),('flags','owned_table_mismatch'),('chain_extra','owned_table_mismatch')]:
        role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
        m.handle_action(install_request(role,nonce),[],state,hooks)
        if mutation=='handle': next(row['table'] for row in current if 'table' in row and row['table']['name']==m.ROLES[role]['table'])['handle']+=100
        elif mutation=='nonce': next(row['table'] for row in current if 'table' in row and row['table']['name']==m.ROLES[role]['table'])['comment']='vg-maintenance-owner-nonce-'+'f'*32
        elif mutation=='flags': next(row['table'] for row in current if 'table' in row and row['table']['name']==m.ROLES[role]['table'])['flags']=['dormant']
        elif mutation=='chain_extra': next(row['chain'] for row in current if 'chain' in row)['comment']='unexpected'
        else: current.append({'counter':{'family':'inet','table':'foreign_fixture','name':'new','handle':90,'packets':0,'bytes':0}})
        assert code(lambda:m.handle_action(release_request(role,nonce,state['receipt_sha256']),[],state,hooks))==expected
        assert len(calls)==1
    print('python-control:stale-kernel-identity-refusal')
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); current[:]=installed
    state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    assert code(lambda:m.handle_action({'role':role,'nonce':nonce,'operation':'inspect'},[],state,hooks))=='owned_table_present'
    print('python-control:fresh-session-no-adoption')
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(1); current[:]=foreign
    state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    assert code(lambda:m.handle_action(install_request(role,nonce),[],state,hooks))=='install_uncertain'
    assert state['installed']=='uncertain' and len(calls)==1 and any(row.get('table',{}).get('name')==m.ROLES[role]['table'] for row in current)
    assert code(lambda:m.handle_action(release_request(role,nonce,state['receipt_sha256']),[],state,hooks))=='release_not_verified' and len(calls)==1
    print('python-control:uncertain-apply-no-release')
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    with mock.patch.object(m,'verify_held_sockets',side_effect=m.GuardError('socket_inventory')):
        assert code(lambda:m.handle_action(install_request(role,nonce),[],state,hooks))=='socket_inventory'
    assert not calls
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    m.handle_action(install_request(role,nonce),[],state,hooks)
    with mock.patch.object(m,'check_fixed_identity',side_effect=m.GuardError('identity_changed')):
        assert code(lambda:m.handle_action(release_request(role,nonce,state['receipt_sha256']),[],state,hooks))=='identity_changed'
    assert len(calls)==1
    print('python-control:held-fd-and-identity-refusal')
    # Exercise the production foreground loop on EOF after installation: it retains the table and never auto-releases.
    class HeldSocket:
        def __init__(self): self.closed=False
        def close(self): self.closed=True
    class EmptyInput:
        buffer=io.BytesIO(b'')
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); socks=[HeldSocket(),HeldSocket(),HeldSocket()]; locks=[]; sleeps=[]; emitted=[]
    real_handle=m.handle_action
    with mock.patch.object(m,'acquire_lane_sockets',return_value=socks), mock.patch.object(m,'acquire_lock',side_effect=lambda create=True:locks.append(create) or 71), mock.patch.object(m.signal,'SIGALRM',14,create=True), mock.patch.object(m.signal,'alarm',create=True), mock.patch.object(m.time,'sleep',side_effect=lambda seconds:sleeps.append(seconds)), mock.patch.object(m.os,'close'), mock.patch.object(m,'emit',side_effect=lambda value:emitted.append(value)), mock.patch.object(m.sys,'stdin',EmptyInput()), mock.patch.object(m,'handle_action',side_effect=lambda request,held,state:real_handle(request,held,state,hooks)):
        assert m.run_session(role,install_request(role,nonce))==0
    assert locks==[True]
    assert sleeps==[m.SESSION_DEADLINE]
    assert len(calls)==1
    assert all(sock.closed for sock in socks)
    assert any(row.get('table',{}).get('name')==m.ROLES[role]['table'] for row in current)
    # Deadline during nft apply leaves an attempting receipt and no delete/replay path.
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env()
    def expire_after_possible_apply(data):
        calls.append(data); current[:]=installed; raise m.DeadlineError()
    hooks['nft_apply']=expire_after_possible_apply; socks=[HeldSocket(),HeldSocket(),HeldSocket()]; locks=[]; sleeps=[]; emitted=[]
    with mock.patch.object(m,'acquire_lane_sockets',return_value=socks), mock.patch.object(m,'acquire_lock',side_effect=lambda create=True:locks.append(create) or 71), mock.patch.object(m.signal,'SIGALRM',14,create=True), mock.patch.object(m.signal,'alarm',create=True), mock.patch.object(m.time,'sleep',side_effect=lambda seconds:sleeps.append(seconds)), mock.patch.object(m.os,'close'), mock.patch.object(m,'emit',side_effect=lambda value:emitted.append(value)), mock.patch.object(m.sys,'stdin',EmptyInput()), mock.patch.object(m,'handle_action',side_effect=lambda request,held,state:real_handle(request,held,state,hooks)):
        assert m.run_session(role,install_request(role,nonce))==1
    assert len(calls)==1 and not any(item.startswith(b'delete table') for item in calls) and sleeps==[]
    assert emitted and emitted[0]['ok'] is False and emitted[0]['code']=='deadline' and emitted[0]['state']=='uncertain'
    print('python-control:eof-and-deadline-retain')
    # A signal inside an identity helper's broad GuardError retry path remains terminal.
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); socks=[HeldSocket(),HeldSocket(),HeldSocket()]; sleeps=[]; emitted=[]
    class CountingInput:
        def __init__(self): self.buffer=self; self.reads=0
        def readline(self,size=-1): self.reads+=1; return b'{"fixture":"must-not-read-after-deadline"}\n'
    counting=CountingInput()
    def expire_nested(path,*args): m._expired(None,None)
    def nested_preflight(role,nonce,held): originals['check_fixed_identity']('LB115',file_reader=expire_nested)
    real_handle=m.handle_action
    with mock.patch.object(m,'acquire_lane_sockets',return_value=socks), mock.patch.object(m,'acquire_lock',return_value=71), mock.patch.object(m.signal,'SIGALRM',14,create=True), mock.patch.object(m.signal,'alarm',create=True), mock.patch.object(m.time,'sleep',side_effect=lambda seconds:sleeps.append(seconds)), mock.patch.object(m.os,'close'), mock.patch.object(m,'emit',side_effect=lambda value:emitted.append(value)), mock.patch.object(m.sys,'stdin',counting), mock.patch.object(m,'validate_guardian_context',return_value={'euid':0,'net_namespace_matches_pid1':True}), mock.patch.object(m,'fixed_preflight',side_effect=nested_preflight), mock.patch.object(m,'handle_action',side_effect=lambda request,held,state:real_handle(request,held,state,hooks)):
        assert m.run_session(role,install_request(role,nonce))==1
    assert counting.reads==0
    assert not sleeps
    assert emitted==[{'ok':False,'code':'deadline','state':False}]
    assert all(sock.closed for sock in socks)
    print('python-control:nested-deadline-terminal')
    class FirstReadExpired:
        @property
        def buffer(self): return self
        def readline(self,size=-1): m._expired(None,None)
    emitted=[]; alarms=[]
    with mock.patch.object(m.signal,'signal'), mock.patch.object(m.signal,'SIGALRM',14,create=True), mock.patch.object(m.signal,'alarm',side_effect=lambda seconds:alarms.append(seconds),create=True), mock.patch.object(m.sys,'stdin',FirstReadExpired()), mock.patch.object(m,'emit',side_effect=lambda value:emitted.append(value)):
        assert m.main()==1
    assert alarms==[m.SESSION_DEADLINE] and emitted==[{'ok':False,'code':'deadline','state':'uncertain'}]
    print('python-control:first-read-deadline-terminal')
    # Exact production file-custody function with all filesystem operations mocked.
    payload=b'fixture-image'; info=SimpleNamespace(st_mode=stat.S_IFREG|0o755,st_uid=0,st_nlink=1,st_size=len(payload),st_gid=0,st_dev=7,st_ino=8,st_mtime_ns=1,st_ctime_ns=1)
    saved={name:getattr(m.os,name) for name in ('open','fstat','stat','read','close')}; reads=[payload,b'',b'']; open_args=[]
    try:
        m.assert_fixed_ancestors=lambda path:None; m.os.open=lambda *args:open_args.append(args) or 17; m.os.fstat=lambda fd:info; m.os.stat=lambda *args,**kwargs:info; m.os.read=lambda fd,size:reads.pop(0); m.os.close=lambda fd:None
        with mock.patch.object(m.os,'O_NOFOLLOW',0x20000,create=True), mock.patch.object(m.os,'O_CLOEXEC',0x80000,create=True):
            assert m.stable_fixed_file('/fixture/image',hashlib.sha256(payload).hexdigest(),len(payload),0o755,None)==payload
            assert open_args[0][1]&0x20000 and open_args[0][1]&0x80000
        info.st_mode=stat.S_IFREG|0o777; reads[:]=[payload,b'',b'']
        with mock.patch.object(m.os,'O_NOFOLLOW',0x20000,create=True), mock.patch.object(m.os,'O_CLOEXEC',0x80000,create=True):
            assert code(lambda:m.stable_fixed_file('/fixture/image',hashlib.sha256(payload).hexdigest(),len(payload),0o755,None))=='identity_changed'
        info.st_mode=stat.S_IFLNK|0o755; reads[:]=[payload,b'',b'']
        with mock.patch.object(m.os,'O_NOFOLLOW',0x20000,create=True), mock.patch.object(m.os,'O_CLOEXEC',0x80000,create=True):
            assert code(lambda:m.stable_fixed_file('/fixture/image',hashlib.sha256(payload).hexdigest(),len(payload),0o755,None))=='identity_changed'
        info.st_mode=stat.S_IFREG|0o755; info.st_nlink=2; reads[:]=[payload,b'',b'']
        with mock.patch.object(m.os,'O_NOFOLLOW',0x20000,create=True), mock.patch.object(m.os,'O_CLOEXEC',0x80000,create=True):
            assert code(lambda:m.stable_fixed_file('/fixture/image',hashlib.sha256(payload).hexdigest(),len(payload),0o755,None))=='identity_changed'
        info.st_nlink=1; named=SimpleNamespace(st_dev=7,st_ino=99,st_size=len(payload),st_nlink=1,st_mode=stat.S_IFREG|0o755)
        m.os.stat=lambda *args,**kwargs:named; reads[:]=[payload,b'',b'']
        with mock.patch.object(m.os,'O_NOFOLLOW',0x20000,create=True), mock.patch.object(m.os,'O_CLOEXEC',0x80000,create=True):
            assert code(lambda:m.stable_fixed_file('/fixture/image',hashlib.sha256(payload).hexdigest(),len(payload),0o755,None))=='identity_changed'
    finally:
        for name,value in saved.items(): setattr(m.os,name,value)
    print('python-control:fixed-file-mode-and-link-custody')
    # Production lock acquisition rejects unsafe mode/link identity and preserves the held descriptor.
    lockinfo=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_dev=2,st_ino=3)
    with mock.patch.object(m,'trusted_directory',return_value=lockinfo):
        opened=[]; flocked=[]
        with mock.patch.object(m.os,'mkdir'), mock.patch.object(m.os,'fstat',return_value=lockinfo), mock.patch.object(m.os,'stat',return_value=lockinfo), mock.patch.object(m.os,'close'), mock.patch.object(m.os,'O_NOFOLLOW',0x20000,create=True), mock.patch.object(m.os,'O_CLOEXEC',0x80000,create=True):
            assert m.acquire_lock(lambda *args:opened.append(args) or 29,lambda *args:flocked.append(args),True)==29 and len(flocked)==1
            assert opened[0][0]==m.LOCK_PATH and opened[0][1]&getattr(m.os,'O_NOFOLLOW',0) and opened[0][1]&getattr(m.os,'O_CLOEXEC',0) and opened[0][2]==0o600
            lockinfo.st_nlink=2
            assert code(lambda:m.acquire_lock(lambda *args:29,lambda *args:None,True))=='lock_custody'
    print('python-control:lock-descriptor-custody')
    # Receipt updates remain bound to the held inode and flush both data and parent directory.
    receipt_info=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_dev=4,st_ino=5)
    named_info=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_dev=4,st_ino=5)
    saved={name:getattr(m.os,name) for name in ('fstat','stat','lseek','ftruncate','write','fsync','open','close')}; writes=[]; synced=[]
    try:
        m.os.fstat=lambda fd:receipt_info; m.os.stat=lambda *args,**kwargs:named_info; m.os.lseek=lambda *args:0; m.os.ftruncate=lambda *args:None
        m.os.write=lambda fd,data:writes.append(bytes(data)) or len(data); m.os.fsync=lambda fd:synced.append(fd); m.os.open=lambda *args:88; m.os.close=lambda fd:None
        value={'schema':'maintenance-guardian-receipt-v1','install_state':'verified'}
        assert m.write_receipt_fd(7,m.RECEIPT_DIR+'/fixture.json',value)==m.sha((m.canonical(value)+'\n').encode('ascii'))
        assert b''.join(writes)==(m.canonical(value)+'\n').encode('ascii') and 7 in synced and 88 in synced
        writes[:]=[]; named_info.st_ino=6
        assert code(lambda:m.write_receipt_fd(7,m.RECEIPT_DIR+'/fixture.json',value))=='receipt_custody'
        assert not writes
    finally:
        for name,value in saved.items(): setattr(m.os,name,value)
    print('python-control:receipt-held-inode-update')
    # Failed durable verified-receipt update is terminal uncertain and release must never delete.
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    def fail_receipt_update(data): raise m.GuardError('receipt_custody')
    hooks['receipt_update']=fail_receipt_update
    assert code(lambda:m.handle_action(install_request(role,nonce),[],state,hooks))=='receipt_custody'
    assert state['installed']=='uncertain' and 'receipt' not in state and len(calls)==1
    assert code(lambda:m.handle_action(release_request(role,nonce,state['receipt_sha256']),[],state,hooks))=='release_not_verified'
    assert len(calls)==1 and not any(item.startswith(b'delete table') for item in calls)
    print('python-control:receipt-update-failure-terminal')
    # Actual production inspect/release paths use descriptor-vs-name custody and terminalize each loss.
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    m.handle_action(install_request(role,nonce),[],state,hooks)
    custody=hooks['custody_fs']; custody.named_lock=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_dev=2,st_ino=999)
    assert code(lambda:m.handle_action({'role':role,'nonce':nonce,'operation':'inspect'},[],state,hooks))=='lock_custody'
    assert state['installed']=='uncertain'
    assert code(lambda:m.handle_action(release_request(role,nonce,state['receipt_sha256']),[],state,hooks))=='release_not_verified' and len(calls)==1
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    m.handle_action(install_request(role,nonce),[],state,hooks)
    hooks['custody_fs'].data=b'{}\n'
    assert code(lambda:m.handle_action({'role':role,'nonce':nonce,'operation':'inspect'},[],state,hooks))=='receipt_custody'
    assert state['installed']=='uncertain' and len(calls)==1
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    m.handle_action(install_request(role,nonce),[],state,hooks); hooks['custody_fs'].named_receipt=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_dev=3,st_ino=999)
    assert code(lambda:m.handle_action({'role':role,'nonce':nonce,'operation':'inspect'},[],state,hooks))=='receipt_custody' and state['installed']=='uncertain'
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    m.handle_action(install_request(role,nonce),[],state,hooks); current.append({'counter':{'family':'inet','table':'foreign_fixture','name':'changed','handle':91,'packets':0,'bytes':0}})
    assert code(lambda:m.handle_action({'role':role,'nonce':nonce,'operation':'inspect'},[],state,hooks))=='foreign_rules_changed' and state['installed']=='uncertain'
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    m.handle_action(install_request(role,nonce),[],state,hooks)
    with mock.patch.object(m,'verify_held_sockets',side_effect=m.GuardError('socket_inventory')):
        assert code(lambda:m.handle_action({'role':role,'nonce':nonce,'operation':'inspect'},[],state,hooks))=='socket_inventory'
    assert state['installed']=='uncertain'
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    m.handle_action(install_request(role,nonce),[],state,hooks)
    with mock.patch.object(m,'check_fixed_identity',side_effect=m.GuardError('identity_changed')):
        assert code(lambda:m.handle_action({'role':role,'nonce':nonce,'operation':'inspect'},[],state,hooks))=='identity_changed'
    assert state['installed']=='uncertain'
    for mutation in ('owned-handle','owned-extra'):
        role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(); state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
        m.handle_action(install_request(role,nonce),[],state,hooks)
        if mutation=='owned-handle': next(row['chain'] for row in current if 'chain' in row and row['chain']['name']=='input')['handle']+=100
        else: current.append({'set':{'family':'inet','table':m.ROLES[role]['table'],'name':'unexpected','handle':99}})
        assert code(lambda:m.handle_action({'role':role,'nonce':nonce,'operation':'inspect'},[],state,hooks))=='owned_table_mismatch'
        assert state['installed']=='uncertain'
        assert code(lambda:m.handle_action(release_request(role,nonce,state['receipt_sha256']),[],state,hooks))=='release_not_verified'
        assert len(calls)==1 and not any(item.startswith(b'delete table') for item in calls)
    print('python-control:installed-inspection-custody')
    # The production bounded HTTPS client consumes the retained socket for each LB role lane.
    body=b'{"status":"ok"}'; raw=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: keep-alive\r\n\r\n'+body
    class FakeSocket:
        def __init__(self,index,response=raw): self.index=index; self.response=response; self.offset=0; self.address=('127.0.0.1',443+index); self.peer=None; self.sent=b''; self.timeout=None
        def getsockname(self): return self.address
        def settimeout(self,value): self.timeout=value
        def connect(self,address): self.peer=address
        def getpeername(self):
            if self.peer is None: raise OSError('not connected')
            return self.peer
        def sendall(self,data): self.sent+=data
        def recv(self,size): result=self.response[self.offset:self.offset+size]; self.offset+=len(result); return result
        def fileno(self): return 100+self.index
        def set_inheritable(self,value): assert value is False
        def get_inheritable(self): return False
        def getsockopt(self,level,option): return 0
    lb_lanes=[FakeSocket(i) for i in range(3)]
    class FakeTLS:
        def wrap_socket(self,sock,server_hostname): assert server_hostname==m.ROLES['LB115']['ip']; return sock
    with mock.patch.object(m.ssl,'create_default_context',return_value=FakeTLS()):
        results=[m.get_fixed_json(lb_lanes,8443,'/healthz',index) for index in range(3)]
    assert [item['source_port'] for item in results]==[443,444,445] and all(sock.peer==('127.0.0.1',8443) and b'Connection: keep-alive' in sock.sent for sock in lb_lanes)
    assert code(lambda:m.get_fixed_json(lb_lanes,8443,'/invented',0))=='diagnostic_failed'
    assert code(lambda:m.get_fixed_json(lb_lanes,8443,'/healthz',3))=='diagnostic_failed'
    oversized=FakeSocket(0,b'HTTP/1.1 200 OK\r\nContent-Length: 65537\r\nConnection: keep-alive\r\n\r\n')
    with mock.patch.object(m.ssl,'create_default_context',return_value=FakeTLS()):
        assert code(lambda:m.get_fixed_json([oversized],8443,'/healthz',0))=='diagnostic_failed'
    print('python-control:fixed-get-all-lb-lanes')
    import socket as fixture_socket, struct
    def v4hex(value): return fixture_socket.inet_aton(value)[::-1].hex().upper()
    def v6hex(value):
        raw=fixture_socket.inet_pton(fixture_socket.AF_INET6,value)
        return b''.join(struct.pack('<I',int.from_bytes(raw[i:i+4],'big')) for i in range(0,16,4)).hex().upper()
    def proc_row(local,local_port,remote,remote_port,state,inode):
        return f'  0: {local}:{local_port:04X} {remote}:{remote_port:04X} {state:02X} 00000000:00000000 00:00000000 00000000 0 0 {inode}\n'
    header='  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n'
    port=8443; low,high=32768,60999
    listener4=proc_row('00000000',port,'00000000',0,0x0A,10)
    server4=proc_row(v4hex('10.0.0.10'),port,v4hex('10.0.0.20'),49152,0x01,11)
    def tuple_reader(lines4='',lines6=''):
        data={'/proc/net/tcp':header+lines4,'/proc/net/tcp6':header+lines6}
        return lambda path,mode,encoding:io.StringIO(data[path])
    # Successful retained GET lanes are the only exact reverse tuples allowed through inspect/release.
    role,nonce,foreign,current,installed,calls,receipts,digest,hooks=env(selected_role='LB115')
    state={'role':role,'nonce':nonce,'installed':False,'receipt_sha256':None,'lock_fd':71}
    roundtrip_lanes=[FakeSocket(i) for i in range(3)]
    with mock.patch.object(m.ssl,'create_default_context',return_value=FakeTLS()):
        m.get_fixed_json(roundtrip_lanes,8443,'/healthz',0)
    reverse4=proc_row(v4hex('127.0.0.1'),8443,v4hex('127.0.0.1'),443,0x01,31)
    hooks['process_tuples']=lambda selected,held:originals['process_protected_client_tuples'](selected,reader=tuple_reader(listener4+reverse4),held=held)
    socket_info=SimpleNamespace(st_mode=stat.S_IFSOCK|0o600,st_uid=0)
    tuple_observation=lambda selected,held=None:originals['process_protected_client_tuples'](selected,reader=tuple_reader(listener4+reverse4),held=held)
    with mock.patch.object(m,'fixed_preflight',new=originals['fixed_preflight']), mock.patch.object(m,'process_protected_client_tuples',side_effect=tuple_observation), mock.patch.object(m,'verify_held_sockets',new=originals['verify_held_sockets']), mock.patch.object(m,'check_fixed_identity',return_value=None), mock.patch.object(m,'ephemeral_range',return_value=(low,high)), mock.patch.object(m,'nft_ruleset',side_effect=lambda:list(current)), mock.patch.object(m,'listening_port_inventory',return_value={}), mock.patch.object(m.os,'fstat',return_value=socket_info):
        preflight=m.handle_action({'role':role,'nonce':nonce,'operation':'preflight'},roundtrip_lanes,state)
        assert preflight['result']['applying'] is False and preflight['result']['held_source_ports']==[443,444,445]
        m.handle_action(install_request(role,nonce),roundtrip_lanes,state,hooks)
        assert m.handle_action({'role':role,'nonce':nonce,'operation':'inspect'},roundtrip_lanes,state,hooks)['result']==state['receipt']['owned']
        assert m.handle_action(release_request(role,nonce,state['receipt_sha256']),roundtrip_lanes,state,hooks)['result']['release_state']=='verified_absent'
        wrong_source=proc_row(v4hex('127.0.0.1'),8443,v4hex('127.0.0.1'),444,0x01,32)
        assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(listener4+wrong_source),held=roundtrip_lanes))=='socket_conflict'
        wrong_state=proc_row(v4hex('127.0.0.1'),8443,v4hex('127.0.0.1'),443,0x02,37)
        assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(listener4+wrong_state),held=roundtrip_lanes))=='socket_conflict'
        wrong_peer=proc_row(v4hex('127.0.0.2'),8443,v4hex('127.0.0.1'),443,0x01,33)
        assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(listener4+wrong_peer),held=roundtrip_lanes))=='socket_conflict'
        listener6_fixture=proc_row('00000000000000000000000000000000',8443,'00000000000000000000000000000000',0,0x0A,36)
        mapped_reverse=proc_row(v6hex('::ffff:127.0.0.1'),8443,v6hex('::ffff:127.0.0.1'),443,0x01,34)
        assert originals['process_protected_client_tuples']('LB115',reader=tuple_reader(lines6=listener6_fixture+mapped_reverse),held=roundtrip_lanes)==()
        mapped_samehost=proc_row(v6hex('::ffff:127.0.0.1'),8443,v6hex('::ffff:10.0.0.115'),49152,0x01,35)
        assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(lines6=listener6_fixture+mapped_samehost),held=roundtrip_lanes))=='socket_conflict'
        with mock.patch.object(m.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFSOCK|0o600,st_uid=1000)):
            assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(listener4+reverse4),held=roundtrip_lanes))=='socket_inventory'
    print('python-control:get-inspect-release-held-reverse-tuple')
    with mock.patch.object(m,'ephemeral_range',return_value=(low,high)):
        assert originals['process_protected_client_tuples']('LB115',reader=tuple_reader(listener4))==()
        assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(listener4+server4)))=='socket_conflict'
        own_ip_alias=proc_row(v4hex('10.0.0.115'),port,v4hex('10.0.0.116'),49152,0x01,38)
        assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(listener4+own_ip_alias)))=='socket_conflict'
        loop4=proc_row(v4hex('127.0.0.1'),port,v4hex('127.0.0.1'),49152,0x01,12)
        assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(listener4+loop4)))=='socket_conflict'
        loop4_other=proc_row(v4hex('127.0.0.2'),port,v4hex('127.0.0.2'),49152,0x01,13)
        assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(listener4+loop4_other)))=='socket_conflict'
        samehost4=proc_row(v4hex('10.0.0.115'),port,v4hex('10.0.0.115'),49152,0x01,14)
        assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(listener4+samehost4)))=='socket_conflict'
        listener6=proc_row('00000000000000000000000000000000',port,'00000000000000000000000000000000',0,0x0A,20)
        loop6=proc_row(v6hex('::1'),port,v6hex('::1'),49152,0x01,21)
        assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(lines6=listener6+loop6)))=='socket_conflict'
        mapped6=proc_row(v6hex('::ffff:10.0.0.115'),port,v6hex('::ffff:127.0.0.2'),49152,0x01,23)
        assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(lines6=listener6+mapped6)))=='socket_conflict'
        syn6=proc_row(v6hex('::1'),port,v6hex('2001:db8::2'),49152,0x02,22)
        assert code(lambda:originals['process_protected_client_tuples']('LB115',reader=tuple_reader(lines6=syn6)))=='socket_conflict'
    print('python-control:protected-client-tuple-classification')

    paused_request={'schema':'maintenance-guard-request-v1','role':'CT200','operation':'preflight','nonce':NONCE,'phase':'agent_paused'}
    assert m.parse_request(json.dumps(paused_request,separators=(',',':')).encode()+b'\n')==paused_request
    for bad in [dict(paused_request,phase='active'),dict(paused_request,phase='future'),dict(paused_request,role='LB115'),dict(paused_request,operation='inspect'),dict(paused_request,operation='get')]:
        assert code(lambda:m.parse_request(json.dumps(bad,separators=(',',':')).encode()+b'\n'))=='phase_invalid'
    operation_requests=[{'role':'CT200','nonce':NONCE,'operation':operation,'phase':'agent_paused'} for operation in ('get','inspect','install','release')]
    operation_requests.append({'role':'LB115','nonce':NONCE,'operation':'preflight','phase':'agent_paused'})
    for bad in operation_requests+[dict(paused_request,phase='future')]:
        effects=[]
        with mock.patch.object(m,'acquire_lane_sockets',side_effect=lambda role:effects.append(role) or []):
            assert code(lambda:m.run_session(bad['role'],bad))=='phase_invalid'
        assert effects==[]
    assert code(lambda:m.handle_action({'role':'CT200','nonce':NONCE,'operation':'get','plane':'ct_node_agent'},[],{'role':'CT200','nonce':NONCE,'phase':'agent_paused'}))=='phase_invalid'
    print('python-control:paused-phase-request-boundaries')

    paused_mode={'name':'positive','agent_calls':0,'native_calls':{},'ip_calls':0,'file_calls':{},'cgroup_calls':0,'commands':[]}
    paused_foreign=[{'metainfo':{'version':'1.0.9','release_name':'fixture','json_schema_version':1}},{'table':{'family':'inet','name':'foreign_fixture','handle':1}}]
    def paused_safe_child(argv,data=None,timeout=m.CHILD_TIMEOUT,env=None,popen_factory=None):
        paused_mode['commands'].append(tuple(argv))
        if argv[0]=='/usr/bin/ip':
            paused_mode['ip_calls']+=1
            address='10.0.0.58' if not (paused_mode['name']=='address_drift' and paused_mode['ip_calls']>1) else '10.0.0.59'
            return 0,json.dumps([{'addr_info':[{'local':address}]}]).encode()
        assert argv[0]=='/usr/bin/systemctl'
        unit=argv[-1]
        if unit=='vram-governor-node-agent.service':
            paused_mode['agent_calls']+=1; call=paused_mode['agent_calls']; name=paused_mode['name']
            active,sub,pid,job,cgroup,dropins='inactive','dead','0','',m.AGENT_SYSTEMD_CGROUP,''
            invocation=''
            if name=='agent_active': active='active'; sub='running'; pid='315'
            if name=='agent_restarting': active='activating'; sub='auto-restart'
            if name=='residual_pid': pid='315'
            if name=='pending_job': job='12 start'
            if name=='dropin': dropins='/etc/systemd/system/vram-governor-node-agent.service.d/x.conf'
            if name=='wrong_cgroup': cgroup='/system.slice/other.service'
            if name=='agent_invocation_drift' and call>=2: invocation='b'*32
            fields={'LoadState':'loaded','ActiveState':active,'SubState':sub,'MainPID':pid,'InvocationID':invocation,'ExecMainStartTimestampMonotonic':'','Job':job,'ControlGroup':cgroup,'DropInPaths':dropins}
        else:
            assert unit in m.CT_NATIVE_UNITS
            calls=paused_mode['native_calls']; calls[unit]=calls.get(unit,0)+1; call=calls[unit]; name=paused_mode['name']
            active,sub,pid='active','running',str({'llama-server.service':219,'comfyui.service':230,'comfy-harness.service':311,'vram-governor-runtime-tunnel.service':316}[unit])
            invocation={'llama-server.service':'1'*32,'comfyui.service':'2'*32,'comfy-harness.service':'3'*32,'vram-governor-runtime-tunnel.service':'4'*32}[unit]
            if name=='native_inactive' and unit=='comfyui.service': active='inactive'; sub='dead'; pid='0'
            if name=='native_invocation_drift' and unit=='comfyui.service' and call>=2: invocation='f'*32
            fields={'LoadState':'loaded','ActiveState':active,'SubState':sub,'MainPID':pid,'InvocationID':invocation,'ExecMainStartTimestampMonotonic':'1000'}
        selected=argv[3].split('=',1)[1].split(',')
        return 0,('\n'.join(key+'='+fields[key] for key in selected)+'\n').encode()
    sizes={m.AGENT_IMAGE_PIN[1]:b'I'*m.AGENT_IMAGE_PIN[1],m.AGENT_UNIT_PIN[1]:b'U'*m.AGENT_UNIT_PIN[1],m.AGENT_CONFIG_PIN[1]:b'C'*m.AGENT_CONFIG_PIN[1]}
    def paused_file_reader(path,digest,size,mode,gid):
        expected={m.AGENT_IMAGE_PATH:(m.AGENT_IMAGE_PIN,0o755,0),m.AGENT_UNIT_PATH:(m.AGENT_UNIT_PIN,0o644,0),m.AGENT_CONFIG_PATH:(m.AGENT_CONFIG_PIN,0o640,989)}
        assert (digest,mode,gid)==(expected[path][0][0],expected[path][1],expected[path][2]) and size==expected[path][0][1]
        paused_mode['file_calls'][path]=paused_mode['file_calls'].get(path,0)+1
        if paused_mode['name']=='artifact_drift' and path==m.AGENT_CONFIG_PATH and paused_mode['file_calls'][path]>1: return b'Z'*size
        return sizes[size]
    def trusted_stat(path,*args,**kwargs):
        if path in ('/proc/self/ns/net','/proc/1/ns/net','/proc/self/ns/cgroup','/proc/1/ns/cgroup'): return SimpleNamespace(st_ino=41)
        if path in ('/usr','/usr/bin'): return SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)
        if path in ('/usr/bin/ip','/usr/bin/systemctl'): return SimpleNamespace(st_mode=stat.S_IFREG|0o755,st_uid=0,st_nlink=1)
        raise AssertionError('unexpected stat path')
    def reset_paused(name='positive'):
        paused_mode.update({'name':name,'agent_calls':0,'native_calls':{},'ip_calls':0,'file_calls':{},'cgroup_calls':0,'commands':[]})
    def paused_check_identity(role,phase='active'):
        return originals['check_fixed_identity'](role,file_reader=paused_file_reader,phase=phase)
    def paused_context():
        return (mock.patch.object(m,'safe_child',side_effect=paused_safe_child),
                mock.patch.object(m,'check_fixed_identity',side_effect=paused_check_identity),
                mock.patch.object(m,'fixed_preflight',new=originals['fixed_preflight']),
                mock.patch.object(m,'inspect_agent_cgroup',side_effect=lambda: (paused_mode.__setitem__('cgroup_calls',paused_mode['cgroup_calls']+1) or ('absent' if (paused_mode['name']=='cgroup_drift' and paused_mode['cgroup_calls']>1) or (paused_mode['name']=='cgroup_appears' and paused_mode['cgroup_calls']==1) else 'empty'))),
                mock.patch.object(m.os,'geteuid',return_value=0,create=True),
                mock.patch.object(m.os,'stat',side_effect=trusted_stat))
    def enter_all(contexts,index=0):
        if index==len(contexts): return run_current()
        with contexts[index]: return enter_all(contexts,index+1)
    class PausedLane:
        def __init__(self): self.closed=False
        def close(self): self.closed=True
    lanes=[PausedLane(),PausedLane(),PausedLane()]
    def run_current():
        effects=[]; emitted=[]
        with mock.patch.object(m,'acquire_lane_sockets',side_effect=lambda role:effects.append(('sockets',role)) or lanes), \
             mock.patch.object(m,'acquire_lock',side_effect=lambda **kwargs:effects.append(('lock',kwargs)) or 99), \
             mock.patch.object(m,'ephemeral_range',side_effect=lambda role:effects.append(('range',role))), \
             mock.patch.object(m,'process_protected_client_tuples',side_effect=lambda role,held=None:effects.append(('tuples',role,held is lanes))), \
             mock.patch.object(m,'nft_ruleset',return_value=paused_foreign), \
             mock.patch.object(m,'verify_held_sockets',side_effect=lambda held:effects.append(('held',held is lanes))), \
             mock.patch.object(m,'listening_port_inventory',return_value={}), \
             mock.patch.object(m,'emit',side_effect=emitted.append), \
             mock.patch.object(m.signal,'SIGALRM',14,create=True), mock.patch.object(m.signal,'alarm',create=True):
            rc=m.run_session('CT200',paused_request)
        assert rc==0 and len(emitted)==1 and emitted[0]['ok'] is True and emitted[0]['result']['identity']['phase']=='agent_paused'
        assert all(event[0] not in ('lock',) for event in effects) and ('sockets','CT200') in effects and all(lane.closed for lane in lanes)
        assert paused_mode['cgroup_calls']==4 and paused_mode['agent_calls']==4 and paused_mode['ip_calls']==4
        return emitted[0]['result']
    reset_paused()
    positive=enter_all(paused_context())
    assert positive['identity']['agent']['pending_job'] is False and positive['identity']['agent']['cgroup_state']=='empty'
    assert set(positive['identity']['native_units'])==set(m.CT_NATIVE_UNITS) and positive['applying'] is False
    print('python-control:paused-agent-production-preflight-positive')

    for name in ('agent_active','agent_restarting','residual_pid','pending_job','dropin','wrong_cgroup','agent_invocation_drift','native_inactive','native_invocation_drift','address_drift','artifact_drift','cgroup_drift','cgroup_appears'):
        reset_paused(name)
        with paused_context()[0], paused_context()[1], paused_context()[2], paused_context()[3], paused_context()[4], paused_context()[5]:
            try: observed=code(lambda:originals['check_fixed_identity']('CT200',file_reader=paused_file_reader,phase='agent_paused'))
            except AssertionError:
                failure=AssertionError(); failure.code='fixture_no_guard_'+name; raise failure
            if observed!='identity_changed':
                failure=AssertionError(); failure.code='fixture_'+name; raise failure
    reset_paused('final_identity_drift')
    real_check=paused_check_identity
    def final_drift_check(role,file_reader=m.stable_fixed_file,phase='active'):
        result=real_check(role,phase)
        if paused_mode['name']=='final_identity_drift' and paused_mode['agent_calls']>=4:
            result=dict(result); result['identity_drift_fixture']=True
        return result
    with paused_context()[0], paused_context()[1], paused_context()[2], paused_context()[3], paused_context()[4], paused_context()[5], \
         mock.patch.object(m,'check_fixed_identity',side_effect=final_drift_check), mock.patch.object(m,'ephemeral_range',return_value=None), \
         mock.patch.object(m,'process_protected_client_tuples',return_value=()), mock.patch.object(m,'nft_ruleset',return_value=paused_foreign), \
         mock.patch.object(m,'verify_held_sockets',return_value=None), mock.patch.object(m,'listening_port_inventory',return_value={}):
        try: observed=code(lambda:m.fixed_preflight('CT200',NONCE,lanes,phase='agent_paused'))
        except AssertionError:
            failure=AssertionError(); failure.code='fixture_final_preflight_no_guard_'+str(paused_mode['agent_calls']); raise failure
        if observed!='identity_changed':
            failure=AssertionError(); failure.code='fixture_final_preflight_'+observed; raise failure
    print('python-control:paused-agent-production-preflight-drift-refusals')

    # A failed paused preflight is terminal: a buffered default-phase install frame must never be read or applied.
    reset_paused('agent_active')
    followup=install_request('CT200',NONCE)
    followup['schema']='maintenance-guard-request-v1'
    followup_bytes=(json.dumps(followup,separators=(',',':'))+'\n').encode('ascii')
    followup_input=io.BytesIO(followup_bytes)
    class FollowupInput: buffer=followup_input
    effects=[]; emitted=[]; session_lanes=[PausedLane(),PausedLane(),PausedLane()]
    receipt_calls=[]
    def blocked_receipt(*args,**kwargs): receipt_calls.append((args,kwargs)); raise AssertionError('receipt action after failed paused preflight')
    with paused_context()[0], paused_context()[1], paused_context()[2], paused_context()[3], paused_context()[4], paused_context()[5], \
         mock.patch.object(m,'acquire_lane_sockets',side_effect=lambda role:effects.append(('sockets',role)) or session_lanes), \
         mock.patch.object(m,'acquire_lock',side_effect=lambda **kwargs:effects.append(('lock',kwargs)) or 99), \
         mock.patch.object(m,'create_receipt_fd',side_effect=blocked_receipt), mock.patch.object(m,'write_receipt_fd',side_effect=blocked_receipt), \
         mock.patch.object(m,'emit',side_effect=emitted.append), mock.patch.object(m.sys,'stdin',FollowupInput()), \
         mock.patch.object(m.signal,'SIGALRM',14,create=True), mock.patch.object(m.signal,'alarm',create=True), mock.patch.object(m.os,'close'):
        result=m.run_session('CT200',paused_request)
    assert result==1 and emitted==[{'ok':False,'code':'identity_changed','state':False}]
    assert followup_input.tell()==0 and not receipt_calls and all(event[0]!='lock' for event in effects)
    assert effects==[('sockets','CT200')] and all(lane.closed for lane in session_lanes)
    assert paused_mode['agent_calls']==1 and all(command[0] in ('/usr/bin/ip','/usr/bin/systemctl') and (command[0]!='/usr/bin/systemctl' or command[1]=='show') for command in paused_mode['commands'])
    print('python-control:paused-preflight-failure-terminal-loop')

    root_info=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0,st_dev=9,st_ino=10)
    file_infos={name:SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_uid=0,st_nlink=1,st_dev=9,st_ino=index+20) for index,name in enumerate(('cgroup.procs','cgroup.threads'))}
    file_infos['unexpected']=SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_uid=0,st_nlink=1,st_dev=9,st_ino=30)
    class CgroupEntry:
        def __init__(self,name,symlink=False,directory=False): self.name=name; self.symlink=symlink; self.directory=directory
        def is_symlink(self): return self.symlink
        def is_dir(self,follow_symlinks=False): return self.directory
        def stat(self,follow_symlinks=False): return file_infos[self.name]
    class CgroupScan:
        def __init__(self,entries): self.entries=entries
        def __enter__(self): return iter(self.entries)
        def __exit__(self,*args): return False
    def cgroup_probe(read_value=b'',entries=None,change_root=False,root_override=None,change_entries=False):
        entries=[CgroupEntry('cgroup.procs'),CgroupEntry('cgroup.threads')] if entries is None else entries
        root_calls={'n':0}; reads={}; fd_paths={}; next_fd={'n':1}; scan_calls={'n':0}
        def stat_fn(path,follow_symlinks=False):
            if path in ('/sys','/sys/fs','/sys/fs/cgroup','/sys/fs/cgroup/system.slice'): return SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)
            if path==m.AGENT_CGROUP_PATH:
                root_calls['n']+=1
                if root_override is not None: return root_override
                if change_root and root_calls['n']>1: return SimpleNamespace(st_mode=root_info.st_mode,st_uid=0,st_dev=9,st_ino=99)
                return root_info
            for name,info in file_infos.items():
                if path==m.os.path.join(m.AGENT_CGROUP_PATH,name): return info
            raise AssertionError('unexpected cgroup stat path')
        def open_fn(path,flags):
            fd=next_fd['n']; next_fd['n']+=1; fd_paths[fd]=path; return fd
        def read_fn(fd,size):
            path=fd_paths[fd]; count=reads.get(path,0); reads[path]=count+1
            return read_value if count==0 else b''
        def fstat_fn(fd): return file_infos[m.os.path.basename(fd_paths[fd])]
        def scan_fn(path):
            scan_calls['n']+=1
            selected=entries+[CgroupEntry('unexpected')] if change_entries and scan_calls['n']>1 else entries
            return CgroupScan(selected)
        try:
            with mock.patch.object(m.os,'stat',side_effect=stat_fn), mock.patch.object(m.os.path,'join',new=posixpath.join), mock.patch.object(m.os.path,'basename',new=posixpath.basename):
                return m.inspect_agent_cgroup(stat_fn=stat_fn,scandir_fn=scan_fn,namespace_check=lambda:True,ancestor_check=m.assert_fixed_ancestors,open_fn=open_fn,read_fn=read_fn,fstat_fn=fstat_fn,close_fn=lambda fd:None)
        except m.GuardError as exc: return exc.code
    def expect_cgroup(label,call,expected):
        try: actual=call()
        except AssertionError:
            failure=AssertionError(); failure.code='fixture_cgroup_assertion_'+label; raise failure
        if actual!=expected:
            failure=AssertionError(); failure.code='fixture_cgroup_'+label+'_'+str(actual); raise failure
    expect_cgroup('empty',lambda:cgroup_probe(),'empty')
    expect_cgroup('descendant',lambda:cgroup_probe(entries=[CgroupEntry('cgroup.procs'),CgroupEntry('cgroup.threads'),CgroupEntry('child',directory=True)]),'identity_changed')
    expect_cgroup('missing_member',lambda:cgroup_probe(entries=[CgroupEntry('cgroup.procs')]),'identity_changed')
    expect_cgroup('linked_member',lambda:cgroup_probe(entries=[CgroupEntry('cgroup.procs',symlink=True),CgroupEntry('cgroup.threads')]),'identity_changed')
    expect_cgroup('entry_inventory_drift',lambda:cgroup_probe(change_entries=True),'identity_changed')
    expect_cgroup('linked_root',lambda:cgroup_probe(root_override=SimpleNamespace(st_mode=stat.S_IFLNK|0o777,st_uid=0,st_dev=9,st_ino=10)),'identity_changed')
    expect_cgroup('writable_root',lambda:cgroup_probe(root_override=SimpleNamespace(st_mode=stat.S_IFDIR|0o777,st_uid=0,st_dev=9,st_ino=10)),'identity_changed')
    expect_cgroup('foreign_root_owner',lambda:cgroup_probe(root_override=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=1000,st_dev=9,st_ino=10)),'identity_changed')
    expect_cgroup('residual_members',lambda:cgroup_probe(read_value=b'315\n'),'identity_changed')
    expect_cgroup('replaced_root',lambda:cgroup_probe(change_root=True),'identity_changed')
    saved_thread_info=file_infos['cgroup.threads']
    for bad_file in (SimpleNamespace(st_mode=stat.S_IFREG|0o646,st_uid=0,st_nlink=1,st_dev=9,st_ino=21),SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_uid=1000,st_nlink=1,st_dev=9,st_ino=21),SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_uid=0,st_nlink=2,st_dev=9,st_ino=21)):
        file_infos['cgroup.threads']=bad_file
        expect_cgroup('unsafe_member_metadata',lambda:cgroup_probe(),'identity_changed')
    file_infos['cgroup.threads']=saved_thread_info
    def absent_stat(path,follow_symlinks=False):
        if path in ('/sys','/sys/fs','/sys/fs/cgroup','/sys/fs/cgroup/system.slice'): return SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)
        raise FileNotFoundError(path)
    with mock.patch.object(m.os,'stat',side_effect=absent_stat), mock.patch.object(m.os.path,'join',new=posixpath.join):
        assert m.inspect_agent_cgroup(stat_fn=absent_stat,namespace_check=lambda:True,ancestor_check=m.assert_fixed_ancestors)=='absent'
        expect_cgroup('namespace_mismatch',lambda:code(lambda:m.inspect_agent_cgroup(stat_fn=absent_stat,namespace_check=lambda:m.fail('identity_changed'),ancestor_check=m.assert_fixed_ancestors)),'identity_changed')
    expect_cgroup('namespace_match',lambda:m.validate_agent_cgroup_namespace(lambda path:SimpleNamespace(st_ino=50)),True)
    expect_cgroup('namespace_mismatch',lambda:code(lambda:m.validate_agent_cgroup_namespace(lambda path:SimpleNamespace(st_ino=50 if path.endswith('self/ns/cgroup') else 51))),'identity_changed')
    print('python-control:paused-agent-cgroup-custody')
    print('python guardian controls passed')
except Exception:
    raise
finally:
    for name,value in originals.items(): setattr(m,name,value)`;

if (!VERIFY_MODE) test(TEST_NAMES[0], () => {
  const lb = buildCombinedInstallPlan({ role: "LB115", ownershipNonce: NONCE });
  const ct = buildCombinedInstallPlan({ role: "CT200", ownershipNonce: NONCE });
  assert.equal(lb.sourcePorts.join(","), "443,444,445");
  assert.equal(ct.sourcePorts.join(","), "443,444,445");
  for (const plan of [lb, ct]) {
    assert.match(plan.transaction, /^create table inet /);
    assert.equal(plan.transaction.endsWith("\n"), true);
    assert.doesNotMatch(plan.transaction, /(?:^|\n)(?:delete|flush|replace|insert)\s/);
    const lines = plan.transaction.trimEnd().split("\n");
    const inputLaneIndices = lines.flatMap((line, index) => line.includes(` ${plan.table} input `) && /tcp sport (?:443|444|445) tcp dport \d+ accept$/.test(line) ? [index] : []);
    const inputDropIndices = lines.flatMap((line, index) => line.includes(` ${plan.table} input `) && / tcp dport \d+ drop$/.test(line) ? [index] : []);
    assert.ok(inputLaneIndices.length > 0 && inputDropIndices.length > 0 && Math.max(...inputLaneIndices) < Math.min(...inputDropIndices));
    for (const source of [443, 444, 445]) for (const destination of plan.validationDestinationPorts) {
      const accept = lines.findIndex((line) => line.includes(` ${plan.table} output `) && line.includes("meta skuid 0") && line.includes(`tcp sport ${source} tcp dport ${destination} accept`));
      const drop = lines.findIndex((line) => line.includes(` ${plan.table} output `) && !line.includes("meta skuid") && line.includes(`tcp sport ${source} tcp dport ${destination} drop`));
      assert.ok(accept >= 0 && drop > accept);
    }
  }
  for (const port of [443, 444, 445]) {
    const lines = lb.transaction.split("\n");
    assert.ok(lines.some((line) => line.includes(`tcp sport ${port} tcp dport 8443 accept`)));
    assert.ok(ct.transaction.includes(`tcp sport ${port} tcp dport 8080 accept`));
  }
  for (const plan of [lb, ct]) {
    for (const destination of plan.validationDestinationPorts) {
    for (const source of [443, 444, 445]) {
      const base = { iifname: "lo", oifname: "lo", uid: 0, ip_saddr: "127.0.0.1", ip_daddr: "127.0.0.1", tcp_sport: source, tcp_dport: destination };
      assert.equal(packetDecision(plan, base), "accept");
      assert.equal(packetDecision(plan, { ...base, uid: 1000 }), "drop");
    }
    }
    for (const port of plan.protectedPorts) {
      const request = { iifname: "lo", oifname: "lo", uid: 0, ip_saddr: "127.0.0.1", ip_daddr: "127.0.0.1", tcp_sport: 32000, tcp_dport: port };
      const reply = { ...request, tcp_sport: 22 };
      assert.equal(packetDecision(plan, request), "drop");
      assert.equal(decision(plan, "output", reply), "accept");
      assert.equal(decision(knownBadBroadOutputPlan(plan), "output", reply), "drop");
    }
    const badOrder = knownBadInterleavedPlan(plan);
    const lane = plan.validationDestinationPorts[0];
    assert.equal(packetDecision(badOrder, { iifname: "lo", oifname: "lo", uid: 0, ip_saddr: "127.0.0.1", ip_daddr: "127.0.0.1", tcp_sport: 443, tcp_dport: lane }), "accept");
    assert.equal(packetDecision(badOrder, { iifname: "lo", oifname: "lo", uid: 0, ip_saddr: "127.0.0.1", ip_daddr: "127.0.0.1", tcp_sport: 444, tcp_dport: lane }), "drop");
    assert.equal(packetDecision(badOrder, { iifname: "lo", oifname: "lo", uid: 0, ip_saddr: "127.0.0.1", ip_daddr: "127.0.0.1", tcp_sport: 445, tcp_dport: lane }), "drop");
  }
  assert.throws(() => buildCombinedInstallPlan({ role: { toString: () => "LB115" }, ownershipNonce: NONCE }));
  assert.throws(() => buildCombinedInstallPlan({ role: "LB115", ownershipNonce: NONCE, table: "arbitrary" }));
});

if (!VERIFY_MODE) test(TEST_NAMES[1], () => {
  const parsed = parseNftRuleset(nftFixture());
  assert.equal(parsed.schema, 1);
  assert.match(inspectForeignSnapshot(parsed, "LB115"), /^[a-f0-9]{64}$/);
  throwsCode(() => parseNftRuleset(nftFixture("1.0.8", 1)), "nft_schema_unknown");
  throwsCode(() => parseNftRuleset(nftFixture("1.0.9", 2)), "nft_schema_unknown");
  throwsCode(() => parseNftRuleset(Buffer.from(JSON.stringify({ nftables: [{ metainfo: { version: "1.0.9", release_name: "x", json_schema_version: 1 } }, { mystery: {} }] }))), "nft_kind_unknown");
  throwsCode(() => parseNftRuleset(Buffer.from(JSON.stringify({ nftables: [{ table: { family: "inet", name: "x", handle: 1 } }] }))), "nft_schema_unknown");
  throwsCode(() => parseNftRuleset(Buffer.from(JSON.stringify({ nftables: [{ metainfo: { version: "1.0.9", release_name: "x", json_schema_version: 1 } }, { metainfo: { version: "1.0.9", release_name: "x", json_schema_version: 1 } }] }))), "nft_metainfo_order");
  throwsCode(() => parseNftRuleset(Buffer.from('{"nftables":[{"metainfo":{"version":"1.0.9","version":"1.0.9","release_name":"x","json_schema_version":1}}]}')), "nft_json_duplicate");
  for (const role of ["LB115", "CT200"]) {
    const plan = buildCombinedInstallPlan({ role, ownershipNonce: NONCE });
    const accepted = inspectOwnedTable(parseNftRuleset(ownedNftFixture(plan)), plan);
    assert.equal(accepted.ownershipNonce, NONCE);
    assert.equal(accepted.ruleHandles.length > 0, true);
    const changedHandle = parseNftRuleset(ownedNftFixture(plan, (rows) => { rows.find((row) => row.kind === "table").value.handle += 100; }));
    throwsCode(() => inspectOwnedTable(changedHandle, plan, accepted), "owned_table_identity");
    for (const kind of ["chain", "rule"]) {
      const changed = parseNftRuleset(ownedNftFixture(plan, (rows) => { rows.find((row) => row.kind === kind).value.handle += 100; }));
      throwsCode(() => inspectOwnedTable(changed, plan, accepted), "owned_table_identity");
    }
    const changedNonce = parseNftRuleset(ownedNftFixture(plan, (rows) => { rows.find((row) => row.kind === "table").value.comment += "x"; }));
    throwsCode(() => inspectOwnedTable(changedNonce, plan), "owned_table_nonce");
    const dormantFlag = parseNftRuleset(ownedNftFixture(plan, (rows) => { rows.find((row) => row.kind === "table").value.flags = ["dormant"]; }));
    throwsCode(() => inspectOwnedTable(dormantFlag, plan), "owned_table_identity");
    const chainExtra = parseNftRuleset(ownedNftFixture(plan, (rows) => { rows.find((row) => row.kind === "chain").value.dev = "lo"; }));
    throwsCode(() => inspectOwnedTable(chainExtra, plan), "owned_chain_identity");
    const extraSet = parseNftRuleset(ownedNftFixture(plan, (rows) => { rows.push({ kind: "set", value: { family: "inet", table: plan.table, name: "extra", handle: 999 } }); }));
    throwsCode(() => inspectOwnedTable(extraSet, plan), "owned_rules_mismatch");
    const badOrder = { ...plan, fixtureTransaction: knownBadInterleavedPlan(plan).transaction };
    throwsCode(() => inspectOwnedTable(parseNftRuleset(ownedNftFixture(badOrder)), plan), "owned_rules_mismatch");
  }
  const foreignOne = parseNftRuleset(nftFixture());
  const changedForeign = Buffer.from(JSON.stringify({ nftables: [{ metainfo: { version: "1.0.9", release_name: "nftables", json_schema_version: 1 } }, { table: { family: "inet", name: "other", handle: 99 } }] }));
  assert.notEqual(inspectForeignSnapshot(foreignOne, "LB115"), inspectForeignSnapshot(parseNftRuleset(changedForeign), "LB115"));
  const receiverPath = path.join(path.dirname(fileURLToPath(import.meta.url)), "maintenance-guard.py");
  const pythonControl = String.raw`import importlib.machinery, json, sys, types
fake=types.ModuleType('fcntl'); fake.LOCK_EX=2; fake.LOCK_NB=4; fake.flock=lambda *args: (_ for _ in ()).throw(AssertionError('unexpected fcntl call')); sys.modules['fcntl']=fake
if sys.flags.optimize != 0: raise RuntimeError('optimized Python forbidden')
m=importlib.machinery.SourceFileLoader('guard_fixture',sys.argv[1]).load_module()
def code(call):
    try: call()
    except m.GuardError as exc: return exc.code
    raise AssertionError('expected GuardError')
good={'family':'inet','table':'vg_native_maintenance','chain':'output','handle':1,'expr':[{'match':{'op':'==','left':{'meta':{'key':'skuid'}},'right':0}},{'accept':None}]}
assert m.normalize_rule_json(good)[1][0][1] == 0
bad=json.loads(json.dumps(good)); bad['expr'][0]['match']['right']=False
assert code(lambda:m.normalize_rule_json(bad)) == 'nft_schema_unknown'
assert code(lambda:m._canonical_ruleset_bytes(b'{"nftables":[{"metainfo":{"version":"1.0.9","release_name":"x","json_schema_version":true}}]}')) == 'nft_schema_unknown'
assert len(m._canonical_ruleset_bytes(b'{"nftables":[{"metainfo":{"version":"1.0.9","release_name":"x","json_schema_version":1}}]}')) == 1
print('python-control:strict-json-and-numeric-bool-rejection')
print('python guardian controls passed')`;
  runPythonControl(pythonControl, receiverPath, PYTHON_PARSER_GROUPS);
});

if (!VERIFY_MODE) test(TEST_NAMES[2], () => {
  assert.deepEqual(parseCli([]), { mode: "preflight", roles: ["LB115", "CT200"] });
  assert.deepEqual(parseCli(["--preflight", "CT200"]), { mode: "preflight", roles: ["CT200"] });
  assert.throws(() => parseCli(["--session", "LB115", "bad"]));
  validatePublicResult("inspect", validInspect());
  assert.throws(() => validatePublicResult("inspect", { ...validInspect(), secret: "x" }));
  assert.throws(() => validatePublicResult("get", { port: 8188, path: "/invented", status: 200, body_bytes: 1, source_port: 444, retained_fd: true }));
  assert.throws(() => validatePublicResult("release", { release_state: "verified_absent", prior_owned_handle: 1, arbitrary: true }));
  const unit = { LoadState: "loaded", ActiveState: "active", SubState: "running", MainPID: "315", InvocationID: NONCE, ExecMainStartTimestampMonotonic: "1000" };
  const lb = { role: "LB115", nonce: NONCE, identity: { role: "LB115", image: "pinned", config_sha256: "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37", ca_sha256: "ddc7359a3f730b1817c7adff7ede84439bdf31cc56ff7cf658142473042c1944", unit, process: { pid: 315, executable_matches_installed: true, fixed_config_argument: true, service_cgroup: true } }, foreign_ruleset_sha256: HASH, held_source_ports: [443, 444, 445], source_sockets: "bound_exclusive_noninheritable", protected_listener_counts: { "4000": 0, "8443": 0, "18082": 0, "9444": 0, "9445": 0 }, owned_table_absent: true, applying: false, diagnostics: "not_performed" };
  assert.equal(validatePreflightResult("LB115", NONCE, lb), true);
  assert.throws(() => validatePreflightResult("LB115", NONCE, { ...lb, applying: true }));
  assert.throws(() => validatePreflightResult("LB115", NONCE, { ...lb, identity: { ...lb.identity, process: { ...lb.identity.process, unexpected: "x" } } }));
  const names = ["vram-governor-node-agent.service", "llama-server.service", "comfyui.service", "comfy-harness.service", "vram-governor-runtime-tunnel.service"];
  const ct = { ...lb, role: "CT200", identity: { role: "CT200", container_ip: "10.0.0.58", net_namespace_matches_pid1: true, units: Object.fromEntries(names.map((name) => [name, unit])), config_or_image_read: false }, protected_listener_counts: { "8080": 0, "8188": 0, "8190": 0 } };
  assert.equal(validatePreflightResult("CT200", NONCE, ct), true);
  assert.throws(() => validatePreflightResult("CT200", NONCE, { ...ct, identity: { ...ct.identity, config_or_image_read: true } }));
});

if (!VERIFY_MODE) test(TEST_NAMES[3], async () => {
  const trial = runFake();
  assert.equal(await trial.promise, true);
  assert.equal(trial.output(), JSON.stringify({ ok: true, operation: "inspect", result: validInspect(), receipt_sha256: null }) + "\n");
  assert.equal(trial.child.wasKilled, false);
  const pairInput = `${JSON.stringify({ operation: "install" })}\n${JSON.stringify({ operation: "release", receipt_sha256: HASH })}\n`;
  const pair = runFake({}, pairInput);
  assert.equal(await pair.promise, true);
  const messages = pair.output().trimEnd().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual(messages.map((item) => item.operation), ["install", "release"]);
  assert.equal(messages[0].receipt_sha256, HASH);
  assert.equal(messages[1].receipt_sha256, HASH);
});

if (!VERIFY_MODE) test(TEST_NAMES[4], async () => {
  const oversized = runFake({}, "x".repeat(16385));
  await assert.rejects(oversized.promise, /session_input_line_bound/);
  assert.equal(oversized.child.wasKilled, true);
  const early = runFake({ closeOnRequest: true });
  await assert.rejects(early.promise, /receiver_response_missing|ssh_closed_early/);
  const errored = runFake({ errorOnRequest: true });
  await assert.rejects(errored.promise, /ssh_child_error/);
  const extra = runFake({ duplicate: true });
  await assert.rejects(extra.promise, /receiver_unsolicited_response/);
  const unsafe = runFake({ unsafe: true });
  await assert.rejects(unsafe.promise, /receiver_response_invalid/);
  const mismatchedPlane = runFake({ responseFactory: () => ({ result: { port: 8443, path: "/healthz", status: 200, body_bytes: 5, source_port: 443, retained_fd: true, reports_ok: true }, receipt_sha256: null }) }, '{"operation":"get","plane":"lb_candidate"}\n');
  await assert.rejects(mismatchedPlane.promise, /receiver_response_invalid/);
  const partial = runFake({ partial: true });
  await assert.rejects(partial.promise, /receiver_response_missing|receiver_response_unterminated/);
  const oversizedOutput = runFake({ oversized: true });
  await assert.rejects(oversizedOutput.promise, /receiver_response_line_bound/);
  const stderr = runFake({ stderrOverflow: true });
  await assert.rejects(stderr.promise, /ssh_stderr_bound/);
  const tooMany = runFake({}, `${'{"operation":"inspect"}\n'.repeat(64)}`);
  await assert.rejects(tooMany.promise, /session_input_count_bound/);
  const stalled = runFake({ silent: true }, undefined, { actionMs: 15 });
  await assert.rejects(stalled.promise, /receiver_response_timeout/);
  const childError = fakeChild();
  const inputWait = new PassThrough(); const outputWait = new PassThrough();
  const waiting = runInteractiveProtocol({ child: childError, inputStream: inputWait, outputStream: outputWait, role: "LB115", nonce: NONCE, receiver: TEST_RECEIVER, timeouts: { sessionMs: 20, actionMs: 10 } });
  await assert.rejects(waiting, /session_input_timeout/);
});

if (!VERIFY_MODE) test(TEST_NAMES[5], () => {
  const receiverPath = path.join(path.dirname(fileURLToPath(import.meta.url)), "maintenance-guard.py");
  runPythonControl(RECEIVER_STATE_CONTROL, receiverPath, PYTHON_STATE_GROUPS);
});

if (!VERIFY_MODE) test(TEST_NAMES[6], () => {
  const output = TEST_NAMES.map((name, index) => `ok ${index + 1} - ${name}`).join("\n") +
    `\n1..${TEST_NAMES.length}\n# tests ${TEST_NAMES.length}\n# pass ${TEST_NAMES.length}\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n`;
  assert.equal(validateTapRun(0, output), true);
  assert.throws(() => validateTapRun(0, ""));
  assert.throws(() => validateTapRun(0, output.replace("ok 2 -", "ok 1 -")));
  assert.throws(() => validateTapRun(0, output.replace("# skipped 0", "# skipped 1")));
  assert.throws(() => validateTapRun(1, output));
});

if (!VERIFY_MODE) test(TEST_NAMES[7], () => {
  assert.deepEqual(parseCli(["--preflight", "CT200", "--phase", "agent_paused"]), { mode: "preflight", roles: ["CT200"], phase: "agent_paused" });
  for (const argv of [
    ["--preflight", "LB115", "--phase", "agent_paused"],
    ["--preflight", "CT200", "--phase", "unknown"],
    ["--session", "CT200", NONCE, "--phase", "agent_paused"],
  ]) assert.throws(() => parseCli(argv));
  assert.throws(() => validatePreflightResult("LB115", NONCE, {}, "agent_paused"));
  const baseUnit = { LoadState: "loaded", ActiveState: "active", SubState: "running", MainPID: "219", InvocationID: NONCE, ExecMainStartTimestampMonotonic: "1000" };
  const names = ["llama-server.service", "comfyui.service", "comfy-harness.service", "vram-governor-runtime-tunnel.service"];
  const result = {
    role: "CT200", nonce: NONCE,
    identity: {
      role: "CT200", phase: "agent_paused", container_ip: "10.0.0.58", net_namespace_matches_pid1: true,
      agent: { image: "pinned", unit_artifact: "pinned", config: "pinned", unit: { LoadState: "loaded", ActiveState: "inactive", SubState: "dead", MainPID: "0", InvocationID: "", ExecMainStartTimestampMonotonic: "" }, pending_job: false, dropins_absent: true, cgroup_state: "absent" },
      native_units: Object.fromEntries(names.map((name) => [name, baseUnit])), config_or_image_read: true,
    },
    foreign_ruleset_sha256: HASH, held_source_ports: [443, 444, 445], source_sockets: "bound_exclusive_noninheritable",
    protected_listener_counts: { "8080": 0, "8188": 0, "8190": 0 }, owned_table_absent: true, applying: false, diagnostics: "not_performed",
  };
  assert.equal(validatePreflightResult("CT200", NONCE, result, "agent_paused"), true);
  assert.throws(() => validatePreflightResult("CT200", NONCE, result));
  assert.throws(() => validatePreflightResult("CT200", NONCE, result, "unknown"));
  assert.throws(() => validatePreflightResult("LB115", NONCE, {}, "agent_paused"));
  for (const mutate of [
    (copy) => { copy.identity.agent.pending_job = true; },
    (copy) => { copy.identity.agent.cgroup_state = "unknown"; },
    (copy) => { copy.identity.agent.unit.MainPID = "315"; },
    (copy) => { copy.identity.agent.unit.ActiveState = "active"; },
    (copy) => { copy.identity.native_units["comfyui.service"].MainPID = "0"; },
    (copy) => { copy.identity.agent.dropins_absent = false; },
  ]) {
    const copy = structuredClone(result); mutate(copy);
    assert.throws(() => validatePreflightResult("CT200", NONCE, copy, "agent_paused"));
  }
});

if (process.argv[2] === "--verify") {
  const child = spawnSync(process.execPath, ["--test", "--test-reporter=tap", fileURLToPath(import.meta.url)], { encoding: "utf8", timeout: 45000, maxBuffer: 2 * 1024 * 1024, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
  try {
    if (child.error) throw new Error("test_runner_error");
    validateTapRun(child.status, child.stdout);
    process.stdout.write("fixed maintenance guardian controls passed\n");
  } catch {
    const failure = child.stdout.split(/\r?\n/).find((line) => line.startsWith("not ok "));
    const failedName = TEST_NAMES.find((name, index) => failure === `not ok ${index + 1} - ${name}`);
    const safeReason = child.stdout.match(/error: '([a-z0-9_]+)'/)?.[1];
    const reportReason = safeReason && (safeReason.startsWith("python_control_") || SAFE_TEST_FAILURES.has(safeReason)) ? safeReason : null;
    process.stderr.write(failedName ? "fixed maintenance guardian control failed: " + failedName + (reportReason ? " [" + reportReason + "]" : "") + "\n" : "fixed maintenance guardian controls failed closed\n");
    process.exitCode = 1;
  }
}
