import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { parseCli, parseSafeResponse, safeErrorCode } from "./capacity-config.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PYTHON = "C:/Program Files/Python38/python.exe";
const RECEIVER = path.join(HERE, "capacity-config.py");
const STAGE = path.join(HERE, "stage.py");
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
export const TEST_NAMES = [
  "Python controls verify byte-preserving capacity transformation and conditioned replacement",
  "CLI accepts only fixed apply and nonce-bound inspect operations",
  "response parser pins public config identities and rejects unsafe or partial receipts",
  "runner inventory validator rejects zero, duplicate, unexpected, skipped, and failed suites",
];

export function validateTapRun(status, output) {
  if (status !== 0 || typeof output !== "string" || output.length > 4 * 1024 * 1024) throw new Error("test_run_failed");
  const lines = output.split(/\r?\n/);
  const terminals = lines.filter((line) => /^(?:ok|not ok)\s+\d+\s+-/.test(line));
  if (terminals.some((line) => /(?:^|\s)#\s*(?:SKIP|TODO)\b/i.test(line))) throw new Error("test_directive_forbidden");
  if (terminals.length !== TEST_NAMES.length || terminals.some((line, index) => line !== `ok ${index + 1} - ${TEST_NAMES[index]}`)) throw new Error("test_inventory_mismatch");
  const plans = lines.filter((line) => /^1\.\.\d+$/.test(line));
  if (plans.length !== 1 || plans[0] !== `1..${TEST_NAMES.length}`) throw new Error("test_plan_mismatch");
  for (const [key, expected] of [["tests", TEST_NAMES.length], ["pass", TEST_NAMES.length], ["fail", 0], ["cancelled", 0], ["skipped", 0], ["todo", 0]]) {
    const values = lines.filter((line) => line.startsWith(`# ${key} `));
    if (values.length !== 1 || values[0] !== `# ${key} ${expected}`) throw new Error("test_summary_mismatch");
  }
  return true;
}

const PY_CONTROLS = String.raw`
import hashlib, importlib.util, json, os, stat, sys, tempfile
stage_path, receiver_path = sys.argv[1:3]
stage_spec=importlib.util.spec_from_file_location('capacity_config_stage',stage_path)
stage=importlib.util.module_from_spec(stage_spec); sys.modules[stage_spec.name]=stage; stage_spec.loader.exec_module(stage)
receiver_spec=importlib.util.spec_from_file_location('capacity_config_receiver',receiver_path)
m=importlib.util.module_from_spec(receiver_spec); sys.modules[receiver_spec.name]=m; receiver_spec.loader.exec_module(m)
checks=0
def ok(value, label):
    global checks
    if not value: raise AssertionError(label)
    checks+=1
def rejects(fn, code):
    global checks
    try: fn()
    except m.ConfigError as exc:
        if exc.args and exc.args[0]==code: checks+=1; return
        raise AssertionError('wrong safe rejection')
    raise AssertionError('invalid fixture accepted')
def digest(data): return hashlib.sha256(data).hexdigest()
original=(b'workloads:\n'
 b'  targets:\n'
 b'  - id: cmp170-video-managed\n'
 b'    adapter: comfy\n'
 b'    runtime_protocol: managed_comfy_v1\n'
 b'    endpoint: http://127.0.0.1:9444\n'
 b'    accelerator_id: cmp170-node-gpu0\n'
 b'    enabled: true\n'
 b'    sharing_enabled: true\n'
 b'    vram_reserve_mb: 2048\n'
 b'  - id: secondary-disabled\n'
 b'    enabled: false\n')
expected=original.replace(b'    sharing_enabled: true\n',b'    accelerator_vram_mb: 10240\n    sharing_enabled: true\n')
transformed=m.transform_config(original,digest(original),len(original),digest(expected),len(expected),fixture=True)
ok(transformed==expected and len(transformed)==len(original)+31,'exact insertion bytes and position')
before=m.parse_yaml(original); after=m.parse_yaml(transformed)
target,_=m._validate_target(before); target['accelerator_vram_mb']=10240
ok(after==before,'semantic change is exactly the reviewed target capacity')
altered=original.replace(b'comfy',b'other',1)
rejects(lambda:m.transform_config(altered,digest(original),len(original),digest(expected),len(expected),fixture=True),'config_identity')
wrong=original.replace(b'cmp170-node-gpu0',b'other-node-gpu0')
rejects(lambda:m.transform_config(wrong,digest(wrong),len(wrong),digest(expected),len(expected),fixture=True),'target_binding')
duplicate=original.replace(b'    enabled: true\n',b'    enabled: true\n    enabled: true\n')
rejects(lambda:m.transform_config(duplicate,digest(duplicate),len(duplicate),digest(expected),len(expected),fixture=True),'config_yaml')
capacity=original.replace(b'    sharing_enabled: true\n',b'    accelerator_vram_mb: 10240\n    sharing_enabled: true\n')
rejects(lambda:m.transform_config(capacity,digest(capacity),len(capacity),digest(expected),len(expected),fixture=True),'target_capacity_present')
wrong_line=original.replace(b'    sharing_enabled: true\n',b'    sharing_enabled: true # retained-comment\n')
rejects(lambda:m.transform_config(wrong_line,digest(wrong_line),len(wrong_line),digest(expected),len(expected),fixture=True),'target_binding')
ambiguous=original.replace(b'  - id: secondary-disabled\n    enabled: false\n',b'  - id: cmp170-video-managed\n    adapter: comfy\n    runtime_protocol: managed_comfy_v1\n    endpoint: http://127.0.0.1:9444\n    accelerator_id: cmp170-node-gpu0\n    enabled: true\n    sharing_enabled: true\n    vram_reserve_mb: 2048\n')
rejects(lambda:m.transform_config(ambiguous,digest(ambiguous),len(ambiguous),digest(expected),len(expected),fixture=True),'target_ambiguous')
absent=original.replace(b'cmp170-video-managed',b'other-managed-target')
rejects(lambda:m.transform_config(absent,digest(absent),len(absent),digest(expected),len(expected),fixture=True),'target_missing')
wrong_path=original.replace(b'  targets:\n',b'  entries:\n')
rejects(lambda:m.transform_config(wrong_path,digest(wrong_path),len(wrong_path),digest(expected),len(expected),fixture=True),'target_binding')
missing=original.replace(b'    vram_reserve_mb: 2048\n',b'')
rejects(lambda:m.transform_config(missing,digest(missing),len(missing),digest(expected),len(expected),fixture=True),'target_binding')

class Info:
    def __init__(self,raw,mode=None,uid=0,gid=0):
        self.st_mode=(stat.S_IFDIR if stat.S_ISDIR(raw.st_mode) else stat.S_IFREG) | (stat.S_IMODE(raw.st_mode) if mode is None else mode)
        self.st_nlink=raw.st_nlink; self.st_size=raw.st_size; self.st_dev=raw.st_dev; self.st_ino=raw.st_ino
        self.st_uid=uid; self.st_gid=gid; self.st_mtime_ns=raw.st_mtime_ns; self.st_ctime_ns=raw.st_ctime_ns
def file_info(path, mode=0o640): return Info(os.stat(path),mode,0,990)
with tempfile.TemporaryDirectory(prefix='capacity-exclusive-') as root:
    hooks={'mode':lambda _info:0o600,'uid':lambda _info:0}
    saved, saved_info=m._write_all_exclusive(root,'old.yaml',b'old-private-bytes',hooks=hooks)
    ok(open(saved,'rb').read()==b'old-private-bytes' and saved_info.st_nlink==1,'exclusive backup positive')
    rejects(lambda:m._write_all_exclusive(root,'old.yaml',b'overwrite',hooks=hooks),'backup_exists')
    nonce='a'*32
    temp_path,_=m._write_all_exclusive(root,'.controller.yaml.capacity-'+nonce+'.tmp',b'nonce-temp',hooks=hooks)
    ok(open(temp_path,'rb').read()==b'nonce-temp','nonce-derived temporary file')
    rejects(lambda:m._write_all_exclusive(root,'.controller.yaml.capacity-not-a-nonce.tmp',b'bad',hooks=hooks),'temp_write')
    write_error=dict(hooks); write_error['write']=lambda _fd,_data: (_ for _ in ()).throw(OSError())
    rejects(lambda:m._write_all_exclusive(root,'new.yaml',b'new',hooks=write_error),'temp_write')
    sync_error=dict(hooks); sync_error['fsync']=lambda _fd: (_ for _ in ()).throw(OSError())
    rejects(lambda:m._write_all_exclusive(root,'receipt.json',b'receipt',hooks=sync_error),'temp_write')
    bad_mode=dict(hooks); bad_mode['mode']=lambda _info:0o644
    rejects(lambda:m._write_all_exclusive(root,'.controller.yaml.capacity-'+'b'*32+'.tmp',b'mode',hooks=bad_mode),'temp_custody')

def replacement_fixture():
    root=tempfile.mkdtemp(prefix='capacity-replace-')
    config=os.path.join(root,'controller.yaml'); temp=os.path.join(root,'.capacity.tmp')
    old=b'old-fixed-fixture'; new=b'new-fixed-fixture'
    open(config,'wb').write(old); open(temp,'wb').write(new)
    config_fd=os.open(config,os.O_RDONLY); os.lseek(config_fd,0,os.SEEK_END)
    def fake_stat(path):
        raw=os.stat(path,follow_symlinks=False)
        if os.path.isdir(path): return Info(raw,0o750,0,990)
        return Info(raw,0o640,0,990)
    def fake_fstat(fd):
        raw=os.fstat(fd)
        return Info(raw,0o640,0,990)
    def read_file(path): return open(path,'rb').read(),fake_stat(path)
    directory_info=fake_stat(root)
    hooks={'config_path':config,'config_dir':root,'stat_path':fake_stat,'read_file':read_file,'fstat':fake_fstat,
      'directory_info':lambda:fake_stat(root),'service_check':lambda _service,_image:None,'sync_dir':lambda _path:None}
    return root,config,temp,old,new,config_fd,fake_stat,fake_fstat,directory_info,hooks

root,config,temp,old,new,config_fd,fake_stat,fake_fstat,directory_info,hooks=replacement_fixture()
try:
    old_info=fake_stat(config); applied={'value':'not_applied'}; temp_fd=os.open(temp,os.O_RDONLY)
    closed={'config':False,'temp':False}
    def platform_replace(source,destination):
        os.close(config_fd); closed['config']=True
        os.close(temp_fd); closed['temp']=True
        os.replace(source,destination)
    hooks['replace']=platform_replace
    result=m._conditioned_replace(config_fd,old_info,old,temp,new,{},None,directory_info,applied,hooks,
      digest(old),digest(new),len(old),len(new),temp_fd)
    ok(open(config,'rb').read()==new and applied['value']=='confirmed' and result.st_size==len(new),'conditioned atomic replacement positive')
finally:
    if not closed['config']: os.close(config_fd)
    if not closed['temp']: os.close(temp_fd)
    import shutil; shutil.rmtree(root)

root,config,temp,old,new,config_fd,fake_stat,fake_fstat,directory_info,hooks=replacement_fixture()
try:
    old_info=fake_stat(config); replacement={'value':'not_applied'}; temp_fd=os.open(temp,os.O_RDONLY)
    closed={'config':False,'temp':False}
    def replace_then_raise(source,destination):
        os.close(config_fd); closed['config']=True
        os.close(temp_fd); closed['temp']=True
        os.replace(source,destination)
        raise OSError()
    hooks['replace']=replace_then_raise
    rejects(lambda:m._conditioned_replace(config_fd,old_info,old,temp,new,{},None,directory_info,replacement,hooks,
      digest(old),digest(new),len(old),len(new),temp_fd),'replace_failed')
    ok(replacement['value']=='unknown','replace attempt begins in unknown state')
    ok(m._resolve_replacement_state(replacement['value'],lambda:open(config,'rb').read(),digest(new),len(new))=='confirmed','exact new bytes confirm uncertain replacement')
    ok(m._resolve_replacement_state(replacement['value'],lambda:(_ for _ in ()).throw(OSError()))=='unknown','failed readback preserves uncertainty')
finally:
    if not closed['config']: os.close(config_fd)
    if not closed['temp']: os.close(temp_fd)
    import shutil; shutil.rmtree(root)

root,config,temp,old,new,config_fd,fake_stat,fake_fstat,directory_info,hooks=replacement_fixture()
try:
    old_info=fake_stat(config); applied={'value':'not_applied'}; temp_fd=os.open(temp,os.O_RDONLY)
    open(config,'wb').write(b'changed-original')
    rejects(lambda:m._conditioned_replace(config_fd,old_info,old,temp,new,{},None,directory_info,applied,hooks,
      digest(old),digest(new),len(old),len(new),temp_fd),'config_changed')
    ok(applied['value']=='not_applied' and open(config,'rb').read()==b'changed-original','changed source prevented replacement')
finally:
    os.close(config_fd); os.close(temp_fd)
    import shutil; shutil.rmtree(root)

root,config,temp,old,new,config_fd,fake_stat,fake_fstat,directory_info,hooks=replacement_fixture()
try:
    old_info=fake_stat(config); applied={'value':'not_applied'}; temp_fd=os.open(temp,os.O_RDONLY)
    def linked_stat(path):
        info=fake_stat(path)
        if path==temp: info.st_mode=stat.S_IFLNK|0o777
        return info
    hooks['stat_path']=linked_stat
    rejects(lambda:m._conditioned_replace(config_fd,old_info,old,temp,new,{},None,directory_info,applied,hooks,
      digest(old),digest(new),len(old),len(new),temp_fd),'temp_custody')
    ok(applied['value']=='not_applied','linked temp prevented replacement')
finally:
    os.close(config_fd); os.close(temp_fd)
    import shutil; shutil.rmtree(root)

root,config,temp,old,new,config_fd,fake_stat,fake_fstat,directory_info,hooks=replacement_fixture()
try:
    old_info=fake_stat(config); applied={'value':'not_applied'}; temp_fd=os.open(temp,os.O_RDONLY)
    def wrong_mode(path):
        info=fake_stat(path)
        if path==temp: info.st_mode=stat.S_IFREG|0o600
        return info
    hooks['stat_path']=wrong_mode
    rejects(lambda:m._conditioned_replace(config_fd,old_info,old,temp,new,{},None,directory_info,applied,hooks,
      digest(old),digest(new),len(old),len(new),temp_fd),'temp_custody')
    ok(applied['value']=='not_applied','wrong temp mode prevented replacement')
finally:
    os.close(config_fd); os.close(temp_fd)
    import shutil; shutil.rmtree(root)
print(json.dumps({'checks':checks},separators=(',',':')))
`;

if (process.argv[2] !== "--verify") {
test(TEST_NAMES[0], () => {
  const output = execFileSync(PYTHON, ["-B", "-c", PY_CONTROLS, STAGE, RECEIVER], { encoding: "utf8", timeout: 30000, windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
  assert.equal(JSON.parse(output).checks, 29);
});

test(TEST_NAMES[1], () => {
  assert.deepEqual(parseCli(["--apply"]), { operation: "apply" });
  assert.deepEqual(parseCli(["--inspect", "0123456789abcdef0123456789abcdef"]), { operation: "inspect", nonce: "0123456789abcdef0123456789abcdef" });
  for (const args of [["--latest"], ["--apply", "--inspect"], ["--inspect", "../etc"], ["--apply", "/etc/controller.yaml"]]) assert.throws(() => parseCli(args), /invalid_cli/);
  const clientSource = readFileSync(path.join(HERE, "capacity-config.mjs"), "utf8");
  assert.match(clientSource, /const SSH_EXE = "C:\/Windows\/System32\/OpenSSH\/ssh\.exe";/);
  assert.match(clientSource, /spawn\(SSH_EXE, args, \{ windowsHide: true, cwd: "C:\/Windows\/System32", stdio: \["pipe", "pipe", "pipe"\] \}\)/);
  assert.doesNotMatch(clientSource, /spawn\(SSH_EXE,\s*args,\s*\{[^}]*\benv\s*:/s);
  for (const option of ['"-F", "none"', '"-T"', '"ConnectTimeout=8"', '"StrictHostKeyChecking=yes"', '`UserKnownHostsFile=${KNOWN_HOSTS}`', '`HostName=${SSH_HOST}`', '"PermitLocalCommand=no"', '"ClearAllForwardings=yes"', '"ForwardAgent=no"', '"ProxyCommand=none"', '"ProxyJump=none"', '"ControlMaster=no"', '"ControlPath=none"', '"CanonicalizeHostname=no"', '"IdentitiesOnly=yes"', '"IdentityAgent=none"', '"-i", SSH_KEY', '`root@${SSH_HOST}`']) assert.ok(clientSource.includes(option), `fixed ssh option missing: ${option}`);
});

test(TEST_NAMES[2], () => {
  const receipt = { schema: "controller-capacity-config-receipt-v1", nonce: "0123456789abcdef0123456789abcdef", old_sha256: "22307f4535286ac56d6ee08b62b5febd8f2e1c6af6e525cbaa8a8b47852ddda0", old_bytes: 6758, new_sha256: "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37", new_bytes: 6789, old_config_dev: 1, old_config_ino: 2, old_backup_dev: 1, old_backup_ino: 3, new_config_dev: 1, new_config_ino: 4, config_uid: 0, config_gid: 990, config_mode: 0o640, pid: 99, invocation: "a".repeat(32), start_ticks: "123", process_dev: 5, process_ino: 6, image_dev: 1, image_ino: 2, activationApproved: false, runtimeConfigReloaded: false };
  const encode = (value) => Buffer.from(`${canonicalJson(value)}\n`, "ascii");
  assert.deepEqual(parseSafeResponse(encode({ ok: true, receipt }), receipt.nonce, "apply"), receipt);
  assert.throws(() => parseSafeResponse(encode({ ok: true, receipt: { ...receipt, activationApproved: true } }), receipt.nonce, "apply"), /receipt_invalid/);
  assert.throws(() => parseSafeResponse(encode({ ok: true, receipt: { ...receipt, new_sha256: "0".repeat(64) } }), receipt.nonce, "inspect"), /receipt_invalid/);
  assert.throws(() => parseSafeResponse(encode({ ok: false, code: "path /secret", replacement: "not_applied" }), receipt.nonce, "apply"), /response_invalid/);
  assert.throws(() => parseSafeResponse(encode({ ok: false, code: "not_a_real_code", replacement: "unknown" }), receipt.nonce, "apply"), /response_invalid/);
  assert.throws(() => parseSafeResponse(encode({ ok: false, code: "config_changed", replacement: "not_applied" }), receipt.nonce, "apply"), /receiver_config_changed_not_applied/);
  assert.throws(() => parseSafeResponse(encode({ ok: false, code: "replace_failed", replacement: "unknown" }), receipt.nonce, "apply"), /receiver_replace_failed_unknown/);
  assert.throws(() => parseSafeResponse(encode({ ok: false, code: "replace_failed", replacement: "confirmed" }), receipt.nonce, "apply"), /receiver_replace_failed_confirmed/);
  assert.equal(safeErrorCode(new Error("secret_path_value")), "operation_failed");
  assert.equal(safeErrorCode(new Error("ssh_timeout")), "ssh_timeout");
  assert.equal(safeErrorCode(new Error("receiver_replace_failed_unknown")), "receiver_replace_failed_unknown");
});

test(TEST_NAMES[3], () => {
  const valid = ["TAP version 13", ...TEST_NAMES.map((name, i) => `ok ${i + 1} - ${name}`), `1..${TEST_NAMES.length}`, `# tests ${TEST_NAMES.length}`, `# pass ${TEST_NAMES.length}`, "# fail 0", "# cancelled 0", "# skipped 0", "# todo 0"].join("\n");
  assert.equal(validateTapRun(0, valid), true);
  assert.throws(() => validateTapRun(0, valid.replace(`1..${TEST_NAMES.length}`, "1..0")), /test_inventory_mismatch|test_plan_mismatch/);
  assert.throws(() => validateTapRun(0, valid.replace(`ok 2 - ${TEST_NAMES[1]}`, `ok 1 - ${TEST_NAMES[0]}`)), /test_inventory_mismatch/);
  assert.throws(() => validateTapRun(0, valid.replace(TEST_NAMES[2], "unexpected test")), /test_inventory_mismatch/);
  assert.throws(() => validateTapRun(0, valid.replace(`ok 4 - ${TEST_NAMES[3]}\n`, "")), /test_inventory_mismatch/);
  assert.throws(() => validateTapRun(0, valid.replace(`ok 2 - ${TEST_NAMES[1]}`, `not ok 2 - ${TEST_NAMES[1]}`)), /test_inventory_mismatch/);
  assert.throws(() => validateTapRun(0, valid.replace(`ok 2 - ${TEST_NAMES[1]}`, `ok 2 - ${TEST_NAMES[1]} # SKIP`)), /test_directive_forbidden/);
  assert.throws(() => validateTapRun(0, valid.replace(`ok 3 - ${TEST_NAMES[2]}`, `ok 3 - ${TEST_NAMES[2]} # TODO`)), /test_directive_forbidden/);
  assert.throws(() => validateTapRun(0, valid.replace("# skipped 0", "# skipped 1")), /test_summary_mismatch/);
  assert.throws(() => validateTapRun(0, valid.replace("# cancelled 0", "# cancelled 1")), /test_summary_mismatch/);
  assert.throws(() => validateTapRun(0, valid.replace("# todo 0", "# todo 1")), /test_summary_mismatch/);
  assert.throws(() => validateTapRun(0, valid.replace("# fail 0", "# fail 1")), /test_summary_mismatch/);
  assert.throws(() => validateTapRun(1, valid), /test_run_failed/);
});
}

if (process.argv[2] === "--verify") {
  const child = spawnSync(process.execPath, ["--test", "--test-reporter=tap", fileURLToPath(import.meta.url)], { encoding: "utf8", timeout: 90000, maxBuffer: 4 * 1024 * 1024, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
  try {
    if (child.error) throw new Error("test_runner_error");
    validateTapRun(child.status, child.stdout);
    process.stdout.write("measured capacity config controls passed\n");
  } catch {
    process.stderr.write("measured capacity config controls failed closed\n");
    process.exitCode = 1;
  }
}
