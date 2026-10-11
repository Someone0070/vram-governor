import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { parseCli, parseSafeResponse } from "./stage.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RECEIVER = path.join(HERE, "stage.py");
const PYTHON = "C:/Program Files/Python38/python.exe";
const TEST_NAMES = [
  "Python receiver helpers enforce framed requests, file custody, and redacted check-config results",
  "CLI exposes only stage and nonce-bound read-only inspect",
  "remote response parser accepts only safe receipt identities and rejects raw failure detail",
  "candidate pre-exec custody and read-only inspection pipelines reject mutations",
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

if (process.argv[2] === "--verify") {
  const child = spawnSync(process.execPath, ["--test", "--test-reporter=tap", fileURLToPath(import.meta.url)], { encoding: "utf8", timeout: 90000, maxBuffer: 4 * 1024 * 1024, windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
  try {
    if (child.error) throw new Error("test_runner_error");
    validateTapRun(child.status, child.stdout);
    process.stdout.write("controller staging unit controls passed\n");
  } catch {
    process.stderr.write("controller staging unit controls failed closed\n");
    process.exitCode = 1;
  }
} else {

const PY_CONTROLS = String.raw`
import importlib.util, io, json, os, stat, tempfile
p = __import__('sys').argv[1]
spec = importlib.util.spec_from_file_location('controller_stage_receiver', p)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
checks = 0
def ok(value, label):
    global checks
    if not value: raise AssertionError(label)
    checks += 1
def rejects(fn, code):
    global checks
    try: fn()
    except m.StageError as exc:
        if exc.args and exc.args[0] == code: checks += 1; return
        raise AssertionError('wrong safe code')
    raise AssertionError('expected rejection')
nonce = '0'*32
request = {'schema':'controller-stage-request-v1','operation':'inspect','nonce':nonce}
line = (json.dumps(request,separators=(',',':'))+'\n').encode()
ok(m.parse_request(line)['operation'] == 'inspect', 'valid request')
rejects(lambda: m.parse_request(b'{"schema":"controller-stage-request-v1","operation":"inspect","nonce":"'+b'0'*32+b'","nonce":"'+b'0'*32+b'"}\n'), 'duplicate_field')
rejects(lambda: m.parse_request(line[:-1]), 'request_frame')
rejects(lambda: m.parse_request(line[:-1]+b' x\n'), 'request_json')
rejects(lambda: m.parse_request(b' '*(m.MAX_FRAME+1)+b'\n'), 'request_frame')
rejects(lambda: m.parse_request((json.dumps(dict(request,extra='x'),separators=(',',':'))+'\n').encode()), 'request_inspect')
rejects(lambda: m.parse_request((json.dumps(dict(request,nonce='bad'),separators=(',',':'))+'\n').encode()), 'request_inspect')
rejects(lambda: m.read_exact(io.BytesIO(b'ab'), 3, 3), 'frame_truncated')
rejects(lambda: m.read_exact(io.BytesIO(b''), 4, 3), 'frame_bound')
ok(m.read_exact(io.BytesIO(b'abcd'), 4, 4) == b'abcd', 'bounded exact read')
ok(m.read_frame(io.BytesIO(line))[0]['nonce'] == nonce, 'inspect frame')
rejects(lambda: m.read_frame(io.BytesIO(line+b'x')), 'frame_trailing')
rejects(lambda: m.read_frame(io.BytesIO(line[:-1]+b' x\n')), 'request_json')
wrong = {'schema':'controller-stage-request-v1','operation':'stage','nonce':nonce,'manifest_sha256':'0'*64,'image_sha256':m.IMAGE_SHA256,'image_bytes':m.IMAGE_BYTES}
rejects(lambda: m.parse_request((json.dumps(wrong,separators=(',',':'))+'\n').encode()), 'request_identity')
good_cmd = m.INSTALLED.encode()+b'\0-config\0'+m.CONFIG.encode()+b'\0'
ok(m.validate_command_line(good_cmd) is None, 'canonical service argv')
rejects(lambda: m.validate_command_line(good_cmd[:-1]), 'service_command')
rejects(lambda: m.validate_command_line(good_cmd+b'\0-extra\0'), 'service_command')
rejects(lambda: m.validate_command_line(good_cmd.replace(b'/etc/vram-governor/controller.yaml',b'/tmp/other.yaml')), 'service_command')
image_control = b'known-fixed-image'
ok(m.validate_bytes(image_control,m._sha(image_control),len(image_control),'candidate_identity') == image_control, 'fixed digest positive')
rejects(lambda: m.validate_bytes(image_control,'0'*64,len(image_control),'candidate_identity'), 'candidate_identity')
rejects(lambda: m.validate_bytes(image_control,m._sha(image_control),len(image_control)+1,'candidate_identity'), 'candidate_identity')
before_service={'pid':123,'invocation':'0'*32,'start':'12'}
ok(m.service_unchanged(before_service,dict(before_service)) is None, 'unchanged service identity')
rejects(lambda: m.service_unchanged(before_service,dict(before_service,pid=124)), 'live_custody_changed')
ok(m.validate_stage_entries(['candidate.bin','receipt.json'],{'candidate.bin','receipt.json'}) is None, 'readonly inspect entry inventory')
rejects(lambda: m.validate_stage_entries(['candidate.bin','receipt.json','extra'],{'candidate.bin','receipt.json'}), 'stage_entries_changed')
rejects(lambda: m.validate_stage_entries(['candidate.bin','candidate.bin'],{'candidate.bin'}), 'stage_entries_changed')
ok(m.validate_stage_capacity(0,0,1,m.MAX_STAGE_BYTES) is None, 'stage quota boundary')
rejects(lambda: m.validate_stage_capacity(m.MAX_STAGE_DIRS,0,1,1), 'stage_quota_reservation')
rejects(lambda: m.validate_stage_capacity(0,m.MAX_STAGE_BYTES,0,1), 'stage_quota_reservation')
ok(m.extract_allowed_environment(b'PATH=/usr/bin\0LANG=C\0VRAM_NODE_COMMAND_SECRET='+b'x'*40+b'\0') == {'VRAM_NODE_COMMAND_SECRET':b'x'*40}, 'allowlisted process secret only')
rejects(lambda: m.extract_allowed_environment(b'VRAM_NODE_COMMAND_SECRET='+b'x'*40+b'\0VRAM_NODE_COMMAND_SECRET='+b'y'*40+b'\0'), 'service_environment_duplicate')
with tempfile.TemporaryDirectory(prefix='controller-stage-fixture-') as root:
    payload = b'fixture-original-bytes'
    fixture_hooks = {'stat_mode':lambda info:0o600}
    path = m._write_exclusive(root, 'backup.bin', payload, hooks=fixture_hooks)
    ok(open(path,'rb').read() == payload, 'exclusive fixture write')
    ok(m.validate_bytes(open(path,'rb').read(),m._sha(payload),len(payload),'original_backup_identity') == payload, 'rollback backup bytes')
    real_lstat = m.os.lstat
    real_stat = m.os.stat(path)
    class FakeInfo:
        def __init__(self, mode, nlink, size=0):
            self.st_mode=mode; self.st_nlink=nlink; self.st_size=size; self.st_uid=0
            self.st_dev=getattr(real_stat,'st_dev',1); self.st_ino=getattr(real_stat,'st_ino',2)
            self.st_mtime_ns=getattr(real_stat,'st_mtime_ns',0); self.st_ctime_ns=getattr(real_stat,'st_ctime_ns',0)
    hard = os.path.join(root,'fixture-hardlink')
    link = os.path.join(root,'fixture-symlink')
    def fixture_lstat(candidate):
        if candidate == hard: return FakeInfo(stat.S_IFREG|0o600,2,len(payload))
        if candidate == link: return FakeInfo(stat.S_IFLNK|0o777,1,len(payload))
        if candidate == path: return FakeInfo(stat.S_IFREG|0o600,1,len(payload))
        return FakeInfo(stat.S_IFDIR|0o755,1)
    ok(m.trusted_path(path, expected_owner=0, stat_reader=fixture_lstat).st_nlink == 1, 'fixture file custody')
    rejects(lambda: m.validate_bytes(payload,'0'*64,len(payload),'original_backup_identity'), 'original_backup_identity')
    rejects(lambda: m._write_exclusive(root, 'backup.bin', payload), 'write_create')
    rejects(lambda: m._write_exclusive(root, '../escape', payload), 'write_shape')
    def fail_sync(fd): raise OSError('secret/path must not escape')
    try: m._write_exclusive(root, 'sync-fail.bin', payload, hooks={'fsync':fail_sync})
    except OSError: checks += 1
    else: raise AssertionError('fsync failure control')
    created = os.lstat(os.path.join(root,'sync-fail.bin'))
    ok(stat.S_ISREG(created.st_mode) and created.st_nlink == 1, 'failed write retained safely')
    rejects(lambda: m._write_exclusive(root,'mode-fail.bin',payload,hooks={'stat_mode':lambda info:0o640}), 'write_custody')
    def fail_write(fd, view):
        os.write(fd,view[:3])
        raise OSError('write fault with secret/path')
    try: m._write_exclusive(root, 'write-fail.bin', payload, hooks={'write':fail_write})
    except OSError: checks += 1
    else: raise AssertionError('write failure control')
    ok(open(os.path.join(root,'write-fail.bin'),'rb').read() == payload[:3], 'write fault retained partial safely')
    rejects(lambda: m.trusted_path(hard, expected_owner=0, stat_reader=fixture_lstat), 'file_custody')
    rejects(lambda: m.trusted_path(link, expected_owner=0, stat_reader=fixture_lstat), 'file_custody')

class Result:
    def __init__(self, code=0, stdout=m.SUCCESS_LINE, stderr=b''):
        self.returncode=code; self.stdout=stdout; self.stderr=stderr
def good_runner(command, env, timeout, executable_fd):
    ok(command[-3:] == ['-config',m.CONFIG,'-check-config'], 'fixed check-config argv')
    ok(executable_fd is None, 'direct check-config seam uses no executable handle')
    ok(timeout == m.CHILD_TIMEOUT and 'secret-token-never-print-0123456789abcdef' == env['VRAM_NODE_COMMAND_SECRET'], 'minimal secret env')
    return Result()
secret = b'secret-token-never-print-0123456789abcdef'
ok(m.run_check_config('/tmp/candidate', 'VRAM_NODE_COMMAND_SECRET', secret, good_runner) == 0, 'check-config success')
rejects(lambda: m.run_check_config('/tmp/candidate','VRAM_NODE_COMMAND_SECRET',secret,lambda *args:Result(4,b'raw secret output')), 'check_config_rejected')
rejects(lambda: m.run_check_config('/tmp/candidate','VRAM_NODE_COMMAND_SECRET',secret,lambda *args:Result(0,m.SUCCESS_LINE,b'secret stderr')), 'check_config_rejected')
rejects(lambda: m.run_check_config('/tmp/candidate','PATH',secret,good_runner), 'check_config_arguments')
rejects(lambda: m.command_secret(b'auth:\n  command_signing_secret_env: VRAM_NODE_COMMAND_SECRET\n',{'VRAM_NODE_COMMAND_SECRET':b'short'}), 'config_identity')
rejects(lambda: m.validated_secret('PATH',{'PATH':secret}), 'secret_environment')
rejects(lambda: m.validated_secret('VRAM_NODE_COMMAND_SECRET',{'VRAM_NODE_COMMAND_SECRET':b'short'}), 'secret_value')
out=io.BytesIO(); m.emit_safe(out,error=RuntimeError('secret-token-never-print /private/path'))
encoded=out.getvalue()
ok(b'secret-token-never-print' not in encoded and b'/private/path' not in encoded and b'operation_failed' in encoded, 'failure output redaction')
rejects(lambda: m.handle({'operation':'stage'}, b'wrong'), 'candidate_identity')
print(json.dumps({'checks':checks},separators=(',',':')))
`;

const PIPELINE_CONTROLS = String.raw`
import importlib.util, json, os, stat, tempfile
p=__import__('sys').argv[1]
spec=importlib.util.spec_from_file_location('controller_stage_receiver_pipeline',p)
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
checks=0
def ok(value,label):
    global checks
    if not value: raise AssertionError(label)
    checks+=1
def rejects(fn,code):
    global checks
    try: fn()
    except m.StageError as exc:
        if exc.args and exc.args[0]==code: checks+=1; return
        raise AssertionError('wrong pipeline rejection')
    raise AssertionError('pipeline mutation accepted')

# Exercise the actual pre-exec validation and post-check identity sequence against a private fixture.
with tempfile.TemporaryDirectory(prefix='controller-exec-custody-') as root:
    candidate=os.path.join(root,'candidate.bin')
    payload=b'fixed-source-fixture-no-execution'
    with open(candidate,'wb') as stream: stream.write(payload)
    real_lstat=os.lstat; real_stat=os.stat(candidate); state={'mode':stat.S_IFREG|0o700,'nlink':1,'ino':real_stat.st_ino,'ancestor_link':False}
    class Info:
        def __init__(self,mode,nlink,size,dev,ino,uid=0,mtime=0,ctime=0):
            self.st_mode=mode; self.st_nlink=nlink; self.st_size=size; self.st_dev=dev; self.st_ino=ino; self.st_uid=uid; self.st_mtime_ns=mtime; self.st_ctime_ns=ctime
    def fake_stat(path):
        if state['ancestor_link'] and path != candidate: return Info(stat.S_IFLNK|0o777,1,0,real_stat.st_dev,real_stat.st_ino)
        if path == candidate: return Info(state['mode'],state['nlink'],len(payload),real_stat.st_dev,state['ino'],0,real_stat.st_mtime_ns,real_stat.st_ctime_ns)
        return Info(stat.S_IFDIR|0o755,1,0,real_stat.st_dev,real_stat.st_ino)
    def fake_fstat(fd):
        opened=os.fstat(fd)
        return Info(state['mode'],state['nlink'],opened.st_size,opened.st_dev,real_stat.st_ino,0,opened.st_mtime_ns,opened.st_ctime_ns)
    def reader(path,digest,size,maximum): return m.read_trusted(path,digest,size,maximum,stat_reader=fake_stat,fstat_reader=fake_fstat)
    def path_reader(path): return m.trusted_path(path,stat_reader=fake_stat)
    secret=b'fixture-command-signing-secret-value-123456'
    calls=[]
    class Result:
        returncode=0; stdout=m.SUCCESS_LINE; stderr=b''
    def runner(command,env,timeout,executable_fd):
        calls.append('check-config')
        ok(command == [candidate,'-config',m.CONFIG,'-check-config'], 'pinned check-config argv')
        ok(executable_fd is not None and os.fstat(executable_fd).st_size == len(payload), 'held candidate descriptor')
        ok(timeout == m.CHILD_TIMEOUT and env['VRAM_NODE_COMMAND_SECRET'] == secret.decode(), 'fixed secret-only environment')
        return Result()
    digest=m._sha(payload)
    state['mode']=stat.S_IFREG|0o700
    ok(m._checked_candidate_config(candidate,'VRAM_NODE_COMMAND_SECRET',secret,runner,reader,path_reader,fake_fstat,digest,len(payload)) == 0, 'pre-exec custody positive')
    ok(calls == ['check-config'], 'one isolated check-config call')
    for mode,nlink,ancestor,expected in ((stat.S_IFREG|0o600,1,False,'candidate_exec_custody'),(stat.S_IFREG|0o700,2,False,'file_custody'),(stat.S_IFLNK|0o777,1,False,'file_custody'),(stat.S_IFREG|0o700,1,True,'ancestor_custody')):
        state.update(mode=mode,nlink=nlink,ancestor_link=ancestor,ino=real_stat.st_ino)
        before=len(calls)
        rejects(lambda: m._checked_candidate_config(candidate,'VRAM_NODE_COMMAND_SECRET',secret,runner,reader,path_reader,fake_fstat,digest,len(payload)),expected)
        ok(len(calls)==before,'pre-exec mutation prevented check-config')
    state.update(mode=stat.S_IFREG|0o700,nlink=1,ancestor_link=False,ino=real_stat.st_ino)
    rejects(lambda: m._checked_candidate_config(candidate,'VRAM_NODE_COMMAND_SECRET',secret,runner,reader,path_reader,fake_fstat,'0'*64,len(payload)),'file_digest')
    ok(len(calls)==1,'wrong candidate hash prevented check-config')
    def replacement_runner(command,env,timeout,executable_fd):
        calls.append('check-config'); state['ino']=real_stat.st_ino+1; return Result()
    rejects(lambda: m._checked_candidate_config(candidate,'VRAM_NODE_COMMAND_SECRET',secret,replacement_runner,reader,path_reader,fake_fstat,digest,len(payload)),'candidate_exec_changed')
    ok(calls==['check-config','check-config'],'replacement detected after held-descriptor check')

# Run the complete production _inspect/_dropin_snapshot flow over isolated read-only providers.
with tempfile.TemporaryDirectory(prefix='controller-inspect-pipeline-') as root:
    nonce='1'*32; stage_root=os.path.join(root,'staging'); stage_dir=os.path.join(stage_root,nonce); drop_dir=os.path.join(root,'dropins')
    os.makedirs(stage_dir); os.makedirs(drop_dir)
    names=['candidate.bin','original.bin','controller.yaml',m.STAGED_UNIT_NAME,'dropin-'+m.REQUIRED_DROPIN,'receipt.json']
    for name in names:
        with open(os.path.join(stage_dir,name),'wb') as stream: stream.write(b'fixture')
    dropin_path=os.path.join(drop_dir,m.REQUIRED_DROPIN)
    with open(dropin_path,'wb') as stream: stream.write(b'fixture')
    blobs={'candidate':b'C'*m.IMAGE_BYTES,'original':b'O'*m.ORIGINAL_BYTES,'config':b'c'*m.CONFIG_BYTES,'ca':b'a'*m.CA_BYTES,'unit':b'u'*64,'dropin':b'dropin-fixture-bytes'}
    wanted={'candidate':m.IMAGE_SHA256,'original':m.ORIGINAL_SHA256,'config':m.CONFIG_SHA256,'ca':m.CA_SHA256,'unit':'a'*64,'dropin':'b'*64}
    data_by_path={}; digest_by_id={}
    def map_path(path):
        if path==m.PARENT: return stage_root
        if path.startswith(m.PARENT+'/'): return stage_root+path[len(m.PARENT):].replace('/',os.sep)
        if path==m.DROPIN: return drop_dir
        if path.startswith(m.DROPIN+'/'): return drop_dir+path[len(m.DROPIN):].replace('/',os.sep)
        fixed={m.CONFIG:'config',m.CA:'ca',m.UNIT:'unit',m.INSTALLED:'original'}
        if path in fixed: return os.path.join(root,'live',os.path.basename(path))
        return path
    os.makedirs(os.path.join(root,'live'))
    stage_data={
      os.path.join(stage_dir,'candidate.bin'):blobs['candidate'],os.path.join(stage_dir,'original.bin'):blobs['original'],os.path.join(stage_dir,'controller.yaml'):blobs['config'],os.path.join(stage_dir,m.STAGED_UNIT_NAME):blobs['unit'],os.path.join(stage_dir,'dropin-'+m.REQUIRED_DROPIN):blobs['dropin'],
      map_path(m.CONFIG):blobs['config'],map_path(m.CA):blobs['ca'],map_path(m.UNIT):blobs['unit'],map_path(m.INSTALLED):blobs['original'],dropin_path:blobs['dropin']}
    for key,data in stage_data.items(): data_by_path[key]=data
    for key,label in ((os.path.join(stage_dir,'candidate.bin'),'candidate'),(os.path.join(stage_dir,'original.bin'),'original'),(os.path.join(stage_dir,'controller.yaml'),'config'),(os.path.join(stage_dir,m.STAGED_UNIT_NAME),'unit'),(os.path.join(stage_dir,'dropin-'+m.REQUIRED_DROPIN),'dropin'),(map_path(m.CONFIG),'config'),(map_path(m.CA),'ca'),(map_path(m.UNIT),'unit'),(map_path(m.INSTALLED),'original'),(dropin_path,'dropin')): digest_by_id[id(data_by_path[key])]=wanted[label]
    receipt={'schema':'controller-stage-receipt-v1','nonce':nonce,'candidate_sha256':m.IMAGE_SHA256,'candidate_bytes':m.IMAGE_BYTES,'manifest_sha256':m.MANIFEST_SHA256,'original_sha256':m.ORIGINAL_SHA256,'original_bytes':m.ORIGINAL_BYTES,'config_sha256':m.CONFIG_SHA256,'config_bytes':m.CONFIG_BYTES,'ca_sha256':m.CA_SHA256,'ca_bytes':m.CA_BYTES,'unit_sha256':wanted['unit'],'dropins':{m.REQUIRED_DROPIN:{'sha256':wanted['dropin'],'bytes':len(blobs['dropin'])}},'pid':1234,'invocation':'2'*32,'start_ticks':'55','process_dev':7,'process_ino':8,'image_dev':9,'image_ino':10,'check_config_exit':0,'check_config_success':True,'activationApproved':False}
    receipt_data=(json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')
    receipt_path=os.path.join(stage_dir,'receipt.json'); data_by_path[receipt_path]=receipt_data
    metadata={}
    class StatInfo:
        def __init__(self,mode,nlink=1,size=0,dev=1,ino=1,uid=0):
            self.st_mode=mode; self.st_nlink=nlink; self.st_size=size; self.st_dev=dev; self.st_ino=ino; self.st_uid=uid; self.st_mtime_ns=11; self.st_ctime_ns=12
    def fake_metadata(path):
        if path not in metadata:
            basename=os.path.basename(path)
            if path in (stage_root,drop_dir): metadata[path]=StatInfo(stat.S_IFDIR|0o700 if path==stage_root else stat.S_IFDIR|0o750,1,0,1,2,0)
            elif path==stage_dir: metadata[path]=StatInfo(stat.S_IFDIR|0o700,1,0,1,3,0)
            else:
                mode=0o700 if basename=='candidate.bin' else 0o600
                if path==map_path(m.INSTALLED): mode=0o755
                if path==map_path(m.CONFIG): mode=0o640
                if path==map_path(m.CA): mode=0o644
                if path==map_path(m.UNIT): mode=0o644
                data=data_by_path.get(path,b'fixture')
                dev,ino=(9,10) if path==map_path(m.INSTALLED) else (1,10+len(metadata))
                metadata[path]=StatInfo(stat.S_IFREG|mode,1,len(data),dev,ino,0)
        return metadata[path]
    def read_fixture(path,limit):
        events.append('read')
        data=data_by_path.get(path)
        if data is None or len(data)>limit: raise m.StageError('fixture_read')
        return data
    events=[]; service_calls=[]; service_state={'stale':False,'change_after':False}
    expected_live={'pid':1234,'invocation':'2'*32,'start':'55','proc_dev':7,'proc_ino':8,'exe_dev':9,'exe_ino':10}
    def service_fixture():
        events.append('service-read'); index=len(service_calls); service_calls.append(index)
        value=dict(expected_live)
        if service_state['stale']: value['pid']=1235
        if service_state['change_after'] and index>0: value['invocation']='3'*32
        return value,{}
    fixture={'path':map_path,'read_small':read_fixture,'trusted_path':fake_metadata,'lstat':fake_metadata,'service_identity':service_fixture,'private_parent':lambda:events.append('parent-read'),'stage_usage':lambda _path:(1,100),'sha256':lambda data:digest_by_id.get(id(data),m._sha(data))}
    side_effects=[]; old_check=m.run_check_config; old_write=m._write_exclusive
    def staged_state():
        result=[]
        for name in sorted(os.listdir(stage_dir)):
            entry=os.path.join(stage_dir,name); info=os.stat(entry)
            result.append((name,info.st_size,info.st_mtime_ns))
        return tuple(result)
    m.run_check_config=lambda *args,**kwargs:side_effects.append('check-config')
    m._write_exclusive=lambda *args,**kwargs:side_effects.append('write')
    try:
        before_stage=staged_state()
        ok(m._inspect(nonce,fixture)==receipt,'complete read-only inspect positive')
        ok(staged_state()==before_stage,'inspect left staged files unchanged')
        ok(len(service_calls)==2 and events.count('service-read')==2,'inspect brackets reads with service identity')
        ok(not side_effects and all(item in ('read','service-read','parent-read') for item in events),'inspect has no check-config or writes')
        service_calls.clear(); events.clear(); service_state['stale']=True
        rejects(lambda:m._inspect(nonce,fixture),'inspect_live_service')
        service_state['stale']=False; service_state['change_after']=True; service_calls.clear(); events.clear()
        rejects(lambda:m._inspect(nonce,fixture),'live_custody_changed')
        service_state['change_after']=False; service_calls.clear(); events.clear()
        extra=os.path.join(drop_dir,'unexpected.conf')
        with open(extra,'wb') as stream: stream.write(b'extra')
        rejects(lambda:m._inspect(nonce,fixture),'dropin_inventory')
        os.unlink(extra)
        os.unlink(dropin_path)
        rejects(lambda:m._inspect(nonce,fixture),'dropin_inventory')
        with open(dropin_path,'wb') as stream: stream.write(b'fixture')
        data_by_path[dropin_path]=b'changed-dropin'
        digest_by_id[id(data_by_path[dropin_path])] ='c'*64
        rejects(lambda:m._inspect(nonce,fixture),'inspect_dropin_changed')
        ok(not side_effects,'all inspect mutants remained read-only')
    finally:
        m.run_check_config=old_check; m._write_exclusive=old_write
print(json.dumps({'checks':checks},separators=(',',':')))
`;

test("Python receiver helpers enforce framed requests, file custody, and redacted check-config results", () => {
  const output = execFileSync(PYTHON, ["-B", "-c", PY_CONTROLS, RECEIVER], { encoding: "utf8", timeout: 30000, windowsHide: true, maxBuffer: 1024 * 1024 });
  const summary = JSON.parse(output);
  assert.equal(summary.checks, 56);
});

test("CLI exposes only stage and nonce-bound read-only inspect", () => {
  assert.deepEqual(parseCli(["--stage"]), { operation: "stage" });
  assert.deepEqual(parseCli(["--inspect", "0123456789abcdef0123456789abcdef"]), { operation: "inspect", nonce: "0123456789abcdef0123456789abcdef" });
  assert.throws(() => parseCli(["--latest"]), /invalid_cli/);
  assert.throws(() => parseCli(["--inspect", "../../etc"]), /invalid_cli/);
  assert.throws(() => parseCli(["--stage", "/tmp/arbitrary"]), /invalid_cli/);
});

test("remote response parser accepts only safe receipt identities and rejects raw failure detail", () => {
  const receipt = { schema: "controller-stage-receipt-v1", nonce: "0123456789abcdef0123456789abcdef", candidate_sha256: "c50f1a7a53ffbca3aa7835786eb1bae67fddfe69260381cd77ec6e7780bdb543", original_sha256: "ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c", manifest_sha256: "d94e61c723d62e6cdf675559298fb6dc3cf6311f7e24b28161f28f2c1ac53fe4", config_sha256: "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37", ca_sha256: "ddc7359a3f730b1817c7adff7ede84439bdf31cc56ff7cf658142473042c1944", check_config_success: true, check_config_exit: 0, activationApproved: false };
  assert.deepEqual(parseSafeResponse(Buffer.from(JSON.stringify({ ok: true, receipt }))), receipt);
  assert.throws(() => parseSafeResponse(Buffer.from(JSON.stringify({ ok: false, code: "secret /private/path" }))), /receiver_response_invalid/);
  assert.throws(() => parseSafeResponse(Buffer.from(JSON.stringify({ ok: true, receipt: { ...receipt, activationApproved: true } }))), /receiver_receipt_invalid/);
});

test("candidate pre-exec custody and read-only inspection pipelines reject mutations", () => {
  const output = execFileSync(PYTHON, ["-B", "-c", PIPELINE_CONTROLS, RECEIVER], { encoding: "utf8", timeout: 30000, windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
  const summary = JSON.parse(output);
  assert.equal(summary.checks, 27);
});

test("runner inventory validator rejects zero, duplicate, unexpected, skipped, and failed suites", () => {
  const lines = ["TAP version 13", ...TEST_NAMES.map((name, index) => `ok ${index + 1} - ${name}`), `1..${TEST_NAMES.length}`, `# tests ${TEST_NAMES.length}`, `# pass ${TEST_NAMES.length}`, "# fail 0", "# cancelled 0", "# skipped 0", "# todo 0"].join("\n");
  assert.equal(validateTapRun(0, lines), true);
  assert.throws(() => validateTapRun(0, lines.replace(`1..${TEST_NAMES.length}`, "1..0")), /test_inventory_mismatch|test_plan_mismatch/);
  assert.throws(() => validateTapRun(0, lines.replace(`ok 4 - ${TEST_NAMES[3]}`, `ok 3 - ${TEST_NAMES[2]}`)), /test_inventory_mismatch/);
  assert.throws(() => validateTapRun(0, lines.replace(TEST_NAMES[2], "unexpected test")), /test_inventory_mismatch/);
  assert.throws(() => validateTapRun(0, lines.replace(`ok 2 - ${TEST_NAMES[1]}`, `ok 2 - ${TEST_NAMES[1]} # SKIP`)), /test_directive_forbidden/);
  assert.throws(() => validateTapRun(0, lines.replace(`ok 3 - ${TEST_NAMES[2]}`, `ok 3 - ${TEST_NAMES[2]} # TODO`)), /test_directive_forbidden/);
  assert.throws(() => validateTapRun(0, lines.replace("# skipped 0", "# skipped 1")), /test_summary_mismatch/);
  assert.throws(() => validateTapRun(0, lines.replace("# todo 0", "# todo 1")), /test_summary_mismatch/);
  assert.throws(() => validateTapRun(0, lines.replace("# fail 0", "# fail 1")), /test_summary_mismatch/);
  assert.throws(() => validateTapRun(1, lines), /test_run_failed/);
});
}
