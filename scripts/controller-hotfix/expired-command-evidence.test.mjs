import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  WIRE_SCHEMA,
  _parseStrictJsonForTest,
  _projectAggregateForTest,
  _validateRowsForTest,
  _lbCompositionFixtureForTest,
  _ctCompositionFixtureForTest,
  validateProbeCli,
} from "./expired-command-evidence.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const pyPath = path.join(here, "expired-command-evidence.py");
const nonce = "0123456789abcdef0123456789abcdef";
const completed = [];
const inventory = ["python production matcher", "fixed CT streaming bootstrap", "strict JSON and exact envelope", "readonly aggregate and authority flags", "fixed CLI", "success-only inventory"];
assert.deepEqual(process.argv.slice(2), ["--verify"], "test CLI is exactly --verify");
const row = {
  id: "cmd-0123456789abcdef01234567", node_id: "fixture-node", idempotency_key: "fixture-idem",
  status: "expired", command: "load_model", target_id: "fixture-target", model: "fixture-model",
  created_at: "2025-01-01T00:00:00.123456Z", expires_at: "2025-01-01T00:00:10.123456Z",
  sent_at: "2025-01-01T00:00:01Z", last_sent_at: null, completed_at: "2025-01-01T00:00:00Z",
  body_id: "cmd-0123456789abcdef01234567", body_node_id: "fixture-node", body_idempotency_key: "fixture-idem",
  body_status: "expired", body_created_at: "2025-01-01T00:00:00.123456789Z",
  body_expires_at: "2025-01-01T00:00:10.123456789Z", body_sent_at: "2025-01-01T00:00:01Z",
  body_last_sent_at: null, body_completed_at: null, args_type: "object", target_type: "string", model_type: "string",
  body_result_present: false,
};

try {
  const composition = _lbCompositionFixtureForTest();
  const ctComposition = _ctCompositionFixtureForTest();
  assert.ok(ctComposition.args.join(" ").length < 8000);
  assert.ok(ctComposition.command.startsWith("exec /usr/sbin/pct exec 200 -- /usr/bin/python3 -I -B -c '"));
  assert.equal(ctComposition.args.at(-1), ctComposition.command);
  assert.ok(ctComposition.args.includes("root@10.0.0.3"));
  const ctKeyFlag = ctComposition.args.indexOf("-i");
  assert.equal(ctComposition.args[ctKeyFlag + 1], "C:/Users/Sasha/.ssh/cmp170_proxmox");
  assert.ok(ctComposition.args.includes("UserKnownHostsFile=C:/Users/Sasha/.ssh/known_hosts"));
  assert.ok(!ctComposition.args.join(" ").includes(ctComposition.nonce));
  const commandBytes = Buffer.from(composition.command, "utf8");
  const composedInput = Buffer.from(composition.input);
  const composerFrame = Buffer.alloc(8 + commandBytes.length + composedInput.length);
  composerFrame.writeUInt32BE(commandBytes.length, 0);
  commandBytes.copy(composerFrame, 4);
  composerFrame.writeUInt32BE(composedInput.length, 4 + commandBytes.length);
  composedInput.copy(composerFrame, 8 + commandBytes.length);
  const pyTests = String.raw`
import importlib.util, json, sys, re, io, subprocess
raw=sys.stdin.buffer.read(); csz=int.from_bytes(raw[:4],"big"); command=raw[4:4+csz].decode("utf-8"); pos=4+csz; psz=int.from_bytes(raw[pos:pos+4],"big"); payload=raw[pos+4:pos+4+psz]
assert pos+4+psz==len(raw) and command.startswith("/usr/bin/python3 -I -B -c '") and command.endswith("'")
program=command[len("/usr/bin/python3 -I -B -c '"):-1]
lengths=re.findall(r"_read_fixed\((\d+)\)",program); receiver_len=int(lengths[0]); helper_len=int(lengths[1]); assert len(payload)==receiver_len+helper_len
nonce="0123456789abcdef0123456789abcdef"
class Intercepted(BaseException): pass
class Tampered(BaseException): pass
original_popen=subprocess.Popen
def forbidden_popen(*args,**kwargs): raise AssertionError("external spawn reached")
def run_composer(source,payload_bytes,expected_nonce,allow_tamper=False):
    seen=[]
    def trace(frame,event,arg):
        if event=="call" and frame.f_code.co_name=="_lb_main":
            g=frame.f_globals; controller=g["_probe_service_and_config"].__globals__
            if frame.f_locals.get("nonce")!=expected_nonce: raise Tampered()
            assert controller["CONFIG_PATH"]=="/etc/vram-governor/controller.yaml" and controller["CONFIG_BYTES"]==6789
            assert controller["CONFIG_SHA256"]=="0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37"
            assert controller["IMAGE_PATH"]=="/usr/local/bin/vram-governor-controller" and controller["IMAGE_BYTES"]==12976280
            assert controller["IMAGE_SHA256"]=="ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c"
            assert controller["FIXED_ENV"]=={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8","HOME":"/nonexistent","PGCONNECT_TIMEOUT":"8","PGAPPNAME":"lb-node-command-share-fence"}
            assert g["CONFIG_PATH"]=="/etc/vram-governor/node-agent.yaml" and g["IMAGE_PATH"]=="/usr/local/bin/vram-governor-node-agent"
            assert g["FIXED_ENV"]=={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LANG":"C","LC_ALL":"C"}
            assert g["_fail"] is not controller["_fail"]
            required=("_probe_service_and_config","_connection_environment","_yaml_database_url","PsqlChannel","_validate_identity","IDENTITY_SQL","RESOLUTION_SQL","_same_original")
            assert all(g[k] is controller[k] for k in required)
            assert g["PsqlChannel"].query.__globals__ is controller and g["_same_original"].__globals__ is controller
            assert all(g[k].__globals__ is controller for k in ("_probe_service_and_config","_connection_environment","_yaml_database_url","_validate_identity"))
            seen.append(True); raise Intercepted()
        return trace
    old_stdin=sys.stdin; old_trace=sys.gettrace(); subprocess.Popen=forbidden_popen
    sys.stdin=io.TextIOWrapper(io.BytesIO(payload_bytes),encoding="utf-8")
    try:
        sys.settrace(trace); exec(compile(source,"<exact-fixed-lb-composer>","exec"),{"__name__":"__main__"})
    except Intercepted: return len(seen)==1
    except Tampered: return False
    finally:
        sys.settrace(old_trace); sys.stdin=old_stdin; subprocess.Popen=original_popen
    return False
assert run_composer(program,payload,nonce)
done=[]
done.append("isolated_production_lb_composition")
for label,offset in (("receiver",0),("helper",receiver_len)):
    broken=bytearray(payload); broken[offset+min(17,len(broken)-offset-1)]^=1
    old_stdin=sys.stdin; sys.stdin=io.TextIOWrapper(io.BytesIO(broken),encoding="utf-8")
    try:
        try: exec(compile(program,"<tampered-fixed-lb-composer>","exec"),{"__name__":"__main__"}); raise AssertionError("source tamper accepted")
        except SystemExit as stop: assert stop.code==3
    finally: sys.stdin=old_stdin
    done.append("source_tamper_rejected_"+label)
tampered_program=program.replace(nonce,"f"*32)
assert not run_composer(tampered_program,payload,nonce)
done.append("nonce_tamper_rejected")
spec=importlib.util.spec_from_file_location("expired_evidence", sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
def check(name, cond):
    assert cond, name
    done.append(name)
def parse_ct(raw):
    old=m.sys.stdin; m.sys.stdin=io.TextIOWrapper(io.BytesIO(raw),encoding="utf-8")
    try: return m._ct_input()
    finally: m.sys.stdin=old
valid_ct=json.dumps({"schema":m.WIRE_SCHEMA,"nonce":"0123456789abcdef0123456789abcdef","rows":[]},separators=(",",":" )).encode()
check("ct_input_valid_header",parse_ct(valid_ct)["rows"]==[])
try: parse_ct(valid_ct.replace(m.WIRE_SCHEMA.encode(),b"bad-schema")); raise AssertionError("bad CT header accepted")
except m.EvidenceError: pass
done.append("ct_input_bad_header_rejected")
try: parse_ct(valid_ct[:-1]); raise AssertionError("truncated CT body accepted")
except m.EvidenceError: pass
done.append("ct_input_truncated_body_rejected")
r={"id":"cmd-0123456789abcdef01234567","node_id":"fixture-node","idempotency_key":"fixture-idem","status":"expired","command":"load_model","target_id":"fixture-target","model":"fixture-model","created_at":"2025-01-01T00:00:00.123456Z","expires_at":"2025-01-01T00:00:10.123456Z","sent_at":"2025-01-01T00:00:01Z","last_sent_at":None,"completed_at":"2025-01-01T00:00:00Z","body_id":"cmd-0123456789abcdef01234567","body_node_id":"fixture-node","body_idempotency_key":"fixture-idem","body_status":"expired","body_created_at":"2025-01-01T00:00:00.123456789Z","body_expires_at":"2025-01-01T00:00:10.123456789Z","body_sent_at":"2025-01-01T00:00:01Z","body_last_sent_at":None,"body_completed_at":None,"args_type":"object","target_type":"string","model_type":"string","body_result_present":False}
def entry(at, ok=True, error=None):
    e={"id":r["id"],"node_id":r["node_id"],"ok":ok,"completed_at":at,"result":{"target_id":"fixture-target","model":"fixture-model","resident":True,"changed":False}}
    if error is not None: e["error"]=error
    if not ok: e.pop("result")
    return e
def cache(e): return {r["id"]:e,"key:"+r["idempotency_key"]:dict(e)}
c=cache(entry("2025-01-01T00:00:09.999999999Z")); out=m.match_cache_rows([r],c,"fixture-node")
check("paired_success",out["matched_pairs"]==1 and out["completed_before_expiry"]==1 and out["ok_true"]==1)
c=cache(entry("2025-01-01T00:00:10.123456789Z")); out=m.match_cache_rows([r],c,"fixture-node")
check("exact_nanosecond_expiry",out["completed_at_expiry"]==1)
c=cache(entry("2025-01-01T00:00:10.123456790Z")); out=m.match_cache_rows([r],c,"fixture-node")
check("one_nanosecond_after",out["completed_after_expiry"]==1)
no_sent=dict(r); no_sent.update({k:None for k in ("sent_at","last_sent_at","body_sent_at","body_last_sent_at")})
out=m.match_cache_rows([no_sent],cache(entry("2025-01-01T00:00:02Z")),"fixture-node")
check("missing_all_sent_unknown",out["time_binding_unknown"]==1 and out["completed_before_expiry"]==0)
one_sent=dict(r); one_sent["sent_at"]=None
check("one_sent_binding_suffices",m.match_cache_rows([one_sent],cache(entry("2025-01-01T00:00:02Z")),"fixture-node")["completed_before_expiry"]==1)
check("pg_microsecond_projection",m._row_valid(r,"fixture-node"))
check("valid_timezone_offset",m._time_ns("2025-01-01T01:30:00.123456789+01:30")==m._time_ns("2025-01-01T00:00:00.123456789Z"))
bad=dict(r); bad["expires_at"]="2025-01-01T00:00:10.123457Z"
check("neighbor_microsecond_rejected",not m._row_valid(bad,"fixture-node"))
for err, key in [("command expired","validation_refusal"),("model is not allowlisted by router discovery","catalog_refusal"),("target runtime does not expose lifecycle control","lifecycle_unsupported"),("private sentinel error","unknown_failure"),(None,"unknown_failure")]:
    c=cache(entry("2025-01-01T00:00:02Z",False,err)); out=m.match_cache_rows([r],c,"fixture-node")
    check("failure_"+key+"_"+str(err),out[key]==1)
exact={"node command signing is not configured":"validation_refusal","command identity is required":"validation_refusal","command is bound to a different node":"validation_refusal","invalid command signature":"validation_refusal","command expired":"validation_refusal","command issue time is in the future":"validation_refusal","target_id and model are required":"validation_refusal","target is not an allowlisted local inference server":"catalog_refusal","model is not allowlisted by router discovery":"catalog_refusal","target runtime does not expose lifecycle control":"lifecycle_unsupported"}
for error, category in exact.items():
    out=m.match_cache_rows([r],cache(entry("2025-01-01T00:00:02Z",False,error)),"fixture-node")
    check("exact_failure_"+category+"_"+str(len(error)),out[category]==1 and out["unknown_failure"]==0)
out=m.match_cache_rows([r],cache(entry("2025-01-01T00:00:02Z",False,"command expired private suffix")),"fixture-node")
check("failure_prefix_not_recognized",out["unknown_failure"]==1 and out["validation_refusal"]==0)
c=cache(entry("2025-01-01T00:00:02Z")); c["key:fixture-idem"]["node_id"]="other"
check("copy_mismatch",m.match_cache_rows([r],c,"fixture-node")["mismatched"]==1)
check("both_copies_missing",m.match_cache_rows([r],{},"fixture-node")["missing"]==1)
check("one_copy_missing",m.match_cache_rows([r],{r["id"]:entry("2025-01-01T00:00:02Z")},"fixture-node")["missing"]==1)
c=cache(entry("2025-01-01T00:00:02Z")); c[r["id"]]["id"]="cmd-ffffffffffffffffffffffff"
check("id_copy_wrong",m.match_cache_rows([r],c,"fixture-node")["mismatched"]==1)
c=cache(entry("2025-01-01T00:00:02Z")); del c["key:fixture-idem"]; c["key:wrong-idem"]=entry("2025-01-01T00:00:02Z")
check("wrong_idempotency_lookup",m.match_cache_rows([r],c,"fixture-node")["missing"]==1)
check("node_binding",m.match_cache_rows([r],cache(entry("2025-01-01T00:00:02Z")),"other")["malformed"]==1)
c=cache(entry("2025-01-01T00:00:02Z")); c["key:fixture-idem"]["result"]["model"]="other"
check("result_binding",m.match_cache_rows([r],c,"fixture-node")["result_mismatch"]==1)
badrow=dict(r); badrow["command"]="unload_model"
check("unsupported_command",m.match_cache_rows([badrow],{},"fixture-node")["malformed"]==1)
try: m.match_cache_rows([r]*33,{},"fixture-node"); raise AssertionError("row bound accepted")
except m.EvidenceError: pass
done.append("row_count_bound")
c=cache(entry("not-a-zoned-timestamp")); out=m.match_cache_rows([r],c,"fixture-node")
check("invalid_zone_unknown",out["time_binding_unknown"]==1)
c=cache(entry("2025-01-01T00:00:00.1234567890Z")); out=m.match_cache_rows([r],c,"fixture-node")
check("fraction_precision_rejected",out["time_binding_unknown"]==1)
c=cache(entry("2025-01-01T00:00:02+00:99")); out=m.match_cache_rows([r],c,"fixture-node")
check("invalid_plus_offset_unknown",out["time_binding_unknown"]==1)
c=cache(entry("2025-01-01T00:00:02-00:99")); out=m.match_cache_rows([r],c,"fixture-node")
check("invalid_minus_offset_unknown",out["time_binding_unknown"]==1)
c=cache(entry("2024-12-31T23:59:59Z")); out=m.match_cache_rows([r],c,"fixture-node")
check("completion_before_created",out["time_binding_unknown"]==1)
c=cache(entry("2025-01-01T00:00:00.5Z")); out=m.match_cache_rows([r],c,"fixture-node")
check("completion_before_sent",out["time_binding_unknown"]==1)
try: m._read_limited(__import__("io").BytesIO(b"12345"),4); raise AssertionError("wire bound accepted")
except m.EvidenceError: pass
done.append("wire_oversize_bound")
c=cache(entry("2025-01-01T00:00:02Z")); c[r["id"]]["error"]="PRIVATE-SENTINEL-DO-NOT-EMIT"
out=m.match_cache_rows([r],c,"fixture-node")
check("matcher_sentinel_suppressed",b"PRIVATE-SENTINEL-DO-NOT-EMIT" not in m._json_bytes(out))
c=cache(entry("2025-01-01T00:00:02Z")); c[r["id"]]["ok"]=1
check("malformed_cache_entry",m.match_cache_rows([r],c,"fixture-node")["malformed"]==1)
badrow=dict(r); badrow["body_result_present"]=True
check("body_result_unmatched_unknown",m.match_cache_rows([badrow],cache(entry("2025-01-01T00:00:02Z")),"fixture-node")["outcome_unknown"]==1)
check("nonstring_cache_key_safe",m.match_cache_rows([r],{**cache(entry("2025-01-01T00:00:02Z")),7:None},"fixture-node")["cache_invalid_entries"]==1)
check("state_parent_root_or_process_owner",m._parent_owner_allowed(0,True,1001) and m._parent_owner_allowed(1001,True,1001))
check("third_party_state_parent_rejected",not m._parent_owner_allowed(1002,True,1001) and not m._parent_owner_allowed(1001,False,1001))
import tempfile, pathlib, stat, types
real_safe=m._safe_parents; real_open_beneath=m._open_beneath_nofollow
real_lstat=m.os.lstat; real_stat=m.os.stat; real_fstat=m.os.fstat; real_read=m.os.read; real_close=m.os.close
with tempfile.TemporaryDirectory() as d:
    p=str(pathlib.Path(d)/"bounded-fixture"); pathlib.Path(p).write_bytes(b"fixed local fixture")
    content=b"fixed local fixture"
    parent_snapshot=(1,2,stat.S_IFDIR|0o700,0,0,1,0,1,1)
    file_stat=types.SimpleNamespace(**dict(zip(("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns"),(1,3,stat.S_IFREG|0o600,0,0,1,len(content),2,2))))
    parent_stat=types.SimpleNamespace(**dict(zip(("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns"),parent_snapshot)))
    def held_parents(path, process_uid=None): return (("fixture-parent",parent_snapshot),)
    def fixture_lstat(name): return file_stat if name==p else real_lstat(name)
    def fixture_stat(name,*args,dir_fd=None,follow_symlinks=True,**kwargs): return file_stat if dir_fd is not None or name==p else real_stat(name,*args,follow_symlinks=follow_symlinks,**kwargs)
    fd_roles={}; read_positions={}
    def open_fixture(path):
        file_fd=m.os.open(path,m.os.O_RDONLY); parent_fd=m.os.open(path,m.os.O_RDONLY); fd_roles[file_fd]="file"; fd_roles[parent_fd]="parent"; read_positions[file_fd]=0
        return file_fd,parent_fd
    def fixture_fstat(fd): return parent_stat if fd_roles.get(fd)=="parent" else file_stat if fd_roles.get(fd)=="file" else real_fstat(fd)
    def fixture_read(fd,size):
        if fd_roles.get(fd)!="file": return real_read(fd,size)
        start=read_positions[fd]; chunk=content[start:start+size]; read_positions[fd]=start+len(chunk); return chunk
    def fixture_close(fd): fd_roles.pop(fd,None); read_positions.pop(fd,None); return real_close(fd)
    m._safe_parents=held_parents; m._open_beneath_nofollow=open_fixture; m.os.lstat=fixture_lstat; m.os.stat=fixture_stat; m.os.fstat=fixture_fstat; m.os.read=fixture_read; m.os.close=fixture_close
    try:
        data,_=m._stable_file(p,128)
        check("stable_file_parent_positive",data==b"fixed local fixture")
        count=[0]
        def swapped_parents(path, process_uid=None):
            count[0]+=1
            swapped=parent_snapshot if count[0]==1 else (1,3,*parent_snapshot[2:])
            return (("fixture-parent",swapped),)
        m._safe_parents=swapped_parents
        try: m._stable_file(p,128); raise AssertionError("ancestor substitution accepted")
        except m.EvidenceError as error: assert error.args==("file_changed",)
        assert count[0]==2
        done.append("stable_file_parent_substitution_rejected")
    finally:
        m._safe_parents=real_safe; m._open_beneath_nofollow=real_open_beneath; m.os.lstat=real_lstat; m.os.stat=real_stat; m.os.fstat=real_fstat; m.os.read=real_read; m.os.close=real_close
try: m._json_load(b'{"a":1,"a":2}'); raise AssertionError("duplicate accepted")
except m.EvidenceError: pass
done.append("duplicate_json_rejected")
missing=dict(r); missing["id"]="cmd-111111111111111111111111"; missing["body_id"]=missing["id"]; missing["idempotency_key"]="missing-idem"; missing["body_idempotency_key"]=missing["idempotency_key"]
unknown=dict(r); unknown["id"]="cmd-222222222222222222222222"; unknown["body_id"]=unknown["id"]; unknown["idempotency_key"]="unknown-idem"; unknown["body_idempotency_key"]=unknown["idempotency_key"]; unknown["body_result_present"]=True
mixed=m.match_cache_rows([r,missing,unknown],cache(entry("2025-01-01T00:00:02Z")),"fixture-node")
print(json.dumps({"inventory":done,"mixedCounts":mixed},separators=(",",":")))
`;
  const py = spawnSync("py", ["-3", "-I", "-B", "-c", pyTests, pyPath], { input: composerFrame, encoding: "utf8", timeout: 10000, windowsHide: true, maxBuffer: 16384, env: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, ProgramData: "C:/ProgramData", PATH: process.env.PATH } });
  assert.equal(py.error, undefined, "bounded Python fixture runner");
  assert.equal(py.status, 0, `Python matcher fixtures (exit=${py.status}, stderrBytes=${Buffer.byteLength(py.stderr ?? "")})`);
  const pyResult = JSON.parse(py.stdout);
  const pyInventory = pyResult.inventory;
  assert.deepEqual(pyInventory, ["isolated_production_lb_composition", "source_tamper_rejected_receiver", "source_tamper_rejected_helper", "nonce_tamper_rejected", "ct_input_valid_header", "ct_input_bad_header_rejected", "ct_input_truncated_body_rejected", "paired_success", "exact_nanosecond_expiry", "one_nanosecond_after", "missing_all_sent_unknown", "one_sent_binding_suffices", "pg_microsecond_projection", "valid_timezone_offset", "neighbor_microsecond_rejected", "failure_validation_refusal_command expired", "failure_catalog_refusal_model is not allowlisted by router discovery", "failure_lifecycle_unsupported_target runtime does not expose lifecycle control", "failure_unknown_failure_private sentinel error", "failure_unknown_failure_None", "exact_failure_validation_refusal_38", "exact_failure_validation_refusal_28", "exact_failure_validation_refusal_36", "exact_failure_validation_refusal_25", "exact_failure_validation_refusal_15", "exact_failure_validation_refusal_35", "exact_failure_validation_refusal_32", "exact_failure_catalog_refusal_51", "exact_failure_catalog_refusal_44", "exact_failure_lifecycle_unsupported_48", "failure_prefix_not_recognized", "copy_mismatch", "both_copies_missing", "one_copy_missing", "id_copy_wrong", "wrong_idempotency_lookup", "node_binding", "result_binding", "unsupported_command", "row_count_bound", "invalid_zone_unknown", "fraction_precision_rejected", "invalid_plus_offset_unknown", "invalid_minus_offset_unknown", "completion_before_created", "completion_before_sent", "wire_oversize_bound", "matcher_sentinel_suppressed", "malformed_cache_entry", "body_result_unmatched_unknown", "nonstring_cache_key_safe", "state_parent_root_or_process_owner", "third_party_state_parent_rejected", "stable_file_parent_positive", "stable_file_parent_substitution_rejected", "duplicate_json_rejected"]);
  assert.ok(py.stderr.length === 0);
  completed.push("python production matcher");

  assert.equal(ctComposition.input.length, ctComposition.helperBytes + ctComposition.wire.length);
  const ctRunner = String.raw`
import os,subprocess,sys
command,nonce,fragment=sys.argv[1:]
fragment=int(fragment)
prefix="exec /usr/sbin/pct exec 200 -- /usr/bin/python3 -I -B -c '"
assert command.startswith(prefix) and command.endswith("'")
program=command[len(prefix):-1]
original_read=os.read
def fragmented_read(fd,size): return original_read(fd,size if fragment<=0 else min(size,fragment))
os.read=fragmented_read
class Intercepted(BaseException): pass
class Rejected(BaseException): pass
def forbidden_popen(*args,**kwargs): raise AssertionError("external spawn reached")
subprocess.Popen=forbidden_popen
def trace(frame,event,arg):
    if event=="call" and frame.f_code.co_name=="_ct_main":
        try: request=frame.f_globals["_ct_input"]()
        except Exception: raise Rejected()
        if request.get("schema")!="fixed-expired-command-evidence-v1" or request.get("nonce")!=nonce or request.get("rows")!=[{"id":"cmd-111111111111111111111111","node_id":"fixture-ct-node"}]: raise Rejected()
        raise Intercepted()
    return trace
try:
    sys.settrace(trace); exec(compile(program,"<exact-production-ct-bootstrap>","exec"),{"__name__":"__main__"})
except Intercepted:
    sys.stdout.write("fixed CT source and queued wire intercepted\n")
except Rejected:
    raise SystemExit(9)
except SystemExit as result:
    raise SystemExit(result.code)
finally:
    sys.settrace(None); os.read=original_read
`;
  const runCt = (fragment, input = ctComposition.input) => spawnSync("py", ["-3", "-I", "-B", "-c", ctRunner,
    ctComposition.command, ctComposition.nonce, String(fragment)],
    { input, encoding: "utf8", timeout: 10000, windowsHide: true, maxBuffer: 4096, env: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, ProgramData: "C:/ProgramData", PATH: process.env.PATH } });
  for (const fragment of [1, 7, 0]) {
    const result = runCt(fragment);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0);
    assert.equal(result.stdout.replace(/\r\n/g, "\n"), "fixed CT source and queued wire intercepted\n");
    assert.equal(result.stderr, "");
  }
  const badDigest = Buffer.from(ctComposition.input); badDigest[0] ^= 1;
  assert.equal(runCt(7, badDigest).status, 3);
  assert.equal(runCt(7, ctComposition.input.subarray(0, ctComposition.helperBytes - 1)).status, 2);
  assert.equal(runCt(7, ctComposition.input.subarray(0, ctComposition.input.length - 1)).status, 9);
  const badHeader = Buffer.concat([ctComposition.input.subarray(0, ctComposition.helperBytes), Buffer.from(ctComposition.wire.toString("utf8").replace("fixed-expired-command-evidence-v1", "bad-schema"), "utf8")]);
  assert.equal(runCt(7, badHeader).status, 9);
  const duplicateHeader = Buffer.from('{"schema":"fixed-expired-command-evidence-v1","nonce":"0123456789abcdef0123456789abcdef","rows":[],"rows":[]}');
  assert.equal(runCt(7, Buffer.concat([ctComposition.input.subarray(0, ctComposition.helperBytes), duplicateHeader])).status, 9);
  completed.push("fixed CT streaming bootstrap");

  const parsed = _parseStrictJsonForTest('{"schema":"x","nested":{"ok":true}}');
  assert.equal(Object.getPrototypeOf(parsed), null);
  assert.throws(() => _parseStrictJsonForTest('{"x":1,"x":2}'));
  const envelope = { schema: WIRE_SCHEMA, nonce, stage: "ok", expired_total: 1, unsupported_expired: 0, load_model_total: 1,
    rows: [row], read_only: true, original_custody_unchanged: true, database_timestamp_precision_limited: true,
    authoritative_outcome: false, permission_to_restart: false, command_history_changed: false };
  assert.equal(_validateRowsForTest(JSON.stringify(envelope), nonce).selected, 1);
  for (const mutate of [v => { v.nonce = "f".repeat(32); }, v => { v.permission_to_restart = true; }, v => { v.unsupported_expired = 1; }, v => { v.rows[0].node_id = "private sentinel"; }, v => { v.rows[0].command = "unload_model"; }, v => { v.load_model_total = 33; }, v => { v.expired_total = 2; }]) {
    const bad = structuredClone(envelope); mutate(bad); assert.throws(() => _validateRowsForTest(JSON.stringify(bad), nonce));
  }
  completed.push("strict JSON and exact envelope");

  const counts = pyResult.mixedCounts;
  assert.equal(counts.selected, 3);
  assert.equal(counts.matched_pairs, 1);
  assert.equal(counts.missing, 1);
  assert.equal(counts.outcome_unknown, 1);
  const ct = { schema: WIRE_SCHEMA, nonce, stage: "ok", counts, cache_custody_unchanged: true, original_custody_unchanged: true,
    database_timestamp_precision_limited: true, authoritative_outcome: false, permission_to_restart: false, command_history_changed: false };
  const result = _projectAggregateForTest(JSON.stringify(ct), nonce, 3, 3);
  assert.equal(result.authoritative_outcome, false);
  assert.equal(result.permission_to_restart, false);
  assert.equal(result.database_timestamp_precision_limited, true);
  assert.ok(!JSON.stringify(result).includes("private sentinel"));
  const promoted = structuredClone(ct); promoted.authoritative_outcome = true;
  assert.throws(() => _projectAggregateForTest(JSON.stringify(promoted), nonce, 3, 3));
  for (const mutate of [v => { v.counts.matched_pairs = 32; }, v => { v.counts.ok_true = 0; }, v => { v.counts.validation_refusal = 1; }, v => { v.counts.completed_before_expiry = 0; }, v => { v.counts.missing = 4; }]) {
    const bad = structuredClone(ct); mutate(bad); assert.throws(() => _projectAggregateForTest(JSON.stringify(bad), nonce, 3, 3));
  }
  const highInvalid = structuredClone(ct); highInvalid.counts.cache_invalid_entries = 74;
  assert.equal(_projectAggregateForTest(JSON.stringify(highInvalid), nonce, 3, 3).counts.cache_invalid_entries, 74);
  assert.throws(() => _projectAggregateForTest(JSON.stringify(ct), nonce, 4, 3));
  completed.push("readonly aggregate and authority flags");

  assert.equal(validateProbeCli(["--probe"]), true);
  for (const args of [[], ["--verify"], ["--probe", "extra"], ["--probe", "--probe"]]) assert.throws(() => validateProbeCli(args));
  completed.push("fixed CLI");
  assert.deepEqual(completed, inventory.slice(0, 5));
  completed.push("success-only inventory");
  assert.deepEqual(completed, inventory);
  process.stdout.write("fixed expired command evidence controls passed\n");
} catch (error) {
  process.stderr.write(`fixed expired command evidence test failed: ${error?.name === "AssertionError" ? error.message : "unknown"}\n`);
  process.exitCode = 1;
}
