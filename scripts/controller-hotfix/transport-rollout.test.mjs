import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { stableReceiver, RECEIVER_BYTES, RECEIVER_SHA256 } from "./command-fence.mjs";
import {
  PIN, PHASES, transition, validateBudgets, validateCli, validatePreflight, _planPinForTest,
} from "./transport-rollout-plan.mjs";
import {
  _buildProjectionForTest, _validateSnapshotForTest, _cliProjectionForTest, runPreflightWithSeams,
  _driveBridgeForTest, _settleChildCloseForTest, _observerCloseWithinDeadlineForTest, _observeCtChildForTest, _verifyCustodyWithinDeadlineForTest, _stopObserverChildForTest, _settleChildCloseWithinDeadlineForTest,
  _rolloutRemoteCommandForTest, _stablePythonSourceForTest, _ctRemoteCommandForTest, _bridgeSourcePinsForTest, _boundedProtectedObservationForTest, _validateCtObservationForTest, _parseCtObservationResponseForTest,
} from "./transport-rollout.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../..");
const EXPECTED = [
  "default-and-unknown-cli-no-effects", "apply-hard-disabled-before-custody", "bounded-phase-plan", "phase-transition-rejects-skip",
  "preflight-keeps-command-clear-false", "transport-predicate-independent-from-command-clear", "startup-admission-explicitly-unproven",
  "counts-must-match-expiry-diagnostic", "unknown-cache-linkage-not-green", "stage-identity-pinned", "effect-flags-always-false",
  "session-fence-close-on-preflight-error", "python-lock-loss-blocks-effect", "python-phase-drift-handoff", "python-keepalive-bound",
  "python-rollback-order-and-release", "python-settled-release", "python-preflight-history-nonauthority", "python-counts-match-expiry", "python-apply-denied",
 "python-actual-candidate-flow-mock", "python-actual-rollback-flow-mock", "python-lock-loss-handoff-no-retry", "phase-fence-same-backend-lock-release", "phase-fence-lost-backend", "ct-observation-valid-private-frame", "ct-observation-malformed-frame-redacted", "ct-real-agent-collector-wiring", "ct-drift-aborts-fenced-preflight", "apply-dispatch-zero-spawn-positive-spy", "actual-health-fragmented-positive", "actual-health-rejects-bad-status", "actual-rejoin-positive", "actual-rejoin-rejects-nonfinite", "systemd-stop-budget-positive", "systemd-stop-budget-exceeds-refused", "bridge-fragmented-frame-positive", "bridge-bad-sequence-refused", "bridge-eof-refused", "bridge-invalid-entry-redacted", "actual-fixed-operations-candidate-bridge-flow", "actual_fixed_operations_rollback_bridge_flow", "receiver-lock-loss-while-stopped-handoff", "receiver-unknown-start-handoff", "receiver-lost-stop-reply-observed-recovery", "receiver-lost-candidate-start-reply-owned-recovery", "receiver-foreign-candidate-before-our-start-not-adopted", "receiver-stop-pending-unverified-safe-handoff", "receiver-reserve-exhaustion-before-install-handoff", "receiver-install-lost-rename-no-unowned-restore", "receiver-restore-failure-no-restart", "atomic-install-success", "atomic-install-temp-fsync-cleanup", "atomic-install-parent-fsync-uncertain", "atomic-install-rename-lost-reply", "node-client-fake-candidate-flow", "node-client-late-responder-deadline", "node-client-child-error-failclosed", "node-child-close-must-be-observed", "bridge-monitor-no-response-byte-theft", "dual-source-bootstrap-exact-bounds-pins", "dual-source-bootstrap-fragmented-exec-positive", "dual-source-bootstrap-rejects-wrong-fence", "dual-source-bootstrap-rejects-wrong-rollout", "dual-source-bootstrap-truncated-sources-no-entry", "bridge-protected-stage-late-frame-refused", "controller-stop-observation-deadline-enforced", "protected-node-responder-budget-timeout", "receiver-protected-native-drift-rollback", "exact-inventory-and-marker",
];
EXPECTED.splice(-1, 0, "receiver-persistent-native-drift-uncertain", "controller-stop-slow-observation-zero-effect", "controller-readiness-slow-observation-no-query", "receiver-ineligible-counts-zero-effects", "receiver-ambiguous-stop-reply-no-foreign-restart", "receiver-candidate-start-ambiguous-no-recovery", "receiver-foreign-stop-pre-spawn-not-restarted", "receiver-post-spawn-stop-dispatch-uncertain", "receiver-foreign-candidate-pre-spawn-not-adopted", "receiver-post-spawn-start-dispatch-uncertain", "phase-fence-close-late-observation-refused");
EXPECTED.splice(-1, 0, "bridge-write-close-refused", "node-client-protected-slow-no-write");
EXPECTED.splice(-1, 0, "node-ct-negative-integers-refused");
EXPECTED.splice(-1, 0, "receiver-readiness-before-final-protected-sample");
EXPECTED.splice(-1, 0, "ct-observer-actual-close-and-uncertainty", "bridge-terminal-late-close-denied", "bridge-final-custody-late-denied", "fixed-capture-bounded-positive", "fixed-capture-spawn-time-in-deadline", "fixed-capture-timeout-cleanup-in-original-budget", "fixed-capture-late-wait-rejected", "command-fence-finish-fallback-kept-inside-reserve");
EXPECTED.splice(-1, 0, "bridge-early-candidate-terminal-refused", "bridge-early-restore-terminal-refused", "bridge-preflight-required-before-protected", "bridge-duplicate-preflight-refused", "bridge-candidate-final-protected-required", "bridge-restored-valid-two-protected", "bridge-restored-valid-three-protected");
EXPECTED.splice(-1, 0, "ct-realistic-nanosecond-wire-roundtrip", "ct-u64-canonical-range-controls");
EXPECTED.splice(-1, 0, "ct-generated-command-posix-bootstrap-positive", "ct-generated-command-mutated-quoting-refused", "ct-generated-command-bad-hash-refused", "ct-generated-command-truncated-source-refused", "ct-generated-command-bad-length-header-refused", "ct-generated-command-bad-hash-header-refused");
for (const obsolete of ["receiver-lost-stop-reply-observed-recovery", "receiver-lost-candidate-start-reply-owned-recovery"]) EXPECTED.splice(EXPECTED.indexOf(obsolete), 1);
const PY_EXPECTED = ["lock_loss","phase_drift_handoff","keepalive","rollback_order_and_release","settled_release","preflight_false_authority","counts_match","apply_denied","actual_candidate_flow","actual_rollback_flow","lock_loss_handoff","phase_fence_close","phase_fence_lost","phase_fence_close_late_observation_refused","ct_valid","ct_redacted","ct_collector_wiring","ct_identity_types_strict","actual_health_fragmented_positive","actual_health_rejects_bad_status","actual_rejoin_positive","actual_rejoin_rejects_nonfinite","systemd_stop_budget_positive","systemd_stop_budget_exceeds_refused","fixed_capture_bounded_positive","fixed_capture_spawn_time_in_deadline","fixed_capture_timeout_cleanup_in_original_budget","fixed_capture_late_wait_rejected","command-fence-finish-fallback_kept-inside-reserve","bridge_fragmented_frame_positive","bridge_bad_sequence_refused","bridge_eof_refused","bridge_write_close_refused","bridge_invalid_entry_redacted","bridge_monitor_no_response_byte_theft","bridge_protected_stage_late_frame_refused","controller_stop_observation_deadline_enforced","controller_stop_slow_observation_zero_effect","controller_readiness_slow_observation_no_query","actual_fixed_operations_candidate_bridge_flow","actual_fixed_operations_rollback_bridge_flow","receiver_lock_loss_while_stopped_handoff","receiver_unknown_start_handoff","receiver_ambiguous_stop_reply_no_foreign_restart","receiver_candidate_start_ambiguous_no_recovery","receiver_foreign_stop_pre_spawn_not_restarted","receiver-post-spawn-stop-dispatch-uncertain","receiver-foreign-candidate-pre-spawn-not-adopted","receiver-post-spawn-start-dispatch-uncertain","receiver-foreign-candidate-before-our-start-not-adopted","receiver_stop_pending_unverified_safe_handoff","receiver-reserve-exhaustion-before-install-handoff","receiver-install-lost-rename-no-unowned-restore","receiver-restore-failure-no-restart","receiver_protected_native_drift_rollback","receiver_persistent_native_drift_uncertain","receiver_invalid_protected_observation_sticky_uncertain","receiver_ineligible_counts_zero_effects","receiver_nonterminal_ineligible_zero_effects","receiver_uncertain_ineligible_zero_effects","receiver_malformed_ineligible_zero_effects","receiver_wrong_sequence_zero_effects","receiver_eof_zero_effects","receiver_write_close_abort","receiver_post_effect_wrong_frame_handoff","receiver_post_effect_eof_handoff","receiver_terminal_write_close_non_green","atomic_install_success","atomic_install_temp_fsync_cleanup","atomic_install_parent_fsync_uncertain","atomic_install_rename_lost_reply","atomic_final_replace_requires_fresh_inactive_same_fence","receiver_readiness_before_final_protected_sample"];
PY_EXPECTED[PY_EXPECTED.findIndex(name => name.startsWith("command-fence-finish-fallback"))] = "command-fence-finish-fallback_kept_inside_reserve";
const completed = [];
const failCli = (args) => {
  const result = spawnSync(process.execPath, [path.join(HERE, "transport-rollout.mjs"), ...args], { cwd: HERE, timeout: 3000, windowsHide: true, encoding: "utf8", maxBuffer: 2048, env: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, ProgramData: "C:/ProgramData", PATH: process.env.PATH } });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "fixed controller transport rollout failed closed\n");
};

failCli([]); failCli(["--bogus"]); completed.push(EXPECTED[0]);
failCli(["--apply"]); assert.equal(validateCli(["--apply"]), "apply"); completed.push(EXPECTED[1]);
assert.deepEqual(PHASES, ["preflight", "original-active", "original-stopped", "candidate-active", "rollback-original-active", "settled"]);
assert.equal(transition("original-active", "stop-verified"), "original-stopped");
assert.throws(() => transition("preflight", "candidate-start-verified"));
assert.deepEqual(validateBudgets({ sessionMs:170000,stopMs:20000,installMs:10000,startMs:5000,healthMs:10000,protectedMs:10000,rollbackReserveMs:80000,cleanupMs:5000}).sessionMs,170000);
assert.throws(() => validateBudgets({ sessionMs: 180001, stopMs: 1, installMs: 1, startMs: 1, healthMs: 1, protectedMs: 1, rollbackReserveMs: 3, cleanupMs: 1 }));
completed.push(EXPECTED[2], EXPECTED[3]);

const candidate = { manifest: { candidate: PIN.candidate, releaseApproved: false, installedBinaryProvenance: false } };
const snapshot = { total: 8, terminal: 8, expired: 2, nonterminal: 0, uncertain: 0, malformed: 0, command_clear: false };
const diagnostic = { schema: "expired-command-evidence-readonly-v1", scope: "expired_command_cache_linkage_readonly", read_only: true, original_custody_unchanged: true, cache_custody_unchanged: true, database_timestamp_precision_limited: true, authoritative_outcome: false, permission_to_restart: false, command_history_changed: false,
  counts: { selected: 2, expired_total: 2, matched_pairs: 2, missing: 0, mismatched: 0, malformed: 0, time_binding_unknown: 0, completed_before_expiry: 0, completed_at_expiry: 0, completed_after_expiry: 2, ok_true: 0, ok_false: 2, validation_refusal: 2, catalog_refusal: 0, lifecycle_unsupported: 0, unknown_failure: 0, outcome_unknown: 0, result_mismatch: 0, cache_invalid_entries: 0 } };
const stageReceipt = { nonce: "d771b06efb5715b296d04d891f3d854d", candidate_sha256: PIN.imageSha256, original_sha256: PIN.originalSha256, config_sha256: PIN.configSha256, activationApproved: false };
const ctUnit=(unit,pid,invocation,start,proc_ino)=>({unit,pid,invocation,start,proc_dev:1,proc_ino,cgroup:`/system.slice/${unit}`,cgroup_dev:1,cgroup_ino:proc_ino+100,cgroup_procs_sha256:"e".repeat(64),command_sha256:"d".repeat(64)});
const ctObservation = { agent: { pid:315,node_id:"fixture-node",proc_dev:1,proc_ino:2,exe_dev:1,exe_ino:3,config:["1","2","1800000000123456789","1800000000123456790"],unit_file:["1","4","1800000001123456789","1800000001123456790"],image:["1","7","1800000002123456789","1800000002123456790"],command_sha256:"a".repeat(64),service:ctUnit("vram-governor-node-agent.service",315,"b".repeat(32),"42",2) }, native:["llama-server.service","comfyui.service","comfy-harness.service","vram-governor-runtime-tunnel.service"].map((unit,i)=>ctUnit(unit,500+i,String(i+1).repeat(32),String(100+i),20+i)) };
_validateCtObservationForTest(ctObservation);
const invalidCtMetadataValues = [1,1800000000123456789,-1,"0180000000123456789","+1","-1","1e3","18446744073709551616",null];
for (const invalidValue of invalidCtMetadataValues) assert.throws(()=>_validateCtObservationForTest({ ...ctObservation, agent:{...ctObservation.agent,config:["1","2",invalidValue,"1800000000123456790"]} }));
_validateCtObservationForTest({ ...ctObservation, agent:{...ctObservation.agent,config:["0","18446744073709551615","1800000000123456789","1800000000123456790"]} });
completed.push("ct-u64-canonical-range-controls");
for (const invalid of [{ ...ctObservation, agent:{...ctObservation.agent,config:["-1","2","3","4"]} },{ ...ctObservation,native:ctObservation.native.map((row,i)=>i===0?{...row,proc_ino:-1}:row) },{...ctObservation,native:ctObservation.native.map((row,i)=>i===0?{...row,cgroup:null}:row)}, {...ctObservation,native:ctObservation.native.map((row,i)=>i===0?{...row,start:123}:row)}, {...ctObservation,native:ctObservation.native.map((row,i)=>i===0?{...row,invocation:7}:row)}, {...ctObservation,native:ctObservation.native.map((row,i)=>i===0?{...row,command_sha256:7}:row)}, {...ctObservation,agent:{...ctObservation.agent,command_sha256:7}}, {...ctObservation,agent:{...ctObservation.agent,service:{...ctObservation.agent.service,start:42}}}]) assert.throws(()=>_validateCtObservationForTest(invalid));
const projection = _buildProjectionForTest(candidate, snapshot, diagnostic, stageReceipt);
assert.equal(projection.command.command_clear, false); completed.push(EXPECTED[4]);
assert.equal(projection.command.transport_only_candidate, true); completed.push(EXPECTED[5]);
assert.equal(projection.startup_admission_proven, false); completed.push(EXPECTED[6]);
const unknownLinkedCommand = { ...projection.command, cache_matched_pairs: 1, cache_unknown: 1, transport_only_candidate: true };
assert.throws(() => validatePreflight({ ...projection, command: unknownLinkedCommand }));
assert.equal(validatePreflight({ ...projection, command: { ...unknownLinkedCommand, transport_only_candidate: false } }).command.transport_only_candidate, false);
assert.throws(() => _buildProjectionForTest(candidate, { ...snapshot, expired: 1 }, diagnostic, stageReceipt)); completed.push(EXPECTED[7]);
assert.throws(() => _buildProjectionForTest(candidate, snapshot, { ...diagnostic, counts: { ...diagnostic.counts, matched_pairs: 1 } }, stageReceipt)); completed.push(EXPECTED[8]);
assert.throws(() => _buildProjectionForTest(candidate, snapshot, diagnostic, { ...stageReceipt, candidate_sha256: "0".repeat(64) })); completed.push(EXPECTED[9]);
assert.throws(() => _buildProjectionForTest(candidate, snapshot, { ...diagnostic, permission_to_restart: true }, stageReceipt)); completed.push(EXPECTED[10]);
await assert.rejects(runPreflightWithSeams({ verifyCandidate: () => candidate, observeCt: async()=>ctObservation, openFence: async () => ({ snapshot: async () => { throw new Error("fixture"); }, close: async () => {}, abort: async () => {} }), readExpiry: () => diagnostic, readStage: () => stageReceipt }));
const order = [];
const preflight = await runPreflightWithSeams({
  verifyCandidate: async () => { order.push("candidate"); return candidate; },
  observeCt: async()=>{ order.push("ct"); return ctObservation; },
  openFence: async () => { order.push("fence"); return { snapshot: async () => { order.push("snapshot"); return snapshot; }, close: async () => order.push("close"), abort: async () => order.push("abort") }; },
  readExpiry: () => { order.push("expiry"); return diagnostic; }, readStage: () => { order.push("stage"); return stageReceipt; },
});
assert.equal(preflight.command.command_clear, false);
assert.deepEqual(order, ["ct", "candidate", "fence", "snapshot", "expiry", "stage", "ct", "snapshot", "close"]);
completed.push(EXPECTED[11]);
let closeClock=0n; let closeDidResolve=false;
const timelyClose=await runPreflightWithSeams({ monotonicNs:()=>closeClock, verifyCandidate:()=>candidate, observeCt:async()=>ctObservation,
  openFence:async()=>({snapshot:async()=>snapshot,close:async()=>{closeDidResolve=true;},abort:async()=>{throw new Error("unexpected abort");}}),
  readExpiry:()=>diagnostic,readStage:()=>stageReceipt });
assert.ok(timelyClose && closeDidResolve);
closeClock=0n;
await assert.rejects(runPreflightWithSeams({ monotonicNs:()=>closeClock, verifyCandidate:()=>candidate, observeCt:async()=>ctObservation,
  openFence:async()=>({snapshot:async()=>snapshot,close:async()=>{closeClock=180000000000n;},abort:async()=>{throw new Error("close already released");}}),
  readExpiry:()=>diagnostic,readStage:()=>stageReceipt }));

const pyScript = String.raw`
import importlib.util,sys,time,os,posixpath,threading,base64
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('_fixed_transport_fixture',sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); M=m.PhaseMachine; bad=m.RolloutRefused; done=[]
ident={'pid':10,'invocation':'a'*32,'start':'1','proc_dev':1,'proc_ino':2,'cgroup':'/system.slice/vram-governor-controller.service','image_dev':1,'image_ino':2,'image_sha256':'b'*64,'config_sha256':'c'*64,'unit_sha256':'d'*64,'timeout_stop_us':15000000}
clock=[1000]
x=M(170000,lambda:clock[0]); x.transition('accept',True,'preflight',ident)
try: x.effect_boundary('controller-stop',False,'original-active',ident); raise AssertionError('lock-loss accepted')
except bad: done.append('lock_loss')
y=M(170000,lambda:clock[0]); y.transition('accept',True,'preflight',ident)
try: y.transition('stop-verified',True,'candidate-active',ident); raise AssertionError('phase drift accepted')
except bad: done.append('phase_drift_handoff')
z=M(170000,lambda:clock[0]); z.transition('accept',True,'preflight',ident); clock[0]+=5001
try: z.effect_boundary('controller-stop',True,'original-active',ident); raise AssertionError('stale keepalive accepted')
except bad: done.append('keepalive')
clock[0]=1000; r=M(170000,lambda:clock[0]); r.transition('accept',True,'preflight',ident); r.effect_boundary('controller-stop',True,'original-active',ident); r.transition('stop-verified',True,'original-active',ident); r.effect_boundary('image-install',True,'original-stopped',ident); r.transition('install-verified',True,'original-stopped',ident); r.effect_boundary('controller-start',True,'original-stopped',ident); r.transition('candidate-start-verified',True,'original-stopped',ident); r.transition('rollback-started',True,'candidate-active',ident); r.effect_boundary('candidate-stop',True,'rollback-original-active',ident); r.effect_boundary('original-restore',True,'rollback-original-active',ident); r.effect_boundary('original-restart',True,'rollback-original-active',ident); r.transition('original-verified',True,'rollback-original-active',ident); r.release(True,True,True,'settled',ident); done.append('rollback_order_and_release')
q=M(170000,lambda:clock[0]); q.transition('accept',True,'preflight',ident); q.transition('stop-verified',True,'original-active',ident); q.effect_boundary('image-install',True,'original-stopped',ident); q.transition('install-verified',True,'original-stopped',ident); q.transition('candidate-start-verified',True,'original-stopped',ident); q.transition('accept',True,'candidate-active',ident); q.release(True,True,True,'settled',ident); done.append('settled_release')
p=m.validate_preflight_counts({'total':8,'terminal':8,'expired':2,'nonterminal':0,'uncertain':0,'malformed':0,'command_clear':False},{'counts':{'selected':2,'expired_total':2,'matched_pairs':2,'outcome_unknown':0}})
assert p['command_clear'] is False and p['startup_admission_proven'] is False and p['transport_only_candidate'] is True; done.append('preflight_false_authority')
try: m.validate_preflight_counts({'total':8,'terminal':8,'expired':1,'nonterminal':0,'uncertain':0,'malformed':0,'command_clear':False},{'counts':{'selected':2,'expired_total':2}}); raise AssertionError('mismatched counts accepted')
except bad: done.append('counts_match')
try: m.apply_cli_refusal(); raise AssertionError('apply enabled')
except bad: done.append('apply_denied')
ORIG='ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c'; CAND='c50f1a7a53ffbca3aa7835786eb1bae67fddfe69260381cd77ec6e7780bdb543'; CONFIG='0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37'; UNIT='a'*64
def running(digest,pid): return {'pid':pid,'invocation':('a' if digest==ORIG else 'b')*32,'start':str(pid),'proc_dev':1,'proc_ino':pid,'cgroup':'/system.slice/vram-governor-controller.service','image_dev':1,'image_ino':2 if digest==ORIG else 3,'image_sha256':digest,'config_sha256':CONFIG,'unit_sha256':UNIT,'timeout_stop_us':15000000}
def inactive(digest): return {'mainpid':0,'active_state':'inactive','sub_state':'dead','job_empty':True,'cgroup':'/system.slice/vram-governor-controller.service','cgroup_pids':[],'image_dev':1,'image_ino':2 if digest==ORIG else 3,'image_sha256':digest,'config_sha256':CONFIG,'unit_sha256':UNIT,'timeout_stop_us':15000000}
class Fence:
 def __init__(self,alive=True): self.alive=alive; self.closed=[]
 def keepalive(self): return self.alive
 def close_phase(self,phase,identity): self.closed.append((phase,identity['image_sha256']))
class Ops:
 def __init__(self,fail_health=False,lose_stop=False): self.state='original-active'; self.image=ORIG; self.restoring=False; self.fail_health=fail_health; self.health_calls=0; self.log=[]; self.fence=None; self.lose_stop=lose_stop; self.candidate_installed_identity=None
 def remaining_ms(self): return 170000
 def repeat_preflight(self,fence): return fence.keepalive()
 def check_deadline(self): return True
 def observe_controller(self):
  if self.state=='original-stopped': return {'phase':self.state,'identity':inactive(self.image)}
  digest=ORIG if self.restoring else self.image
  return {'phase':self.state,'identity':running(digest,12 if digest==ORIG and self.restoring else 10 if digest==ORIG else 11)}
 def observe_protected(self): return {'ct_agent':'fixture','native_units':'fixture'}
 def write_journal(self,phase,effects,uncertain): self.log.append('journal:'+phase)
 def stop_controller(self,budget,fence): self.log.append('stop'); self.stop_command_completed=True
 def wait_controller_stopped(self,budget,fence): self.state='original-stopped'; self.log.append('stopped')
 def install_candidate(self,budget,fence): self.image=CAND; self.candidate_installed_identity=running(CAND,11); self.log.append('install')
 def start_controller(self,budget,fence): self.state='candidate-active' if not self.restoring else 'original-active'; self.start_command_completed=True; self.start_attempted=True; self.log.append('start')
 def check_readiness(self,budget,fence):
  self.health_calls+=1
  if self.fail_health and self.health_calls==1: raise RuntimeError('fixture readiness failure')
 def stop_candidate(self,identity,budget,fence): self.state='original-stopped'; self.log.append('stop-candidate')
 def restore_original(self,identity,budget,fence): self.image=ORIG; self.restoring=True; self.log.append('restore')
budget={'session_ms':170000,'stop_ms':20000,'install_ms':10000,'start_ms':5000,'health_ms':10000,'protected_ms':10000,'rollback_reserve_ms':80000,'cleanup_ms':5000}
f=Fence(); o=Ops(); result=m.run_controller_rollout(f,o,budget); assert result['phase']=='candidate-active' and f.closed==[('candidate-active',CAND)] and o.log.index('journal:stop_intent')<o.log.index('stop'); done.append('actual_candidate_flow')
f=Fence(); o=Ops(fail_health=True); result=m.run_controller_rollout(f,o,budget); assert result['phase']=='original-active' and result['rollback'] is True and f.closed==[('original-active',ORIG)] and o.log.index('stop-candidate')<o.log.index('restore')<o.log.index('start',o.log.index('restore')); done.append('actual_rollback_flow')
f=Fence(); o=Ops(lose_stop=True); o.fence=f
def lose_after_stop(budget,fence):
 o.log.append('stop-intent-issued'); o.state='original-stopped'; fence.alive=False; raise RuntimeError('uncertain stop reply')
o.stop_controller=lose_after_stop; result=m.run_controller_rollout(f,o,budget); assert result['phase']=='handoff' and 'install' not in o.log and 'restore' not in o.log and 'journal:handoff_fence_lost' in o.log; done.append('lock_loss_handoff')
class DB:
 def __init__(self,lose=False): self.calls=[]; self.finished=False; self.aborted=False; self.lose=lose; self.holds=0; self.snapshot={'total':8,'terminal':8,'expired':2,'nonterminal':0,'uncertain':0,'malformed':0}
 def query(self,sql,marker,timeout=3):
  self.calls.append(marker)
  if marker=='identity': return {'database':'fixed','role':'fixed','search_path':'public'}
  if marker=='resolution': return {'resolution_matches':True}
  if marker=='transaction': return {'transaction':True}
  if marker=='readwrite': return {'read_only':'off'}
  if marker in ('lock','held'):
   self.holds+=1
   answer={'held':not(self.lose and self.holds>2)}
   if sql==m.PHASE_LOCK_SQL: answer['resolution_matches']=True
   return answer
  if marker=='snapshot': return dict(self.snapshot)
  if marker=='rollback': return {'rollback':True}
  if marker=='absent': return {'absent':True}
  raise AssertionError('unexpected fixed marker')
 def finish(self,timeout=5): self.finished=True
 def abort(self): self.aborted=True
 def rollback_cleanup(self): self.aborted=True
class FN:
 IDENTITY_SQL='identity'; READ_WRITE_SQL='readwrite'; RESOLUTION_SQL='resolution'; LOCK_SQL='held'; ABSENT_SQL='absent'; SNAPSHOT_SQL='snapshot'
 @staticmethod
 def _probe_service_and_config(): return {'service':{},'config':('cfg',),'bytes':b'fixed'}
 @staticmethod
 def _connection_environment(x): return {}
 @staticmethod
 def _yaml_database_url(x): return 'dsn'
 @staticmethod
 def _validate_identity(x): return True
 @staticmethod
 def _project_summary(x): return dict(x,command_clear=False)
 @staticmethod
 def _config_bytes(): return b'fixed',('cfg',)
 def __new__(cls,db): obj=object.__new__(cls); obj.PsqlChannel=lambda env:db; return obj
db=DB(); ns=FN(db); pf=m.PhaseFence(ns,180,lambda:1000); snap=pf.snapshot()
with patch.object(m,'_observe_controller_fixed',lambda deadline=None:{'phase':'candidate-active','identity':running(CAND,11)}): closed_phase=pf.close_phase('candidate-active',running(CAND,11))
assert snap['expired']==2 and closed_phase is True and db.finished and db.calls.count('held')>=3; done.append('phase_fence_close')
db=DB(lose=True); ns=FN(db); pf=m.PhaseFence(ns,180,lambda:1000)
try: pf.snapshot(); raise AssertionError('lost granted lock accepted')
except bad: pf.abort(); assert db.aborted and not db.finished; done.append('phase_fence_lost')
late_fence_clock=[1000.0]; late_db=DB(); late_fence=m.PhaseFence(FN(late_db),10,lambda:late_fence_clock[0])
def late_phase_observation(deadline=None): late_fence_clock[0]=1010.0; return {'phase':'candidate-active','identity':running(CAND,11)}
with patch.object(m,'_observe_controller_fixed',late_phase_observation):
 try: late_fence.close_phase('candidate-active',running(CAND,11)); raise AssertionError('late final phase observation released fence')
 except bad: late_fence.abort()
assert not late_db.finished and late_fence.cleanup_outcome=='uncertain'; done.append('phase_fence_close_late_observation_refused')
import io
service=lambda u,pid,inv,start,ino:{'unit':u,'pid':pid,'invocation':inv,'start':start,'proc_dev':1,'proc_ino':ino,'cgroup':'/system.slice/'+u,'cgroup_dev':1,'cgroup_ino':ino+100,'cgroup_procs_sha256':'e'*64,'command_sha256':'d'*64}
agent={'pid':315,'node_id':'fixture-node','proc_dev':1,'proc_ino':2,'exe_dev':1,'exe_ino':3,'config':['1','2','1800000000123456789','1800000000123456790'],'unit_file':['1','4','1800000001123456789','1800000001123456790'],'image':['1','7','1800000002123456789','1800000002123456790'],'command_sha256':'a'*64,'service':service('vram-governor-node-agent.service',315,'b'*32,'42',2)}
units=[service(u,500+i,str(i+1)*32,str(100+i),20+i) for i,u in enumerate(('llama-server.service','comfyui.service','comfy-harness.service','vram-governor-runtime-tunnel.service'))]
observation={'agent':agent,'native':units}; m.observe_ct_identity=lambda:observation
request={'schema':'controller-transport-ct-observation-v1','nonce':'0123456789abcdef0123456789abcdef','operation':'observe'}; out=io.BytesIO(); assert m.serve_ct_observation(io.BytesIO((__import__('json').dumps(request)+'\n').encode()),out)==0
response=__import__('json').loads(out.getvalue()); assert response['ok'] is True and response['observation']==observation; done.append('ct_valid')
out=io.BytesIO(); malformed=b'{"schema":"controller-transport-ct-observation-v1","nonce":"private-sentinel","nonce":"0123456789abcdef0123456789abcdef","operation":"observe"}\n'; assert m.serve_ct_observation(io.BytesIO(malformed),out)==1
assert b'private-sentinel' not in out.getvalue() and b'nonce":null' in out.getvalue(); done.append('ct_redacted')
from unittest.mock import patch
from types import SimpleNamespace
import builtins
config=b'node_id: fixture-node\ncommand_state_path: /var/lib/vram-governor/node-command-state.json\n'; config += b'#'+b'x'*(1821-len(config)-2)+b'\n'
unit=b'u'*773; image=b'i'*658
epoch_ns=1800000000123456789
meta_cfg=(1,2,epoch_ns,epoch_ns+1); meta_unit=(1,4,epoch_ns+100,epoch_ns+101); meta_image=(1,7,epoch_ns+200,epoch_ns+201)
exe_command=m.CT_IMAGE.encode()+b'\0-config\0'+m.CT_CONFIG.encode()+b'\0'
proc_stat=SimpleNamespace(st_dev=1,st_ino=2); exe_stat=SimpleNamespace(st_dev=1,st_ino=7)
real_open=builtins.open
def fixture_open(name,*args,**kwargs):
 if name=='/proc/315/cmdline': return io.BytesIO(exe_command)
 raise AssertionError('unexpected collector file access')
def file_fixture(name,length,digest,mode,gid):
 if name==m.CT_CONFIG: return config,meta_cfg
 if name==m.CT_UNIT: return unit,meta_unit
 if name==m.CT_IMAGE: return image,meta_image
 raise AssertionError('unexpected fixed file')
fixture_units=lambda name: service(name,315 if name=='vram-governor-node-agent.service' else 501,'b'*32,'42',2)
with patch.object(m,'CT_CONFIG_BYTES',len(config)),patch.object(m,'CT_CONFIG_SHA256',__import__('hashlib').sha256(config).hexdigest()),patch.object(m,'CT_UNIT_BYTES',len(unit)),patch.object(m,'_ct_file',file_fixture),patch.object(m,'_ct_unit',fixture_units),patch.object(m.os,'stat',lambda p: exe_stat if p.endswith('/exe') else proc_stat),patch.object(m.os,'readlink',lambda p:m.CT_IMAGE),patch.object(builtins,'open',fixture_open):
 actual=m._ct_agent(); m.validate_ct_identity({'agent':actual,'native':[fixture_units(name) for name in m.CT_NATIVE]})
 assert actual['config']==['1','2',str(epoch_ns),str(epoch_ns+1)] and int(actual['config'][3])-int(actual['config'][2])==1
 wire_observation={'agent':actual,'native':[fixture_units(name) for name in m.CT_NATIVE]}
 m.observe_ct_identity=lambda:wire_observation
 wire_request={'schema':m.CT_SCHEMA,'nonce':'0123456789abcdef0123456789abcdef','operation':'observe'}; wire_output=io.BytesIO()
 assert m.serve_ct_observation(io.BytesIO((__import__('json').dumps(wire_request,separators=(',',':'))+'\n').encode()),wire_output)==0
 wire_response=__import__('json').loads(wire_output.getvalue()); assert wire_response['ok'] is True and wire_response['observation']==wire_observation
 ct_wire_b64=base64.b64encode(wire_output.getvalue().rstrip(b'\n')).decode('ascii')
 badcfg=config.replace(b'fixture-node',b'bad node')
 with patch.object(m,'_ct_file',lambda name,*args:(badcfg if name==m.CT_CONFIG else (unit if name==m.CT_UNIT else image),meta_cfg if name==m.CT_CONFIG else (meta_unit if name==m.CT_UNIT else meta_image))):
  try: m._ct_agent(); raise AssertionError('invalid configured node accepted')
  except bad: pass
done.append('ct_collector_wiring')
assert m._ct_stat_tuple((0,1,m.CT_STAT_U64_MAX,m.CT_STAT_U64_MAX))==['0','1',str(m.CT_STAT_U64_MAX),str(m.CT_STAT_U64_MAX)]
for bad_metadata in ((0,1,-1,4),(0,1,m.CT_STAT_U64_MAX+1,4),(0,1,True,4)):
 try: m._ct_stat_tuple(bad_metadata); raise AssertionError('out-of-range CT stat metadata encoded')
 except bad: pass
for broken in (
 {'agent':{**agent,'service':{**agent['service'],'start':42}},'native':units},
 {'agent':agent,'native':[dict(units[0],invocation=7),*units[1:]]},
 {'agent':agent,'native':[dict(units[0],command_sha256=7),*units[1:]]},
):
 try: m.validate_ct_identity(broken); raise AssertionError('non-string CT identity accepted')
 except bad: pass
for bad_value in (0,True,'00','01','+1','-1','1e3',str(m.CT_STAT_U64_MAX+1),'9'*21):
 broken={'agent':dict(agent),'native':units}; broken['agent']['config']=['1','2',bad_value,'4']
 try: m.validate_ct_identity(broken); raise AssertionError('noncanonical CT uint64 accepted')
 except bad: pass
done.append('ct_identity_types_strict')
import socket,ssl
response=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+str(len(m.CONTROLLER_HEALTH_BODY)).encode()+b'\r\nConnection: close\r\n\r\n'+m.CONTROLLER_HEALTH_BODY
class FakeSocket:
 def __init__(self,data): self.data=data; self.timeouts=[]
 def __enter__(self): return self
 def __exit__(self,*args): return False
 def settimeout(self,value): self.timeouts.append(value)
 def sendall(self,data): assert data.startswith(b'GET /healthz HTTP/1.1') and b'Host: '+m.CONTROLLER_ADDRESS.encode()+b'\r\n' in data
 def recv(self,n): value=self.data[:min(n,7)]; self.data=self.data[len(value):]; return value
class FakeTLS:
 check_hostname=True; verify_mode=ssl.CERT_REQUIRED
 def wrap_socket(self,sock,server_hostname): assert server_hostname==m.CONTROLLER_ADDRESS; return sock
def health(data=response):
 fs=FakeSocket(data)
 with patch.object(m,'_read_pinned_file',lambda *a,**k:(b'-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n',{})),patch.object(m.ssl,'create_default_context',lambda **kw:FakeTLS()),patch.object(m.socket,'create_connection',lambda *a,**k:fs):
  try: m._fixed_controller_health_get(time.monotonic()+2); return True
  except bad: return False
assert health() is True; done.append('actual_health_fragmented_positive')
assert health(response.replace(b'200 OK',b'503 Nope')) is False; done.append('actual_health_rejects_bad_status')
clock=[1000.0]; db=DB(); fence=m.PhaseFence(FN(db),180); calls=[]
fence.keepalive=lambda:True
fence._query=lambda sql,marker,timeout=3:(calls.append((sql,marker,timeout)) or {'found':True,'connected':True,'ready':True,'heartbeat_epoch':time.time()})
assert m._fixed_node_rejoin_query(fence,'fixture-node',time.time()-1,time.monotonic()+1) is True and calls[0][1]=='snapshot' and calls[0][2]<=0.75; done.append('actual_rejoin_positive')
fence._query=lambda sql,marker,timeout=3:{'found':True,'connected':True,'ready':True,'heartbeat_epoch':float('nan')}
try: m._fixed_node_rejoin_query(fence,'fixture-node',time.time()-1,time.monotonic()+0.02); raise AssertionError('nonfinite heartbeat accepted')
except bad: done.append('actual_rejoin_rejects_nonfinite')
assert m._systemd_timeout_us('15s')==15000000; done.append('systemd_stop_budget_positive')
try: m._systemd_timeout_us('21s'); raise AssertionError('oversized stop timeout accepted')
except bad: done.append('systemd_stop_budget_exceeds_refused')
class CaptureStream:
 def __init__(self,fd): self.fd=fd; self.closed=False
 def fileno(self): return self.fd
 def close(self): self.closed=True
class CaptureChild:
 def __init__(self,clock=None,wait_delay=0): self.stdin=CaptureStream(1); self.stdout=CaptureStream(2); self.stderr=CaptureStream(3); self.code=None; self.killed=False; self.waits=[]; self.clock=clock; self.wait_delay=wait_delay
 def poll(self): return self.code
 def wait(self,timeout=None): self.waits.append(timeout); self.clock[0]+=self.wait_delay if self.clock is not None else 0; self.code=0 if not self.killed else -9; return self.code
 def kill(self): self.killed=True
class CaptureSelector:
 def __init__(self,clock,delay=0): self.clock=clock; self.delay=delay; self.keys={}
 def register(self,stream,event,data): self.keys[stream.fileno()]=SimpleNamespace(fileobj=stream,data=data)
 def get_map(self): return self.keys
 def select(self,timeout=None): self.clock[0]+=self.delay; return [(key,None) for key in list(self.keys.values())]
 def unregister(self,stream): self.keys.pop(stream.fileno(),None)
 def close(self): self.keys.clear()
def fixed_capture_case(spawn_delay=0,select_delay=0,wait_delay=0):
 clock=[10.0]; child=CaptureChild(clock,wait_delay); selected=CaptureSelector(clock,select_delay); callback=[]
 def spawn_child(*args,**kwargs): clock[0]+=spawn_delay; return child
 def read_empty(fd,n): return b''
 try:
  with patch.object(m.time,'monotonic',lambda:clock[0]),patch.object(m.subprocess,'Popen',spawn_child),patch.object(m.selectors,'DefaultSelector',lambda:selected),patch.object(m.os,'read',read_empty),patch.object(m.os,'killpg',lambda *a:None,create=True):
   result=m._fixed_capture(['/usr/bin/systemctl','stop',m.CONTROLLER_UNIT],2000,output_limit=4096,on_spawn=lambda proc:callback.append(proc))
  return 'ok',clock[0],child,callback,result
 except bad:
  return 'failed',clock[0],child,callback,None
cap_status,cap_clock,cap_child,cap_cb,cap_out=fixed_capture_case(0.1,0)
assert cap_status=='ok' and cap_out==b'' and len(cap_cb)==1 and not cap_child.killed; done.append('fixed_capture_bounded_positive')
cap_status,cap_clock,cap_child,cap_cb,cap_out=fixed_capture_case(1.0,0)
assert cap_status=='failed' and len(cap_cb)==1 and cap_child.killed and cap_clock<=12.0; done.append('fixed_capture_spawn_time_in_deadline')
cap_status,cap_clock,cap_child,cap_cb,cap_out=fixed_capture_case(0,1.0)
assert cap_status=='failed' and len(cap_cb)==1 and cap_child.killed and cap_clock<=12.0; done.append('fixed_capture_timeout_cleanup_in_original_budget')
cap_status,cap_clock,cap_child,cap_cb,cap_out=fixed_capture_case(0,0,1.0)
assert cap_status=='failed' and len(cap_cb)==1 and not cap_child.killed and cap_clock>10.95 and cap_clock<=12.0; done.append('fixed_capture_late_wait_rejected')
cf_spec=importlib.util.spec_from_file_location('_fixed_fence_fixture',os.path.join(os.path.dirname(sys.argv[1]),'command-fence.py')); cf=importlib.util.module_from_spec(cf_spec); cf_spec.loader.exec_module(cf)
finish_clock=[0.0]
class FenceChild:
 def __init__(self): self.pid=99; self.returncode=None; self.stdin=CaptureStream(11); self.stdout=CaptureStream(12); self.stderr=CaptureStream(13); self.waits=[]
 def poll(self): return self.returncode
 def wait(self,timeout=None):
  self.waits.append(timeout); finish_clock[0]+=timeout
  if len(self.waits)<3: raise cf.subprocess.TimeoutExpired('fixture',timeout)
  self.returncode=0; return 0
class FenceSelector:
 def __init__(self): self.closed=False
 def close(self): self.closed=True
channel=object.__new__(cf.PsqlChannel); channel.closed=False; channel.child=FenceChild(); channel.selector=FenceSelector()
with patch.object(cf.os,'killpg',lambda *a:None,create=True): channel.finish(timeout=1)
assert channel.child.waits==[1,1,2,2] and finish_clock[0]==6 and channel.selector.closed and channel.closed; done.append('command-fence-finish-fallback_kept_inside_reserve')
import io,json
class ChunkRaw(io.RawIOBase):
 def __init__(self,data): self.data=bytearray(data)
 def readable(self): return True
 def readinto(self,b):
  if not self.data: return 0
  n=min(len(b),3,len(self.data)); b[:n]=self.data[:n]; del self.data[:n]; return n
nonce='0123456789abcdef0123456789abcdef'; schema=m.BRIDGE_SCHEMA
begin={'schema':schema,'operation':'begin','nonce':nonce}
reply={'schema':schema,'nonce':nonce,'seq':1,'kind':'response','operation':'protected_identity','payload':{'observation':{}}}
source=io.BufferedReader(ChunkRaw((json.dumps(begin)+'\n'+json.dumps(reply)+'\n').encode())); target=io.BytesIO(); wire=m.NodeObservationWire(source,target,nonce)
wire.begin(); assert wire.exchange('protected_identity',{})=={'observation':{}} and target.getvalue().count(b'\n')==2; wire.monitor_stop.set(); done.append('bridge_fragmented_frame_positive')
badseq=dict(reply,seq=2); wire=m.NodeObservationWire(io.BytesIO((json.dumps(begin)+'\n'+json.dumps(badseq)+'\n').encode()),io.BytesIO(),nonce); wire.begin()
try: wire.exchange('protected_identity',{}); raise AssertionError('bad bridge sequence accepted')
except bad: done.append('bridge_bad_sequence_refused')
wire=m.NodeObservationWire(io.BytesIO((json.dumps(begin)+'\n').encode()),io.BytesIO(),nonce); wire.begin()
try: wire.exchange('protected_identity',{}); raise AssertionError('bridge EOF accepted')
except bad: done.append('bridge_eof_refused')
write_wire=object.__new__(m.NodeObservationWire); write_wire.state_lock=threading.Lock(); write_wire.closed=threading.Event(); write_wire.lost=threading.Event(); write_wire.clock=time.monotonic; write_wire.deadline=time.monotonic()+1; write_wire.bytes_seen=0; write_wire.frames=0; write_wire.output_fd=77; write_wire.target=io.BytesIO()
with patch.object(m.select,'select',lambda *a:([],[77],[])),patch.object(m.os,'write',lambda *a:(_ for _ in ()).throw(BrokenPipeError('fixture peer closed'))):
 try: write_wire._write({'kind':'response'}); raise AssertionError('closed bridge writer accepted')
 except bad: pass
assert write_wire.lost.is_set() and write_wire.target.getvalue()==b''; done.append('bridge_write_close_refused')
out=io.BytesIO(); malformed=b'{"schema":"controller-transport-rollout-bridge-v1","operation":"begin","nonce":"private","nonce":"0123456789abcdef0123456789abcdef"}\n'; assert m.serve_rollout_bridge({},io.BytesIO(malformed),out)==1 and b'private' not in out.getvalue(); done.append('bridge_invalid_entry_redacted')
wire=object.__new__(m.NodeObservationWire); wire.state_lock=threading.Lock(); wire.awaiting=False; wire.fd=77; wire.lost=threading.Event(); wire.closed=threading.Event(); wire.monitor_stop=threading.Event(); entered=threading.Event(); release=threading.Event(); order=[]
def gated_select(*args): entered.set(); release.wait(1); return ([77],[],[])
def monitored_read(fd,n): order.append('read'); return b'late'
def set_waiting():
 with wire.state_lock: wire.awaiting=True; order.append('exchange')
with patch.object(m.select,'select',gated_select),patch.object(m.os,'read',monitored_read):
 monitor=threading.Thread(target=wire._monitor_input); monitor.start(); assert entered.wait(1)
 setter=threading.Thread(target=set_waiting); setter.start(); time.sleep(0.01); release.set(); monitor.join(1); setter.join(1)
assert order==['read','exchange'] and wire.lost.is_set() and wire.closed.is_set(); wire.monitor_stop.set(); done.append('bridge_monitor_no_response_byte_theft')
late_clock=[0.0]
class LateProtectedReply(io.BytesIO):
 def __init__(self,data): super().__init__(data); self.reads=0
 def readline(self,size=-1):
  line=super().readline(size); self.reads+=1
  if self.reads==2: late_clock[0]+=10.01
  return line
late_input=LateProtectedReply((json.dumps(begin)+'\n'+json.dumps(reply)+'\n').encode()); late_wire=m.NodeObservationWire(late_input,io.BytesIO(),nonce,clock=lambda:late_clock[0]); late_wire.begin()
try: late_wire.exchange('protected_identity',{}); raise AssertionError('protected observation accepted after stage deadline')
except bad: done.append('bridge_protected_stage_late_frame_refused')
stop_clock=[10.0]
class StopFence:
 def __init__(self): self.deadline=20.0
 def keepalive(self): return True
 def remaining_ms(self): return max(0,int((self.deadline-stop_clock[0])*1000))
stop_fence=StopFence(); stop_ops=object.__new__(m.FixedOperations); stop_ops.fence=stop_fence; stop_ops.wire=SimpleNamespace(ensure_open=lambda:True)
with patch.object(m.time,'monotonic',lambda:stop_clock[0]),patch.object(m,'_observe_controller_fixed',lambda deadline=None:{'phase':'original-stopped'}):
 assert stop_ops.wait_controller_stopped(50,stop_fence) is True
 stop_clock[0]=10.0
 def late_inactive_observation(deadline=None): stop_clock[0]+=0.051; return {'phase':'original-stopped'}
 with patch.object(m,'_observe_controller_fixed',late_inactive_observation):
  try: stop_ops.wait_controller_stopped(50,stop_fence); raise AssertionError('late inactive observation accepted')
  except bad: pass
done.append('controller_stop_observation_deadline_enforced')
stop_clock[0]=10.0; stop_ops.initial_identity={'image_sha256':ORIG,'image_dev':1,'image_ino':2,'config_sha256':CONFIG,'unit_sha256':UNIT,'timeout_stop_us':15000000}; stop_effects=[]
def slow_original_observation(deadline=None): stop_clock[0]+=0.051; return {'phase':'original-active','identity':stop_ops.initial_identity}
with patch.object(m.time,'monotonic',lambda:stop_clock[0]),patch.object(m,'_observe_controller_fixed',slow_original_observation),patch.object(m,'_fixed_capture',lambda *a,**k:stop_effects.append('capture')):
 try: stop_ops.stop_controller(50,stop_fence); raise AssertionError('stop effect followed an expired eligibility observation')
 except bad: pass
assert stop_effects==[]; done.append('controller_stop_slow_observation_zero_effect')
stop_clock[0]=10.0; stop_ops.start_requested_wall=9.0; stop_ops.ct_node_id='fixture-node'; readiness_queries=[]
with patch.object(m.time,'monotonic',lambda:stop_clock[0]),patch.object(m,'_observe_controller_fixed',slow_original_observation),patch.object(m,'_fixed_controller_health_get',lambda deadline:readiness_queries.append('health')),patch.object(m,'_fixed_node_rejoin_query',lambda *a:readiness_queries.append('rejoin')):
 try: stop_ops.check_readiness(50,stop_fence); raise AssertionError('readiness queries followed an expired identity observation')
 except bad: pass
assert readiness_queries==[]; done.append('controller_readiness_slow_observation_no_query')
rows={'total':8,'terminal':8,'expired':2,'nonterminal':0,'uncertain':0,'malformed':0}
diag={'counts':{'selected':2,'expired_total':2,'matched_pairs':2,'outcome_unknown':0}}
stage={'nonce':'d771b06efb5715b296d04d891f3d854d','candidate_sha256':CAND,'original_sha256':ORIG,'config_sha256':CONFIG,'activationApproved':False}
bridge_input=[{'schema':schema,'operation':'begin','nonce':nonce}]
for seq,op,payload in ((1,'preflight_evidence',{'stage':stage,'diagnostic':diag}),(2,'protected_identity',{'observation':observation}),(3,'protected_identity',{'observation':observation}),(4,'protected_identity',{'observation':observation})):
 bridge_input.append({'schema':schema,'nonce':nonce,'seq':seq,'kind':'response','operation':op,'payload':payload})
class AdapterState:
 phase='original-active'; image=ORIG; journal=[]
class ClosedWriter(io.BytesIO):
 def write(self,data): raise BrokenPipeError('fixture bridge peer closed')
class TerminalClosedWriter(io.BytesIO):
 def __init__(self): super().__init__(); self.terminal_attempted=False
 def write(self,data):
  if b'"kind":"complete"' in data: self.terminal_attempted=True; raise BrokenPipeError('fixture terminal acknowledgement peer closed')
  return super().write(data)
state=AdapterState()
def observed(deadline=None):
 if state.phase=='original-stopped': return {'phase':state.phase,'identity':inactive(state.image)}
 return {'phase':state.phase,'identity':running(state.image,10 if state.image==ORIG else 11)}
def capture(argv,*args,**kwargs):
 if kwargs.get('on_spawn'): kwargs['on_spawn'](object())
 if argv[-2:]==['stop',m.CONTROLLER_UNIT]: state.phase='original-stopped'
 elif argv[-2:]==['start',m.CONTROLLER_UNIT]: state.phase='candidate-active' if state.image==CAND else 'original-active'
 else: raise AssertionError('unrecognized fixed service adapter')
 return b''
def fake_stage(path,*args,**kwargs):
 if path==m.CANDIDATE_STAGE: return b'candidate',('candidate',)
 if path==m.ORIGINAL_STAGE: return b'original',('original',)
 return b'config',('config',)
db=DB(); namespace=FN(db); receiver_library=SimpleNamespace(**{name:getattr(namespace,name) for name in ('IDENTITY_SQL','READ_WRITE_SQL','RESOLUTION_SQL','LOCK_SQL','ABSENT_SQL','SNAPSHOT_SQL','PsqlChannel','_probe_service_and_config','_connection_environment','_yaml_database_url','_validate_identity','_project_summary','_config_bytes')}); result_out=io.BytesIO(); begin_input='\n'.join(json.dumps(item,separators=(',',':')) for item in bridge_input)
with patch.object(m,'_read_pinned_file',fake_stage),patch.object(m.os.path,'isfile',lambda p:True),patch.object(m,'_observe_controller_fixed',observed),patch.object(m,'_fixed_capture',capture),patch.object(m,'_atomic_install_fixed',lambda source,digest,size,preserve,deadline,fence:setattr(state,'image',digest)),patch.object(m,'_write_private_journal',lambda phase,effects,uncertain:state.journal.append(phase)),patch.object(m,'_fixed_controller_health_get',lambda deadline:True),patch.object(m,'_fixed_node_rejoin_query',lambda fence,node,started,deadline:True):
 errors=[]; oldfail=m._fail; OldFence=m.PhaseFence
 class DebugFence(OldFence):
  def __init__(self,*a,**k):
   try: super().__init__(*a,**k)
   except Exception: errors.append(__import__('traceback').format_exc()); raise
 def capture_fail():
  try: oldfail()
  except Exception: errors.append(__import__('traceback').format_exc()); raise
 with patch.object(m,'_fail',capture_fail),patch.object(m,'PhaseFence',DebugFence): bridge_rc=m.serve_rollout_bridge(receiver_library,io.BytesIO((begin_input+'\n').encode()),result_out)
 assert bridge_rc==0,repr(result_out.getvalue())+' '+(errors[-1] if errors else '')
frames=[json.loads(line) for line in result_out.getvalue().splitlines()]; assert frames[0]['kind']=='ready' and frames[-1]['kind']=='complete' and frames[-1]['status']=='candidate_verified' and state.image==CAND and db.finished
assert [f['operation'] for f in frames if f.get('kind')=='request']==['preflight_evidence','protected_identity','protected_identity']; done.append('actual_fixed_operations_candidate_bridge_flow')
state2=AdapterState(); state2.journal=[]; state2.pid=10; result2=io.BytesIO(); db2=DB(); library2=FN(db2); lib2=SimpleNamespace(**{name:getattr(library2,name) for name in ('IDENTITY_SQL','READ_WRITE_SQL','RESOLUTION_SQL','LOCK_SQL','ABSENT_SQL','SNAPSHOT_SQL','PsqlChannel','_probe_service_and_config','_connection_environment','_yaml_database_url','_validate_identity','_project_summary','_config_bytes')})
def observed2(deadline=None): return {'phase':state2.phase,'identity':inactive(state2.image)} if state2.phase=='original-stopped' else {'phase':state2.phase,'identity':running(state2.image,state2.pid)}
def capture2(argv,*args,**kwargs):
 if kwargs.get('on_spawn'): kwargs['on_spawn'](object())
 if argv[-2:]==['stop',m.CONTROLLER_UNIT]: state2.phase='original-stopped'
 elif argv[-2:]==['start',m.CONTROLLER_UNIT]: state2.pid+=1; state2.phase='candidate-active' if state2.image==CAND else 'original-active'
 else: raise AssertionError('unrecognized rollback service adapter')
 return b''
frames_in=[{'schema':schema,'operation':'begin','nonce':nonce}]
for seq,op,payload in ((1,'preflight_evidence',{'stage':stage,'diagnostic':diag}),(2,'protected_identity',{'observation':observation}),(3,'protected_identity',{'observation':observation}),(4,'protected_identity',{'observation':observation})):
 frames_in.append({'schema':schema,'nonce':nonce,'seq':seq,'kind':'response','operation':op,'payload':payload})
rollback_frames='\n'.join(json.dumps(item,separators=(',',':')) for item in frames_in); health_count=[0]
def health_once(deadline):
 health_count[0]+=1
 if health_count[0]==1: raise bad('fixture health failure')
 return True
with patch.object(m,'_read_pinned_file',fake_stage),patch.object(m.os.path,'isfile',lambda p:True),patch.object(m,'_observe_controller_fixed',observed2),patch.object(m,'_fixed_capture',capture2),patch.object(m,'_atomic_install_fixed',lambda source,digest,size,preserve,deadline,fence:setattr(state2,'image',digest)),patch.object(m,'_write_private_journal',lambda phase,effects,uncertain:state2.journal.append(phase)),patch.object(m,'_fixed_controller_health_get',health_once),patch.object(m,'_fixed_node_rejoin_query',lambda fence,node,started,deadline:True):
 assert m.serve_rollout_bridge(lib2,io.BytesIO((rollback_frames+'\n').encode()),result2)==0
frames2=[json.loads(line) for line in result2.getvalue().splitlines()]; assert frames2[-1]['status']=='original_restored' and state2.image==ORIG and state2.journal.count('candidate_installed')==1 and state2.journal[-1]=='settled_original' and db2.finished; assert [f['operation'] for f in frames2 if f.get('kind')=='request']==['preflight_evidence','protected_identity','protected_identity']; done.append('actual_fixed_operations_rollback_bridge_flow')
def run_handoff(fault):
 st=AdapterState(); st.journal=[]; st.unexpected=[]; st.readiness=[]; st.timeline=[]; st.effects=[]; st.pid=10; dbx=DB()
 if fault=='ineligible_nonterminal': dbx.snapshot.update(total=8,terminal=7,nonterminal=1)
 elif fault=='ineligible_uncertain': dbx.snapshot.update(uncertain=1)
 elif fault=='ineligible_malformed': dbx.snapshot.update(malformed=1)
 fnx=FN(dbx); libx=SimpleNamespace(**{name:getattr(fnx,name) for name in ('IDENTITY_SQL','READ_WRITE_SQL','RESOLUTION_SQL','LOCK_SQL','ABSENT_SQL','SNAPSHOT_SQL','PsqlChannel','_probe_service_and_config','_connection_environment','_yaml_database_url','_validate_identity','_project_summary','_config_bytes')})
 def deny_readiness(name):
  def denied(*args,**kwargs): st.unexpected.append(name); raise AssertionError('unexpected readiness boundary in handoff fixture')
  return denied
 def obsx(deadline=None):
  if st.phase=='unknown' and fault not in ('stop_pending','foreign_candidate_before_start'): raise bad('unobserved transitional service identity')
  if fault=='foreign_candidate_before_start' and st.phase=='candidate-active': return {'phase':st.phase,'identity':running(CAND,99)}
  value={'phase':'original-active' if fault=='stop_pending' and st.phase=='unknown' else st.phase,'identity':inactive(st.image)} if st.phase=='original-stopped' else {'phase':'original-active' if fault in ('stop_pending','lost_stop_reply') and st.phase=='unknown' else st.phase,'identity':running(st.image,st.pid)}
  if fault=='stop_pending': value['identity']['timeout_stop_us']=15000
  return value
 def capx(argv,*args,**kwargs):
  is_stop=argv[-2:]==['stop',m.CONTROLLER_UNIT]; is_start=argv[-2:]==['start',m.CONTROLLER_UNIT]
  if fault=='foreign_inactive_pre_spawn' and is_stop:
   st.phase='original-stopped'; raise bad('fixed capture refused before process creation')
  if fault=='foreign_inactive_post_spawn' and is_stop:
   if kwargs.get('on_spawn'): kwargs['on_spawn'](object())
   st.phase='original-stopped'; raise bad('capture child spawned but stop dispatch was not proven')
  if fault=='foreign_candidate_pre_spawn' and is_start:
   st.phase='candidate-active'; st.pid=99; raise bad('fixed capture refused before process creation')
  if fault=='foreign_candidate_post_spawn' and is_start:
   if kwargs.get('on_spawn'): kwargs['on_spawn'](object())
   st.phase='candidate-active'; st.pid=99; raise bad('capture child spawned but start dispatch was not proven')
  if kwargs.get('on_spawn'): kwargs['on_spawn'](object())
  if is_stop:
   st.effects.append('stop'); st.phase='unknown' if fault=='stop_pending' else 'original-stopped'
   if fault=='lost_fence': dbx.lose=True
   if fault=='lost_stop_reply': raise bad('stop helper reply lost after observed stop effect')
  elif is_start:
   st.effects.append('start'); st.pid+=1; st.phase='unknown' if fault=='unknown_start' else ('candidate-active' if st.image==CAND else 'original-active')
   if fault=='lost_candidate_start_reply' and st.image==CAND: raise bad('candidate start reply lost after independently observed active transition')
  else: raise AssertionError('unexpected fixed service effect')
  return b''
 evidence_diag=diag
 if fault in ('ineligible_counts','ineligible_unknown'): evidence_diag={'counts':{'selected':2,'expired_total':2,'matched_pairs':1,'outcome_unknown':1}}
 if fault in ('ineligible_nonterminal','ineligible_uncertain','ineligible_malformed'): evidence_diag={'counts':{'selected':2,'expired_total':2,'matched_pairs':2,'outcome_unknown':0}}
 source_frames=[{'schema':schema,'operation':'begin','nonce':nonce},
  {'schema':schema,'nonce':nonce,'seq':1,'kind':'response','operation':'preflight_evidence','payload':{'stage':stage,'diagnostic':evidence_diag}},
  {'schema':schema,'nonce':nonce,'seq':2,'kind':'response','operation':'protected_identity','payload':{'observation':observation}}]
 if fault in ('lost_stop_reply','lost_candidate_start_reply'): source_frames.append({'schema':schema,'nonce':nonce,'seq':3,'kind':'response','operation':'protected_identity','payload':{'observation':observation}})
 if fault in ('protected_drift','persistent_protected_drift','invalid_protected_observation'):
  changed=json.loads(json.dumps(observation)); changed['native'][0]['pid']+=1
  later=changed if fault=='persistent_protected_drift' else observation
  if fault=='invalid_protected_observation': changed['native'][0]['start']=42
  source_frames.extend([{'schema':schema,'nonce':nonce,'seq':3,'kind':'response','operation':'protected_identity','payload':{'observation':changed}}, {'schema':schema,'nonce':nonce,'seq':4,'kind':'response','operation':'protected_identity','payload':{'observation':later}}])
 if fault in ('bridge_eof_after_start','bridge_wrong_after_start','terminal_write_close','healthy_candidate'): source_frames.append({'schema':schema,'nonce':nonce,'seq':3,'kind':'response','operation':'protected_identity','payload':{'observation':observation}})
 outx=ClosedWriter() if fault=='bridge_write_close' else (TerminalClosedWriter() if fault=='terminal_write_close' else io.BytesIO()); code=None
 def call_bridge():
  selected=source_frames[:2] if fault=='bridge_eof_protected' else source_frames
  if fault=='bridge_wrong_sequence': selected=json.loads(json.dumps(source_frames)); selected[1]['seq']=2
  if fault=='bridge_wrong_after_start': selected=json.loads(json.dumps(source_frames)); selected[3]['seq']=4
  if fault=='bridge_eof_after_start': selected=source_frames[:3]
  encoded='\n'.join(json.dumps(item,separators=(',',':')) for item in selected)+'\n'
  return m.serve_rollout_bridge(libx,io.BytesIO(encoded.encode()),outx)
 def journalx(phase,effects,uncertain):
  st.journal.append(phase)
  if fault=='foreign_candidate_before_start' and phase=='candidate_start_requested': st.phase='candidate-active'; st.pid=99
 def health_fail(deadline): st.readiness.append('health'); raise bad('fixture candidate health failure')
 def healthy_health(deadline): st.readiness.append('health'); st.timeline.append('health'); return True
 def healthy_rejoin(fence,node,started,deadline): st.readiness.append('rejoin'); st.timeline.append('rejoin'); return True
 health_adapter=healthy_health if fault in ('lost_stop_reply','lost_candidate_start_reply','protected_drift','persistent_protected_drift','invalid_protected_observation','bridge_wrong_after_start','bridge_eof_after_start','terminal_write_close','healthy_candidate') else (health_fail if fault=='restore_failure' else deny_readiness('health'))
 rejoin_adapter=healthy_rejoin if fault in ('lost_stop_reply','lost_candidate_start_reply','protected_drift','persistent_protected_drift','invalid_protected_observation','bridge_wrong_after_start','bridge_eof_after_start','terminal_write_close','healthy_candidate') else deny_readiness('rejoin')
 def atomicx(source,digest,size,preserve,deadline,fence):
  st.image=digest
  if fault=='install_lost_reply' or (fault=='restore_failure' and source==m.ORIGINAL_STAGE): raise bad('fixture atomic commit reply uncertain')
 old_protected=m.FixedOperations.observe_protected
 def protectedx(self): st.timeline.append('protected'); return old_protected(self)
 with patch.object(m,'_read_pinned_file',fake_stage),patch.object(m.os.path,'isfile',lambda p:True),patch.object(m,'_observe_controller_fixed',obsx),patch.object(m,'_fixed_capture',capx),patch.object(m,'_atomic_install_fixed',atomicx),patch.object(m,'_write_private_journal',journalx),patch.object(m,'_fixed_controller_health_get',health_adapter),patch.object(m,'_fixed_node_rejoin_query',rejoin_adapter),patch.object(m.FixedOperations,'observe_protected',protectedx):
  if fault=='stop_pending':
   old_stop=m.ROLLOUT_BUDGETS['stop_ms']; m.ROLLOUT_BUDGETS['stop_ms']=20000; original_mono=m.time.monotonic; simulated=[original_mono()]
   try:
    with patch.object(m.time,'monotonic',lambda:simulated[0]),patch.object(m.time,'sleep',lambda delay:simulated.__setitem__(0,simulated[0]+delay)):
     code=call_bridge()
   finally: m.ROLLOUT_BUDGETS['stop_ms']=old_stop
  elif fault=='reserve_exhausted':
   real_remaining=m.FixedOperations.remaining_ms
   with patch.object(m.FixedOperations,'remaining_ms',lambda self:1000 if st.phase=='original-stopped' else real_remaining(self)):
    code=call_bridge()
  elif fault in ('install_lost_reply','restore_failure'):
   if fault=='restore_failure': source_frames.extend([{'schema':schema,'nonce':nonce,'seq':3,'kind':'response','operation':'protected_identity','payload':{'observation':observation}},{'schema':schema,'nonce':nonce,'seq':4,'kind':'response','operation':'protected_identity','payload':{'observation':observation}}])
   code=call_bridge()
  else: code=call_bridge()
 framesx=[json.loads(line) for line in outx.getvalue().splitlines()]
 st.terminal_attempted=getattr(outx,'terminal_attempted',False)
 assert st.unexpected==[]
 return code,framesx,st,dbx
code_x,frames_x,state_x,db_x=run_handoff('lost_fence'); assert code_x==1 and frames_x[-1]['status']=='handoff' and 'handoff_fence_lost' in state_x.journal and state_x.image==ORIG and db_x.aborted and not db_x.finished; done.append('receiver_lock_loss_while_stopped_handoff')
code_x,frames_x,state_x,db_x=run_handoff('unknown_start'); assert code_x==1 and frames_x[-1]['status']=='handoff' and 'handoff_uncertain' in state_x.journal and state_x.image==CAND and db_x.aborted and not db_x.finished; done.append('receiver_unknown_start_handoff')
code_x,frames_x,state_x,db_x=run_handoff('lost_stop_reply'); assert code_x==1 and frames_x[-1]['status']=='handoff' and 'handoff_uncertain' in state_x.journal and state_x.phase=='original-stopped' and state_x.effects==['stop'] and not state_x.readiness and db_x.aborted and not db_x.finished; done.append('receiver_ambiguous_stop_reply_no_foreign_restart')
code_x,frames_x,state_x,db_x=run_handoff('lost_candidate_start_reply'); assert code_x==1 and frames_x[-1]['status']=='handoff' and 'candidate_installed' in state_x.journal and 'handoff_uncertain' in state_x.journal and state_x.image==CAND and state_x.effects==['stop','start'] and not state_x.readiness and db_x.aborted and not db_x.finished; done.append('receiver_candidate_start_ambiguous_no_recovery')
for fault,label in (('foreign_inactive_pre_spawn','receiver_foreign_stop_pre_spawn_not_restarted'),('foreign_inactive_post_spawn','receiver-post-spawn-stop-dispatch-uncertain')):
 code_x,frames_x,state_x,db_x=run_handoff(fault); assert code_x==1 and frames_x[-1]['status']=='handoff' and state_x.phase=='original-stopped' and 'start' not in state_x.effects and 'restore' not in state_x.effects and db_x.aborted and not db_x.finished; done.append(label)
for fault,label in (('foreign_candidate_pre_spawn','receiver-foreign-candidate-pre-spawn-not-adopted'),('foreign_candidate_post_spawn','receiver-post-spawn-start-dispatch-uncertain')):
 code_x,frames_x,state_x,db_x=run_handoff(fault); assert code_x==1 and frames_x[-1]['status']=='handoff' and state_x.phase=='candidate-active' and state_x.pid==99 and state_x.effects==['stop'] and db_x.aborted and not db_x.finished; done.append(label)
code_x,frames_x,state_x,db_x=run_handoff('foreign_candidate_before_start'); assert code_x==1 and frames_x[-1]['status']=='handoff' and 'candidate_start_requested' in state_x.journal and 'handoff_uncertain' in state_x.journal and state_x.image==CAND and state_x.effects==['stop'] and not state_x.readiness and db_x.aborted and not db_x.finished; done.append('receiver-foreign-candidate-before-our-start-not-adopted')
code_x,frames_x,state_x,db_x=run_handoff('stop_pending'); assert code_x==1 and frames_x[-1]['status']=='handoff' and 'handoff_uncertain' in state_x.journal and state_x.image==ORIG and state_x.phase=='unknown' and db_x.aborted and not db_x.finished; done.append('receiver_stop_pending_unverified_safe_handoff')
code_x,frames_x,state_x,db_x=run_handoff('reserve_exhausted'); assert code_x==1 and frames_x[-1]['status']=='handoff' and 'handoff_uncertain' in state_x.journal and state_x.image==ORIG and state_x.phase=='original-stopped' and state_x.effects==['stop'] and 'candidate_installed' not in state_x.journal and db_x.aborted and not db_x.finished; done.append('receiver-reserve-exhaustion-before-install-handoff')
code_x,frames_x,state_x,db_x=run_handoff('install_lost_reply'); assert code_x==1 and frames_x[-1]['status']=='handoff' and 'candidate_installed' not in state_x.journal and 'handoff_uncertain' in state_x.journal and state_x.image==CAND and state_x.effects==['stop'] and db_x.aborted and not db_x.finished; done.append('receiver-install-lost-rename-no-unowned-restore')
code_x,frames_x,state_x,db_x=run_handoff('restore_failure'); assert code_x==1 and frames_x[-1]['status']=='handoff' and 'candidate_installed' in state_x.journal and 'handoff_uncertain' in state_x.journal and state_x.image==ORIG and state_x.effects==['stop','start','stop'] and state_x.readiness==['health'] and db_x.aborted and not db_x.finished; done.append('receiver-restore-failure-no-restart')
code_x,frames_x,state_x,db_x=run_handoff('protected_drift'); assert code_x==1 and frames_x[-1]['status']=='handoff' and 'settled_original' not in state_x.journal and 'handoff_uncertain' in state_x.journal and state_x.image==ORIG and state_x.effects==['stop','start','stop','start'] and state_x.readiness==['health','rejoin','health','rejoin'] and db_x.aborted and not db_x.finished; done.append('receiver_protected_native_drift_rollback')
code_x,frames_x,state_x,db_x=run_handoff('persistent_protected_drift'); assert code_x==1 and frames_x[-1]['status']=='handoff' and 'settled_original' not in state_x.journal and 'handoff_uncertain' in state_x.journal and state_x.effects==['stop','start','stop','start'] and db_x.aborted and not db_x.finished; done.append('receiver_persistent_native_drift_uncertain')
code_x,frames_x,state_x,db_x=run_handoff('invalid_protected_observation'); assert code_x==1 and frames_x[-1]['status']=='handoff' and 'settled_original' not in state_x.journal and 'handoff_uncertain' in state_x.journal and state_x.image==ORIG and state_x.effects==['stop','start','stop','start'] and db_x.aborted and not db_x.finished; done.append('receiver_invalid_protected_observation_sticky_uncertain')
code_x,frames_x,state_x,db_x=run_handoff('healthy_candidate'); assert code_x==0 and frames_x[-1]['status']=='candidate_verified' and state_x.timeline==['protected','health','rejoin','protected'] and db_x.finished and not db_x.aborted
code_x,frames_x,state_x,db_x=run_handoff('ineligible_counts'); assert code_x==1 and frames_x[-1]['kind']=='failed' and state_x.effects==[] and state_x.image==ORIG and not state_x.readiness and db_x.aborted and not db_x.finished; done.append('receiver_ineligible_counts_zero_effects')
for fault,marker in (('ineligible_nonterminal','receiver_nonterminal_ineligible_zero_effects'),('ineligible_uncertain','receiver_uncertain_ineligible_zero_effects'),('ineligible_malformed','receiver_malformed_ineligible_zero_effects')):
 code_x,frames_x,state_x,db_x=run_handoff(fault); assert code_x==1 and frames_x[-1]['kind']=='failed' and state_x.effects==[] and state_x.image==ORIG and not state_x.readiness and db_x.aborted and not db_x.finished; done.append(marker)
code_x,frames_x,state_x,db_x=run_handoff('bridge_wrong_sequence'); assert code_x==1 and frames_x[-1]['kind']=='request' and frames_x[-1]['operation']=='preflight_evidence' and state_x.effects==[] and state_x.image==ORIG and db_x.aborted and not db_x.finished; done.append('receiver_wrong_sequence_zero_effects')
code_x,frames_x,state_x,db_x=run_handoff('bridge_eof_protected'); assert code_x==1 and frames_x[-1]['kind']=='request' and frames_x[-1]['operation']=='protected_identity' and state_x.effects==[] and state_x.image==ORIG and db_x.aborted and not db_x.finished; done.append('receiver_eof_zero_effects')
code_x,frames_x,state_x,db_x=run_handoff('bridge_write_close'); assert code_x==1 and frames_x==[] and state_x.effects==[] and state_x.image==ORIG and db_x.aborted and not db_x.finished; done.append('receiver_write_close_abort')
for fault in ('bridge_wrong_after_start','bridge_eof_after_start'):
 code_x,frames_x,state_x,db_x=run_handoff(fault); assert code_x==1 and state_x.effects==['stop','start'] and state_x.image==CAND and db_x.aborted and not db_x.finished and 'settled_candidate' not in state_x.journal and 'settled_original' not in state_x.journal
done.append('receiver_post_effect_wrong_frame_handoff'); done.append('receiver_post_effect_eof_handoff')
code_x,frames_x,state_x,db_x=run_handoff('terminal_write_close'); assert code_x==1 and state_x.effects==['stop','start'] and state_x.image==CAND and 'settled_candidate' in state_x.journal and db_x.finished and not db_x.aborted and state_x.terminal_attempted and all(frame['kind']!='complete' for frame in frames_x); done.append('receiver_terminal_write_close_non_green')
class FakeOS:
 def __init__(self,fail_fsync=None,rename_then_raise=False,guard_fault=None): self.files={}; self.fds={}; self.next=10; self.fail_fsync=fail_fsync; self.fsyncs=0; self.rename_then_raise=rename_then_raise; self.guard_fault=guard_fault; self.active=False; self.fence_held=True; self.renames=0; self.path=posixpath; self.failures=[]
 def __getattr__(self,name): return getattr(os,name)
 def _stat(self,ino,data,mode,dir=False): return SimpleNamespace(st_dev=1,st_ino=ino,st_mode=(m.stat.S_IFDIR if dir else m.stat.S_IFREG)|mode,st_nlink=1,st_uid=0,st_gid=0,st_size=len(data),st_mtime_ns=ino,st_ctime_ns=ino)
 def _record(self,path):
  ino=self.files[path]; rec=self.fds.setdefault(('file',ino),{'data':bytearray(self.store[ino]),'mode':self.modes[ino],'cursor':0}); return ino,rec
 store={}; modes={}
 def make(self,image,source):
  self.store={1:bytearray(image),2:bytearray(source)}; self.modes={1:0o755,2:0o700}; self.files={'/mock/controller':1,'/mock/candidate':2}; self.fds[3]={'kind':'file','ino':2,'data':self.store[2],'mode':self.modes[2],'cursor':0}; return 3
 def open(self,path,flags,mode=0o777,dir_fd=None):
  self.next+=1
  if dir_fd is None: self.fds[self.next]={'kind':'dir','path':path}; return self.next
  if flags & self.O_CREAT:
   ino=self.next+100; self.store[ino]=bytearray(); self.modes[ino]=mode; self.fds[self.next]={'kind':'file','ino':ino,'data':self.store[ino],'mode':mode,'cursor':0}; self.files[posixpath.join(self.fds[dir_fd]['path'],path)]=ino; return self.next
  full=posixpath.join(self.fds[dir_fd]['path'],path); ino=self.files[full]; self.fds[self.next]={'kind':'file','ino':ino,'data':self.store[ino],'mode':self.modes[ino],'cursor':0}; return self.next
 def fstat(self,fd):
  rec=self.fds[fd]
  if rec['kind']=='dir': return self._stat(9,b'',0o755,True)
  return self._stat(rec['ino'],rec['data'],rec['mode'])
 def lstat(self,path):
  if path=='/mock': return self._stat(9,b'',0o755,True)
  return self._stat(self.files[path],self.store[self.files[path]],self.modes[self.files[path]])
 def stat(self,path,dir_fd=None,follow_symlinks=True):
  full=posixpath.join(self.fds[dir_fd]['path'],path) if dir_fd is not None else path
  if full=='/mock': return self._stat(9,b'',0o755,True)
  if full not in self.files: raise FileNotFoundError(full)
  ino=self.files[full]; return self._stat(ino,self.store[ino],self.modes[ino])
 def read(self,fd,n):
  rec=self.fds[fd]; pos=rec['cursor']; out=bytes(rec['data'][pos:pos+n]); rec['cursor']+=len(out); return out
 def write(self,fd,data): self.fds[fd]['data'].extend(data); return len(data)
 def fchown(self,fd,uid,gid): return None
 def fchmod(self,fd,mode): self.fds[fd]['mode']=mode; self.modes[self.fds[fd]['ino']]=mode
 def fsync(self,fd):
  self.fsyncs+=1
  if self.fsyncs==1 and self.guard_fault=='active_after_prepare': self.active=True
  if self.fsyncs==1 and self.guard_fault=='fence_lost_after_prepare': self.fence_held=False
  if self.fsyncs==self.fail_fsync: self.failures.append('fsync-'+str(self.fsyncs)); raise OSError('fixture fsync failure')
 def replace(self,src,dst,src_dir_fd=None,dst_dir_fd=None):
  self.renames+=1
  parent=self.fds[src_dir_fd]['path']; ino=self.files.pop(posixpath.join(parent,src)); self.files[posixpath.join(parent,dst)]=ino
  if self.rename_then_raise: self.failures.append('rename-after'); raise OSError('fixture lost rename response')
 def unlink(self,path,dir_fd=None): del self.files[posixpath.join(self.fds[dir_fd]['path'],path)]
 def close(self,fd): self.fds.pop(fd,None)
def install_case(fail_fsync=None,rename_lost=False,guard_fault=None):
 original=b'orig'; candidate_bytes=b'cand'; digest=__import__('hashlib').sha256(candidate_bytes).hexdigest(); fake=FakeOS(fail_fsync,rename_lost,guard_fault); sourcefd=fake.make(original,candidate_bytes); source_path='/mock/candidate'; image_path='/mock/controller'; oldhash=__import__('hashlib').sha256(original).hexdigest(); preserve=inactive(oldhash); preserve['image_ino']=1; old_size=m.IMAGE_BYTES; old_candidate=m.CANDIDATE_STAGE; fence=m.PhaseFence.__new__(m.PhaseFence); fence.closed=False; fence.heartbeat=SimpleNamespace(is_alive=lambda:True); fence.heartbeat_error=threading.Event(); fence.keepalive=lambda:fake.fence_held
 source_stat=fake._stat(2,candidate_bytes,0o700); source_identity=(source_stat.st_dev,source_stat.st_ino,source_stat.st_mode,source_stat.st_uid,source_stat.st_gid,source_stat.st_size,source_stat.st_mtime_ns,source_stat.st_ctime_ns)
 def read_source(path,*args,**kwargs): return candidate_bytes,source_identity,sourcefd
 try:
  def fresh_inactive(deadline=None):
   if fake.active: return {'phase':'original-active','identity':running(oldhash,10)}
   saved=inactive(oldhash); saved['image_ino']=1
   return {'phase':'original-stopped','identity':saved}
  with patch.object(m,'_fixed_parents',lambda p:p),patch.object(m,'_read_pinned_file',read_source),patch.object(m,'_controller_file_identities',lambda:{'image_dev':1,'image_ino':fake.files[image_path],'image_sha256':digest}),patch.object(m,'_observe_controller_fixed',fresh_inactive),patch.object(m,'CONTROLLER_IMAGE',image_path),patch.object(m,'CANDIDATE_STAGE',source_path),patch.object(m,'IMAGE_BYTES',len(original)),patch.object(m,'os',fake):
   m._atomic_install_fixed(source_path,digest,len(candidate_bytes),preserve,time.monotonic()+2,fence)
  result='ok'
 except Exception: result='failed'
 return fake,result,digest
fake,result,digest=install_case(); assert result=='ok' and fake.failures==[] and fake.fsyncs==2 and bytes(fake.store[fake.files['/mock/controller']])==b'cand' and not any('/mock/.vram-governor-controller.rollout-' in p for p in fake.files) and not fake.fds; done.append('atomic_install_success')
fake,result,digest=install_case(fail_fsync=1); assert result=='failed' and fake.failures==['fsync-1'] and bytes(fake.store[fake.files['/mock/controller']])==b'orig' and len(fake.files)==2 and not fake.fds; done.append('atomic_install_temp_fsync_cleanup')
fake,result,digest=install_case(fail_fsync=2); assert result=='failed' and fake.failures==['fsync-2'] and bytes(fake.store[fake.files['/mock/controller']])==b'cand' and len(fake.files)==2 and not fake.fds; done.append('atomic_install_parent_fsync_uncertain')
fake,result,digest=install_case(rename_lost=True); assert result=='failed' and fake.failures==['rename-after'] and bytes(fake.store[fake.files['/mock/controller']])==b'cand' and len(fake.files)==2 and not fake.fds; done.append('atomic_install_rename_lost_reply')
for fault in ('active_after_prepare','fence_lost_after_prepare'):
 fake,result,digest=install_case(guard_fault=fault); assert result=='failed' and fake.renames==0 and bytes(fake.store[fake.files['/mock/controller']])==b'orig' and len(fake.files)==2 and not fake.fds
if True: done.append('atomic_final_replace_requires_fresh_inactive_same_fence')
done.append('receiver_readiness_before_final_protected_sample')
print('|'.join(done))
print('CTWIRE:'+ct_wire_b64)
`;
const py = spawnSync("py", ["-3", "-I", "-B", "-", path.join(HERE, "transport-rollout.py")], { cwd: HERE, timeout: 8000, maxBuffer: 8192, encoding: "utf8", windowsHide: true, input: pyScript, env: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, ProgramData: "C:/ProgramData", PATH: process.env.PATH } });
assert.equal(py.status, 0, `bounded Python phase controls status=${py.status} signal=${py.signal} error=${py.error?.code ?? "none"} (${(py.stderr ?? "").slice(-400)})`);
assert.equal(py.stderr, "");
const pyLines=py.stdout.trim().split(/\r?\n/);
assert.equal(pyLines.length,2);
assert.deepEqual(pyLines[0].split("|"), PY_EXPECTED);
assert.ok(pyLines[1].startsWith("CTWIRE:"));
const ctWireBytes=Buffer.from(pyLines[1].slice("CTWIRE:".length),"base64");
assert.ok(ctWireBytes.length>0 && ctWireBytes.toString("base64")===pyLines[1].slice("CTWIRE:".length));
const ctWireObservation=_parseCtObservationResponseForTest(ctWireBytes.toString("ascii"),"0123456789abcdef0123456789abcdef");
assert.deepEqual(ctWireObservation.agent.config,["1","2","1800000000123456789","1800000000123456790"]);
assert.equal(BigInt(ctWireObservation.agent.config[3])-BigInt(ctWireObservation.agent.config[2]),1n);
assert.notEqual(ctWireObservation.agent.config[2],ctWireObservation.agent.config[3]);
completed.push("ct-realistic-nanosecond-wire-roundtrip");
const ctSourceBytes=_stablePythonSourceForTest(), generatedCtCommand=_ctRemoteCommandForTest();
const shellApostropheToken="'\"'\"'";
assert.ok(generatedCtCommand.includes(shellApostropheToken));
const ctObserverNonce="0123456789abcdef0123456789abcdef";
const ctRequestBytes=Buffer.from(JSON.stringify({schema:"controller-transport-ct-observation-v1",nonce:ctObserverNonce,operation:"observe"})+"\n","ascii");
const ctHeaderBytes=Buffer.from(`${ctSourceBytes.length}\n${_bridgeSourcePinsForTest().rolloutSha256}\n`,"ascii");
const ctBootstrapPayload=Buffer.concat([ctHeaderBytes,ctSourceBytes,ctRequestBytes]);
const ctBootstrapHarness=String.raw`import base64,builtins,hashlib,io,json,os,shlex,sys,types
hostout=sys.stdout; packet=json.loads(sys.stdin.read()); calls=[0]
try:
 argv=shlex.split(packet['command'],posix=True); expected=shlex.split(packet['expected_command'],posix=True)
 if argv!=expected or argv[:8]!=['/usr/sbin/pct','exec','200','--','/usr/bin/python3','-I','-B','-c'] or len(argv)!=9: raise ValueError('fixed command lexical form mismatch')
 bootstrap=argv[8]
except Exception:
 hostout.write(json.dumps({'status':'command_rejected','calls':0})+'\n'); raise SystemExit(0)
raw=io.BytesIO(base64.b64decode(packet['payload_b64'],validate=True)); output=io.BytesIO(); observation=packet['observation']; consumed=[0]; hook_filenames=[]; boundary_errors=[]
real_read=os.read
def chunk_read(fd,count):
 data=raw.read(min(3,count)); consumed[0]+=len(data); return data
stdin_before=sys.stdin; stdout_before=sys.stdout; exec_before=builtins.exec
real_exec=exec_before
def observe_fixture(): calls[0]+=1; return observation
def hooked_exec(code,globals_dict=None,locals_dict=None):
 filename=getattr(code,'co_filename',''); hook_filenames.append(filename)
 if filename=='<fixed-controller-transport-observer>':
  original_name=globals_dict.get('__name__'); globals_dict['__name__']='_closed_ct_observer_fixture'; real_exec(code,globals_dict,locals_dict); globals_dict['__name__']=original_name
  globals_dict['observe_ct_identity']=observe_fixture; original_fail=globals_dict['_ct_fail']
  def tracked_fail():
   try: original_fail()
   except Exception as error: boundary_errors.append(type(error).__name__); raise
  globals_dict['_ct_fail']=tracked_fail
  raise SystemExit(globals_dict['serve_ct_observation']())
 return real_exec(code,globals_dict,locals_dict)
os.read=chunk_read; sys.stdin=types.SimpleNamespace(buffer=raw); sys.stdout=types.SimpleNamespace(buffer=output); builtins.exec=hooked_exec; status=0
try:
 real_exec(compile(bootstrap,'<actual-generated-ct-bootstrap>','exec'),{'__name__':'__main__'})
except SystemExit as error: status=error.code if type(error.code) is int else 1
finally: os.read=real_read; sys.stdin=stdin_before; sys.stdout=stdout_before; builtins.exec=exec_before
hostout.write(json.dumps({'status':status,'calls':calls[0],'hook_filenames':hook_filenames,'boundary_errors':boundary_errors,'consumed':consumed[0],'remaining':len(raw.getvalue())-raw.tell(),'response_b64':base64.b64encode(output.getvalue()).decode('ascii')})+'\n')`;
function runGeneratedCtBootstrap(payload,command=generatedCtCommand) {
  const result=spawnSync("py",["-3","-I","-B","-c",ctBootstrapHarness],{cwd:HERE,timeout:8000,maxBuffer:8192,encoding:"utf8",windowsHide:true,input:JSON.stringify({command,expected_command:generatedCtCommand,payload_b64:payload.toString("base64"),observation:ctWireObservation}),env:{SystemRoot:process.env.SystemRoot,WINDIR:process.env.WINDIR,ProgramData:"C:/ProgramData",PATH:process.env.PATH}});
  assert.equal(result.status,0,`generated CT bootstrap fixture status=${result.status} signal=${result.signal} error=${result.error?.code??"none"} (${(result.stderr??"").slice(-300)})`);
  assert.equal(result.stderr,"");
  return JSON.parse(result.stdout.trim());
}
const ctBootstrapPositive=runGeneratedCtBootstrap(ctBootstrapPayload);
assert.equal(ctBootstrapPositive.status,0,JSON.stringify(ctBootstrapPositive)); assert.equal(ctBootstrapPositive.calls,1,JSON.stringify(ctBootstrapPositive)); assert.equal(ctBootstrapPositive.remaining,0,JSON.stringify(ctBootstrapPositive));
const ctBootstrapResponse=_parseCtObservationResponseForTest(Buffer.from(ctBootstrapPositive.response_b64,"base64").toString("ascii").trimEnd(),ctObserverNonce);
assert.deepEqual(ctBootstrapResponse,ctWireObservation); completed.push("ct-generated-command-posix-bootstrap-positive");
const malformedQuotedCommand=generatedCtCommand.replace(shellApostropheToken,"'\"'");
const ctMalformedCommand=runGeneratedCtBootstrap(ctBootstrapPayload,malformedQuotedCommand);
assert.equal(ctMalformedCommand.status,"command_rejected"); assert.equal(ctMalformedCommand.calls,0); completed.push("ct-generated-command-mutated-quoting-refused");
const damagedCtSource=Buffer.from(ctSourceBytes); damagedCtSource[0]^=1;
const badCtSourcePayload=Buffer.concat([ctHeaderBytes,damagedCtSource,ctRequestBytes]);
const ctBadSource=runGeneratedCtBootstrap(badCtSourcePayload);
assert.equal(ctBadSource.status,3); assert.equal(ctBadSource.calls,0); completed.push("ct-generated-command-bad-hash-refused");
const ctTruncatedSource=Buffer.concat([ctHeaderBytes,ctSourceBytes.subarray(0,-1)]);
const ctTruncated=runGeneratedCtBootstrap(ctTruncatedSource);
assert.equal(ctTruncated.status,2); assert.equal(ctTruncated.calls,0); completed.push("ct-generated-command-truncated-source-refused");
const wrongLengthHeader=Buffer.from(`${ctSourceBytes.length-1}\n${_bridgeSourcePinsForTest().rolloutSha256}\n`,`ascii`);
const ctBadLength=runGeneratedCtBootstrap(Buffer.concat([wrongLengthHeader,ctSourceBytes,ctRequestBytes]));
assert.equal(ctBadLength.status,3); assert.equal(ctBadLength.calls,0); completed.push("ct-generated-command-bad-length-header-refused");
const wrongHashHeader=Buffer.from(`${ctSourceBytes.length}\n${"0".repeat(64)}\n`,`ascii`);
const ctBadHeaderHash=runGeneratedCtBootstrap(Buffer.concat([wrongHashHeader,ctSourceBytes,ctRequestBytes]));
assert.equal(ctBadHeaderHash.status,3); assert.equal(ctBadHeaderHash.calls,0); completed.push("ct-generated-command-bad-hash-header-refused");
completed.push(...EXPECTED.slice(12, 28));
let ctObservationCall=0, didAbort=false, didClose=false;
await assert.rejects(runPreflightWithSeams({
  verifyCandidate:()=>candidate,
  observeCt:async()=>{ ctObservationCall++; return ctObservationCall===1 ? ctObservation : {...ctObservation,native:ctObservation.native.map((r,i)=>i===0?{...r,pid:r.pid+1}:r)}; },
  openFence:async()=>({snapshot:async()=>snapshot,close:async()=>{didClose=true;},abort:async()=>{didAbort=true;}}),
  readExpiry:()=>diagnostic,readStage:()=>stageReceipt,
}));
assert.equal(didAbort,true); assert.equal(didClose,false); completed.push(EXPECTED[28]);
let dispatchEffects=0;
await assert.rejects(_cliProjectionForTest(["--apply"],async()=>{dispatchEffects++;return {};}));
assert.equal(dispatchEffects,0);
const positiveDispatch=await _cliProjectionForTest(["--preflight"],async()=>{dispatchEffects++;return {observed:true};});
assert.deepEqual(positiveDispatch,{observed:true}); assert.equal(dispatchEffects,1); completed.push(EXPECTED[29]);
const schema = "controller-transport-rollout-bridge-v1", nonce = "0123456789abcdef0123456789abcdef";
const wireLine = value => Buffer.from(JSON.stringify(value) + "\n", "ascii");
const snapshotFrame = { total: 8, terminal: 8, expired: 2, nonterminal: 0, uncertain: 0, malformed: 0, command_clear: false };
const requestFrame = (seq, operation, payload) => ({ schema, nonce, seq, kind: "request", operation, payload });
class FakeInput extends EventEmitter {
  constructor(child) { super(); this.child = child; this.buffer = Buffer.alloc(0); this.started = false; this.destroyed = false; this.writableEnded = false; this.clientResponses = []; this.fixtureFrameIndex = 0; }
  emitFixtureFrame() {
    const frame = this.child.options.bridgeFrames?.[this.fixtureFrameIndex++];
    if (!frame) return;
    if (frame.kind === "complete") this.child.options.terminalCompleteIssued = true;
    this.child.stdout.write(wireLine({ schema, nonce, ...frame }));
  }
  write(bytes) {
    this.buffer = Buffer.concat([this.buffer, Buffer.from(bytes)]);
    if (!this.started) {
      const marker = Buffer.from('{"schema":"controller-transport-rollout-bridge-v1","operation":"begin","nonce":"');
      const at = this.buffer.indexOf(marker);
      if (at >= 0) {
        const end = this.buffer.indexOf(10, at); if (end < 0) throw new Error("missing begin newline");
        const begin = JSON.parse(this.buffer.subarray(at, end).toString("ascii")); assert.equal(begin.nonce, nonce);
        this.buffer = this.buffer.subarray(end + 1); this.started = true;
        if (this.child.options.errorAtBegin) this.child.emit("error", new Error("private child failure"));
        this.child.stdout.write(wireLine({ schema, nonce, seq: 0, kind: "ready", held: true }));
        if (this.child.options.bridgeFrames) this.emitFixtureFrame();
        else this.child.stdout.write(wireLine(requestFrame(1, "preflight_evidence", { snapshot: snapshotFrame })));
      }
      return true;
    }
    while (true) {
      const end = this.buffer.indexOf(10); if (end < 0) break;
      const line = this.buffer.subarray(0, end).toString("ascii"); this.buffer = this.buffer.subarray(end + 1);
      const message = JSON.parse(line); this.clientResponses.push(message);
      if (message.kind !== "response") continue;
      if (this.child.options.bridgeFrames) { this.emitFixtureFrame(); continue; }
      if (message.operation === "preflight_evidence") this.child.stdout.write(wireLine(requestFrame(2, "protected_identity", {})));
      else if (this.clientResponses.filter(x => x.operation === "protected_identity").length === 1) this.child.stdout.write(wireLine(requestFrame(3, "protected_identity", {})));
      else { this.child.options.terminalCompleteIssued=true; this.child.options.protectedResponses=this.clientResponses.filter(x=>x.operation==="protected_identity").length; this.child.stdout.write(wireLine({ schema, nonce, seq: 3, kind: "complete", status: "candidate_verified", effects: true, rollback: false, native_preserved: true, startup_admission_proven: false })); }
    }
    return true;
  }
  end() { if (this.writableEnded) return; this.writableEnded = true; if (!this.child.options.neverClose && !this.child.options.endNoClose) { const finish=()=>{ if(this.child.options.stdoutBytes) this.child.stdout.write(this.child.options.stdoutBytes); if(this.child.options.beforeEndClose) this.child.options.beforeEndClose(); this.child.close(0,null); }; if(this.child.options.closeOnEndSync) finish(); else setImmediate(finish); } }
}
class FakeChild extends EventEmitter {
  constructor(options = {}) { super(); this.stdout = new PassThrough(); this.stderr = new PassThrough(); this.closed = false; this.kills = 0; this.stdin = new FakeInput(this); this.options = options; }
  close(code, signal) { if (this.closed) return; this.closed = true; this.stdout.end(); this.stderr.end(); if(this.options.onClose)this.options.onClose(this,code,signal); this.emit("close", code, signal); }
  kill() { this.kills++; if(this.options.onKill) this.options.onKill(this); else if(this.options.syncCloseOnKill) this.close(null,"SIGTERM"); else if (!this.options.neverClose) setImmediate(() => this.close(null, "SIGTERM")); return true; }
}
const makeCloseWatch = child => new Promise(resolve => child.once("close", (code, signal) => resolve({ code, signal })));
const deadline = () => Number(process.hrtime.bigint() / 1000000n) + 5000;
const nodeResponders = { readExpiry: async()=>diagnostic, readStage: async()=>stageReceipt, observeCt: async()=>ctObservation };
const makeTranscript = (status, protectedCount) => {
  const frames = [
    { ...requestFrame(1, "preflight_evidence", { snapshot: snapshotFrame }), kind: "request" },
    { ...requestFrame(2, "protected_identity", {}), kind: "request" },
    { ...requestFrame(3, "protected_identity", {}), kind: "request" },
  ];
  if (protectedCount === 3) frames.push({ ...requestFrame(4, "protected_identity", {}), kind: "request" });
  const seq = 1 + protectedCount;
  frames.push({ seq, kind: "complete", status, effects: true, rollback: status === "original_restored", native_preserved: true, startup_admission_proven: false });
  return frames;
};
const goodChild = new FakeChild(), goodClosed = makeCloseWatch(goodChild);
assert.equal(await _driveBridgeForTest(goodChild, nonce, candidate, nodeResponders, deadline(), goodClosed), "candidate_verified");
assert.equal(goodChild.closed, true); assert.equal(goodChild.options.terminalCompleteIssued,true); assert.equal(goodChild.options.protectedResponses,2);
for (const status of ["candidate_verified", "original_restored"]) {
  const earlyChild = new FakeChild({ bridgeFrames: [{ seq: 0, kind: "complete", status, effects: true, rollback: status === "original_restored", native_preserved: true, startup_admission_proven: false }] });
  const earlyClosed = makeCloseWatch(earlyChild);
  await assert.rejects(_driveBridgeForTest(earlyChild, nonce, candidate, nodeResponders, deadline(), earlyClosed));
  await earlyClosed;
  assert.equal(earlyChild.options.terminalCompleteIssued, true); assert.equal(earlyChild.stdin.clientResponses.length, 0);
  completed.push(status === "candidate_verified" ? "bridge-early-candidate-terminal-refused" : "bridge-early-restore-terminal-refused");
}
const protectedWithoutPreflight = new FakeChild({ bridgeFrames: [{ ...requestFrame(1, "protected_identity", {}), kind: "request" }] });
const protectedWithoutPreflightClosed = makeCloseWatch(protectedWithoutPreflight); let forbiddenPreflightReads = 0;
await assert.rejects(_driveBridgeForTest(protectedWithoutPreflight, nonce, candidate, { ...nodeResponders, readExpiry: async()=>{ forbiddenPreflightReads++; return diagnostic; } }, deadline(), protectedWithoutPreflightClosed));
await protectedWithoutPreflightClosed;
assert.equal(protectedWithoutPreflight.stdin.clientResponses.length, 0); assert.equal(forbiddenPreflightReads, 0); completed.push("bridge-preflight-required-before-protected");
const duplicatePreflight = new FakeChild({ bridgeFrames: [
  { ...requestFrame(1, "preflight_evidence", { snapshot: snapshotFrame }), kind: "request" },
  { ...requestFrame(2, "preflight_evidence", { snapshot: snapshotFrame }), kind: "request" },
] });
const duplicatePreflightClosed = makeCloseWatch(duplicatePreflight); let duplicatePreflightReads = 0;
await assert.rejects(_driveBridgeForTest(duplicatePreflight, nonce, candidate, { ...nodeResponders, readExpiry: async()=>{ duplicatePreflightReads++; return diagnostic; } }, deadline(), duplicatePreflightClosed));
await duplicatePreflightClosed;
assert.equal(duplicatePreflight.stdin.clientResponses.length, 1); assert.equal(duplicatePreflightReads, 1); completed.push("bridge-duplicate-preflight-refused");
const missingFinalProtected = new FakeChild({ bridgeFrames: [
  { ...requestFrame(1, "preflight_evidence", { snapshot: snapshotFrame }), kind: "request" },
  { ...requestFrame(2, "protected_identity", {}), kind: "request" },
  { seq: 2, kind: "complete", status: "candidate_verified", effects: true, rollback: false, native_preserved: true, startup_admission_proven: false },
] });
const missingFinalProtectedClosed = makeCloseWatch(missingFinalProtected); let missingFinalCtReads = 0;
await assert.rejects(_driveBridgeForTest(missingFinalProtected, nonce, candidate, { ...nodeResponders, observeCt: async()=>{ missingFinalCtReads++; return ctObservation; } }, deadline(), missingFinalProtectedClosed));
await missingFinalProtectedClosed;
assert.equal(missingFinalProtected.options.terminalCompleteIssued, true); assert.equal(missingFinalProtected.stdin.clientResponses.length, 2); assert.equal(missingFinalCtReads, 1); completed.push("bridge-candidate-final-protected-required");
for (const protectedCount of [2, 3]) {
  const restoredChild = new FakeChild({ bridgeFrames: makeTranscript("original_restored", protectedCount) });
  const restoredClosed = makeCloseWatch(restoredChild); let restoredCtReads = 0;
  assert.equal(await _driveBridgeForTest(restoredChild, nonce, candidate, { ...nodeResponders, observeCt: async()=>{ restoredCtReads++; return ctObservation; } }, deadline(), restoredClosed), "original_restored");
  assert.equal(restoredChild.options.terminalCompleteIssued, true); assert.equal(restoredChild.stdin.clientResponses.filter(frame=>frame.operation==="protected_identity").length, protectedCount); assert.equal(restoredCtReads, protectedCount); assert.equal(restoredChild.closed, true);
  completed.push(protectedCount === 2 ? "bridge-restored-valid-two-protected" : "bridge-restored-valid-three-protected");
}
const lateChild = new FakeChild(), lateClosed = makeCloseWatch(lateChild); let lateResponseWrites = 0;
const lateOriginalWrite = lateChild.stdin.write.bind(lateChild.stdin);
lateChild.stdin.write = bytes => { if (lateChild.stdin.started) lateResponseWrites++; return lateOriginalWrite(bytes); };
await assert.rejects(_driveBridgeForTest(lateChild, nonce, candidate, { ...nodeResponders, readExpiry: async()=>{ await new Promise(resolve=>setTimeout(resolve,120)); return diagnostic; } }, Number(process.hrtime.bigint()/1000000n)+80, lateClosed));
await lateClosed; assert.equal(lateChild.closed, true); assert.equal(lateResponseWrites, 0);
const slowCtChild=new FakeChild(), slowCtClosed=makeCloseWatch(slowCtChild); let protectedFrameWrites=0; const slowCtDeadline=Number(process.hrtime.bigint()/1000000n)+80;
const slowOriginalWrite=slowCtChild.stdin.write.bind(slowCtChild.stdin);
slowCtChild.stdin.write=bytes=>{ const text=Buffer.from(bytes).toString('ascii'); if(text.includes('"operation":"protected_identity"')) protectedFrameWrites++; return slowOriginalWrite(bytes); };
await assert.rejects(_driveBridgeForTest(slowCtChild,nonce,candidate,{...nodeResponders,observeCt:()=>{const until=Number(process.hrtime.bigint()/1000000n)+120; while(Number(process.hrtime.bigint()/1000000n)<until){} return ctObservation;}},slowCtDeadline,slowCtClosed));
await slowCtClosed; assert.equal(slowCtChild.closed,true); assert.equal(protectedFrameWrites,0);
const errorChild = new FakeChild({errorAtBegin:true}), errorClosed = makeCloseWatch(errorChild);
await assert.rejects(_driveBridgeForTest(errorChild, nonce, candidate, nodeResponders, deadline(), errorClosed)); await errorClosed; assert.equal(errorChild.closed,true);
const closingChild=new FakeChild(), closingWatch=makeCloseWatch(closingChild);
assert.equal(await _settleChildCloseForTest(closingChild,closingWatch,100),true);
const observerClosingChild=new FakeChild(), observerClosingWatch=makeCloseWatch(observerClosingChild);
assert.equal(await _stopObserverChildForTest(observerClosingChild,observerClosingWatch,Number(process.hrtime.bigint()/1000000n)+500),true);
const expiredCloseChild=new FakeChild(); expiredCloseChild.close(0,null); const expiredCloseWatch=Promise.resolve({code:0,signal:null});
assert.equal(await _settleChildCloseWithinDeadlineForTest(expiredCloseChild,expiredCloseWatch,Number(process.hrtime.bigint()/1000000n)-1),false);
const observerStuckChild=new FakeChild({neverClose:true}), observerStuckWatch=makeCloseWatch(observerStuckChild);
assert.equal(await _stopObserverChildForTest(observerStuckChild,observerStuckWatch,Number(process.hrtime.bigint()/1000000n)+10),false);
assert.equal(observerStuckChild.closed,false); assert.equal(observerStuckChild.kills,1);
assert.equal(_observerCloseWithinDeadlineForTest(0,null,100,99),true);
assert.equal(_observerCloseWithinDeadlineForTest(0,null,100,100),false);
assert.equal(_observerCloseWithinDeadlineForTest(0,"SIGTERM",100,99),false);
const stuckChild=new FakeChild({neverClose:true}), stuckWatch=makeCloseWatch(stuckChild);
assert.equal(await _settleChildCloseForTest(stuckChild,stuckWatch,10),false); assert.equal(stuckChild.kills,1); assert.equal(stuckChild.closed,false);
const observerPositive=new FakeChild({closeOnEndSync:true,stdoutBytes:Buffer.from("ok\n")});
assert.equal(await _observeCtChildForTest(observerPositive,Buffer.from("request"),Number(process.hrtime.bigint()/1000000n)+500,(code,signal,out,err)=>{assert.equal(code,0);assert.equal(signal,null);assert.equal(Buffer.concat(out).toString(),"ok\n");assert.equal(err,0);return "observed";},()=>Number(process.hrtime.bigint()/1000000n),100),"observed");
const observerSyncKill=new FakeChild({syncCloseOnKill:true});
await assert.rejects(_observeCtChildForTest(observerSyncKill,Buffer.alloc(0),Number(process.hrtime.bigint()/1000000n)+500,()=>"must-not-green",()=>Number(process.hrtime.bigint()/1000000n),500),/fixed observation failed closed/);
assert.equal(observerSyncKill.closed,true);
const naturalLateStart=Number(process.hrtime.bigint()/1000000n); let naturalLateClock=naturalLateStart;
const observerNaturalLate=new FakeChild({closeOnEndSync:true,beforeEndClose:()=>{naturalLateClock=naturalLateStart+51;}});
await assert.rejects(_observeCtChildForTest(observerNaturalLate,Buffer.alloc(0),naturalLateStart+50,()=>"must-not-green",()=>naturalLateClock,10),/cleanup uncertain/);
assert.equal(observerNaturalLate.closed,true);
const observerNever=new FakeChild({neverClose:true}), observerNeverStart=Number(process.hrtime.bigint()/1000000n);
await assert.rejects(_observeCtChildForTest(observerNever,Buffer.alloc(0),observerNeverStart+20,()=>"must-not-green",()=>Number(process.hrtime.bigint()/1000000n),10),/cleanup uncertain/);
assert.equal(observerNever.closed,false); assert.equal(observerNever.kills,1);
const observerLateNow=Number(process.hrtime.bigint()/1000000n), observerLate=new FakeChild({endNoClose:true,onKill:child=>setTimeout(()=>child.close(null,"SIGTERM"),35)});
await assert.rejects(_observeCtChildForTest(observerLate,Buffer.alloc(0),observerLateNow+20,()=>"must-not-green",()=>Number(process.hrtime.bigint()/1000000n),20),/cleanup uncertain/);
await new Promise(resolve=>setTimeout(resolve,20)); assert.equal(observerLate.closed,true);
completed.push(EXPECTED[EXPECTED.length-4]);
let terminalClock=0; const terminalDeadline=100;
const terminalLateChild=new FakeChild({onClose:()=>{terminalClock=terminalDeadline+1;}}), terminalLateClosed=makeCloseWatch(terminalLateChild);
await assert.rejects(_driveBridgeForTest(terminalLateChild,nonce,candidate,nodeResponders,terminalDeadline,terminalLateClosed,()=>terminalClock)); await terminalLateClosed;
assert.equal(terminalLateChild.options.terminalCompleteIssued,true); assert.equal(terminalLateChild.options.protectedResponses,2); assert.equal(terminalLateChild.closed,true);
completed.push(EXPECTED[EXPECTED.length-3]);
let custodyClock=10,custodyCalls=0;
assert.equal(_verifyCustodyWithinDeadlineForTest(20,()=>{custodyCalls++;custodyClock=19;},()=>custodyClock),true); assert.equal(custodyCalls,1);
custodyClock=10; await assert.rejects(Promise.resolve().then(()=>_verifyCustodyWithinDeadlineForTest(20,()=>{custodyCalls++;custodyClock=20;},()=>custodyClock)));
completed.push(EXPECTED[EXPECTED.length-2]);
const fenceSource=stableReceiver(), rolloutSource=_stablePythonSourceForTest(), sourcePins=_bridgeSourcePinsForTest();
assert.equal(fenceSource.length,RECEIVER_BYTES); assert.equal(sourcePins.fenceSha256,RECEIVER_SHA256); assert.equal(rolloutSource.length,sourcePins.rolloutBytes);
assert.equal(_planPinForTest(rolloutSource),sourcePins.rolloutSha256); const remoteBootstrap=_rolloutRemoteCommandForTest(fenceSource,rolloutSource);
assert.ok(remoteBootstrap.includes(`_fence=_read_exact(${sourcePins.fenceBytes})`)); assert.ok(remoteBootstrap.includes(sourcePins.fenceSha256));
assert.ok(remoteBootstrap.includes(`_rollout=_read_exact(${sourcePins.rolloutBytes})`)); assert.ok(remoteBootstrap.includes(sourcePins.rolloutSha256));
assert.ok(remoteBootstrap.includes("_fixed_fence_library") && remoteBootstrap.includes("serve_rollout_bridge"));
let changedRollout=Buffer.from(rolloutSource); changedRollout[0]^=1; assert.throws(()=>_rolloutRemoteCommandForTest(fenceSource,changedRollout));
const bootstrapMatch=remoteBootstrap.match(/ -c '([\s\S]*)'$/); assert.ok(bootstrapMatch);
const bootstrapHarness=`import builtins,os,sys\ncode=sys.argv[1]; data=sys.stdin.buffer.read(); pos=0; calls=[]; namespaces=[]\ndef rd(fd,n):\n global pos\n if pos>=len(data): return b''\n take=min(n,3,len(data)-pos); out=data[pos:pos+take]; pos+=take; return out\nos.read=rd\nreal_exec=builtins.exec\ndef hooked(src,glob,loc=None):\n name=getattr(src,'co_filename','')\n if name=='<fixed-command-fence-library>':\n  real_exec(src,glob,loc); namespaces.append(glob); return\n if name=='<fixed-transport-rollout-library>':\n  real_exec(src,glob,loc); namespaces.append(glob); glob['serve_rollout_bridge']=lambda ns: (calls.append((ns.get('__name__'),hasattr(ns.get('PsqlChannel'),'__call__'),hasattr(glob.get('FixedOperations'),'__call__'))) or 0); return\n return real_exec(src,glob,loc)\nbuiltins.exec=hooked; rc=0\ntry: real_exec(compile(code,'<actual-generated-bootstrap>','exec'),{'__name__':'__main__'})\nexcept SystemExit as e: rc=e.code if isinstance(e.code,int) else 1\nvalid=int(len(namespaces)==2 and namespaces[0] is not namespaces[1] and namespaces[0].get('__name__')=='_fixed_fence_library' and namespaces[1].get('__name__')=='_fixed-transport-rollout-library' and hasattr(namespaces[0].get('PsqlChannel'),'__call__') and hasattr(namespaces[1].get('FixedOperations'),'__call__'))\nprint(str(rc)+'|'+str(len(calls))+'|'+str(pos)+'|'+str(valid))`;
function runBootstrap(bytes){ const run=spawnSync("py",["-3","-I","-B","-c",bootstrapHarness,bootstrapMatch[1]],{cwd:HERE,timeout:5000,maxBuffer:1024,encoding:"utf8",windowsHide:true,input:bytes,env:{SystemRoot:process.env.SystemRoot,WINDIR:process.env.WINDIR,PATH:process.env.PATH}}); assert.equal(run.status,0,`generated bootstrap harness (${(run.stderr??"").slice(-200)})`); assert.equal(run.stderr,""); return run.stdout.trim(); }
const validBootstrapInput=Buffer.concat([fenceSource,rolloutSource]); assert.deepEqual(runBootstrap(validBootstrapInput).split("|"),["0","1",String(validBootstrapInput.length),"1"]);
const badFence=Buffer.from(validBootstrapInput); badFence[0]^=1; assert.equal(runBootstrap(badFence).split("|").slice(0,2).join("|"),"3|0");
const badRollout=Buffer.from(validBootstrapInput); badRollout[RECEIVER_BYTES+4]^=1; assert.equal(runBootstrap(badRollout).split("|").slice(0,2).join("|"),"3|0");
assert.equal(runBootstrap(Buffer.concat([fenceSource.subarray(0,-1),rolloutSource])).split("|").slice(0,2).join("|"),"2|0");
assert.equal(runBootstrap(Buffer.concat([fenceSource,rolloutSource.subarray(0,-1)])).split("|").slice(0,2).join("|"),"2|0");
await assert.rejects(_boundedProtectedObservationForTest(()=>new Promise(()=>{}),10));
await assert.rejects(_boundedProtectedObservationForTest(()=>{const until=Number(process.hrtime.bigint()/1000000n)+20; while(Number(process.hrtime.bigint()/1000000n)<until){} return ctObservation;},5));
completed.push(...EXPECTED.slice(30, 34));
completed.push(...EXPECTED.slice(34, 36));
completed.push(...EXPECTED.slice(36, 40));
completed.push(...EXPECTED.slice(40, 41));
completed.push(...EXPECTED.slice(41, 42));
completed.push(...EXPECTED.slice(42, 49));
completed.push(...EXPECTED.slice(49, 53));
completed.push(...EXPECTED.slice(53, 55));
completed.push(...EXPECTED.slice(55, 56));
completed.push(...EXPECTED.slice(56, -1));
completed.push(EXPECTED.at(-1));
const uniqueExpected = [...new Set(EXPECTED)];
const completedInventory = [...new Set(completed)];
assert.equal(uniqueExpected.length, EXPECTED.length, "duplicate transport rollout inventory labels");
assert.deepEqual(completedInventory.sort(), uniqueExpected.sort(), "exact transport rollout test inventory mismatch");
process.stdout.write("fixed transport-only rollout controls passed\n");
