#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const args = process.argv.slice(2);
const mode = args.length === 0 ? 'default' : args.length === 1 ? args[0] : '';
const success = {
  default: 'LLM displacement journal verification passed',
  '--faults': 'LLM displacement lease guard verification passed',
  '--postgres-semantics': 'LLM displacement PostgreSQL semantics verification passed',
};
if (!Object.hasOwn(success, mode)) {
  console.error('usage: node scripts/verify-llm-displacement-journal.mjs [--faults|--postgres-semantics]');
  process.exit(2);
}

const memory = [
  'TestLLMDisplacementJournalMemory',
  'TestLLMDisplacementJournalMemory/create_from_actual_acquired_lease',
  'TestLLMDisplacementJournalMemory/create_idempotency_and_full_identity',
  'TestLLMDisplacementJournalMemory/create_rejects_stale_stored_world',
  'TestLLMDisplacementJournalMemory/create_rejects_stale_stored_world/victim_revision',
  'TestLLMDisplacementJournalMemory/create_rejects_stale_stored_world/urgent_owner',
  'TestLLMDisplacementJournalMemory/create_rejects_stale_stored_world/cross_node',
  'TestLLMDisplacementJournalMemory/create_rejects_stale_stored_world/cross_target',
  'TestLLMDisplacementJournalMemory/create_rejects_stale_stored_world/controller_plan_mismatch',
  'TestLLMDisplacementJournalMemory/create_rejects_stale_stored_world/stale_fence',
  'TestLLMDisplacementJournalMemory/create_rejects_stale_stored_world/expired_lease',
  'TestLLMDisplacementJournalMemory/create_rejects_stale_stored_world/missing_lease',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/missing_urgent_plan',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/missing_urgent_artifact_digest',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/missing_victim_runtime',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/missing_victim_profile',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/missing_urgent_context',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/missing_checkpoint_proof',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/missing_alias_inventory',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/missing_controller_plan',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/missing_local_pinned_plan',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/missing_actual_alias',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/duplicate_alias_inventory',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/actual_alias_not_in_inventory',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/cross_node_binding',
  'TestLLMDisplacementJournalMemory/victim_and_urgent_bindings_are_complete/cross_accelerator_binding',
  'TestLLMDisplacementJournalMemory/one_unresolved_accelerator_and_expired_lease_guard',
  'TestLLMDisplacementJournalMemory/malformed_completed_normal_revision_retains_custody_for_acquire_and_create',
  'TestLLMDisplacementJournalMemory/sealed_intent_snapshot_cas_and_completion',
  'TestLLMDisplacementJournalMemory/uncertain_and_manual_reconciliation_retain_custody',
  'TestLLMDisplacementJournalMemory/uncertain_and_manual_reconciliation_retain_custody/pending',
  'TestLLMDisplacementJournalMemory/uncertain_and_manual_reconciliation_retain_custody/uncertain',
  'TestLLMDisplacementJournalMemory/uncertain_and_manual_reconciliation_retain_custody/manual_reconciliation',
  'TestLLMDisplacementJournalMemory/concurrent_same_accelerator_creation',
];
const pgSemantics = [
  'TestPostgresLLMDisplacementSemantics',
  'TestPostgresLLMDisplacementSemantics/create_locks_before_idempotency_and_is_idempotent',
  'TestPostgresLLMDisplacementSemantics/create_validates_stored_world',
  'TestPostgresLLMDisplacementSemantics/create_validates_stored_world/victim_revision',
  'TestPostgresLLMDisplacementSemantics/create_validates_stored_world/cross_owner',
  'TestPostgresLLMDisplacementSemantics/create_validates_stored_world/cross_node',
  'TestPostgresLLMDisplacementSemantics/create_validates_stored_world/cross_target',
  'TestPostgresLLMDisplacementSemantics/create_validates_stored_world/stale_fence',
  'TestPostgresLLMDisplacementSemantics/create_validates_stored_world/expired_lease',
  'TestPostgresLLMDisplacementSemantics/create_validates_stored_world/missing_lease',
  'TestPostgresLLMDisplacementSemantics/create_validates_stored_world/lease_expiry_precision_mismatch',
  'TestPostgresLLMDisplacementSemantics/create_validates_stored_world/controller_plan_mismatch',
  'TestPostgresLLMDisplacementSemantics/newly_acquired_expiry_is_microsecond_canonical',
  'TestPostgresLLMDisplacementSemantics/fail_closed_completed_and_malformed_displacement_rows',
  'TestPostgresLLMDisplacementSemantics/fail_closed_completed_and_malformed_displacement_rows/malformed_completed_normal_phase_revision',
  'TestPostgresLLMDisplacementSemantics/fail_closed_completed_and_malformed_displacement_rows/malformed_completed_history',
  'TestPostgresLLMDisplacementSemantics/fail_closed_completed_and_malformed_displacement_rows/indexed_phase_body_mismatch',
  'TestPostgresLLMDisplacementSemantics/fail_closed_completed_and_malformed_displacement_rows/indexed_revision_body_mismatch',
  'TestPostgresLLMDisplacementSemantics/fail_closed_completed_and_malformed_displacement_rows/unknown_phase_history',
  'TestPostgresLLMDisplacementSemantics/validated_completed_displacement_allows_acquisition',
  'TestPostgresLLMDisplacementSemantics/ordinary_and_recovery_acquire_block_after_shared_lock',
  'TestPostgresLLMDisplacementSemantics/unique_unresolved_conflict_rolls_back',
  'TestPostgresLLMDisplacementSemantics/concurrent_intent_creation_serializes',
];
const pgCAS = ['TestPostgresLLMDisplacementCAS'];
const suites = mode === '--faults' ? [...memory, ...pgSemantics]
  : mode === '--postgres-semantics' ? [...pgSemantics, ...pgCAS]
    : [...memory, ...pgCAS];

function read(path) { return readFileSync(path, 'utf8'); }
function requireMatch(condition, message) { if (!condition) throw new Error(message); }

const migration = read('migrations/0022_llm_displacement.sql').toLowerCase();
const postgres = read('internal/store/postgres_workloads.go').toLowerCase();
const journalPG = read('internal/store/postgres_llm_displacement.go').toLowerCase();
const journal = read('internal/store/llm_displacement.go');
const semanticTest = read('internal/store/postgres_contract_test.go');
requireMatch(/create unique index if not exists llm_displacement_unresolved_accelerator_idx[\s\S]*?where phase <> 'completed'/.test(migration), 'migration lacks unique unresolved accelerator custody');
requireMatch(/unique\s*\(owner_id, idempotency_key\)/.test(migration), 'migration lacks idempotency uniqueness');
requireMatch(migration.includes('victim_target_id') && migration.includes('urgent_target_id') && migration.includes('node_id'), 'migration omits concrete victim/urgent target and node associations');
requireMatch(migration.includes('settlement_intent_sealed') && migration.includes("body->'original_lease'") && migration.includes("body->'victim_binding'->>'actual_alias'"), 'migration omits sealed settlement or exact lease/model alias identity');
requireMatch(migration.includes("controller_plan_id") && migration.includes("controller_plan_hash") && migration.includes("local_plan_hash"), 'migration omits controller execution and independent local pinned-plan bindings');
requireMatch(/insert into accelerator_lease_fences\(accelerator_id,last_token\) values\(\$1,0\) on conflict\(accelerator_id\) do update set last_token=accelerator_lease_fences\.last_token returning last_token/.test(postgres), 'create-or-lock fence row statement is missing');
const acquireStart = postgres.indexOf('func (p *postgresworkloadstore) acquireacceleratorlease(');
const acquireEnd = postgres.indexOf('\nfunc (p *postgresworkloadstore) renewacceleratorlease', acquireStart);
const acquire = postgres.slice(acquireStart, acquireEnd);
const lockIndex = acquire.indexOf('lockacceleratorleasefence(ctx, tx, acceleratorid)');
const leaseIndex = acquire.indexOf('select accelerator_id, workload_id, fencing_token');
const displacementIndex = acquire.indexOf('from llm_displacement_operations');
function assertLockOrder(lock, lease, displacement) { if (lock < 0 || lease < 0 || displacement < 0 || lock >= lease || lock >= displacement) throw new Error('Acquire fence lock order invalid'); }
requireMatch(acquireStart >= 0 && acquireEnd > acquireStart, 'Acquire implementation was not found');
assertLockOrder(lockIndex, leaseIndex, displacementIndex);
requireMatch(acquire.includes('select phase,revision,body from llm_displacement_operations where accelerator_id=$1') && /indexedphase\s*!=\s*displacement\.phase/.test(acquire) && acquire.includes('indexedrevision') && acquire.includes('decodellmdisplacementbody') && !acquire.includes('union all select case'), 'Acquire does not use the strict typed all-row displacement scan');
let negativeLockRejected = false; try { assertLockOrder(5, 2, 8); } catch { negativeLockRejected = true; }
let removedLockRejected = false; try { assertLockOrder(-1, 2, 8); } catch { removedLockRejected = true; }
requireMatch(negativeLockRejected && removedLockRejected, 'negative lock-order oracle failed to reject a removed/moved lease guard');
const create = journalPG.slice(journalPG.indexOf('func (p *postgresworkloadstore) createllmdisplacementoperation'), journalPG.indexOf('func translateLLMDisplacementSQLError'.toLowerCase()));
const createLock = create.indexOf('lockacceleratorleasefence(ctx, tx, prepared.acceleratorid)');
const createCustodyScan = create.indexOf('select phase,revision,body from llm_displacement_operations where accelerator_id=$1');
const workloadReadCall = create.indexOf('readdisplacementworkload(ctx, tx, prepared.victimworkloadid)');
const leaseRead = create.indexOf('from accelerator_leases');
requireMatch(createLock >= 0 && createLock < create.indexOf('select body from llm_displacement_operations') && createLock < createCustodyScan && createCustodyScan < workloadReadCall && workloadReadCall < leaseRead && leaseRead < create.indexOf('validatellmdisplacementworld'), 'intent creation does not lock the shared fence row before idempotency, unresolved, workload, and lease reads/validation');
const workloadHelperStart = journalPG.indexOf('func readdisplacementworkload');
const workloadHelperEnd = journalPG.indexOf('\nfunc translateLLMDisplacementSQLError', workloadHelperStart);
const workloadHelper = journalPG.slice(workloadHelperStart, workloadHelperEnd);
requireMatch(workloadHelper.includes('from workloads where id=$1 for update'), 'Create workload reads are not row-locked');
requireMatch(semanticTest.includes('TestPostgresLLMDisplacementSemantics') && semanticTest.includes('backing.CreateLLMDisplacementOperation') && semanticTest.includes('backing.AcquireAcceleratorLeaseForCheckpointRecovery'), 'deterministic fixture does not invoke production SQL methods');
requireMatch(semanticTest.includes('semantic fixture, never a live PostgreSQL claim'), 'PostgreSQL fixture evidence is not qualified as semantic only');
requireMatch(journal.includes('CommandIntents') && journal.includes('ObservedResults') && journal.includes('SnapshotIdentity') && journal.includes('manual_reconciliation'), 'immutable intent, observation, snapshot, or manual custody model is missing');
for (const field of ['VictimBinding', 'UrgentBinding', 'ActualAlias', 'CatalogAliases', 'LocalPlanID', 'ControllerPlanID', 'EnvelopeDigest', 'KeyID', 'Signature', 'ArtifactDigest', 'RuntimeIdentity', 'ProfileIdentity', 'ContextIdentity', 'CheckpointDigest', 'NodeID', 'AcceleratorID', 'settlement_intent_sealed']) requireMatch(journal.includes(field), `displacement binding is missing ${field}`);
requireMatch(/op\.revision != uint64\(phaseindex\+1\)/.test(journal.toLowerCase()) && /op\.revision != uint64\(len\(op\.commandintents\)\+len\(op\.observedresults\)\+2\)/.test(journal.toLowerCase()), 'stored normal/reconciliation revision is not checked against phase and history');
requireMatch(/persistedcandidate\.revision\+\+[\s\S]*?validatellmdisplacementidentity\(persistedcandidate\)/.test(journal.toLowerCase()), 'Update does not validate the post-CAS persisted revision while accepting the caller expected revision');

const selection = suites.map((name) => name.split('/')[0]).filter((name, index, all) => all.indexOf(name) === index);
const testRegex = `^(${selection.join('|')})$`;
const proc = spawnSync('go', ['test', '-json', './internal/store', '-run', testRegex, '-count=1', '-timeout=60s'], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, timeout: 120_000 });
if (proc.error) throw proc.error;
const events = [];
for (const line of proc.stdout.split(/\r?\n/)) {
  if (!line.trim()) continue;
  try { events.push(JSON.parse(line)); } catch { throw new Error(`go test emitted malformed JSON: ${line.slice(0, 180)}`); }
}
if (proc.status !== 0) {
  process.stderr.write(proc.stderr || '');
  process.stderr.write(proc.stdout || '');
  throw new Error(`go test exited ${proc.status}`);
}
function audit(eventsToAudit, expected) {
const observedRuns = eventsToAudit.filter((event) => event.Action === 'run' && event.Test).map((event) => event.Test);
const uniqueRuns = new Set(observedRuns);
const duplicates = observedRuns.filter((name, index) => observedRuns.indexOf(name) !== index);
const skips = eventsToAudit.filter((event) => event.Action === 'skip' && event.Test).map((event) => event.Test);
const failures = eventsToAudit.filter((event) => event.Action === 'fail').map((event) => event.Test || event.Package || '(unknown)');
const passed = eventsToAudit.filter((event) => event.Action === 'pass' && event.Test).map((event) => event.Test);
const passCounts = new Map(); for (const name of passed) passCounts.set(name, (passCounts.get(name) || 0) + 1);
const expectedSet = new Set(expected);
const unexpected = [...uniqueRuns].filter((name) => !expectedSet.has(name));
const unexpectedPass = [...passCounts.keys()].filter((name) => !expectedSet.has(name));
const missing = expected.filter((name) => !uniqueRuns.has(name));
const missingPass = expected.filter((name) => passCounts.get(name) !== 1);
requireMatch(duplicates.length === 0, `duplicate test inventory entries: ${duplicates.join(', ')}`);
requireMatch(skips.length === 0, `tests skipped: ${skips.join(', ')}`);
requireMatch(failures.length === 0, `tests failed: ${failures.join(', ')}`);
requireMatch(unexpected.length === 0, `unexpected tests ran: ${unexpected.join(', ')}`);
requireMatch(unexpectedPass.length === 0, `unexpected test PASS terminals: ${unexpectedPass.join(', ')}`);
requireMatch(missing.length === 0, `expected tests did not run: ${missing.join(', ')}`);
requireMatch(missingPass.length === 0, `expected tests lack exactly one PASS terminal: ${missingPass.join(', ')}`);
}
audit(events, suites);
for (const [label, malformed] of [
  ['duplicate-run', [{ Action: 'run', Test: 'T' }, { Action: 'run', Test: 'T' }, { Action: 'pass', Test: 'T' }]],
  ['duplicate-pass', [{ Action: 'run', Test: 'T' }, { Action: 'pass', Test: 'T' }, { Action: 'pass', Test: 'T' }]],
  ['missing-pass', [{ Action: 'run', Test: 'T' }]],
  ['skip', [{ Action: 'run', Test: 'T' }, { Action: 'skip', Test: 'T' }]],
  ['failure', [{ Action: 'run', Test: 'T' }, { Action: 'fail', Test: 'T' }]],
  ['unexpected', [{ Action: 'run', Test: 'T' }, { Action: 'pass', Test: 'T' }, { Action: 'pass', Test: 'U' }]],
]) { let rejected = false; try { audit(malformed, ['T']); } catch { rejected = true; } requireMatch(rejected, `parser oracle accepted ${label}`); }
console.log(success[mode]);
