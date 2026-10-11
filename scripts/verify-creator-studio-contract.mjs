import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const read = (path) => readFileSync(resolve(root, path), "utf8");
const domain = read("internal/domain/creator_studio.go");
const workloadDomain = read("internal/domain/workload.go");
const api = read("internal/api/creator_studio.go");
const artifactApi = read("internal/api/artifacts.go");
const routes = read("internal/api/http.go");
const manager = read("internal/workloads/manager.go");
const workloadSupport = read("internal/workloads/creator_studio.go");
const memoryStore = read("internal/store/memory.go");
const migration = read("migrations/0015_creator_studio_contract.sql");
const alignmentMigration = read("migrations/0016_creator_contract_alignment.sql");
const artifactStore = read("internal/artifacts/store.go");
const artifactTests = read("internal/artifacts/store_test.go");
const workloadTests = read("internal/workloads/creator_studio_test.go");
const tests = read("internal/api/creator_studio_test.go");
const managerTests = read("internal/workloads/manager_test.go");
const docs = read("docs/creator-studio-integration.md");

function requireAll(label, haystack, needles) {
  for (const needle of needles) {
    assert.ok(haystack.includes(needle), `${label} is missing ${JSON.stringify(needle)}`);
  }
}

requireAll("routes", routes, [
  'GET /api/v1/capabilities',
  'POST /api/v1/workloads',
  'POST /api/v1/workloads/batch',
  'GET /api/v1/batches/{batch_id}',
  'GET /api/v1/workloads/{id}',
  'POST /api/v1/workloads/{id}/cancel',
  'POST /api/v1/artifacts',
  'GET /api/v1/artifacts/{id}',
  'GET /api/v1/artifacts/{id}/content',
  'POST /api/v1/working-set',
  'PUT /api/v1/sessions/{session_id}/working-set/{phase_id}',
  'DELETE /api/v1/sessions/{session_id}/working-set/{phase_id}',
  'GET /api/v1/health',
]);

requireAll("immutable profile domain", domain, [
  'ProfileID', 'Version', 'Digest', 'Operations', 'Features',
  'CapabilityRevision', 'CapabilityDefinitionHash', 'Modality',
  'ExecutionLocality', 'InputSchema', 'OutputSchema',
  'AcceptedArtifactTypes', 'ProducedArtifactTypes',
  'CompatibilityOperations', 'RuntimeAvailability',
  'Adapter', '`json:"-" yaml:"adapter"`',
  'Model', '`json:"-" yaml:"model"`',
  'type WorkingSet struct', 'ReleasedAt',
]);
requireAll("workload semantics", workloadDomain, [
  'PlaneCreatorStudio', 'Operation', 'QualityClass', 'CapabilityRequirements',
  'ProfilePreferences', 'SessionID', 'BatchID', 'AffinityKey', 'Ordered',
  'Parallelism', 'Dependencies', 'LatencyClass', 'PriorityClass',
  'ContinuationRef', 'ProfileDigest',
  'CompatibilityToken', 'ArtifactProducer', 'ArtifactMedia',
  'ArtifactCompatibility',
]);

requireAll("API semantics", api + workloadSupport, [
  'decodeStrictCreator', 'DisallowUnknownFields',
  'CAPABILITY_UNAVAILABLE', 'PROFILE_REQUIRED',
  'CAPACITY_UNAVAILABLE', 'DEADLINE_EXPIRED', 'NO_FEASIBLE_ROUTE',
  'APPROVAL_REQUIRED', 'SOURCE_ARTIFACT_INCOMPATIBLE',
  'equivalent_or_better_only', 'preferred_only',
  'artifact://', 'continuation_ref',
  'interactive_user', 'review_blocking', 'production',
  'autonomous_content', 'background_calibration', 'maintenance',
  'queued', 'preparing', 'running', 'completed', 'failed', 'cancelled', 'blocked',
]);
requireAll("Artifact API", artifactApi + artifactStore, [
  'handleCreatorArtifactUpload', 'handleCreatorArtifactMetadata',
  'handleCreatorArtifactContent', 'PutWithMetadata', 'MaxArtifactBytes',
  'artifact://', 'media_metadata',
]);

const responseStart = api.indexOf("type creatorWorkloadResponse struct");
const responseEnd = api.indexOf("type creatorBlockedResponse struct");
assert.ok(responseStart >= 0 && responseEnd > responseStart, "public response struct could not be isolated");
const publicResponse = api.slice(responseStart, responseEnd).toLowerCase();
const forbiddenPublicFields = ["target_id", "accelerator_id", "endpoint", "vram", "gpu_id", "worker_address", "resident_models", "cache_path"];
assert.ok(forbiddenPublicFields.some((field) => (`fixture ${field}`).includes(field)), "negative-control fixture is broken");
for (const field of forbiddenPublicFields) {
  assert.ok(!publicResponse.includes(field), `Creator Studio public response leaks ${field}`);
}

requireAll("scheduler integration", manager + workloadSupport + memoryStore, [
  'creatorProfileForTarget', 'dependencyBlocker', 'creatorHintAdjustment',
  'ProfileTemporarilyBusy', 'targetHasProfile',
  'runtime profile identity already exists with a different digest',
  'DEPENDENCY_PENDING', 'DEPENDENCY_FAILED',
  'materializeCreatorOutputs', 'CapabilityDefinitionHash',
]);

requireAll("durability migration", migration, [
  'CREATE TABLE runtime_profiles',
  'PRIMARY KEY (profile_id, version)',
  'CREATE TABLE creator_working_sets',
  'WHERE released_at IS NULL',
]);
requireAll("alignment migration", alignmentMigration, [
  'capability_revision', 'capability_definition_hash', 'modality',
  'execution_locality', 'workflow', 'runtime_profiles_definition_hash_idx',
]);
const migrations = readdirSync(resolve(root, "migrations")).filter((name) => /^\d{4}_.+\.sql$/.test(name)).sort();
assert.equal(migrations.at(-1), "0020_accelerator_lease_cleanup.sql", "current source migration set does not end at 0020");
assert.equal(migrations.indexOf("0015_creator_studio_contract.sql"), 14, "creator contract migration moved unexpectedly");
assert.ok(migrations.includes("0016_creator_contract_alignment.sql"), "creator contract alignment migration is missing");

requireAll("Creator Studio tests", tests, [
  'TestCreatorStudioCapabilities',
  'TestCreatorStudioWorkloads',
  'hardware-neutral submission and no silent downgrade',
  'ordered batch dependencies and accepted creative output',
  'offline profile becomes runnable when capacity appears',
  'TestCreatorStudioWorkingSet',
  'TestCreatorAsyncLLMOutputs',
  'TestCreatorArtifactCompatibilityAndUpload',
  'TestCreatorBlockingReasons',
  'TestCreatorBatchPartialAcceptance',
]);
requireAll("workflow registration tests", workloadTests, [
  'TestRuntimeProfileRegistrationRequiresCallableWorkflowContract',
  'component or non-workflow profiles were advertised',
]);
requireAll("Artifact provenance tests", artifactTests, [
  'TestArtifactProvenanceRoundTrip', 'ProducerImplementation',
]);
requireAll("existing node-loss evidence", managerTests, [
  'TestNodeLossRequeuesRecoverableWorkAndIgnoresLateFencedResult',
  'TestNodeLossDoesNotDuplicateRecoverableWorkWhenBackendStopIsUnconfirmed',
]);

requireAll("integration documentation", docs, [
  '# Creator Studio integration',
  '## Responsibility boundary',
  '## LB execution implementation versus Studio Production Profile',
  '## Capability and implementation schema',
  '## Workload request schema',
  '## Status, result, and reason contract',
  '## Async LLM result retrieval',
  '## Artifact upload and provenance schema',
  '## Compatibility-token behavior',
  '## Batch and dependency semantics',
  '## Working-set semantics',
  '## Infrastructure retry versus creative retry',
  '## Acceptance evidence',
  'llm.inference', 'image.generate', 'video.generate_sequence',
  'audio.sfx_generate', 'training.lora', 'spatial.blender_previs', 'qa.vision',
  'The LB never selects an unlisted implementation',
  'it is not an unload, sleep, RAM, VRAM, worker, or GPU command',
]);

assert.ok(!/\b(?:TODO|TBD)\b/.test(docs), "integration documentation contains a placeholder");
console.log("Creator Studio contract verification passed");
