import { existsSync, mkdtempSync, readFileSync, cpSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cleanupWarnings = [];
const removeTempTree = (path) => {
  try {
    rmSync(path, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
  } catch (error) {
    cleanupWarnings.push({ path, error: String(error) });
  }
};
const owned = [
  "internal/runtime/driver.go", "internal/runtime/llamacpp/driver.go", "internal/runtime/llamacpp/driver_test.go",
  "internal/probe/probe.go", "internal/probe/probe_test.go", "internal/nodeagent/probe.go",
  "internal/nodeagent/commands.go", "internal/nodeagent/commands_test.go",
  "internal/nodeagent/llamacpp_checkpoint.go", "internal/nodeagent/llamacpp_checkpoint_test.go",
  "internal/nodeagent/config.go", "internal/nodeagent/config_test.go", "internal/nodeagent/agent.go",
  "internal/domain/workload.go",
  "internal/workloads/manager.go", "internal/workloads/manager_test.go", "internal/workloads/adapters.go",
  "internal/workloads/adapters_test.go", "internal/workloads/llamacpp_checkpoint.go", "internal/workloads/llamacpp_checkpoint_test.go",
  "internal/store/store.go", "internal/store/memory.go", "internal/store/postgres_workloads.go", "internal/store/llm_checkpoint_test.go",
  "migrations/0021_llm_checkpoints.sql",
  "internal/api/server.go", "internal/api/ws.go", "internal/api/node_commands.go", "internal/api/node_commands_test.go",
  "internal/api/config.go", "internal/api/config_test.go", "internal/api/workloads_http.go", "internal/api/workloads_http_test.go",
  "internal/api/native_checkpoint_e2e_test.go", "internal/wsproto/messages.go",
  "internal/safefile/nofollow.go", "internal/safefile/nofollow_unix.go", "internal/safefile/nofollow_windows.go",
  "internal/safefile/nofollow_other.go", "internal/safefile/nofollow_test.go", "internal/safefile/nofollow_unix_test.go",
  "go.mod", "go.sum", "cmd/controller/main.go", "cmd/controller/main_test.go", "configs/controller.yaml", "configs/node-agent.yaml",
  "scripts/verify-llm-checkpoint-preemption.mjs",
];
for (const file of owned) if (!existsSync(resolve(root, file))) throw new Error(`missing owned artifact: ${file}`);

const checks = [
  ["proof", "./internal/probe", "TestProductionCheckpointProofRequiresEveryBoundary"],
  ["proof-probe-only", "./internal/probe", "TestProductionCheckpointProofRejectsProbeOnlyWithAllBoundaries"],
  ["advertisement", "./internal/nodeagent", "TestApplyProductionCheckpointProofIsFailClosed"],
  ["runtime-path", "./internal/runtime/llamacpp", "TestSnapshotNameAndPathAreBounded"],
  ["checkpoint-order", "./internal/workloads", "TestProductionCheckpointOrderAndKVReuse"],
  ["save-fault-rollback", "./internal/workloads", "TestCheckpointDoesNotAdvertiseProbeOnlyAndPreservesOriginalOnSaveFault"],
  ["fault-matrix", "./internal/workloads", "TestCheckpointFaultMatrixEveryLifecycleBoundary"],
  ["production-e2e", "./internal/api", "TestHTTPAdapterNodeCommandCheckpointContinuationE2E"],
  ["native-normal-completion-live-slot", "./internal/api", "TestNativeCheckpointNormalCompletionReleasesDurableSlot"],
  ["native-resumed-disconnect-cleanup", "./internal/api", "TestNativeNodeCheckpointResumedDisconnectSignsCancelAndRelease"],
  ["bounded-silent-node-timeout", "./internal/api", "TestExecuteNodeCommandHonorsExpiryOnConnectedSilentNode"],
  ["snapshot-security", "./internal/workloads", "TestSnapshotStoreRejectsTraversalSymlinkAndQuota"],
  ["snapshot-quota-overflow", "./internal/workloads", "TestSnapshotStoreQuotaAccountingFailsClosedAtMaxInt64"],
  ["snapshot-quota-replacement-arithmetic", "./internal/workloads", "TestSnapshotStoreQuotaReplacementAccountingChecksBothDirections"],
  ["snapshot-overwrite-and-nofollow", "./internal/workloads", "TestSnapshotStorePutOverwriteGuardsAndSameOwnerIdempotence"],
  ["snapshot-delete-guards-and-restart", "./internal/workloads", "TestSnapshotStoreDeleteRejectsActiveReferenceAndPreservesRestartRestore"],
  ["snapshot-corrupt-external-metadata-fails-closed", "./internal/workloads", "TestSnapshotStoreCorruptExternalMetadataFailsClosedForScanOwnerAndReplacement"],
  ["stream-stitch", "./internal/workloads", "TestPartialOutputStitchAvoidsDuplicatePrefix"],
  ["command-envelope", "./internal/api", "TestValidateNodeCommandCheckpointEnvelope"],
  ["node-envelope", "./internal/nodeagent", "TestCheckpointCommandEnvelopeRejectsCrossOwner"],
  ["store-restart-cas", "./internal/store", "TestLLMCheckpointOperationRestartAndCAS"],
  ["store-slot-serialization", "./internal/store", "TestLLMCheckpointOperationSameSlotSerialization"],
  ["urgent-production-policy", "./internal/workloads", "TestCheckpointableVictimResumesAfterPriorityPreemption"],
  ["urgent-no-consent-policy", "./internal/workloads", "TestCheckpointableVictimWithoutInterruptionConsentCannotBePreempted"],
  ["urgent-locked-policy", "./internal/workloads", "TestLockedVictimCannotBePreemptedByPriority"],
  ["external-command-readiness-and-serialization", "./internal/nodeagent", "TestCommandBlockingDoesNotBlockHeartbeatReadiness"],
  ["manager-stop-before-release", "./internal/workloads", "TestCancellationOwnsLeaseUntilBackendStopAndWinsObserverRace"],
  ["native-compensation-exact-slot-fence", "./internal/workloads", "TestNativeCommandProcessorAuthorizesExactCompensationCancel"],
  ["manager-refresh-stop-fence", "./internal/workloads", "TestResumeRefreshRaceKeepsFenceUntilStopRetry"],
  ["manager-publication-stop-fence", "./internal/workloads", "TestResumePublicationCASFailureKeepsFenceUntilStopRetry"],
  ["manager-sharing-stop-fence", "./internal/workloads", "TestResumeSharingYieldFailureKeepsFenceUntilStopRetry"],
  ["resumed-cleanup-restart-custody", "./internal/workloads", "TestCheckpointRecoveryCrashBeforeFreshHandleJournalRetriesStopWithoutDuplicateRestore"],
  ["offline-cleanup-retry-renews-owned-fence", "./internal/workloads", "TestCheckpointCleanupRetryRetainsFenceUntilStopAndStoppedRestartIsIdempotent"],
  ["lease-renewal-across-adapters", "./internal/workloads", "TestLongStreamRenewsPhysicalLeaseAcrossAdapters"],
  ["owned-admission-scans-all-unresolved", "./internal/store", "TestAcceleratorLeaseAdmissionScansEveryUnresolvedCheckpointRow"],
  ["cas-compensation", "./internal/workloads", "TestCheckpointCASCompensationReacquiresAndResumes"],
  ["outer-cas-native-adoption", "./internal/workloads", "TestNativeHTTPCheckpointCASConflictAdoptsDurably"],
  ["outer-cas-crash-seam", "./internal/workloads", "TestCheckpointRecoveryCrashAfterPhysicalRestoreBeforeAdoption"],
  ["newcomer-cas-real-crash-seam", "./internal/workloads", "TestCheckpointPreemptionNewcomerCASCrashRecoversDurableRestore"],
  ["missing-intent-cancel-retry", "./internal/workloads", "TestCheckpointRestoreMissingIntentCancelFailureKeepsFreshFence"],
  ["compensation-cancel-retry", "./internal/workloads", "TestCheckpointCompensationCancelFailureRetriesFromFailedIntent"],
  ["restore-missing-intent-custody", "./internal/workloads", "TestCheckpointRestoreMissingIntentCreatesDurableCustody"],
  ["workload-revision-replay", "./internal/store", "TestLLMCheckpointOperationWorkloadRevisionReplayIdentity"],
  ["workload-revision-required-parity", "./internal/store", "TestLLMCheckpointOperationWorkloadRevisionValidationParity"],
  ["live-stream-prefix-and-done", "./internal/workloads", "TestLiveStreamStitchesRepeatedPrefixAndCanonicalizesDone"],
  ["live-stream-missing-done", "./internal/workloads", "TestLiveStreamMissingDoneIsVisibleFailure"],
  ["resumed-cleanup-errors-visible", "./internal/workloads", "TestReleaseCheckpointBindingDoesNotReleaseAfterCancelFailure"],
  ["stopped-before-release-restart-converges", "./internal/workloads", "TestCheckpointStoppedBoundaryRestartReleasesWithoutSecondCancel"],
  ["stopped-release-failure-retains-stopped", "./internal/workloads", "TestCheckpointStoppedBoundaryReleaseFailureRetainsStoppedAndConverges"],
  ["stopped-projection-never-rewrites-owned", "./internal/workloads", "TestCheckpointRecoveryStoppedProjectionNeverReAdoptsOrCancels"],
  ["stopped-release-failure-converges-exactly-once", "./internal/workloads", "TestCheckpointStoppedReleaseFailureIsIdempotentAcross100Retries"],
  ["public-stream-missing-done", "./internal/api", "TestNativeCheckpointPublicStreamMissingDoneFailsWithoutSuccess"],
  ["public-stream-duplicate-done", "./internal/api", "TestNativeCheckpointPublicStreamIgnoresDuplicateDoneAndPostDoneContent"],
  ["portable-nofollow-native", "./internal/safefile", "TestOpenReadOnlyNoFollowReadsTheOpenedDescriptor"],
  ["windows-reparse-same-handle", "./internal/safefile", "TestOpenReadOnlyNoFollowRejectsDeterministicWindowsReparseSwap"],
  ["node-quota-maxint64", "./internal/nodeagent", "TestCheckpointQuotaArithmeticAndMaxInt64OwnerAccountingFailClosed"],
  ["managed-proof-generation-binding", "./internal/nodeagent", "TestGenerateProductionCheckpointProofManagedLifecycleAndDiscovery"],
  ["proof-intermediate-failure-deferred-cleanup", "./internal/nodeagent", "TestGenerateProductionCheckpointProofCleansEveryIntermediateFailure"],
  ["durable-proof-expiry-rotation-and-immutable-binding", "./internal/nodeagent", "TestDurableCheckpointProofIssuanceAcceptsFreshExerciseAfterExpiry"],
  ["durable-proof-rebind-cas-and-advanced-fence", "./internal/nodeagent", "TestDurableCheckpointProofRebindRequiresPriorCASAndAdvancedFence"],
  ["discovery-rebinds-live-proof-across-runtime-facts-and-restart", "./internal/nodeagent", "TestDiscoveryRebindsLiveProofAcrossModelProfileContextAndRestart"],
  ["profile-switch-defers-proof-until-serialized-refresh", "./internal/nodeagent", "TestSignedRuntimeProfileSwitchDefersManagedProofUntilSerializedRefresh"],
  ["managed-proof-refresh-reentry", "./internal/nodeagent", "TestRefreshCapabilitiesManagedProofReentryIsBounded"],
  ["controller-proof-high-water-restart-refresh", "./internal/api", "TestCheckpointProofHighWaterSurvivesControllerRestartAndSessionRefresh"],
  ["controller-proof-journal-v2-parser", "./internal/api", "TestCheckpointProofJournalV2ParserRejectsCorruptionAndDowngrade"],
  ["uncertain-command-recovery", "./internal/api", "TestAdminNodeCommandUncertainReplayUsesQueryRecovery"],
  ["checkpoint-evidence-recovery", "./internal/workloads", "TestCheckpointRecoveryRejectsMismatchedNodeEvidence"],
];

const checkKeys = new Set();
for (const [name, pkg, test] of checks) {
  const key = `${pkg}:${test}`;
  if (checkKeys.has(key)) throw new Error(`duplicate exact Go-test invocation: ${key}`);
  checkKeys.add(key);
}

const results = [];
for (const [name, pkg, test] of checks) {
  const listed = spawnSync("go", ["test", pkg, "-list", "^Test"], { cwd: root, encoding: "utf8", timeout: 180000 });
  const listOutput = `${listed.stdout ?? ""}${listed.stderr ?? ""}`;
  if (listed.status !== 0 || !listOutput.split(/\r?\n/).includes(test)) {
  results.push({ name, package: pkg, test, behavioralInvocation: { package: pkg, test }, status: 1, evidence: false, output: `missing exact behavioral test: ${test}\n${listOutput}`.slice(-4000) });
    continue;
  }
  const run = spawnSync("go", ["test", pkg, "-run", `^${test}$`, "-count=1", "-v"], { cwd: root, encoding: "utf8", timeout: 180000 });
  const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
  results.push({ name, package: pkg, test, behavioralInvocation: { package: pkg, test }, status: run.status ?? 1, evidence: run.status === 0 && new RegExp(`--- PASS: ${test}`).test(output), output: output.slice(-4000) });
}

// The checked-in parser regression is intentionally kept in the repository's
// package tests, but this verifier also exercises the recursive-key and all
// three orphan-identity cases in a fresh package copy.  This prevents a
// shallow top-level fixture from certifying a parser whose structural walk is
// still permissive in arrays/objects nested below the envelope.
function runStrictProofJournalParserCheck() {
  const temp = mkdtempSync(join(tmpdir(), "llm-checkpoint-parser-"));
  try {
    cpSync(root, temp, { recursive: true, filter: (source) => !source.includes(`${join(root, ".git")}`) && !source.includes(`${join(root, ".cache")}`) && !source.includes(`${join(root, ".unlazy")}`) && !source.includes(`${join(root, "dist")}`) && !source.includes(`${join(root, "web")}`) && !source.includes(".tmp-") });
    const generatedPath = join(temp, "internal", "api", "repair21_verifier_strict_journal_test.go");
    const generated = String.raw`package api

import "testing"

func TestVerifierRepair21StrictProofJournal(t *testing.T) {
	if err := rejectDuplicateJSONKeys([]byte("{\"outer\":[{\"inner\":1,\"inner\":2}] }")); err == nil {
		t.Fatal("recursive duplicate JSON key was accepted")
	}
	validV2 := "{\"version\":\"llm-checkpoint-proof-journal-v2\",\"nonces\":{\"node-runtime|nonce\":\"digest\"},\"issued_at\":{\"node-runtime|nonce\":\"2026-01-02T03:04:05Z\"},\"high_water\":{\"node|runtime\":4},\"fences\":{\"node|runtime\":8},\"generations\":{\"node|runtime\":3}}"
	cases := []struct {
		name string
		body string
		ok bool
	}{
		{"orphan high-water identity", "{\"version\":\"llm-checkpoint-proof-journal-v2\",\"nonces\":{},\"issued_at\":{},\"high_water\":{\"node|runtime\":4},\"fences\":{},\"generations\":{}}", false},
		{"orphan fence identity", "{\"version\":\"llm-checkpoint-proof-journal-v2\",\"nonces\":{},\"issued_at\":{},\"high_water\":{},\"fences\":{\"node|runtime\":8},\"generations\":{}}", false},
		{"orphan generation identity", "{\"version\":\"llm-checkpoint-proof-journal-v2\",\"nonces\":{},\"issued_at\":{},\"high_water\":{},\"fences\":{},\"generations\":{\"node|runtime\":3}}", false},
		{"valid v2", validV2, true},
		{"valid explicit legacy", "{\"node-runtime|legacy\":\"digest\"}", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newCheckpointProofTestServer(&Config{}, "pppppppppppppppppppppppppppppppp", "")
			err := server.loadCheckpointProofNonceBody([]byte(tc.body))
			if tc.ok && err != nil {
				t.Fatalf("valid journal rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("invalid journal was accepted")
			}
		})
	}
}
`;
    writeFileSync(generatedPath, generated);
    const run = spawnSync("go", ["test", "./internal/api", "-run", "^TestVerifierRepair21StrictProofJournal$", "-count=1", "-v"], { cwd: temp, encoding: "utf8", timeout: 180000 });
    const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
    const passed = run.status === 0 && /--- PASS: TestVerifierRepair21StrictProofJournal/.test(output);
    return { status: passed ? 0 : 1, evidence: passed, output: output.slice(-5000) };
  } finally {
    removeTempTree(temp);
  }
}

const strictProofJournal = runStrictProofJournalParserCheck();
results.push({ name: "strict-proof-journal-parser-recursive-and-orphan-identities", package: "./internal/api", test: "TestVerifierRepair21StrictProofJournal", behavioralInvocation: { package: "./internal/api", test: "TestVerifierRepair21StrictProofJournal" }, status: strictProofJournal.status, evidence: strictProofJournal.evidence, output: strictProofJournal.output });

const freshStoppedCleanupTest = String.raw`package workloads

import (
	"context"
	"errors"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func TestVerifierRepair21FreshStoppedCleanup(t *testing.T) {
	ctx := context.Background()
	backing := store.NewMemoryStore()
	adapter := &checkpointRecoveryCrashAdapter{}
	target := Target{ID: "repair21-fresh-target", NodeID: "repair21-fresh-node", Adapter: "preempt", AcceleratorID: "repair21-fresh-gpu", RuntimeIdentity: "runtime", Enabled: true}
	mgr := NewManager(quietLogger(), backing, time.Minute)
	mgr.RegisterAdapter(adapter)
	mgr.RegisterTarget(target)
	lease, acquired, err := backing.AcquireAcceleratorLease(ctx, target.AcceleratorID, "repair21-fresh-workload", time.Minute)
	if err != nil || !acquired || lease == nil {
		t.Fatalf("acquire fresh stopped lease: lease=%+v acquired=%v err=%v", lease, acquired, err)
	}
	operation := &store.LLMCheckpointOperation{
		ID: "repair21-fresh-operation", IdempotencyKey: "repair21-fresh-operation", OwnerID: "owner", WorkloadID: lease.WorkloadID,
		NodeID: target.NodeID, AcceleratorID: target.AcceleratorID, TargetID: target.ID, Model: "model", ModelFingerprint: "model",
		RuntimeIdentity: target.RuntimeIdentity, ProfileFingerprint: "profile", ContextFingerprint: "ctx:4096", ConversationID: "repair21-fresh-conversation",
		WorkloadRevision: 1, SnapshotName: "repair21-fresh.kv", SlotID: 0, Generation: 7, Fence: uint64(lease.FencingToken), Phase: "restore_planned",
		PhaseOrdinal: checkpointRecoveryOrdinal("restore_planned"), CleanupOperationID: "repair21-fresh-operation", CleanupSlotID: 0,
		CleanupConversationID: "repair21-fresh-conversation", CleanupState: "stopped", CleanupHandle: &domain.ExecutionHandle{ExternalID: "repair21-fresh-handle"},
		CleanupTargetID: target.ID, CleanupNodeID: target.NodeID, CleanupAcceleratorID: target.AcceleratorID, CleanupGeneration: 7, CleanupFence: uint64(lease.FencingToken),
	}
	if _, inserted, err := backing.CreateLLMCheckpointOperation(ctx, operation); err != nil || !inserted {
		t.Fatalf("create fresh stopped operation: inserted=%v err=%v", inserted, err)
	}
	if err := mgr.cleanupFreshCheckpointRestore(ctx, adapter, target, operation.CleanupHandle, lease, operation.ID); err != nil {
		t.Fatalf("fresh stopped cleanup did not converge: %v", err)
	}
	if len(adapter.cancelled) != 0 {
		t.Fatalf("fresh stopped cleanup issued a duplicate cancel: %v", adapter.cancelled)
	}
	confirmed, err := backing.GetLLMCheckpointOperation(ctx, operation.ID)
	if err != nil || confirmed.CleanupState != "confirmed" {
		t.Fatalf("fresh stopped cleanup did not persist confirmed release: op=%+v err=%v", confirmed, err)
	}
	if _, err := backing.GetAcceleratorLease(ctx, target.AcceleratorID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("fresh stopped cleanup retained exact lease: err=%v", err)
	}
}
`;

function runFreshStoppedCleanupCheck() {
  const temp = mkdtempSync(join(tmpdir(), "llm-checkpoint-fresh-cleanup-"));
  try {
    cpSync(root, temp, { recursive: true, filter: (source) => !source.includes(`${join(root, ".git")}`) && !source.includes(`${join(root, ".cache")}`) && !source.includes(`${join(root, ".unlazy")}`) && !source.includes(`${join(root, "dist")}`) && !source.includes(`${join(root, "web")}`) && !source.includes(".tmp-") });
    const generatedPath = join(temp, "internal", "workloads", "repair21_verifier_fresh_cleanup_test.go");
    writeFileSync(generatedPath, freshStoppedCleanupTest);
    const run = spawnSync("go", ["test", "./internal/workloads", "-run", "^TestVerifierRepair21FreshStoppedCleanup$", "-count=1", "-v"], { cwd: temp, encoding: "utf8", timeout: 180000 });
    const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
    const passed = run.status === 0 && /--- PASS: TestVerifierRepair21FreshStoppedCleanup/.test(output);
    return { status: passed ? 0 : 1, evidence: passed, output: output.slice(-5000) };
  } finally {
    removeTempTree(temp);
  }
}

const freshStoppedCleanup = runFreshStoppedCleanupCheck();
results.push({ name: "fresh-stopped-cleanup-skips-cancel-and-releases", package: "./internal/workloads", test: "TestVerifierRepair21FreshStoppedCleanup", behavioralInvocation: { package: "./internal/workloads", test: "TestVerifierRepair21FreshStoppedCleanup" }, status: freshStoppedCleanup.status, evidence: freshStoppedCleanup.evidence, output: freshStoppedCleanup.output });

// The checked-in controller template is the operator-facing migration oracle.
// Keep the executable deployment guidance aligned with the owned 0021 schema;
// otherwise a fresh controller can be configured against a pre-checkpoint DB.
const controllerTemplate = readFileSync(resolve(root, "configs/controller.yaml"), "utf8");
const migrationGuidance = /ordered migrations\/0001\.\.0021[\s\S]*0021_llm_checkpoints\.sql/.test(controllerTemplate);
results.push({
  name: "controller-config-migration-0021-guidance",
  status: migrationGuidance ? 0 : 1,
  evidence: migrationGuidance,
  output: migrationGuidance ? "controller config documents migration 0021" : "controller config omits migration 0021 guidance",
});

function runPortabilityCheck() {
  const temp = mkdtempSync(join(tmpdir(), "llm-checkpoint-portability-"));
  const targets = [
    ["linux", "amd64"], ["linux", "arm64"], ["darwin", "amd64"],
    ["darwin", "arm64"], ["freebsd", "amd64"], ["windows", "amd64"],
  ];
  const outcomes = [];
  try {
    for (const [goos, goarch] of targets) {
      const env = { ...process.env, GOOS: goos, GOARCH: goarch, CGO_ENABLED: "0" };
      const suffix = goos === "windows" ? ".exe" : "";
      const testOut = join(temp, `safefile-${goos}-${goarch}.test${suffix}`);
      const test = spawnSync("go", ["test", "-c", "-o", testOut, "./internal/safefile"], { cwd: root, env, encoding: "utf8", timeout: 180000 });
      const nodeagentTestOut = join(temp, `nodeagent-${goos}-${goarch}.test${suffix}`);
      const nodeagentTest = spawnSync("go", ["test", "-c", "-o", nodeagentTestOut, "./internal/nodeagent"], { cwd: root, env, encoding: "utf8", timeout: 180000 });
      const controllerOut = join(temp, `controller-${goos}-${goarch}${suffix}`);
      const controller = spawnSync("go", ["build", "-o", controllerOut, "./cmd/controller"], { cwd: root, env, encoding: "utf8", timeout: 180000 });
      const nodeOut = join(temp, `node-agent-${goos}-${goarch}${suffix}`);
      const node = spawnSync("go", ["build", "-o", nodeOut, "./cmd/node-agent"], { cwd: root, env, encoding: "utf8", timeout: 180000 });
      const output = [test, nodeagentTest, controller, node].map((run) => `${run.stdout ?? ""}${run.stderr ?? ""}`).join("\n");
      outcomes.push({ target: `${goos}/${goarch}`, status: test.status === 0 && nodeagentTest.status === 0 && controller.status === 0 && node.status === 0 ? 0 : 1, output: output.slice(-3000) });
    }
  } finally {
    removeTempTree(temp);
  }
  const passed = outcomes.every((outcome) => outcome.status === 0);
  return { status: passed ? 0 : 1, evidence: passed, outcomes };
}

const portability = runPortabilityCheck();
results.push({ name: "portable-nofollow", status: portability.status, evidence: portability.evidence, output: JSON.stringify(portability) });

function runMutationCheck() {
  const mutations = [
    {
      name: "stitch",
      file: ["internal", "workloads", "llamacpp_checkpoint.go"],
      needle: "if len(resumed) >= len(p.Prefix) && string(resumed[:len(p.Prefix)]) == string(p.Prefix) {",
      replacement: "if false && len(resumed) >= len(p.Prefix) && string(resumed[:len(p.Prefix)]) == string(p.Prefix) {",
      pkg: "./internal/workloads", test: "TestPartialOutputStitchAvoidsDuplicatePrefix",
    },
    {
      name: "proof-completeness",
      file: ["internal", "runtime", "driver.go"],
      needle: "return p.Verified && !p.ProbeOnly && p.SlotAssignment &&",
      replacement: "return false && p.Verified && !p.ProbeOnly && p.SlotAssignment &&",
      pkg: "./internal/probe", test: "TestProductionCheckpointProofRequiresEveryBoundary",
    },
    {
      name: "durable-proof-binding-must-reject-immutable-mismatch",
      file: ["internal", "nodeagent", "llamacpp_checkpoint.go"],
      needle: "} else if priorBinding != \"\" && priorBinding != binding {",
      replacement: "} else if false && priorBinding != \"\" && priorBinding != binding {",
      pkg: "./internal/nodeagent", test: "TestDurableCheckpointProofIssuanceAcceptsFreshExerciseAfterExpiry",
    },
    {
      name: "discovery-must-compare-cached-proof-to-current-runtime-facts",
      file: ["internal", "nodeagent", "agent.go"],
      needle: "bindingMatches := checkpointProofMatchesAdvertisement(persisted, cfg, server, advertisement)",
      replacement: "bindingMatches := true",
      pkg: "./internal/nodeagent", test: "TestDiscoveryRebindsLiveProofAcrossModelProfileContextAndRestart",
    },
    {
      name: "proof-rebind-must-compare-expected-prior-binding-cas",
      file: ["internal", "nodeagent", "llamacpp_checkpoint.go"],
      needle: "if priorBinding == \"\" || priorBinding != checkpointProofBindingDigest(*expectedPrior) {",
      replacement: "if false && (priorBinding == \"\" || priorBinding != checkpointProofBindingDigest(*expectedPrior)) {",
      pkg: "./internal/nodeagent", test: "TestDurableCheckpointProofRebindRequiresPriorCASAndAdvancedFence",
    },
    {
      name: "proof-rebind-must-reject-reused-fence",
      file: ["internal", "nodeagent", "llamacpp_checkpoint.go"],
      edits: [
        {
          needle: "if proof.NewFence <= prior.NewFence {",
          replacement: "if false && proof.NewFence <= prior.NewFence {",
        },
        {
          needle: "if proof.NewFence < prior || expectedPrior != nil && proof.NewFence <= prior {",
          replacement: "if proof.NewFence < prior {",
        },
        {
          needle: "if proof.NewFence == prior && state.Exercises[key] != \"\" && state.Exercises[key] != exercise {",
          replacement: "if false && proof.NewFence == prior && state.Exercises[key] != \"\" && state.Exercises[key] != exercise {",
        },
        {
          needle: "if expectedPrior != nil && proof.NewFence <= expectedPrior.NewFence {",
          replacement: "if false && expectedPrior != nil && proof.NewFence <= expectedPrior.NewFence {",
        },
      ],
      pkg: "./internal/nodeagent", test: "TestDurableCheckpointProofRebindRequiresPriorCASAndAdvancedFence",
    },
    {
      name: "discovery-must-converge-after-issuance-commit-before-proof-persist",
      file: ["internal", "nodeagent", "agent.go"],
      needle: "if rotateErr != nil {\n\t\t\t\t\t\t\t// The proof file can lag a durable issuance commit after a\n\t\t\t\t\t\t\t// crash. Strict rotation converges only if the sidecar already\n\t\t\t\t\t\t\t// holds this freshly observed binding; it still enforces the\n\t\t\t\t\t\t\t// committed fence, generation, exercise, and epoch high-waters.\n\t\t\t\t\t\t\trotated, rotateErr = RotateCheckpointProofNonceDurable(issuancePath, proof, cfg.CommandSigningSecret)\n\t\t\t\t\t\t}",
      replacement: "if false && rotateErr != nil {\n\t\t\t\t\t\t\t// The proof file can lag a durable issuance commit after a\n\t\t\t\t\t\t\t// crash. Strict rotation converges only if the sidecar already\n\t\t\t\t\t\t\t// holds this freshly observed binding; it still enforces the\n\t\t\t\t\t\t\t// committed fence, generation, exercise, and epoch high-waters.\n\t\t\t\t\t\t\trotated, rotateErr = RotateCheckpointProofNonceDurable(issuancePath, proof, cfg.CommandSigningSecret)\n\t\t\t\t\t\t}",
      pkg: "./internal/nodeagent", test: "TestDiscoveryRebindsLiveProofAcrossModelProfileContextAndRestart",
    },
    {
      name: "durable-proof-rotation-must-advance-epoch",
      file: ["internal", "nodeagent", "llamacpp_checkpoint.go"],
      needle: "state.Epoch++",
      replacement: "state.Epoch += 0",
      pkg: "./internal/nodeagent", test: "TestDurableCheckpointProofIssuanceAcceptsFreshExerciseAfterExpiry",
    },
    {
      name: "managed-refresh-must-pass-reentrant-processor-context",
      file: ["internal", "nodeagent", "commands.go"],
      needle: "commandCtxBase = context.WithValue(ctx, commandProcessorContextKey{}, p)",
      replacement: "commandCtxBase = ctx",
      pkg: "./internal/nodeagent", test: "TestRefreshCapabilitiesManagedProofReentryIsBounded",
    },
    {
      name: "recovery-readiness",
      file: ["internal", "workloads", "llamacpp_checkpoint.go"],
      needle: "rows, err := c.Operations.ListLLMCheckpointOperations(ctx, \"\")",
      replacement: "rows := []*store.LLMCheckpointOperation{}; err := error(nil)",
      pkg: "./internal/workloads", test: "TestCheckpointRecoveryKeepsReadyFalseOnUnresolvedOperation",
    },
    {
      name: "cas-compensation-noop",
      file: ["internal", "workloads", "manager.go"],
      needle: "if victim == nil || victim.Plan == nil || checkpoint == \"\" || oldLease == nil {",
      replacement: "if true {",
      pkg: "./internal/workloads", test: "TestCheckpointCASCompensationReacquiresAndResumes",
    },
    {
      name: "stop-before-release-cancel-guard-bypass",
      file: ["internal", "workloads", "adapters.go"],
      needle: "if _, err := control(cleanupCtx, nodeID, \"checkpoint_cancel\", args, args[\"idempotency_key\"].(string)); err != nil {",
      replacement: "if _, err := control(cleanupCtx, nodeID, \"checkpoint_cancel\", args, args[\"idempotency_key\"].(string)); false {",
      pkg: "./internal/workloads", test: "TestReleaseCheckpointBindingDoesNotReleaseAfterCancelFailure",
    },
    {
      name: "sharing-yield-failure-must-retain-fence",
      file: ["internal", "workloads", "manager.go"],
      needle: "if stopErr != nil {\n\t\t\t\t\tcleanupDisposition = \"failure\"\n\t\t\t\t\tcleanupMessage = fmt.Sprintf(\"adaptive sharing rollback: %s; yield failed: %v; backend stop is unconfirmed: %v\", reason, yieldErr, stopErr)",
      replacement: "if false && stopErr != nil {\n\t\t\t\t\tcleanupDisposition = \"failure\"\n\t\t\t\t\tcleanupMessage = fmt.Sprintf(\"adaptive sharing rollback: %s; yield failed: %v; backend stop is unconfirmed: %v\", reason, yieldErr, stopErr)",
      pkg: "./internal/workloads", test: "TestResumeSharingYieldFailureKeepsFenceUntilStopRetry",
    },
    {
      name: "managed-proof-must-clear-readiness-before-unlocked-work",
      file: ["internal", "nodeagent", "commands.go"],
      needle: "p.beginExternalWork()",
      replacement: "// mutated missing beginExternalWork()",
      pkg: "./internal/nodeagent", test: "TestRefreshCapabilitiesManagedProofReentryIsBounded",
    },
    {
      name: "normal-success-does-not-cancel-resumed-stream",
      file: ["internal", "workloads", "adapters.go"],
      needle: "if binding.Resumed && cancelResumed {",
      replacement: "if binding.Resumed && (cancelResumed || !cancelResumed) {",
      expectedCount: 2,
      pkg: "./internal/api", test: "TestHTTPAdapterNodeCommandCheckpointContinuationE2E",
    },
    {
      name: "outer-cas-must-persist-recovery-intent",
      file: ["internal", "workloads", "manager.go"],
      needle: "intent, intentErr := m.persistCheckpointRecoveryIntent(context.WithoutCancel(ctx), victim, victimTarget, checkpoint, transition.ID, checkpointLease)",
      replacement: "intent, intentErr := (*store.LLMCheckpointOperation)(nil), errors.New(\"mutated missing outer recovery intent\")",
      expectedCount: 2,
      pkg: "./internal/workloads", test: "TestNativeHTTPCheckpointCASConflictAdoptsDurably",
    },
    {
      name: "newcomer-cas-must-persist-before-restore",
      file: ["internal", "workloads", "manager.go"],
      needle: "// recovery root; a crash after physical restore can otherwise leave a\n\t\t\t// live handle with no authoritative owner.\n\t\t\tintent, intentErr := m.persistCheckpointRecoveryIntent(context.WithoutCancel(ctx), victim, victimTarget, checkpoint, transition.ID, checkpointLease)",
      replacement: "// recovery root; a crash after physical restore can otherwise leave a\n\t\t\t// live handle with no authoritative owner.\n\t\t\tintent, intentErr := (*store.LLMCheckpointOperation)(nil), errors.New(\"mutated missing newcomer recovery intent\")",
      pkg: "./internal/workloads", test: "TestCheckpointPreemptionNewcomerCASCrashRecoversDurableRestore",
    },
    {
      name: "normal-started-to-stopped-edge",
      file: ["internal", "store", "store.go"],
      needle: '"started": {"paused": {}, "stopped": {}, "failed": {}, "cancelled": {}},',
      replacement: '"started": {"paused": {}, "failed": {}, "cancelled": {}},',
      pkg: "./internal/api", test: "TestNativeCheckpointNormalCompletionReleasesDurableSlot",
    },
    {
      name: "stopped-projection-must-not-rewrite-owned-running-workload",
      file: ["internal", "workloads", "manager.go"],
      needle: "\t\t\t\t\tif requeueErr := m.requeueCheckpointVictimAfterCleanup(context.WithoutCancel(ctx), w.Request.ID, op.TargetID, op.SnapshotName); requeueErr != nil {",
      replacement: "\t\t\t\t\tif requeueErr := error(nil); requeueErr != nil {",
      pkg: "./internal/workloads", test: "TestCheckpointRecoveryStoppedProjectionNeverReAdoptsOrCancels",
    },
    {
      name: "fresh-stopped-cleanup-must-skip-cancel",
      file: ["internal", "workloads", "manager.go"],
      needle: "if cleanupOp == nil || cleanupOp.CleanupState != \"stopped\" {",
      replacement: "if cleanupOp == nil || true {",
      pkg: "./internal/workloads", test: "TestVerifierRepair21FreshStoppedCleanup",
      generatedTest: { path: ["internal", "workloads", "repair21_verifier_fresh_cleanup_test.go"], source: freshStoppedCleanupTest },
    },
    {
      name: "release-failure-must-retain-durable-stopped-state",
      file: ["internal", "workloads", "manager.go"],
      needle: "if stopped, markErr := m.recordCheckpointCleanupState(ctx, op.ID, \"stopped\", handle, target, lease, op.CleanupTerminalDisposition, pendingMessage); markErr == nil && stopped != nil {",
      replacement: "if stopped, markErr := m.recordCheckpointCleanupState(ctx, op.ID, \"failed\", handle, target, lease, op.CleanupTerminalDisposition, pendingMessage); markErr == nil && stopped != nil {",
      pkg: "./internal/workloads", test: "TestCheckpointStoppedBoundaryReleaseFailureRetainsStoppedAndConverges",
    },
    {
      name: "bounded-timeout-must-honor-expiry",
      file: ["internal", "api", "node_commands.go"],
      needle: "if !current.ExpiresAt.IsZero() && !time.Now().UTC().Before(current.ExpiresAt) {\n\t\t\t// A connected-but-silent node is still an ambiguous side-effect\n\t\t\t// boundary.",
      replacement: "if false && !current.ExpiresAt.IsZero() && !time.Now().UTC().Before(current.ExpiresAt) {\n\t\t\t// A connected-but-silent node is still an ambiguous side-effect\n\t\t\t// boundary.",
      pkg: "./internal/api", test: "TestExecuteNodeCommandHonorsExpiryOnConnectedSilentNode",
    },
    {
      name: "crash-seam-must-record-fresh-handle",
      file: ["internal", "workloads", "manager.go"],
      needle: 'op.RecoveryState = "restored"',
      replacement: 'op.RecoveryState = "pending"',
      pkg: "./internal/workloads", test: "TestCheckpointRecoveryCrashAfterPhysicalRestoreBeforeAdoption",
    },
    {
      name: "snapshot-put-must-not-overwrite-active-bundle",
      file: ["internal", "workloads", "llamacpp_checkpoint.go"],
      needle: "if existing.CommandID == metadata.CommandID && existing.WorkloadRevision == metadata.WorkloadRevision && existing.Identity == metadata.Identity && existing.Fence == metadata.Fence && existing.OldFence == metadata.OldFence && existing.NewFence == metadata.NewFence && snapshotPayloadMatches(data, metadata, existing) {",
      replacement: "if false && existing.CommandID == metadata.CommandID && existing.WorkloadRevision == metadata.WorkloadRevision && existing.Identity == metadata.Identity && existing.Fence == metadata.Fence && existing.OldFence == metadata.OldFence && existing.NewFence == metadata.NewFence && snapshotPayloadMatches(data, metadata, existing) {",
      pkg: "./internal/workloads", test: "TestSnapshotStorePutOverwriteGuardsAndSameOwnerIdempotence",
    },
    {
      name: "quota-addition-must-check-int64-overflow",
      file: ["internal", "workloads", "llamacpp_checkpoint.go"],
      needle: "if right > math.MaxInt64-left {\n\t\treturn 0, fmt.Errorf(\"snapshot quota accounting overflow\")\n\t}",
      replacement: "if false && right > math.MaxInt64-left {\n\t\treturn 0, fmt.Errorf(\"snapshot quota accounting overflow\")\n\t}",
      pkg: "./internal/workloads", test: "TestSnapshotStoreQuotaAccountingFailsClosedAtMaxInt64",
    },
    {
      name: "quota-replacement-must-check-underflow",
      file: ["internal", "workloads", "llamacpp_checkpoint.go"],
      needle: "if left < 0 || right < 0 || right > left {\n\t\treturn 0, fmt.Errorf(\"snapshot quota accounting underflow\")\n\t}",
      replacement: "if false && (left < 0 || right < 0 || right > left) {\n\t\treturn 0, fmt.Errorf(\"snapshot quota accounting underflow\")\n\t}",
      pkg: "./internal/workloads", test: "TestSnapshotStoreQuotaReplacementAccountingChecksBothDirections",
    },
    {
      name: "node-quota-addition-must-check-maxint64",
      file: ["internal", "nodeagent", "llamacpp_checkpoint.go"],
      needle: "if right > math.MaxInt64-left {\n\t\treturn 0, fmt.Errorf(\"checkpoint quota accounting overflow\")\n\t}",
      replacement: "if false && right > math.MaxInt64-left {\n\t\treturn 0, fmt.Errorf(\"checkpoint quota accounting overflow\")\n\t}",
      pkg: "./internal/nodeagent", test: "TestCheckpointQuotaArithmeticAndMaxInt64OwnerAccountingFailClosed",
    },
    {
      name: "node-quota-replacement-must-check-underflow",
      file: ["internal", "nodeagent", "llamacpp_checkpoint.go"],
      needle: "withoutReplacement, err := checkedCheckpointSub(used, replaced)\n\tif err != nil {\n\t\treturn 0, err\n\t}\n\treturn checkedCheckpointAdd(withoutReplacement, incoming)",
      replacement: "withoutReplacement := used - replaced\n\treturn withoutReplacement + incoming, nil",
      pkg: "./internal/nodeagent", test: "TestCheckpointQuotaArithmeticAndMaxInt64OwnerAccountingFailClosed",
    },
    {
      name: "managed-proof-must-bind-exercised-generation",
      file: ["internal", "nodeagent", "llamacpp_checkpoint.go"],
      needle: "if exercised, ok := driver.(interface{ CheckpointGeneration() uint64 }); ok && exercised.CheckpointGeneration() != generation {",
      replacement: "if exercised, ok := driver.(interface{ CheckpointGeneration() uint64 }); ok && false && exercised.CheckpointGeneration() != generation {",
      pkg: "./internal/nodeagent", test: "TestGenerateProductionCheckpointProofManagedLifecycleAndDiscovery",
    },
    {
      name: "controller-proof-sidecar-load-must-not-be-ignored",
      file: ["internal", "api", "server.go"],
      needle: "return s.loadCheckpointProofNonceBody(body)",
      replacement: "return nil",
      pkg: "./internal/api", test: "TestCheckpointProofHighWaterSurvivesControllerRestartAndSessionRefresh",
    },
    {
      name: "proof-journal-must-reject-partial-v2",
      file: ["internal", "api", "server.go"],
      needle: "return fmt.Errorf(\"checkpoint proof replay journal v2 is missing %s\", key)",
      replacement: "return nil",
      pkg: "./internal/api", test: "TestCheckpointProofJournalV2ParserRejectsCorruptionAndDowngrade",
    },
    {
      name: "proof-journal-must-reject-high-water-downgrade",
      file: ["internal", "api", "server.go"],
      needle: "return fmt.Errorf(\"checkpoint proof replay journal high-water rollback for %q\", key)",
      replacement: "return nil",
      pkg: "./internal/api", test: "TestCheckpointProofJournalV2ParserRejectsCorruptionAndDowngrade",
    },
    {
      name: "proof-journal-must-reject-all-orphan-identities",
      file: ["internal", "api", "server.go"],
      edits: [
        {
          needle: "if _, ok := envelope.Fences[key]; !ok {",
          replacement: "if false {",
          expectedCount: 2,
        },
        {
          needle: "if _, ok := envelope.Generations[key]; !ok {",
          replacement: "if false {",
          expectedCount: 2,
        },
        {
          needle: "if _, ok := envelope.HighWater[key]; !ok {",
          replacement: "if false {",
          expectedCount: 2,
        },
      ],
      pkg: "./internal/api", test: "TestCheckpointProofJournalV2ParserRejectsCorruptionAndDowngrade",
    },
    {
      name: "proof-journal-must-reject-recursive-duplicate-keys",
      file: ["internal", "api", "server.go"],
      needle: "if _, exists := seen[key]; exists {",
      replacement: "if false {",
      pkg: "./internal/api", test: "TestCheckpointProofJournalV2ParserRejectsCorruptionAndDowngrade",
    },
    {
      name: "live-stream-must-stitch-before-emit",
      file: ["internal", "workloads", "adapters.go"],
      needle: "out, terminal := state.process(block)",
      replacement: "out, terminal := append([]byte(nil), block...), sseBlockHasDone(block)",
      pkg: "./internal/workloads", test: "TestLiveStreamStitchesRepeatedPrefixAndCanonicalizesDone",
    },
    {
      name: "live-stream-must-require-done",
      file: ["internal", "workloads", "adapters.go"],
      needle: "if state.done {\n\t\t\t\treturn true, nil\n\t\t\t}\n\t\t\treturn false, fmt.Errorf(\"stream ended before terminal data: [DONE]\")",
      replacement: "if state.done {\n\t\t\t\treturn true, nil\n\t\t\t}\n\t\t\treturn true, nil",
      pkg: "./internal/workloads", test: "TestLiveStreamMissingDoneIsVisibleFailure",
    },
    {
      name: "resumed-public-stream-must-require-done",
      file: ["internal", "workloads", "adapters.go"],
      needle: "if state.done {\n\t\t\t\treturn true, nil\n\t\t\t}\n\t\t\treturn false, fmt.Errorf(\"stream ended before terminal data: [DONE]\")",
      replacement: "if state.done {\n\t\t\t\treturn true, nil\n\t\t\t}\n\t\t\treturn true, nil",
      pkg: "./internal/api", test: "TestNativeCheckpointPublicStreamMissingDoneFailsWithoutSuccess",
    },
    {
      name: "resumed-public-stream-must-ignore-post-done",
      file: ["internal", "workloads", "adapters.go"],
      edits: [
        {
          needle: "if s == nil || s.done {\n\t\treturn nil, true\n\t}",
          replacement: "if s == nil {\n\t\treturn nil, true\n\t}",
        },
        {
          needle: "if err != nil || terminal {\n\t\t\t\t\treturn terminal, err\n\t\t\t\t}",
          replacement: "if err != nil {\n\t\t\t\t\treturn terminal, err\n\t\t\t\t}",
          expectedCount: 2,
        },
      ],
      pkg: "./internal/api", test: "TestNativeCheckpointPublicStreamIgnoresDuplicateDoneAndPostDoneContent",
    },
    {
      name: "workload-revision-must-be-nonzero",
      file: ["internal", "store", "store.go"],
      needle: "if op.WorkloadRevision == 0 {\n\t\treturn errors.New(\"checkpoint operation workload revision is required\")\n\t}",
      replacement: "if false && op.WorkloadRevision == 0 {\n\t\treturn errors.New(\"checkpoint operation workload revision is required\")\n\t}",
      pkg: "./internal/store", test: "TestLLMCheckpointOperationWorkloadRevisionValidationParity",
    },
    {
      name: "windows-nofollow-must-open-reparse-point",
      file: ["internal", "safefile", "nofollow_windows.go"],
      needle: "windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS",
      replacement: "windows.FILE_FLAG_BACKUP_SEMANTICS",
      pkg: "./internal/safefile", test: "TestOpenReadOnlyNoFollowRejectsDeterministicWindowsReparseSwap",
    },
    {
      name: "native-compensation-must-bind-physical-slot",
      file: ["internal", "nodeagent", "commands.go"],
      needle: "if compensationOf == \"\" || !exists || state.OwnerID != owner || state.WorkloadID != workload || state.TargetID != targetID || state.AcceleratorID != acceleratorID || state.Generation != generation || state.Fence != fence || state.SlotID != requestedSlot || state.Phase < checkpointPhase(\"resume\") {",
      replacement: "if compensationOf == \"\" || !exists || state.OwnerID != owner || state.WorkloadID != workload || state.TargetID != targetID || state.AcceleratorID != acceleratorID || state.Generation != generation || state.Fence != fence || state.Phase < checkpointPhase(\"resume\") {",
      pkg: "./internal/workloads", test: "TestNativeCommandProcessorAuthorizesExactCompensationCancel",
    },
    {
      name: "offline-cleanup-must-renew-owned-fence",
      file: ["internal", "workloads", "manager.go"],
      needle: "if renewErr := m.store.RenewAcceleratorLease(ctx, lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, m.leaseTTL); renewErr != nil {",
      replacement: "if renewErr := m.store.RenewAcceleratorLease(ctx, lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, 0); renewErr != nil {",
      pkg: "./internal/workloads", test: "TestCheckpointCleanupRetryRetainsFenceUntilStopAndStoppedRestartIsIdempotent",
    },
    {
      name: "offline-cleanup-must-stop-before-confirming-release",
      file: ["internal", "workloads", "manager.go"],
      needle: "handle := cleanupJournalHandle(op)\n\tif op.CleanupState != \"stopped\" {",
      replacement: "handle := cleanupJournalHandle(op)\n\tif false {",
      pkg: "./internal/workloads", test: "TestCheckpointCleanupRetryRetainsFenceUntilStopAndStoppedRestartIsIdempotent",
    },
    {
      name: "admission-must-fence-every-unresolved-row",
      file: ["internal", "store", "memory.go"],
      needle: "return &domain.AcceleratorLease{AcceleratorID: acceleratorID, WorkloadID: op.WorkloadID, FencingToken: fence, ExpiresAt: now.Add(ttl)}, false, nil",
      replacement: "continue",
      pkg: "./internal/store", test: "TestAcceleratorLeaseAdmissionScansEveryUnresolvedCheckpointRow",
    },
    {
      name: "pre-restore-custody-must-bind-physical-compensation-operation",
      file: ["internal", "workloads", "manager.go"],
      needle: "command := CheckpointCommand{ID: transitionID + \":compensate\", IdempotencyKey: transitionID + \":compensate\", OwnerID: victim.Request.OwnerID, WorkloadID: victim.Request.ID, WorkloadRevision: victim.Revision, Generation: m.targetGeneration(target.ID), RuntimeIdentity: target.RuntimeIdentity, ModelFingerprint: victim.Plan.ModelFingerprint, ProfileFingerprint: victim.Plan.ProfileDigest, ContextLimit: victim.Plan.TargetContextLimit, Fence: uint64(lease.FencingToken), SnapshotName: checkpoint, CompensationOf: transitionID + \":checkpoint\"}",
      replacement: "command := CheckpointCommand{ID: transitionID, IdempotencyKey: transitionID, OwnerID: victim.Request.OwnerID, WorkloadRevision: victim.Revision, WorkloadID: victim.Request.ID, Generation: m.targetGeneration(target.ID), RuntimeIdentity: target.RuntimeIdentity, ModelFingerprint: victim.Plan.ModelFingerprint, ProfileFingerprint: victim.Plan.ProfileDigest, ContextLimit: victim.Plan.TargetContextLimit, Fence: uint64(lease.FencingToken), SnapshotName: checkpoint, CompensationOf: transitionID + \":checkpoint\"}",
      pkg: "./internal/workloads", test: "TestCheckpointRecoveryCrashBeforeFreshHandleJournalRetriesStopWithoutDuplicateRestore",
    },
    {
      name: "proof-intermediate-errors-must-use-deferred-cleanup",
      file: ["internal", "nodeagent", "llamacpp_checkpoint.go"],
      needle: "releaseErr := driver.ReleaseSlot(cleanupCtx, slot)",
      replacement: "releaseErr := error(nil)",
      pkg: "./internal/nodeagent", test: "TestGenerateProductionCheckpointProofCleansEveryIntermediateFailure",
    },
    {
      name: "proof-reconnect-must-advance-fence",
      file: ["internal", "nodeagent", "llamacpp_checkpoint.go"],
      needle: "fence = uint64(maxFence + 1)",
      replacement: "fence = uint64(maxFence)",
      pkg: "./internal/nodeagent", test: "TestDurableCheckpointProofIssuanceAcceptsFreshExerciseAfterExpiry",
    },
    {
      name: "postgres-recovery-must-not-skip-owned-row",
      file: ["internal", "store", "postgres_workloads.go"],
      needle: "if cleanupOp == recoveryOp {\n\t\t\tcontinue\n\t\t}",
      replacement: "if false {\n\t\t\tcontinue\n\t\t}",
      pkg: "./internal/store", test: "TestAcceleratorLeaseAdmissionScansEveryUnresolvedCheckpointRow",
    },
  ];
  const countOccurrences = (source, needle) => {
    if (needle.length === 0) return 0;
    let count = 0;
    let offset = 0;
    while (true) {
      const index = source.indexOf(needle, offset);
      if (index < 0) return count;
      count++;
      offset = index + needle.length;
    }
  };
  const outcomes = [];
  const hasMutationFilter = Object.hasOwn(process.env, "LLM_VERIFIER_MUTATION_FILTER");
  let selectedMutations = mutations;
  if (hasMutationFilter) {
    const requestedNames = process.env.LLM_VERIFIER_MUTATION_FILTER.split(",").map((name) => name.trim());
    const knownNames = new Set(mutations.map((mutation) => mutation.name));
    const invalidNames = requestedNames.filter((name) => name === "" || !knownNames.has(name));
    const duplicateNames = requestedNames.filter((name, index) => requestedNames.indexOf(name) !== index);
    if (requestedNames.length === 0 || invalidNames.length > 0 || duplicateNames.length > 0) {
      const details = [];
      if (requestedNames.length === 0 || requestedNames.some((name) => name === "")) details.push("filter contains an empty mutation name");
      if (invalidNames.some((name) => name !== "")) details.push(`unknown mutation name(s): ${invalidNames.filter(Boolean).join(", ")}`);
      if (duplicateNames.length > 0) details.push(`duplicate mutation name(s): ${[...new Set(duplicateNames)].join(", ")}`);
      return {
        status: 1,
        evidence: false,
        complete: false,
        fullSelection: false,
        selectedNames: [],
        requiredCount: mutations.length,
        outcomes: [{ name: "mutation-filter", status: 1, evidence: false, output: details.join("; ") }],
      };
    }
    const requested = new Set(requestedNames);
    selectedMutations = mutations.filter((mutation) => requested.has(mutation.name));
  }
  for (const mutation of selectedMutations) {
    const temp = mkdtempSync(join(tmpdir(), `llm-checkpoint-verifier-${mutation.name}-`));
    try {
      cpSync(root, temp, { recursive: true, filter: (source) => !source.includes(`${join(root, ".git")}`) && !source.includes(`${join(root, ".cache")}`) && !source.includes(`${join(root, ".unlazy")}`) && !source.includes(`${join(root, "dist")}`) && !source.includes(`${join(root, "web")}`) && !source.includes(".tmp-") });
      const file = join(temp, ...mutation.file);
      let source = readFileSync(file, "utf8");
      const edits = mutation.edits ?? [{ needle: mutation.needle, replacement: mutation.replacement }];
      let ambiguous = null;
      let appliedMutations = 0;
      let expectedMutations = 0;
      for (const edit of edits) {
        const occurrences = countOccurrences(source, edit.needle);
        const expected = edit.expectedCount ?? mutation.expectedCount ?? 1;
        expectedMutations += expected;
        if (occurrences !== expected) {
          ambiguous = `mutation anchor occurrence mismatch for ${mutation.name}: expected ${expected}, found ${occurrences}: ${edit.needle}`;
          break;
        }
        // An exact-count mutation must modify every intended occurrence.  A
        // single String.replace() silently mutates only the first occurrence,
        // producing a falsely precise mutant for repeated lifecycle branches.
        const mutated = expected > 1
          ? source.split(edit.needle).join(edit.replacement)
          : source.replace(edit.needle, edit.replacement);
        const remaining = countOccurrences(mutated, edit.needle);
        const expectedRemaining = Math.max(0, occurrences - expected);
        if (remaining !== expectedRemaining) {
          ambiguous = `mutation replacement count mismatch for ${mutation.name}: expected ${expected} edits, applied ${occurrences - remaining}: ${edit.needle}`;
          break;
        }
        source = mutated;
        appliedMutations += occurrences - remaining;
      }
      if (ambiguous) {
        outcomes.push({ name: mutation.name, status: 1, evidence: false, output: ambiguous });
        continue;
      }
      if (appliedMutations !== expectedMutations) {
        outcomes.push({ name: mutation.name, status: 1, evidence: false, output: `mutation count mismatch for ${mutation.name}: expected ${expectedMutations}, applied ${appliedMutations}` });
        continue;
      }
      writeFileSync(file, source);
      if (mutation.generatedTest) {
        writeFileSync(join(temp, ...mutation.generatedTest.path), mutation.generatedTest.source);
      }
      const run = spawnSync("go", ["test", mutation.pkg, "-run", `^${mutation.test}$`, "-count=1"], { cwd: temp, encoding: "utf8", timeout: 180000 });
      const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
      const timedOutOrSpawnFailed = Boolean(run.error) || Boolean(run.signal) || run.status === null;
      const compileOrCrash = /(panic:|\[build failed\]|undefined:|syntax error|cannot find package|no required module|fatal error|runtime error|timeout)/i.test(output);
      const assertionFailed = !timedOutOrSpawnFailed && !compileOrCrash && run.status !== 0 && new RegExp(`--- FAIL: ${mutation.test}`).test(output);
      outcomes.push({ name: mutation.name, status: assertionFailed ? 0 : 1, evidence: assertionFailed, output: assertionFailed ? output.slice(-4000) : (run.status === 0 ? `${mutation.name} mutant survived` : `mutation did not produce a clean assertion failure\n${output.slice(-4000)}`) });
    } finally {
      removeTempTree(temp);
    }
  }
  const allSelectedMutationsKilled = outcomes.length === selectedMutations.length && outcomes.every((outcome) => outcome.status === 0 && outcome.evidence);
  const fullSelection = selectedMutations.length === mutations.length;
  const complete = fullSelection && allSelectedMutationsKilled;
  return {
    status: complete ? 0 : 1,
    evidence: complete,
    complete,
    fullSelection,
    selectedNames: selectedMutations.map((mutation) => mutation.name),
    requiredCount: mutations.length,
    outcomes,
  };
}

const mutation = runMutationCheck();
results.push({ name: "active-mutation-oracle", status: mutation.status, evidence: mutation.evidence, output: JSON.stringify(mutation.outcomes) });
const passed = results.every((result) => result.status === 0 && result.evidence !== false);
const mutantsKilled = mutation.outcomes.filter((outcome) => outcome.status === 0 && outcome.evidence).length;
const behavioralInvocations = results.flatMap((result) => result.behavioralInvocation ? [result.behavioralInvocation] : []);
const distinctBehavioralInvocationKeys = new Set(behavioralInvocations.map(({ package: pkg, test }) => `${pkg}:${test}`));
const report = {
  schema: "llm-checkpoint-verifier-v4",
  checks: results,
  exactGoBehavioralInvocations: behavioralInvocations.length,
  distinctBehavioralChecks: distinctBehavioralInvocationKeys.size,
  portabilityAggregate: { targets: portability.outcomes.length, passed: portability.outcomes.filter((outcome) => outcome.status === 0).length, status: portability.status },
  mutationAggregate: { mutants: mutation.requiredCount, selected: mutation.selectedNames.length, killed: mutantsKilled, complete: mutation.complete, status: mutation.status },
  totalResults: results.length,
  mutation,
  mutantsKilled,
  mutantCount: mutation.requiredCount,
  mutantsRun: mutation.outcomes.length,
  cleanupWarnings,
  passed,
};
if (process.env.LLM_VERIFIER_SUMMARY === "1") {
  process.stdout.write(JSON.stringify({
    schema: report.schema,
    exactGoBehavioralInvocations: report.exactGoBehavioralInvocations,
    distinctBehavioralChecks: report.distinctBehavioralChecks,
    portabilityAggregate: report.portabilityAggregate,
    mutationAggregate: report.mutationAggregate,
    totalResults: report.totalResults,
    mutantsKilled: report.mutantsKilled,
    mutantCount: report.mutantCount,
    mutantsRun: report.mutantsRun,
    cleanupWarnings: report.cleanupWarnings,
    passed: report.passed,
    failedChecks: report.checks.filter((result) => result.status !== 0 || result.evidence === false).map((result) => ({ name: result.name, status: result.status, evidence: result.evidence, output: result.output })),
    survivingMutants: report.mutation.outcomes.filter((outcome) => outcome.status !== 0 || outcome.evidence === false),
  }) + "\n");
} else {
  process.stdout.write(JSON.stringify(report) + "\n");
}
if (!passed) process.exit(1);
console.log("LLM checkpoint preemption verification passed");
