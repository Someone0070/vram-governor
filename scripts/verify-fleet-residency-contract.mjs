import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";

const root = path.resolve(import.meta.dirname, "..");
const allowedArguments = new Set(["--api-ui-config"]);
for (const argument of process.argv.slice(2)) {
  if (!allowedArguments.has(argument)) throw new Error(`unsupported verifier argument: ${argument}`);
}
const expectedFeatureTests = [
  ["internal/nodeagent/config_test.go", "TestNodeConfigDefaultsVersionAndSingleAcceleratorCeiling"],
  ["internal/nodeagent/config_test.go", "TestNodeConfigRejectsUnsafeByteBudgetsAndCapabilityProofs"],
  ["internal/nodeagent/config_test.go", "TestNodeConfigNormalizesNestedPlacementCeiling"],
  ["internal/nodeagent/config_test.go", "TestNodeRegistrationAndRefreshCarryCapabilityEnvelope"],
  ["internal/api/config_test.go", "TestResidencyContractValidatesByteBudgetsAndKeepsCheckpointSeparate"],
  ["internal/api/config_test.go", "TestPlacementCeilingDefaultsIndependentlyOfLegacyModelPolicy"],
  ["internal/api/config_test.go", "TestNestedPlacementCeilingNormalizesOmittedOuterValue"],
  ["internal/api/config_test.go", "TestOperatorConfigCannotMintVerifiedResidencyProof"],
  ["internal/api/config_test.go", "TestTargetCapabilityOverrideGetsContractRevisionDuringLoad"],
  ["internal/api/config_test.go", "TestTargetCannotRaiseInheritedAcceleratorCeiling"],
  ["internal/api/config_test.go", "TestTargetCapacityOverrideRejectsNegativeRawBudget"],
  ["internal/api/config_test.go", "TestTargetCapacityOverrideCannotRaiseInheritedHardCaps"],
  ["internal/api/config_test.go", "TestResidencyEvidenceRejectsDanglingProofs"],
  ["internal/api/config_test.go", "TestOperatorConfigCannotAssertCheckpointCapability"],
  ["internal/api/config_test.go", "TestTargetCapabilityAliasesMergeAfterGlobalFallback"],
  ["internal/api/config_test.go", "TestTargetCapabilityAliasConflictFailsClosed"],
  ["internal/api/config_test.go", "TestOperatorConfigCannotAssertYieldCapability"],
  ["internal/api/config_test.go", "TestStaticTargetCannotMintCapacityEvidence"],
  ["internal/api/ws_test.go", "TestNodeCapabilityAdvertisementIsVersionedAndSeparatesResidencyProofs"],
  ["internal/api/ws_test.go", "TestAdmissionBlockerCodesRemainStable"],
  ["internal/api/ws_test.go", "TestWireCapabilityValidationRejectsKnownBrokenFixture"],
  ["internal/api/ws_test.go", "TestWireCapabilityValidationPreservesLegacyAdvertisement"],
  ["internal/api/ws_test.go", "TestWireCapabilityValidationRejectsVersionAndBudgetMismatches"],
  ["internal/api/ws_test.go", "TestWireCapabilityValidationRejectsUnverifiedYield"],
  ["internal/api/ws_test.go", "TestWireCapabilityValidationReconcilesMixedAliasesAndResidentConflict"],
  ["internal/api/ws_test.go", "TestWireCapabilityValidationRejectsDanglingResidencyEvidence"],
  ["internal/api/ws_test.go", "TestWireCapabilityValidationRejectsAdapterCeilingAboveNode"],
  ["internal/api/ws_test.go", "TestAdapterRegistrationRejectsCapacityAboveInheritedHardCaps"],
  ["internal/api/ws_test.go", "TestWireCapabilityValidationReconcilesAdapterRuntimeIdentityAliases"],
  ["internal/api/ws_test.go", "TestLegacyAdapterRefreshInheritsStoredNodeEnvelope"],
  ["internal/api/ws_test.go", "TestCapabilityRefreshPresenceDistinguishesLegacyOmissionAndRevocation"],
  ["internal/api/ws_test.go", "TestCapabilitiesPayloadRejectsNestedAdapterAndProfileAliases"],
  ["internal/api/ws_test.go", "TestRegisterRejectsInvalidNestedAdapterBeforeStore"],
  ["internal/api/ws_test.go", "TestRegisterPayloadStrictlyRejectsUnknownAndNullNestedFields"],
  ["internal/api/ws_test.go", "TestCapabilitiesPayloadRejectsNoncanonicalTopLevelAndNullSafetyFields"],
  ["internal/api/ws_test.go", "TestCapabilityRefreshRejectsNoncanonicalCapacityFields"],
  ["internal/nodeagent/llamacpp_test.go", "TestLlamaRouterAbsentModelIsAuthoritativeUnloaded"],
  ["internal/nodeagent/llamacpp_test.go", "TestLlamaRouterRejectsMalformedNonmatchingEntry"],
  ["internal/nodeagent/llamacpp_test.go", "TestSignedUnloadAcceptsAbsentModelAsCold"],
  ["internal/nodeagent/llamacpp_test.go", "TestSignedLoadRejectsAbsentModelAfterMutation"],
  ["internal/nodeagent/commands_test.go", "TestReconcilePendingLoadTransitionalRemainsPendingAfterRestart"],
  ["internal/nodeagent/commands_test.go", "TestReconcilePendingWarmTransitionalRemainsPendingAfterRestart"],
  ["internal/nodeagent/commands_test.go", "TestReconcilePendingPersistsCanonicalReplayForAllResidencyActions"],
  ["internal/nodeagent/commands_test.go", "TestReconcilePendingRejectsManifestOperationMismatch"],
  ["internal/nodeagent/commands_test.go", "TestReconcilePendingManifestMismatchMatrix"],
  ["internal/nodeagent/commands_test.go", "TestReconcilePendingJournalCrashReplaysWithoutMutation"],
  ["internal/nodeagent/commands_test.go", "TestHandleCachedAuthoritativeObservationReplayAllResidencyActions"],
  ["internal/nodeagent/commands_test.go", "TestCachedAuthoritativeObservationRejectsAliasBindingAndProofDrift"],
  ["internal/nodeagent/commands_test.go", "TestReconcilePendingRejectsCachedResultEnvelopeDrift"],
  ["internal/nodeagent/commands_test.go", "TestCachedLegacyMutationReplayExactHotColdSchema"],
  ["internal/nodeagent/commands_test.go", "TestResidencyCacheLegacyCurrentBranchMatrix"],
  ["internal/nodeagent/commands_test.go", "TestLiveHandleCanonicalResidencyQueryMatrixAllActions"],
  ["internal/nodeagent/commands_test.go", "TestLiveHandleAllEightResidencyActionsDurableMatrix"],
  ["internal/nodeagent/commands_test.go", "TestHandleCachedResidencyDriftFailsClosedLiveCausal"],
  ["internal/nodeagent/commands_test.go", "TestHandleCachedReplayRejectsLiveCapabilityContextDrift"],
  ["internal/nodeagent/commands_test.go", "TestHandleLegacyCacheRejectsMismatchedFenceProof"],
  ["internal/nodeagent/commands_test.go", "TestHandleCurrentCacheRejectsSlotsProofLossAndChange"],
  ["internal/nodeagent/commands_test.go", "TestHandleCurrentCacheRejectsRemovedAndDisabledRuntimeTargets"],
  ["internal/nodeagent/commands_test.go", "TestHandleCurrentCacheRejectsMixedInvalidSlotsForMutationAndQuery"],
  ["internal/nodeagent/commands_test.go", "TestSignedLlamaCPPCommandRejectsPassiveRuntimeLifecycle"],
  ["internal/nodeagent/llamacpp_test.go", "TestLlamaSlotsRejectsMalformedRowsAndMixedCapacity"],
  ["internal/nodeagent/llamacpp_test.go", "TestDiscoverLlamaCPPMixedSlotsNeverVerifiesCapacity"],
  ["internal/nodeagent/llamacpp_test.go", "TestDiscoverLlamaCPPPassiveStatusDoesNotAdvertiseLifecycle"],
  ["internal/nodeagent/llamacpp_test.go", "TestDiscoverLlamaCPPUsesRuntimeContextAndSlots"],
  ["internal/nodeagent/llamacpp_test.go", "TestDiscoverLlamaCPPUsesOllamaRunningModelsForResidency"],
  ["internal/api/ws_test.go", "TestPassiveLlamaAdvertisementRoundTripsFalseLifecycleThroughController"],
  ["internal/api/ws_test.go", "TestWireCapabilityValidationPreservesVerifiedFalseTargetCapabilities"],
  ["internal/nodeagent/commands_test.go", "TestHandleCachedSuccessNeverBypassesBlockedResidencyState"],
  ["internal/workloads/warmram_test.go", "TestObserveResidencyResultExactActionTierProofSchema"],
  ["internal/workloads/warmram_test.go", "TestControllerAdapterAllResidencyActionsCurrentEnvelope"],
  ["internal/workloads/warmram_test.go", "TestControllerAdapterAllResidencyActionsDispatchesThroughTransition"],
  ["internal/workloads/warmram_test.go", "TestControllerAdapterAllResidencyActionsDispatchSchemaNegatives"],
  ["internal/api/workloads_http_test.go", "TestControllerResidencyInverseSettleUncertainAllActions"],
  ["internal/api/workloads_http_test.go", "TestControllerResidencySettleRejectsBindingAndProofDrift"],
  ["internal/api/ws_test.go", "TestNodeEnvelopePlacementCeilingRejectsNegativeAndContradictoryValues"],
  ["internal/api/ws_test.go", "TestAdapterCapabilityValidationFencesStateBeforeRegistration"],
  ["cmd/controller/main_test.go", "TestPrepareControllerDefaultsResidencyContractAndSingleAccelerator"],
];

for (const [relative, testName] of expectedFeatureTests) {
  const file = fs.readFileSync(path.join(root, relative), "utf8");
  if (!file.includes(`func ${testName}(`)) {
    throw new Error(`missing required feature test ${testName} in ${relative}`);
  }
}

const featureNames = expectedFeatureTests.map(([, name]) => name);
const featurePattern = `^(${featureNames.join("|")})$`;
const goCheck = spawnSync("go", ["test", "./internal/api", "./internal/nodeagent", "./internal/workloads", "./cmd/controller", "-v", "-run", featurePattern, "-count=1"], { cwd: root, encoding: "utf8" });
if (goCheck.status !== 0) {
  process.stderr.write(goCheck.stdout ?? "");
  process.stderr.write(goCheck.stderr ?? "");
  throw new Error("Go product-backed contract fixtures failed");
}
for (const name of featureNames) {
  if (!(goCheck.stdout ?? "").includes(`--- PASS: ${name}`)) {
    throw new Error(`feature test was not actually executed: ${name}`);
  }
}

const forbiddenPolicy = /(?:3080|3090|\bcmp\b)/i;
const policyFiles = [
  "internal/domain/domain.go",
  "internal/domain/workload.go",
  "internal/wsproto/messages.go",
  "internal/workloads/adapter.go",
  "internal/nodeagent/config.go",
  "internal/api/config.go",
  "internal/api/ws.go",
  "cmd/controller/main.go",
  "internal/nodeagent/agent.go",
];
const knownPositiveBrokenControl = "scheduler policy for 3080 must be rejected";
if (!forbiddenPolicy.test(knownPositiveBrokenControl)) {
  throw new Error("product-name absence control fixture did not fail closed");
}
for (const relative of policyFiles) {
  const source = fs.readFileSync(path.join(root, relative), "utf8");
  if (forbiddenPolicy.test(source)) throw new Error(`product-name scheduling policy found in ${relative}`);
}

console.log(process.argv.includes("--api-ui-config") ? "fleet residency surface integration passed" : "fleet residency contract verification passed");
