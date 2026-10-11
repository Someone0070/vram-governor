# Unified platform acceptance matrix

The deterministic suite exercises the single-controller release without
requiring a physical GPU, PostgreSQL service, ComfyUI, llama.cpp, S3, or cloud
credentials. HTTP simulators implement the real protocol boundaries; the
production PostgreSQL path is compiled against the aggregate `store.Store`
interface and migrations `0001` through `0020`, ending at
`0020_accelerator_lease_cleanup.sql`.

| Roadmap scenario | Automated evidence |
|---|---|
| Shared physical inventory across LLM and Comfy | `TestLLMAndComfyShareOnePhysicalLease`, `TestLongStreamRenewsPhysicalLeaseAcrossAdapters` |
| Same model, different context/slot profiles and sticky clients | `TestContextBestFitPreservesLargeContextTarget`, `TestStickyPlacementDoesNotSpillClientToLargerTarget`, `TestOpenAIStreamingRoutesTwoSameModelProfilesAndHoldsStickySlot` |
| Side-effect-free scheduling preview preserves scarce long-context capacity | `TestPreviewPreservesLongContextProfileForRequestsThatFitShortProfile` |
| Durable runtime target safety policy | `TestTargetPolicyOverrideIsValidatedAndDurable`, `TestCapacityArrivalReappliesPersistedSharingPolicy` |
| Durable identity, leases, prompt routes, transitions, and restart recovery | `TestMemoryWorkloadIdempotencyIsOwnerScoped`, `TestMemoryLeaseFencingAndExclusion`, `TestComfyPromptMappingTracksTargetAndBackendWithoutOverwriteRace`, `TestRestartReconcilesTransitionWithoutReplayingRouterCommand`, `TestRestartDoesNotReplayInterruptedTransitionPlan`, `TestRestartReattachesCompletedExternalExecutionWithoutDuplicateStart`, `TestRestartDoesNotReplayUnknownLocalLLMExecution` |
| Remote Comfy staging, history, cancellation, and central outputs | `TestComfyStagesCentralInputsAndCollectsOutputs`, API Comfy tests |
| Missing model/custom node is filtered without installation | `TestCompatibilityAndEgressFilterProduceHonestWaitingDecision`, `TestDiscoverComfyUIReportsExistingCapabilitiesOnly` |
| Model demand load, safe eviction/rollback, idle and quiet-hours unload | `TestDemandLoadEvictsLeastProtectedResidentUnderOneLease`, `TestPinnedResidentBlocksDemandReplacement`, `TestFailedDemandLoadRestoresEvictedResident`, `TestIdleReconcilerUnloadsButQueuedDemandRetainsModel`, `TestQuietHoursAcrossMidnight` |
| Cloud policy, budget, actual settlement, quarantine, bounded fallback | `TestCloudBudgetReservationPreventsBudgetEscape`, `TestOpenRouterProviderIsPinnedAndActualUsageSettlesBudget`, `TestQuarantinedCloudRouteIsNotEligible`, `TestOpenRouterRateLimitFallsBackOnceWithoutRetryStorm` |
| Locked victim and consent/budget-aware checkpoint preemption | `TestLockedVictimCannotBePreemptedByPriority`, `TestCheckpointableVictimResumesAfterPriorityPreemption` |
| Adaptive envelopes, guarded learning, and rollback | `TestExclusiveLearningBootstrapsUnknownStandaloneEnvelopes`, `TestRestartRestoresLearnedStandaloneEnvelope`, `TestMeasuredCrossRuntimeSharingUsesOnePhysicalLease`, `TestUnknownSharingIsConservativeAndGuardedRollbackAbortsNewcomer`, `TestCompletedSlowdownUsesMeasuredStandaloneDuration` |
| Exact transformation approval and capability invalidation | `TestTransformationApprovalIsBoundToExactPlanAndCapabilities`, `TestComfyTransformationPlanContainsMaterialChangeAndRequiresProof`, `TestDelegatedReviewRejectsUnsafeTransformation` |
| Node loss fencing and late-result rejection | `TestNodeLossRequeuesRecoverableWorkAndIgnoresLateFencedResult`, `TestNodeLossDoesNotReplayWhenBackendStopIsUnconfirmed`, `TestOpenTransportGetsGraceBeforeNodeLost` |
| Owner, plane, node, CSRF, and private-admin boundaries | `TestWorkloadAuthPriorityClampAndOwnership`, `TestSecurityPlaneCannotBeBypassedWithWildcardScope`, `TestNodeWebSocketRequiresBoundNodePlaneCredential`, `TestNodeReportCredentialCannotWriteAnotherNode`, `TestBrowserSessionRequiresCSRFForMutations`, `TestAdminRequiresScopeAndPrivateNetwork` |
| Signed/idempotent commands and webhook SSRF/retry protection | `TestAdminNodeCommandIsSignedDurableAndIdempotent`, `TestSignedModelCommandIsAllowlistedAndDurablyIdempotent`, `TestSignedWebhookRetriesFromDurableOutbox`, `TestWebhookSSRFProtectionRejectsPrivateAddressBeforeDial` |
| System-agent authority and egress separation | `TestMonitoringAgentSeverityIsClampedWithoutAdminAuthority` |
| S3-compatible and filesystem artifact durability | `TestS3StoreRoundTripUsesSigV4AndDurableMetadata`, `TestFileStoreRoundTripAndTraversalRejection` |
| Creator Studio immutable hardware-neutral capabilities | `TestCreatorStudioCapabilities` |
| Creator Studio strict requirements, explicit fallback, idempotency, batches, ordered dependencies, late binding, and creative/infrastructure separation | `TestCreatorStudioWorkloads` |
| Creator Studio advisory working-set create/list/release without hardware control | `TestCreatorStudioWorkingSet` |
| Runnable workflow definitions, schema/Artifact contracts, and locality | `TestRuntimeProfileRegistrationRequiresCallableWorkflowContract` |
| Generic Artifact upload, provenance, compatibility tokens, and incompatible-source rejection | `TestArtifactProvenanceRoundTrip`, `TestCreatorArtifactCompatibilityAndUpload` |
| Artifact-backed local/hosted-style async LLM results and idempotent replay | `TestCreatorAsyncLLMOutputs` |
| Stable capability/capacity/busy/deadline/route/approval reasons | `TestCreatorBlockingReasons` |
| Explicit partial batch acceptance and replay safety | `TestCreatorBatchPartialAcceptance` |

Local release verification:

```powershell
go test ./... -count=3
go vet ./...
cd web/ui
npm.cmd run build
npm.cmd audit --offline --audit-level=high
```

A deployment should additionally apply all migrations to its actual PostgreSQL
version and run the same API scenarios against its real llama.cpp, ComfyUI, S3,
and OpenRouter endpoints before enabling those targets.
