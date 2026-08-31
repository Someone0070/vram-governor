# Unified platform acceptance matrix

The deterministic suite exercises the single-controller release without
requiring a physical GPU, PostgreSQL service, ComfyUI, llama.cpp, S3, or cloud
credentials. HTTP simulators implement the real protocol boundaries; the
production PostgreSQL path is compiled against the aggregate `store.Store`
interface and migrations `0001`–`0014`.

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
