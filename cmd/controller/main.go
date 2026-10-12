// Command controller runs the unified VRAM Governor control plane, protocol
// gateways, workload scheduler, node channel, and embedded browser interfaces.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"vram-governor/internal/api"
	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
	"vram-governor/internal/jobs"
	"vram-governor/internal/logging"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
	"vram-governor/web/dashboard"
	"vram-governor/web/ui"
)

func main() {
	cfg, checked, err := prepareController(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		panic(err)
	}
	if checked {
		return
	}
	log := logging.New("controller", cfg.LogLevel)

	if cfg.Auth.SharedToken == "" && len(cfg.Auth.Credentials) == 0 {
		log.Warn("no credentials configured — authenticated API and node channels will reject all callers")
	}

	var controllerStore store.Store = store.NewMemoryStore()
	if cfg.DatabaseURL != "" {
		connectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		postgresStore, openErr := store.OpenPostgresWorkloadStore(connectCtx, cfg.DatabaseURL)
		cancel()
		if openErr != nil {
			log.Error("PostgreSQL controller store unavailable", "err", openErr)
			os.Exit(1)
		}
		defer postgresStore.Close()
		controllerStore = postgresStore
	}

	// Legacy job compatibility uses deterministic in-process workers by
	// default. Unified GPU workloads use the adapter targets configured below.
	jobsMgr := jobs.NewManager(log,
		controllerStore,
		time.Duration(cfg.Jobs.LeaseTTLSeconds)*time.Second,
		time.Duration(cfg.Jobs.ReaperIntervalMillis)*time.Millisecond,
		cfg.Jobs.DefaultMaxAttempts,
	)
	registerVerificationMockWorkers(jobsMgr)

	var workloadStore store.WorkloadStore = controllerStore
	workloadMgr := workloads.NewManager(log, workloadStore, time.Duration(cfg.Workloads.LeaseTTLSeconds)*time.Second)
	modelPolicies := make(map[string]int, len(cfg.Workloads.ModelCapacityPolicies))
	for _, policy := range cfg.Workloads.ModelCapacityPolicies {
		modelPolicies[policy.Model] = policy.MaxAccelerators
	}
	workloadMgr.SetModelCapacityPolicies(cfg.Workloads.DefaultMaxAcceleratorsPerModel, modelPolicies)
	idleLinger := 5 * time.Second
	if cfg.Workloads.GPUIdleLingerSeconds != nil {
		idleLinger = time.Duration(*cfg.Workloads.GPUIdleLingerSeconds) * time.Second
	}
	workloadMgr.SetGPUIdleLinger(idleLinger)
	if export := cfg.Workloads.ResultExport; export.Dir != "" {
		types := export.MediaTypes
		if len(types) == 0 {
			types = []string{"image/*", "video/*", "audio/*"}
		}
		workloadMgr.SetResultExport(workloads.ResultExport{Dir: export.Dir, MediaTypes: types})
	}
	residencyEnabled := true
	if cfg.Workloads.Residency.Enabled != nil {
		residencyEnabled = *cfg.Workloads.Residency.Enabled
	}
	workloadMgr.SetResidencyOptions(workloads.ResidencyOptions{
		Enabled:                residencyEnabled,
		ReconcileInterval:      time.Duration(cfg.Workloads.Residency.ReconcileSeconds) * time.Second,
		DefaultIdleUnloadAfter: time.Duration(cfg.Workloads.Residency.IdleUnloadSeconds) * time.Second,
		DefaultMinResidency:    time.Duration(cfg.Workloads.Residency.MinResidencySeconds) * time.Second,
		TransitionTimeout:      time.Duration(cfg.Workloads.Residency.TransitionTimeoutSeconds) * time.Second,
		QuietHoursStart:        cfg.Workloads.Residency.QuietHoursStart,
		QuietHoursEnd:          cfg.Workloads.Residency.QuietHoursEnd,
	})
	notificationSecret := cfg.Notifications.SigningSecret
	if cfg.Notifications.SigningSecretEnv != "" {
		notificationSecret = os.Getenv(cfg.Notifications.SigningSecretEnv)
	}
	if err := workloadMgr.SetNotificationOptions(workloads.NotificationOptions{
		Enabled: cfg.Notifications.Enabled, SigningSecret: []byte(notificationSecret),
		AllowedHosts: cfg.Notifications.AllowedHosts, AllowedPrivateCIDRs: cfg.Notifications.AllowedPrivateCIDRs,
		AllowHTTP: cfg.Notifications.AllowHTTP, MaxAttempts: cfg.Notifications.MaxAttempts,
		BaseRetry:        time.Duration(cfg.Notifications.BaseRetrySeconds) * time.Second,
		RequestTimeout:   time.Duration(cfg.Notifications.RequestTimeoutSeconds) * time.Second,
		DispatchInterval: time.Duration(cfg.Notifications.DispatchIntervalSeconds) * time.Second,
	}); err != nil {
		log.Error("notification configuration invalid", "err", err)
		os.Exit(1)
	}
	var artifactStore artifacts.Store
	if cfg.Workloads.ArtifactStore.Type == "s3" {
		artifactStore, err = artifacts.NewS3Store(artifacts.S3Options{Endpoint: cfg.Workloads.ArtifactStore.Endpoint, Bucket: cfg.Workloads.ArtifactStore.Bucket, Region: cfg.Workloads.ArtifactStore.Region, Prefix: cfg.Workloads.ArtifactStore.Prefix, AccessKey: os.Getenv(cfg.Workloads.ArtifactStore.AccessKeyEnv), SecretKey: os.Getenv(cfg.Workloads.ArtifactStore.SecretKeyEnv), SessionToken: os.Getenv(cfg.Workloads.ArtifactStore.SessionTokenEnv)})
	} else {
		artifactStore, err = artifacts.NewFileStore(cfg.Workloads.ArtifactRoot)
	}
	if err != nil {
		log.Error("artifact store initialization failed", "err", err)
		os.Exit(1)
	}
	workloadMgr.SetArtifactStore(artifactStore)
	workloadMgr.SetNodeStore(controllerStore)
	llamaAdapter := workloads.NewHTTPAdapter("llamacpp", "llama", nil)
	var checkpointCoordinator *workloads.CheckpointCoordinator
	checkpointCfg := cfg.Workloads.Checkpoint
	if checkpointCfg.Enabled {
		checkpointRoot := checkpointCfg.Root
		if checkpointStore, storeErr := workloads.NewSnapshotStore(checkpointRoot, checkpointCfg.MaxBytes, checkpointCfg.MaxFiles); storeErr == nil {
			if quotaErr := checkpointStore.ConfigureQuotas(checkpointCfg.MaxBytes, checkpointCfg.MaxFiles, checkpointCfg.PerOwnerMaxBytes, checkpointCfg.PerOwnerMaxFiles, checkpointCfg.MaxMetadataBytes, checkpointCfg.MaxOutputBytes); quotaErr != nil {
				log.Warn("LLM checkpoint store quotas invalid; capability remains locked", "error", quotaErr)
				checkpointStore = nil
			}
			if checkpointStore != nil {
				if storageErr := checkpointStore.ConfigureStorage(checkpointCfg.ExpirySeconds, checkpointCfg.LockStaleSeconds); storageErr != nil {
					log.Warn("LLM checkpoint store expiry/locking invalid; capability remains locked", "error", storageErr)
					checkpointStore = nil
				}
				if checkpointStore != nil {
					if cleanupErr := checkpointStore.CleanupExpired(); cleanupErr != nil {
						log.Warn("LLM checkpoint expiry cleanup incomplete; capability remains locked", "error", cleanupErr)
						checkpointStore = nil
					}
				}
			}
			if checkpointStore == nil {
				log.Warn("LLM checkpoint store configuration rejected; capability remains locked")
			}
			if checkpointStore != nil {
				// Proof is target-scoped and arrives only in the authenticated node
				// advertisement. The controller starts fail-closed; Manager.RegisterTarget
				// installs a complete live proof on the coordinator when one arrives.
				coordinator := workloads.NewCheckpointCoordinator(nil, checkpointStore, workloads.ProbeCapabilityProof())
				checkpointCoordinator = coordinator
				if operations, ok := controllerStore.(store.LLMCheckpointOperationStore); ok {
					coordinator.Operations = operations
				}
				llamaAdapter.SetLLMCheckpointCoordinator(coordinator)
			}
		} else {
			log.Warn("LLM checkpoint store unavailable; capability remains locked", "error", storeErr)
		}
	}
	workloadMgr.RegisterAdapter(llamaAdapter)
	comfyAdapter := workloads.NewHTTPAdapter("comfy", "comfy", nil)
	comfyAdapter.SetArtifactStore(artifactStore)
	workloadMgr.RegisterAdapter(comfyAdapter)
	workloadMgr.RegisterAdapter(workloads.NewHTTPAdapter("openrouter", "openrouter", nil))
	workloadMgr.RegisterAdapter(workloads.NewMockAdapter())
	for _, configured := range cfg.Workloads.Targets {
		enabled := true
		if configured.Enabled != nil {
			enabled = *configured.Enabled
		}
		authorization := configured.Authorization
		if configured.AuthorizationEnv != "" {
			authorization = os.Getenv(configured.AuthorizationEnv)
		}
		capabilityVersion := configured.CapabilityVersion
		capabilityRevision := configured.CapabilityRevision
		if capabilityRevision == "" {
			capabilityRevision = cfg.Workloads.CapabilityVersion
		}
		capabilities := configured.Capabilities
		if capabilities == (domain.ResidencyCapabilities{}) {
			capabilities = cfg.Workloads.Capabilities
		}
		capacity := configured.Capacity
		if capacity == (domain.CapacityBudget{}) {
			capacity = cfg.Workloads.Capacity
		}
		maxAccelerators := configured.MaxAcceleratorsPerWorkload
		if maxAccelerators == 0 {
			maxAccelerators = cfg.Workloads.MaxAcceleratorsPerWorkload
		}
		workloadMgr.RegisterTarget(workloads.Target{ID: configured.ID, Adapter: configured.Adapter, Endpoint: configured.Endpoint, RuntimeProtocol: configured.RuntimeProtocol, AcceleratorID: configured.AcceleratorID, Models: configured.Models, Profiles: configured.Profiles, ResidentModels: configured.ResidentModels, CustomNodes: configured.CustomNodes, ContextLimit: configured.ContextLimit, Slots: configured.Slots, CapabilityVersion: capabilityVersion, CapabilityRevision: capabilityRevision, Capabilities: capabilities, Capacity: capacity, MaxAcceleratorsPerWorkload: maxAccelerators, ModelFingerprint: configured.ModelFingerprint, CapacitySource: configured.CapacitySource, CapacityVerified: configured.CapacityVerified, SupportsModelLifecycle: configured.SupportsModelLifecycle, SupportsAcceleratorReclaim: configured.SupportsAcceleratorReclaim, MaxResidentModels: configured.MaxResidentModels, WarmRAMSupported: configured.WarmRAMSupported, ResidencyPolicy: domain.ResidencyPolicyMode(configured.ResidencyPolicy), IdleUnloadAfter: time.Duration(configured.IdleUnloadSeconds) * time.Second, MinResidency: time.Duration(configured.MinResidencySeconds) * time.Second, Cloud: configured.Cloud, Enabled: enabled, Authorization: authorization, InputCentsPerMTok: configured.InputCentsPerMTok, OutputCentsPerMTok: configured.OutputCentsPerMTok, WorkloadClass: configured.WorkloadClass, StandaloneVRAMMB: configured.StandaloneVRAMMB, AcceleratorVRAMMB: configured.AcceleratorVRAMMB, VRAMReserveMB: configured.VRAMReserveMB, SharingEnabled: configured.SharingEnabled, GuardedExploration: configured.GuardedExploration, PredictedSlowdown: configured.PredictedSlowdown, MaxSlowdown: configured.MaxSlowdown, SafetyCritical: configured.SafetyCritical, Provider: configured.Provider, Quarantined: configured.Quarantined})
	}
	srv := api.NewServer(cfg, log, controllerStore, jobsMgr, dashboard.FS())
	defer srv.Close()
	srv.SetWorkloadManager(workloadMgr, workloadStore)
	if checkpointCoordinator != nil {
		checkpointCoordinator.SetRecoveryEvidenceQuery(func(ctx context.Context, op *store.LLMCheckpointOperation) (workloads.RecoveryObservation, error) {
			if op == nil {
				return workloads.RecoveryObservation{}, fmt.Errorf("nil checkpoint recovery operation")
			}
			contextLimit := 1
			if strings.HasPrefix(op.ContextFingerprint, "ctx:") {
				if parsed, parseErr := strconv.Atoi(strings.TrimPrefix(op.ContextFingerprint, "ctx:")); parseErr == nil && parsed > 0 {
					contextLimit = parsed
				}
			}
			args := map[string]any{"target_kind": "llamacpp", "target_id": op.TargetID, "accelerator_id": op.AcceleratorID, "model": op.ModelFingerprint, "runtime_identity": op.RuntimeIdentity, "capability_version": "checkpoint-recovery", "capability_revision": "checkpoint-recovery", "profile_fingerprint": op.ProfileFingerprint, "context_fingerprint": op.ContextFingerprint, "owner_id": op.OwnerID, "workload_id": op.WorkloadID, "generation": op.Generation, "fencing_token": op.Fence, "context_limit": contextLimit, "checkpoint_action": "state_query", "checkpoint_operation_id": op.ID, "idempotency_key": op.IdempotencyKey + ":recovery-query", "slot_id": op.SlotID, "conversation_id": op.ConversationID, "continuation_conversation_id": op.ContinuationConversationID}
			if op.SnapshotName != "" {
				args["snapshot_name"] = op.SnapshotName
			}
			if op.SnapshotDigest != "" {
				args["snapshot_digest"] = op.SnapshotDigest
			}
			var result map[string]any
			var queryErr error
			for attempt := 0; attempt < 3; attempt++ {
				result, queryErr = srv.ExecuteNodeCommand(ctx, op.NodeID, "checkpoint_state_query", args, op.IdempotencyKey+":recovery-query")
				if queryErr == nil {
					break
				}
				select {
				case <-ctx.Done():
					return workloads.RecoveryObservation{}, ctx.Err()
				case <-time.After(time.Duration(attempt+1) * 150 * time.Millisecond):
				}
			}
			if queryErr != nil {
				if strings.Contains(strings.ToLower(queryErr.Error()), "not_found") {
					return workloads.RecoveryObservation{}, fmt.Errorf("%w: %v", workloads.ErrCheckpointNotFound, queryErr)
				}
				return workloads.RecoveryObservation{}, queryErr
			}
			if _, notFound := result["not_found"]; notFound {
				return workloads.RecoveryObservation{}, workloads.ErrCheckpointNotFound
			}
			observation := workloads.RecoveryObservation{SlotID: -1}
			observation.NodeID, _ = result["node_id"].(string)
			observation.TargetID, _ = result["target_id"].(string)
			observation.AcceleratorID = op.AcceleratorID
			observation.OperationID, _ = result["checkpoint_operation_id"].(string)
			observation.Phase, _ = result["observed_phase"].(string)
			observation.SnapshotName, _ = result["observed_snapshot_name"].(string)
			observation.SnapshotDigest, _ = result["observed_snapshot_digest"].(string)
			observation.ConversationID, _ = result["observed_conversation_id"].(string)
			observation.ContinuationConversationID, _ = result["observed_continuation_conversation_id"].(string)
			observation.RuntimeIdentity, _ = result["observed_runtime_identity"].(string)
			observation.ModelFingerprint, _ = result["observed_model_fingerprint"].(string)
			observation.ProfileFingerprint, _ = result["observed_profile_fingerprint"].(string)
			observation.ContextFingerprint, _ = result["observed_context_fingerprint"].(string)
			switch value := result["observed_slot_id"].(type) {
			case int:
				observation.SlotID = value
			case int64:
				observation.SlotID = int(value)
			case float64:
				observation.SlotID = int(value)
			}
			switch value := result["observed_phase_ordinal"].(type) {
			case int:
				observation.PhaseOrdinal = value
			case int64:
				observation.PhaseOrdinal = int(value)
			case float64:
				observation.PhaseOrdinal = int(value)
			}
			return observation, nil
		})
		checkpointCoordinator.SetRecoveryCorrection(func(ctx context.Context, op *store.LLMCheckpointOperation, observed workloads.RecoveryObservation, reason string) error {
			if op == nil || op.NodeID == "" || op.TargetID == "" || op.AcceleratorID == "" {
				return fmt.Errorf("checkpoint correction identity is incomplete")
			}
			contextLimit := 1
			if strings.HasPrefix(op.ContextFingerprint, "ctx:") {
				if parsed, parseErr := strconv.Atoi(strings.TrimPrefix(op.ContextFingerprint, "ctx:")); parseErr == nil && parsed > 0 {
					contextLimit = parsed
				}
			}
			base := func(action string, slot int) map[string]any {
				args := map[string]any{"target_kind": "llamacpp", "target_id": op.TargetID, "accelerator_id": op.AcceleratorID, "model": op.ModelFingerprint, "runtime_identity": op.RuntimeIdentity, "capability_version": "checkpoint-recovery", "capability_revision": "checkpoint-recovery", "profile_fingerprint": op.ProfileFingerprint, "context_fingerprint": op.ContextFingerprint, "owner_id": op.OwnerID, "workload_id": op.WorkloadID, "generation": op.Generation, "fencing_token": op.Fence, "context_limit": contextLimit, "checkpoint_action": action, "checkpoint_operation_id": op.ID, "idempotency_key": op.IdempotencyKey + ":recovery-" + action, "slot_id": slot, "conversation_id": op.ConversationID, "continuation_conversation_id": op.ContinuationConversationID}
				if op.SnapshotName != "" {
					args["snapshot_name"] = op.SnapshotName
				}
				if op.SnapshotDigest != "" {
					args["snapshot_digest"] = op.SnapshotDigest
				}
				if action == "cancel" {
					args["compensation_of"] = op.ID
				}
				return args
			}
			run := func(action string, slot int) error {
				var err error
				for attempt := 0; attempt < 3; attempt++ {
					_, err = srv.ExecuteNodeCommand(ctx, op.NodeID, "checkpoint_"+action, base(action, slot), op.IdempotencyKey+":recovery-"+action)
					if err == nil {
						return nil
					}
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(time.Duration(attempt+1) * 150 * time.Millisecond):
					}
				}
				return err
			}
			slot := observed.SlotID
			if slot < 0 {
				slot = op.SlotID
			}
			phase := strings.ToLower(strings.TrimSpace(observed.Phase))
			if reason == "not_found" || reason == "snapshotless" || reason == "snapshot_missing" || (phase == "" && op.SnapshotName == "") {
				return checkpointCoordinator.TerminalizeOperation(ctx, op.ID, "failed", "checkpoint recovery found no authoritative node phase")
			}
			switch phase {
			case "slot_assign", "assigned", "start", "started", "pause", "paused":
				if err := run("pause", slot); err != nil {
					return err
				}
				if err := run("stop_confirm", slot); err != nil {
					return err
				}
				if err := run("release", slot); err != nil {
					return err
				}
				return checkpointCoordinator.TerminalizeOperation(ctx, op.ID, "failed", "checkpoint recovery released an incomplete operation")
			case "save", "saved", "stop_confirm", "stopped":
				if err := run("stop_confirm", slot); err != nil {
					return err
				}
				if err := run("release", slot); err != nil {
					return err
				}
				return checkpointCoordinator.TerminalizeOperation(ctx, op.ID, "failed", "checkpoint recovery released an incomplete operation")
			case "reload", "restore", "resume", "continue", "reuse_verify":
				if err := run("cancel", slot); err != nil {
					return err
				}
				if err := run("release", slot); err != nil {
					return err
				}
				return checkpointCoordinator.TerminalizeOperation(ctx, op.ID, "restore_failed", "checkpoint recovery cancelled an unresolved restore")
			case "release", "released":
				if op.Phase == "restore_planned" || op.Phase == "restore_assigned" {
					return nil
				}
				return checkpointCoordinator.TerminalizeOperation(ctx, op.ID, "failed", "checkpoint recovery observed a released operation")
			default:
				return fmt.Errorf("checkpoint correction does not recognize node phase %q", observed.Phase)
			}
		})
		srv.SetCheckpointRecovery(func() error { return checkpointCoordinator.Recover(context.Background()) })
		if recoverErr := checkpointCoordinator.Recover(context.Background()); recoverErr != nil {
			log.Warn("LLM checkpoint operation recovery incomplete; capability remains locked", "error", recoverErr)
		}
	}
	srv.SetArtifactStore(artifactStore)
	srv.SetAppFS(ui.FS())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	jobsMgr.Start(ctx)
	defer jobsMgr.Stop()
	workloadMgr.Start(ctx)
	defer workloadMgr.Close()

	go srv.RunLivenessMonitor(ctx)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	tlsEnabled := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	log.Info("controller listening", "addr", cfg.ListenAddr, "tls", tlsEnabled)
	serve := httpSrv.ListenAndServe
	if tlsEnabled {
		serve = func() error { return httpSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile) }
	}
	if err := serve(); err != nil && err != http.ErrServerClosed {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
}

// prepareController parses command-line options and validates the complete
// configuration before any listener, database connection, or worker starts.
// Deployment tooling uses -check-config as a side-effect-free preflight.
func prepareController(args []string, stdout, stderr io.Writer) (*api.Config, bool, error) {
	flags := flag.NewFlagSet("vram-governor-controller", flag.ContinueOnError)
	flags.SetOutput(stderr)
	cfgPath := flags.String("config", "configs/controller.yaml", "path to controller config YAML")
	listenOverride := flags.String("listen", "", "optional listen address override (useful for local verification)")
	checkConfig := flags.Bool("check-config", false, "validate configuration and exit without starting services")
	if err := flags.Parse(args); err != nil {
		return nil, false, err
	}
	if flags.NArg() != 0 {
		return nil, false, fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	cfg, err := api.LoadConfig(*cfgPath)
	if err != nil {
		return nil, false, err
	}
	if *listenOverride != "" {
		cfg.ListenAddr = *listenOverride
	}
	if *checkConfig {
		_, _ = fmt.Fprintf(stdout, "configuration valid: %s\n", *cfgPath)
		return cfg, true, nil
	}
	return cfg, false, nil
}

// registerVerificationMockWorkers wires up a small heterogeneous pool of
// jobs.MockWorker instances so the legacy work queue can be exercised
// end-to-end without a GPU, per the hard environment constraint (no real
// llama.cpp engine is launched by this entrypoint). Slot counts are derived
// from a fabricated domain.PerformanceProfile.Concurrency the same way a
// real Phase 2 measured profile would feed capacity — this is the "capacity
// from measured profile" wiring point (internal/jobs/manager.go
// RegisterWorker), just with synthetic profiles standing in for real
// measurements in this GPU-less verification environment.
func registerVerificationMockWorkers(mgr *jobs.Manager) {
	fast := jobs.NewMockWorker("mock-fast", jobs.MockWorkerConfig{
		MinLatency: 20 * time.Millisecond, MaxLatency: 60 * time.Millisecond,
	})
	mgr.RegisterWorker(fast, &domain.PerformanceProfile{ID: "profile-fast", Concurrency: 8})

	medium := jobs.NewMockWorker("mock-medium", jobs.MockWorkerConfig{
		MinLatency: 40 * time.Millisecond, MaxLatency: 120 * time.Millisecond,
	})
	mgr.RegisterWorker(medium, &domain.PerformanceProfile{ID: "profile-medium", Concurrency: 4})

	slow := jobs.NewMockWorker("mock-slow", jobs.MockWorkerConfig{
		MinLatency: 80 * time.Millisecond, MaxLatency: 200 * time.Millisecond,
	})
	// No profile yet -> unmeasured, defaults conservatively to 1 slot
	// (measurement.md honesty rule), surfaced via jobs.WorkerStatus.
	mgr.RegisterWorker(slow, nil)

	flaky := jobs.NewMockWorker("mock-flaky", jobs.MockWorkerConfig{
		MinLatency: 10 * time.Millisecond, MaxLatency: 30 * time.Millisecond,
		AlwaysFail: true,
	})
	mgr.RegisterWorker(flaky, &domain.PerformanceProfile{ID: "profile-flaky", Concurrency: 4})
}
