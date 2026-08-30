// Command controller runs the unified VRAM Governor control plane, protocol
// gateways, workload scheduler, node channel, and embedded browser interfaces.
package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
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
	cfgPath := flag.String("config", "configs/controller.yaml", "path to controller config YAML")
	listenOverride := flag.String("listen", "", "optional listen address override (useful for local verification)")
	flag.Parse()

	cfg, err := api.LoadConfig(*cfgPath)
	if err != nil {
		panic(err)
	}
	if *listenOverride != "" {
		cfg.ListenAddr = *listenOverride
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
	workloadMgr.SetNodeStore(controllerStore)
	workloadMgr.RegisterAdapter(workloads.NewHTTPAdapter("llamacpp", "llama", nil))
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
		workloadMgr.RegisterTarget(workloads.Target{ID: configured.ID, Adapter: configured.Adapter, Endpoint: configured.Endpoint, AcceleratorID: configured.AcceleratorID, Models: configured.Models, ResidentModels: configured.ResidentModels, CustomNodes: configured.CustomNodes, ContextLimit: configured.ContextLimit, Slots: configured.Slots, CapabilityVersion: configured.CapabilityVersion, ModelFingerprint: configured.ModelFingerprint, CapacitySource: configured.CapacitySource, CapacityVerified: configured.CapacityVerified, SupportsModelLifecycle: configured.SupportsModelLifecycle, SupportsAcceleratorReclaim: configured.SupportsAcceleratorReclaim, MaxResidentModels: configured.MaxResidentModels, WarmRAMSupported: configured.WarmRAMSupported, ResidencyPolicy: domain.ResidencyPolicyMode(configured.ResidencyPolicy), IdleUnloadAfter: time.Duration(configured.IdleUnloadSeconds) * time.Second, MinResidency: time.Duration(configured.MinResidencySeconds) * time.Second, Cloud: configured.Cloud, Enabled: enabled, Authorization: authorization, InputCentsPerMTok: configured.InputCentsPerMTok, OutputCentsPerMTok: configured.OutputCentsPerMTok, WorkloadClass: configured.WorkloadClass, StandaloneVRAMMB: configured.StandaloneVRAMMB, AcceleratorVRAMMB: configured.AcceleratorVRAMMB, VRAMReserveMB: configured.VRAMReserveMB, SharingEnabled: configured.SharingEnabled, GuardedExploration: configured.GuardedExploration, PredictedSlowdown: configured.PredictedSlowdown, MaxSlowdown: configured.MaxSlowdown, SafetyCritical: configured.SafetyCritical, Provider: configured.Provider, Quarantined: configured.Quarantined})
	}
	srv := api.NewServer(cfg, log, controllerStore, jobsMgr, dashboard.FS())
	srv.SetWorkloadManager(workloadMgr, workloadStore)
	srv.SetArtifactStore(artifactStore)
	srv.SetAppFS(ui.FS())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	jobsMgr.Start(ctx)
	defer jobsMgr.Stop()
	workloadMgr.Start(ctx)

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

	log.Info("controller listening", "addr", cfg.ListenAddr, "tls", cfg.Production)
	serve := httpSrv.ListenAndServe
	if cfg.Production {
		serve = func() error { return httpSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile) }
	}
	if err := serve(); err != nil && err != http.ErrServerClosed {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
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
