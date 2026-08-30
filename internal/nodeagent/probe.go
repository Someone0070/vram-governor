package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"vram-governor/internal/domain"
	"vram-governor/internal/probe"
	"vram-governor/internal/runtime"
	"vram-governor/internal/runtime/llamacpp"
)

// servingProfilesFile is the on-disk shape of configs/serving-profiles.yaml.
type servingProfilesFile struct {
	Profiles []servingProfileEntry `yaml:"profiles"`
}

type servingProfileEntry struct {
	ID             string         `yaml:"id"`
	Runtime        string         `yaml:"runtime"`
	ContextLimit   int            `yaml:"context_limit"`
	MaxSequences   int            `yaml:"max_sequences"`
	ExpectedVRAMMB int64          `yaml:"expected_vram_mb"`
	RuntimeArgs    map[string]any `yaml:"runtime_args"`
	ModelArtifact  struct {
		ID           string `yaml:"id"`
		Name         string `yaml:"name"`
		Revision     string `yaml:"revision"`
		Quantization string `yaml:"quantization"`
		Format       string `yaml:"format"`
		Tokenizer    string `yaml:"tokenizer"`
		Source       string `yaml:"source"`
	} `yaml:"model_artifact"`
}

// LoadServingProfile reads path and returns the entry matching id.
func LoadServingProfile(path, id string) (servingProfileEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return servingProfileEntry{}, fmt.Errorf("read serving profiles %s: %w", path, err)
	}
	var f servingProfilesFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return servingProfileEntry{}, fmt.Errorf("parse serving profiles %s: %w", path, err)
	}
	for _, p := range f.Profiles {
		if p.ID == id {
			return p, nil
		}
	}
	names := make([]string, 0, len(f.Profiles))
	for _, p := range f.Profiles {
		names = append(names, p.ID)
	}
	return servingProfileEntry{}, fmt.Errorf("serving profile %q not found in %s (have: %s)", id, path, strings.Join(names, ", "))
}

func (e servingProfileEntry) toDomain() (domain.ServingProfile, domain.ModelArtifact) {
	artifact := domain.ModelArtifact{
		ID: e.ModelArtifact.ID, Name: e.ModelArtifact.Name, Revision: e.ModelArtifact.Revision,
		Quantization: e.ModelArtifact.Quantization, Format: e.ModelArtifact.Format,
		Tokenizer: e.ModelArtifact.Tokenizer, Source: e.ModelArtifact.Source,
	}
	sp := domain.ServingProfile{
		ID: e.ID, ModelArtifactID: artifact.ID, Runtime: e.Runtime,
		ContextLimit: e.ContextLimit, MaxSequences: e.MaxSequences,
		RuntimeArgs: e.RuntimeArgs, ExpectedVRAMMB: e.ExpectedVRAMMB,
	}
	return sp, artifact
}

// ProbeOptions configures an on-demand Phase 2 probe run (RunProbeOnDemand).
type ProbeOptions struct {
	ProfileID        string
	ControllerAPIURL string // e.g. http://127.0.0.1:8080; empty = don't report, just print
}

// RunProbeOnDemand loads the named ServingProfile, launches it via the
// llama.cpp driver, runs the full Phase 2 measurement suite, and — if
// ControllerAPIURL is set — reports the resulting EngineInstance and
// PerformanceProfile to the controller over its HTTP API. This is the
// "on-demand" node-agent responsibility from measurement.md §4; a fuller
// on-join/background trigger is a later-phase wiring of the same call.
func RunProbeOnDemand(ctx context.Context, cfg *Config, log *slog.Logger, opts ProbeOptions) error {
	entry, err := LoadServingProfile(cfg.ServingProfilesFile, opts.ProfileID)
	if err != nil {
		return err
	}
	sp, artifact := entry.toDomain()

	driver := llamacpp.NewDriver(cfg.LlamaServerPath, cfg.GPUIndex)
	prober := probe.New(driver, cfg.GPUIndex)

	spec := runtime.LaunchSpec{Profile: sp, WorkDir: cfg.ProbeWorkDir}

	log.Info("starting Phase 2 probe", "profile_id", sp.ID, "model_path", sp.RuntimeArgs["model_path"], "work_dir", cfg.ProbeWorkDir)

	profile, engine, err := prober.Run(ctx, spec, artifact.ID, artifact.Quantization, probe.Config{})
	if err != nil {
		return fmt.Errorf("probe run failed: %w", err)
	}
	engine.NodeID = cfg.NodeID

	out, _ := json.MarshalIndent(profile, "", "  ")
	fmt.Println(string(out))

	if opts.ControllerAPIURL == "" {
		log.Info("no controller API URL set — printed profile only, not reported")
		return nil
	}

	if err := postJSON(ctx, cfg, opts.ControllerAPIURL+"/nodes/"+cfg.NodeID+"/engines", engine); err != nil {
		log.Warn("failed to report engine to controller", "err", err)
	} else {
		log.Info("reported engine instance to controller", "engine_id", engine.ID)
	}
	if err := postJSON(ctx, cfg, opts.ControllerAPIURL+"/nodes/"+cfg.NodeID+"/profiles", profile); err != nil {
		return fmt.Errorf("failed to report profile to controller: %w", err)
	}
	log.Info("reported performance profile to controller", "profile_id", profile.ID)
	return nil
}

func postJSON(ctx context.Context, cfg *Config, url string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: status %d", url, resp.StatusCode)
	}
	return nil
}
