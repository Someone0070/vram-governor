package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vram-governor/internal/wsproto"
)

type commandProcessor struct {
	cfg     *Config
	log     *slog.Logger
	mu      sync.Mutex
	results map[string]wsproto.CommandResultPayload
}

func newCommandProcessor(cfg *Config, log *slog.Logger) *commandProcessor {
	processor := &commandProcessor{cfg: cfg, log: log, results: make(map[string]wsproto.CommandResultPayload)}
	processor.load()
	return processor
}

func (p *commandProcessor) Handle(ctx context.Context, command wsproto.CommandPayload) wsproto.CommandResultPayload {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cached, ok := p.results[command.ID]; ok {
		return cached
	}
	if cached, ok := p.results["key:"+command.IdempotencyKey]; ok {
		return cached
	}
	result := wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, CompletedAt: time.Now().UTC()}
	p.log.Info("node command received", "command_id", command.ID, "command", command.Command)
	switch {
	case len(p.cfg.CommandSigningSecret) < 16:
		result.Error = "node command signing is not configured"
	case command.ID == "" || command.IdempotencyKey == "":
		result.Error = "command identity is required"
	case command.NodeID != p.cfg.NodeID:
		result.Error = "command is bound to a different node"
	case !wsproto.VerifyCommand(command, []byte(p.cfg.CommandSigningSecret)):
		result.Error = "invalid command signature"
	case time.Now().UTC().After(command.ExpiresAt):
		result.Error = "command expired"
	case command.IssuedAt.After(time.Now().UTC().Add(2 * time.Minute)):
		result.Error = "command issue time is in the future"
	default:
		commandCtx, cancel := context.WithDeadline(ctx, command.ExpiresAt)
		result.Result, result.Error = p.execute(commandCtx, command)
		cancel()
		result.OK = result.Error == ""
	}
	result.CompletedAt = time.Now().UTC()
	if result.OK {
		p.log.Info("node command completed", "command_id", command.ID, "command", command.Command)
	} else {
		p.log.Warn("node command failed", "command_id", command.ID, "command", command.Command, "error", result.Error)
	}
	p.results[command.ID] = result
	p.results["key:"+command.IdempotencyKey] = result
	p.save()
	return result
}

func (p *commandProcessor) execute(ctx context.Context, command wsproto.CommandPayload) (map[string]any, string) {
	switch command.Command {
	case "refresh_capabilities":
		advertisements := discoverAdapters(ctx, p.cfg, p.log)
		return map[string]any{"adapters": advertisements}, ""
	case "load_model", "unload_model":
		targetID, _ := command.Args["target_id"].(string)
		model, _ := command.Args["model"].(string)
		if targetID == "" || model == "" {
			return nil, "target_id and model are required"
		}
		server, ok := p.routerTarget(targetID)
		if !ok {
			return nil, "target is not an allowlisted local inference server"
		}
		discovery, err := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
		if err != nil {
			return nil, "router discovery failed: " + err.Error()
		}
		available := false
		for _, candidate := range discovery.Models {
			if candidate == model {
				available = true
				break
			}
		}
		if !available {
			return nil, "model is not allowlisted by router discovery"
		}
		if !discovery.SupportsModelLifecycle {
			return nil, "target runtime does not expose lifecycle control"
		}
		load := command.Command == "load_model"
		if err := mutateRuntimeModel(ctx, server, model, load); err != nil {
			return nil, err.Error()
		}
		for {
			observed, observeErr := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
			if observeErr == nil {
				resident := false
				for _, candidate := range observed.ResidentModels {
					if candidate == model {
						resident = true
						break
					}
				}
				if resident == load {
					break
				}
			}
			select {
			case <-ctx.Done():
				return nil, "router did not confirm model state before command expiry"
			case <-time.After(100 * time.Millisecond):
			}
		}
		return map[string]any{"target_id": targetID, "model": model, "resident": load}, ""
	case "reclaim_accelerator":
		targetID, _ := command.Args["target_id"].(string)
		if targetID != p.cfg.NodeID+"-comfy" || p.cfg.ComfyUI.Endpoint == "" {
			return nil, "target is not the allowlisted local ComfyUI runtime"
		}
		if err := reclaimComfy(ctx, p.cfg.ComfyUI.Endpoint); err != nil {
			return nil, err.Error()
		}
		return map[string]any{"target_id": targetID, "reclaimed": true}, ""
	case "drain_runtimes":
		return p.drainRuntimes(ctx)
	default:
		return nil, "command is not allowlisted"
	}
}

func (p *commandProcessor) drainRuntimes(ctx context.Context) (map[string]any, string) {
	unloaded := make([]string, 0)
	for _, server := range p.cfg.LlamaCPP.Servers {
		discovery, err := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
		if err != nil {
			return nil, "runtime discovery failed: " + err.Error()
		}
		for _, model := range discovery.ResidentModels {
			if err := mutateRuntimeModel(ctx, server, model, false); err != nil {
				return nil, err.Error()
			}
			unloaded = append(unloaded, server.ID+":"+model)
		}
	}
	comfyReclaimed := false
	if p.cfg.ComfyUI.Endpoint != "" {
		if err := reclaimComfy(ctx, p.cfg.ComfyUI.Endpoint); err != nil {
			return nil, err.Error()
		}
		comfyReclaimed = true
	}
	return map[string]any{"unloaded_models": unloaded, "comfy_reclaimed": comfyReclaimed}, ""
}

func (p *commandProcessor) routerTarget(targetID string) (LlamaCPPServerConfig, bool) {
	shortID := strings.TrimPrefix(targetID, p.cfg.NodeID+"-")
	for _, server := range p.cfg.LlamaCPP.Servers {
		if server.ID == targetID || server.ID == shortID {
			return server, true
		}
	}
	return LlamaCPPServerConfig{}, false
}

func mutateRouterModel(ctx context.Context, endpoint, model string, load bool) error {
	path := "/models/unload"
	if load {
		path = "/models/load"
	}
	body, _ := json.Marshal(map[string]string{"model": model})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("router mutation returned %d: %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	return nil
}

func mutateRuntimeModel(ctx context.Context, server LlamaCPPServerConfig, model string, load bool) error {
	if isOllamaServer(ctx, server) {
		keepAlive := 0
		if load {
			keepAlive = -1
		}
		body, _ := json.Marshal(map[string]any{"model": model, "prompt": "", "stream": false, "keep_alive": keepAlive})
		if err := postRuntimeJSON(ctx, strings.TrimRight(server.Endpoint, "/")+"/api/generate", body, "Ollama model transition"); err != nil {
			return err
		}
		return nil
	}
	if !server.RouterManaged {
		return fmt.Errorf("runtime lifecycle was discovered but no allowlisted mutation protocol is configured")
	}
	return mutateRouterModel(ctx, server.Endpoint, model, load)
}

func isOllamaServer(ctx context.Context, server LlamaCPPServerConfig) bool {
	for _, argument := range server.RuntimeArgs {
		if strings.Contains(strings.ToLower(argument), "ollama") {
			return true
		}
	}
	_, err := getJSON(ctx, strings.TrimRight(server.Endpoint, "/")+"/api/ps")
	return err == nil
}

func reclaimComfy(ctx context.Context, endpoint string) error {
	body, _ := json.Marshal(map[string]bool{"unload_models": true, "free_memory": true})
	return postRuntimeJSON(ctx, strings.TrimRight(endpoint, "/")+"/free", body, "ComfyUI runtime drain")
}

func postRuntimeJSON(ctx context.Context, url string, body []byte, operation string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("%s returned %d: %s", operation, response.StatusCode, strings.TrimSpace(string(message)))
	}
	return nil
}

func (p *commandProcessor) load() {
	body, err := os.ReadFile(p.cfg.CommandStatePath)
	if err == nil {
		_ = json.Unmarshal(body, &p.results)
	}
}

func (p *commandProcessor) save() {
	if p.cfg.CommandStatePath == "" {
		return
	}
	body, err := json.MarshalIndent(p.results, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p.cfg.CommandStatePath), 0o700); err != nil {
		return
	}
	_ = os.WriteFile(p.cfg.CommandStatePath, body, 0o600)
}
