package workloads

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"vram-governor/internal/domain"
)

// ResultExport copies the final media outputs of succeeded workloads to a
// plain directory (on CT200's network the NAS share), named for people:
//
//	<dir>/2026-10-12/image-krea2-turbo_fox-1.png  (+ .json with prompt/seed)
//
// It is best effort: the artifact store stays authoritative, and a failed
// copy is logged, never surfaced as a workload failure. Intermediate files
// are never exported; only artifacts recorded as a workload's outputs are.
type ResultExport struct {
	Dir        string
	MediaTypes []string // e.g. image/*, video/*, audio/*
}

// SetResultExport enables exporting; an empty Dir disables it.
func (m *Manager) SetResultExport(export ResultExport) {
	m.mu.Lock()
	m.resultExport = export
	m.mu.Unlock()
}

var exportNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func exportSafeName(value string) string {
	value = strings.Trim(exportNameUnsafe.ReplaceAllString(value, "-"), "-.")
	if len(value) > 80 {
		value = value[:80]
	}
	return value
}

type exportSidecar struct {
	WorkloadID string          `json:"workload_id"`
	OwnerID    string          `json:"owner_id"`
	Operation  string          `json:"operation,omitempty"`
	Workflow   json.RawMessage `json:"workflow,omitempty"`
	ProfileID  string          `json:"profile,omitempty"`
	ArtifactID string          `json:"artifact_id"`
	MediaType  string          `json:"media_type"`
	SHA256     string          `json:"sha256,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

// exportResults runs in the background after a workload succeeded.
func (m *Manager) exportResults(workload *domain.Workload) {
	m.mu.RLock()
	export, store := m.resultExport, m.artifacts
	m.mu.RUnlock()
	if export.Dir == "" || store == nil || workload == nil || len(workload.OutputRefs) == 0 {
		return
	}
	snapshot := *workload
	snapshot.OutputRefs = append([]string(nil), workload.OutputRefs...)
	go func() {
		if err := m.writeResultExport(m.lifecycleContext(), export, &snapshot); err != nil {
			m.log.Warn("result export failed", "workload_id", snapshot.Request.ID, "error", err)
		}
	}()
}

func (m *Manager) writeResultExport(ctx context.Context, export ResultExport, workload *domain.Workload) error {
	var payload struct {
		Workflow json.RawMessage `json:"workflow"`
	}
	_ = json.Unmarshal(workload.Request.Payload, &payload)
	var workflow struct {
		Ref string `json:"ref"`
	}
	_ = json.Unmarshal(payload.Workflow, &workflow)
	label := strings.SplitN(workflow.Ref, "@", 2)[0]
	if label == "" {
		label = workload.Request.Operation
	}
	if label == "" {
		label = workload.Request.Adapter
	}
	finished := time.Now()
	if workload.FinishedAt != nil {
		finished = *workload.FinishedAt
	}
	dir := filepath.Join(export.Dir, finished.Local().Format("2006-01-02"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	base := exportSafeName(label) + "_" + exportSafeName(workload.Request.ID)
	exported := 0
	for _, ref := range workload.OutputRefs {
		artifact, reader, err := m.artifacts.Open(ctx, ref)
		if err != nil {
			return fmt.Errorf("open %s: %w", ref, err)
		}
		if !MediaTypeMatches(export.MediaTypes, artifact.MediaType) {
			reader.Close()
			continue
		}
		name := base
		if exported > 0 {
			name = fmt.Sprintf("%s_%d", base, exported+1)
		}
		ext := strings.ToLower(filepath.Ext(artifact.Name))
		if ext == "" {
			if exts, _ := mime.ExtensionsByType(artifact.MediaType); len(exts) > 0 {
				ext = exts[0]
			}
		}
		err = writeExportFile(filepath.Join(dir, name+ext), reader)
		reader.Close()
		if err != nil {
			return err
		}
		sidecar, _ := json.MarshalIndent(exportSidecar{
			WorkloadID: workload.Request.ID, OwnerID: workload.Request.OwnerID, Operation: workload.Request.Operation,
			Workflow: payload.Workflow, ProfileID: workload.Decision.ProfileID, ArtifactID: artifact.ID,
			MediaType: artifact.MediaType, SHA256: artifact.SHA256, CreatedAt: workload.CreatedAt, FinishedAt: workload.FinishedAt,
		}, "", "  ")
		if err := writeExportFile(filepath.Join(dir, name+".json"), strings.NewReader(string(sidecar)+"\n")); err != nil {
			return err
		}
		exported++
	}
	return nil
}

// writeExportFile writes through a temporary name so a reader of the share
// never sees a partial file.
func writeExportFile(path string, content io.Reader) error {
	tmp := filepath.Join(filepath.Dir(path), ".partial-"+filepath.Base(path))
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, content); err != nil {
		file.Close()
		os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
