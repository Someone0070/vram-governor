package workloads

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func TestResultExportCopiesFinalMediaWithSidecar(t *testing.T) {
	ctx := context.Background()
	artifactStore, err := artifacts.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	image, _ := artifactStore.Put(ctx, "owner", "fox-1", "krea2_00001_.png", "image/png", strings.NewReader("png-bytes"))
	second, _ := artifactStore.Put(ctx, "owner", "fox-1", "krea2_00002_.png", "image/png", strings.NewReader("png-2"))
	manifest, _ := artifactStore.Put(ctx, "owner", "fox-1", "result.json", "application/json", strings.NewReader("{}"))
	manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	manager.SetArtifactStore(artifactStore)
	dir := t.TempDir()
	export := ResultExport{Dir: dir, MediaTypes: []string{"image/*", "video/*"}}
	finished := time.Date(2026, 10, 12, 15, 0, 0, 0, time.Local)
	workload := &domain.Workload{
		Request:    domain.WorkloadRequest{ID: "fox-1", OwnerID: "owner", Operation: "image.generate", Payload: json.RawMessage(`{"managed_chunks":[],"workflow":{"ref":"image-krea2-turbo@1","params":{"prompt":"a fox","seed":7}}}`)},
		OutputRefs: []string{manifest.ID, image.ID, second.ID},
		FinishedAt: &finished,
	}
	if err := manager.writeResultExport(ctx, export, workload); err != nil {
		t.Fatal(err)
	}
	day := filepath.Join(dir, "2026-10-12")
	entries, _ := os.ReadDir(day)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := "image-krea2-turbo_fox-1.json,image-krea2-turbo_fox-1.png,image-krea2-turbo_fox-1_2.json,image-krea2-turbo_fox-1_2.png"
	if strings.Join(names, ",") != want {
		t.Fatalf("exported %v, want %s", names, want)
	}
	if data, _ := os.ReadFile(filepath.Join(day, "image-krea2-turbo_fox-1.png")); string(data) != "png-bytes" {
		t.Fatalf("image content = %q", data)
	}
	var sidecar map[string]any
	data, _ := os.ReadFile(filepath.Join(day, "image-krea2-turbo_fox-1.json"))
	if err := json.Unmarshal(data, &sidecar); err != nil {
		t.Fatal(err)
	}
	workflow, _ := sidecar["workflow"].(map[string]any)
	params, _ := workflow["params"].(map[string]any)
	if sidecar["artifact_id"] != image.ID || workflow["ref"] != "image-krea2-turbo@1" || params["prompt"] != "a fox" {
		t.Fatalf("sidecar = %s", data)
	}
}

func TestResultExportNamesRawGraphRunsByOperation(t *testing.T) {
	ctx := context.Background()
	artifactStore, _ := artifacts.NewFileStore(t.TempDir())
	video, _ := artifactStore.Put(ctx, "owner", "x", "out.mp4", "video/mp4", strings.NewReader("mp4"))
	manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	manager.SetArtifactStore(artifactStore)
	dir := t.TempDir()
	workload := &domain.Workload{Request: domain.WorkloadRequest{ID: "studio/../run 1", Operation: "video.image_to_video", Payload: json.RawMessage(`{"managed_chunks":[]}`)}, OutputRefs: []string{video.ID}}
	if err := manager.writeResultExport(ctx, ResultExport{Dir: dir, MediaTypes: []string{"video/*"}}, workload); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*", "video.image_to_video_studio-..-run-1.mp4"))
	if len(matches) != 1 {
		all, _ := filepath.Glob(filepath.Join(dir, "*", "*"))
		t.Fatalf("raw graph export names = %v", all)
	}
}

func TestResultExportSkipsWhenDiskIsNearlyFull(t *testing.T) {
	ctx := context.Background()
	artifactStore, _ := artifacts.NewFileStore(t.TempDir())
	image, _ := artifactStore.Put(ctx, "owner", "x", "a.png", "image/png", strings.NewReader("png"))
	manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	manager.SetArtifactStore(artifactStore)
	original := exportDiskFree
	defer func() { exportDiskFree = original }()
	exportDiskFree = func(string) (int64, error) { return 512 << 20, nil }
	dir := t.TempDir()
	workload := &domain.Workload{Request: domain.WorkloadRequest{ID: "x", Operation: "image.generate", Payload: json.RawMessage(`{}`)}, OutputRefs: []string{image.ID}}
	err := manager.writeResultExport(ctx, ResultExport{Dir: dir, MediaTypes: []string{"image/*"}}, workload)
	if err == nil || !strings.Contains(err.Error(), "export skipped") {
		t.Fatalf("err = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("wrote %d entries despite low disk", len(entries))
	}
	exportDiskFree = func(string) (int64, error) { return 10 << 30, nil }
	if err := manager.writeResultExport(ctx, ResultExport{Dir: dir, MediaTypes: []string{"image/*"}}, workload); err != nil {
		t.Fatal(err)
	}
}
