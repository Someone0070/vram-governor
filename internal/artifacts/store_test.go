package artifacts

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"vram-governor/internal/domain"
)

func TestFileStoreRoundTripAndTraversalRejection(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := store.Put(context.Background(), "owner", "workload", "../unsafe.png", "image/png", strings.NewReader("bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Name != "unsafe.png" || artifact.Size != 5 {
		t.Fatalf("bad metadata: %+v", artifact)
	}
	metadata, reader, err := store.Open(context.Background(), artifact.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, _ := io.ReadAll(reader)
	if metadata.OwnerID != "owner" || string(data) != "bytes" {
		t.Fatalf("round trip mismatch: %+v %q", metadata, data)
	}
	if _, _, err := store.Open(context.Background(), "../escape"); err == nil {
		t.Fatal("path traversal artifact id was accepted")
	}
}

func TestArtifactProvenanceRoundTrip(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	producer := &domain.ArtifactProducer{ProfileID: "video_impl", ProfileVersion: "8", ProfileDigest: "digest-8", CapabilityRevision: "4", Operation: "video.generate"}
	compatibility := &domain.ArtifactCompatibility{ProducerImplementation: "video_impl@8", CapabilityRevision: "4", Tokens: map[string]string{"video.continue_sequence": "opaque-token"}}
	created, err := store.PutWithMetadata(context.Background(), PutOptions{OwnerID: "owner", WorkloadID: "workload", Name: "result.mp4", MediaType: "video/mp4", Media: domain.ArtifactMedia{Width: 1920, Height: 1080, FrameRate: 24, DurationMS: 1000}, Producer: producer, Compatibility: compatibility}, strings.NewReader("video bytes"))
	if err != nil {
		t.Fatal(err)
	}
	opened, reader, err := store.Open(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	if opened.Producer == nil || opened.Producer.ProfileDigest != "digest-8" || opened.Media.MediaType != "video/mp4" || opened.Media.Width != 1920 || opened.Media.ByteSize != int64(len("video bytes")) || opened.Compatibility == nil || opened.Compatibility.SourceArtifactID != opened.ID || opened.Compatibility.Tokens["video.continue_sequence"] != "opaque-token" {
		t.Fatalf("artifact metadata did not survive lookup: %+v", opened)
	}
}

func TestS3StoreRoundTripUsesSigV4AndDurableMetadata(t *testing.T) {
	var mu sync.Mutex
	var data []byte
	var metadata string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=access/") || r.Header.Get("X-Amz-Content-Sha256") == "" {
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodPut:
			mu.Lock()
			data, _ = io.ReadAll(r.Body)
			metadata = r.Header.Get("X-Amz-Meta-Vram-Governor")
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			mu.Lock()
			defer mu.Unlock()
			w.Header().Set("X-Amz-Meta-Vram-Governor", metadata)
			_, _ = w.Write(data)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	store, err := NewS3Store(S3Options{Endpoint: server.URL, Bucket: "artifacts", Region: "test-1", AccessKey: "access", SecretKey: "secret", Client: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	producer := &domain.ArtifactProducer{ProfileID: "director_hosted", ProfileVersion: "4", ProfileDigest: "hosted-digest", CapabilityRevision: "2", CapabilityDefinitionHash: "definition-hash", Operation: "llm.inference"}
	compatibility := &domain.ArtifactCompatibility{ProducerImplementation: "director_hosted@4", CapabilityRevision: "2", CapabilityDefinitionHash: "definition-hash", Tokens: map[string]string{"llm.inference": "opaque-token"}}
	artifact, err := store.PutWithMetadata(context.Background(), PutOptions{OwnerID: "owner", WorkloadID: "workload", Name: "output.bin", MediaType: "application/octet-stream", Producer: producer, Compatibility: compatibility}, strings.NewReader("durable bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(artifact.StorageRef, "s3://artifacts/") {
		t.Fatalf("unexpected storage ref: %+v", artifact)
	}
	opened, reader, err := store.Open(context.Background(), artifact.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, _ := io.ReadAll(reader)
	if opened.OwnerID != "owner" || string(got) != "durable bytes" || opened.SHA256 != artifact.SHA256 || opened.Producer == nil || opened.Producer.ProfileDigest != "hosted-digest" || opened.Compatibility == nil || opened.Compatibility.SourceArtifactID != artifact.ID || opened.Compatibility.Tokens["llm.inference"] != "opaque-token" {
		t.Fatalf("S3 round trip mismatch: %+v data=%q", opened, got)
	}
}
