package artifacts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vram-governor/internal/domain"
)

type Store interface {
	Put(context.Context, string, string, string, string, io.Reader) (*domain.Artifact, error)
	PutWithMetadata(context.Context, PutOptions, io.Reader) (*domain.Artifact, error)
	Open(context.Context, string) (*domain.Artifact, io.ReadCloser, error)
}

const MaxArtifactBytes int64 = 2 << 30

type PutOptions struct {
	OwnerID       string
	WorkloadID    string
	Name          string
	MediaType     string
	Producer      *domain.ArtifactProducer
	Media         domain.ArtifactMedia
	Compatibility *domain.ArtifactCompatibility
}

// FileStore is the development ArtifactStore. IDs, not caller filenames,
// determine paths; metadata sidecars make uploads recoverable after restart.
type FileStore struct{ root string }

func NewFileStore(root string) (*FileStore, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o750); err != nil {
		return nil, err
	}
	return &FileStore{root: abs}, nil
}

func artifactID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "art-" + hex.EncodeToString(b[:])
}

func (s *FileStore) paths(id string) (string, string, error) {
	if !strings.HasPrefix(id, "art-") || strings.ContainsAny(id, `/\\`) {
		return "", "", fmt.Errorf("invalid artifact id")
	}
	data := filepath.Join(s.root, id+".blob")
	meta := filepath.Join(s.root, id+".json")
	if filepath.Dir(data) != s.root {
		return "", "", fmt.Errorf("artifact path escaped root")
	}
	return data, meta, nil
}

func (s *FileStore) Put(ctx context.Context, ownerID, workloadID, name, mediaType string, src io.Reader) (*domain.Artifact, error) {
	return s.PutWithMetadata(ctx, PutOptions{OwnerID: ownerID, WorkloadID: workloadID, Name: name, MediaType: mediaType}, src)
}

func (s *FileStore) PutWithMetadata(ctx context.Context, options PutOptions, src io.Reader) (*domain.Artifact, error) {
	id := artifactID()
	dataPath, metaPath, _ := s.paths(id)
	temp := dataPath + ".tmp"
	f, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(f, h), &contextReader{ctx: ctx, reader: io.LimitReader(src, MaxArtifactBytes+1)})
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(temp)
		return nil, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(temp)
		return nil, closeErr
	}
	if size > MaxArtifactBytes {
		_ = os.Remove(temp)
		return nil, fmt.Errorf("artifact exceeds %d-byte limit", MaxArtifactBytes)
	}
	if err := os.Rename(temp, dataPath); err != nil {
		_ = os.Remove(temp)
		return nil, err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	artifact := &domain.Artifact{ID: id, OwnerID: options.OwnerID, WorkloadID: options.WorkloadID, Name: filepath.Base(options.Name), Producer: options.Producer, Media: options.Media, Compatibility: options.Compatibility, MediaType: options.MediaType, Size: size, StorageRef: "file://" + dataPath, SHA256: digest, CreatedAt: time.Now().UTC()}
	normalizeArtifactMetadata(artifact)
	metadata, _ := json.Marshal(artifact)
	if err := os.WriteFile(metaPath, metadata, 0o640); err != nil {
		_ = os.Remove(dataPath)
		return nil, err
	}
	return artifact, nil
}

func (s *FileStore) Open(ctx context.Context, id string) (*domain.Artifact, io.ReadCloser, error) {
	dataPath, metaPath, err := s.paths(id)
	if err != nil {
		return nil, nil, err
	}
	metadata, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, nil, err
	}
	var artifact domain.Artifact
	if err := json.Unmarshal(metadata, &artifact); err != nil {
		return nil, nil, err
	}
	normalizeArtifactMetadata(&artifact)
	f, err := os.Open(dataPath)
	if err != nil {
		return nil, nil, err
	}
	return &artifact, f, nil
}

func normalizeArtifactMetadata(artifact *domain.Artifact) {
	if artifact == nil {
		return
	}
	if artifact.MediaType == "" {
		artifact.MediaType = artifact.Media.MediaType
	}
	if artifact.Size == 0 {
		artifact.Size = artifact.Media.ByteSize
	}
	if artifact.SHA256 == "" {
		artifact.SHA256 = artifact.Media.SHA256
	}
	artifact.Media.MediaType = artifact.MediaType
	artifact.Media.ByteSize = artifact.Size
	artifact.Media.SHA256 = artifact.SHA256
	if artifact.Compatibility != nil {
		artifact.Compatibility.SourceArtifactID = artifact.ID
	}
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(p)
	}
}
