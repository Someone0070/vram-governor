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
	Open(context.Context, string) (*domain.Artifact, io.ReadCloser, error)
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
	id := artifactID()
	dataPath, metaPath, _ := s.paths(id)
	temp := dataPath + ".tmp"
	f, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(f, h), &contextReader{ctx: ctx, reader: io.LimitReader(src, 2<<30)})
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(temp)
		return nil, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(temp)
		return nil, closeErr
	}
	if err := os.Rename(temp, dataPath); err != nil {
		_ = os.Remove(temp)
		return nil, err
	}
	artifact := &domain.Artifact{ID: id, OwnerID: ownerID, WorkloadID: workloadID, Name: filepath.Base(name), MediaType: mediaType, Size: size, StorageRef: "file://" + dataPath, SHA256: hex.EncodeToString(h.Sum(nil)), CreatedAt: time.Now().UTC()}
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
	f, err := os.Open(dataPath)
	if err != nil {
		return nil, nil, err
	}
	return &artifact, f, nil
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
