package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
)

type creatorArtifactResponse struct {
	ArtifactID    string                        `json:"artifact_id"`
	ArtifactRef   string                        `json:"artifact_ref"`
	OwnerID       string                        `json:"owner_id"`
	WorkloadID    string                        `json:"workload_id,omitempty"`
	Name          string                        `json:"name"`
	Producer      *domain.ArtifactProducer      `json:"producer,omitempty"`
	Media         domain.ArtifactMedia          `json:"media"`
	Compatibility *domain.ArtifactCompatibility `json:"compatibility,omitempty"`
	CreatedAt     time.Time                     `json:"created_at"`
	ContentURL    string                        `json:"content_url"`
}

func publicArtifact(artifact *domain.Artifact) creatorArtifactResponse {
	return creatorArtifactResponse{ArtifactID: artifact.ID, ArtifactRef: "artifact://" + artifact.ID, OwnerID: artifact.OwnerID, WorkloadID: artifact.WorkloadID, Name: artifact.Name, Producer: artifact.Producer, Media: artifact.Media, Compatibility: artifact.Compatibility, CreatedAt: artifact.CreatedAt, ContentURL: "/api/v1/artifacts/" + artifact.ID + "/content"}
}

func (s *Server) ownedArtifact(w http.ResponseWriter, r *http.Request, principal Principal, id string) (*domain.Artifact, io.ReadCloser, bool) {
	id = stripArtifactScheme(id)
	if s.artifacts == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "artifact store unavailable"})
		return nil, nil, false
	}
	artifact, reader, err := s.artifacts.Open(r.Context(), id)
	if err != nil || (!hasScope(principal, "admin") && artifact.OwnerID != principal.OwnerID) {
		if reader != nil {
			reader.Close()
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "artifact not found"})
		return nil, nil, false
	}
	return artifact, reader, true
}

func (s *Server) handleCreatorArtifactUpload(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r, "artifacts:write")
	if !ok {
		return
	}
	if s.artifacts == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "artifact store unavailable"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, artifacts.MaxArtifactBytes+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or oversized multipart artifact upload"})
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file part is required"})
		return
	}
	defer file.Close()
	mediaType := strings.TrimSpace(header.Header.Get("Content-Type"))
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	media := domain.ArtifactMedia{MediaType: mediaType}
	if raw := strings.TrimSpace(r.FormValue("media_metadata")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &media); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "media_metadata must be valid JSON"})
			return
		}
		media.MediaType = mediaType
	}
	artifact, err := s.artifacts.PutWithMetadata(r.Context(), artifacts.PutOptions{OwnerID: principal.OwnerID, Name: header.Filename, MediaType: mediaType, Media: media}, file)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("store artifact: %v", err)})
		return
	}
	writeJSON(w, http.StatusCreated, publicArtifact(artifact))
}

func (s *Server) handleCreatorArtifactMetadata(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r, "artifacts:read")
	if !ok {
		return
	}
	artifact, reader, ok := s.ownedArtifact(w, r, principal, r.PathValue("id"))
	if !ok {
		return
	}
	reader.Close()
	writeJSON(w, http.StatusOK, publicArtifact(artifact))
}

func (s *Server) handleCreatorArtifactContent(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r, "artifacts:read")
	if !ok {
		return
	}
	artifact, reader, ok := s.ownedArtifact(w, r, principal, r.PathValue("id"))
	if !ok {
		return
	}
	defer reader.Close()
	if artifact.MediaType != "" {
		w.Header().Set("Content-Type", artifact.MediaType)
	}
	w.Header().Set("Content-Length", strconv.FormatInt(artifact.Size, 10))
	w.Header().Set("ETag", `"`+artifact.SHA256+`"`)
	_, _ = io.Copy(w, reader)
}
