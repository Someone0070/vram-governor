package api

import (
	"encoding/json"
	"net/http"

	"vram-governor/internal/domain"
	"vram-governor/internal/jobs"
	"vram-governor/internal/store"
)

// submitJobRequest is the POST /jobs body shape (architecture.md §33).
// Each item carries a simple payload map (a {"prompt": "..."} completion-
// style request in this phase, since no real engine is used — see
// docs Phase 3 scope).
type submitJobRequest struct {
	Operation   string           `json:"operation"`
	Pool        string           `json:"pool"`
	MaxAttempts int              `json:"max_attempts,omitempty"`
	Items       []jobs.ItemInput `json:"items"`
}

// jobDetailResponse is the GET /jobs/{id} shape: the job (with §29 progress
// fields), its work items, and worker-pool visibility (including the
// unmeasured-capacity flag, per docs/measurement.md's honesty rule).
type jobDetailResponse struct {
	*domain.Job
	Items   []*domain.WorkItem  `json:"items"`
	Workers []jobs.WorkerStatus `json:"workers"`
}

func (s *Server) jobsUnavailable(w http.ResponseWriter) bool {
	if s.jobs == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "job queue not enabled on this server"})
		return true
	}
	return false
}

func (s *Server) handleSubmitJob(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(w, r, "jobs:submit"); !ok {
		return
	}
	if s.jobsUnavailable(w) {
		return
	}
	var req submitJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad job payload: " + err.Error()})
		return
	}
	if len(req.Items) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "items must not be empty"})
		return
	}
	job, err := s.jobs.SubmitJob(req.Operation, req.Pool, req.Items, req.MaxAttempts)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, job)
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(w, r, "jobs:read"); !ok {
		return
	}
	if s.jobsUnavailable(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.jobs.ListJobs())
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(w, r, "jobs:read"); !ok {
		return
	}
	if s.jobsUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	job, items, err := s.jobs.GetJob(id)
	if err != nil {
		if err == store.ErrNotFound {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, jobDetailResponse{Job: job, Items: items, Workers: s.jobs.Workers()})
}

func (s *Server) handlePauseJob(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(w, r, "jobs:mutate"); !ok {
		return
	}
	if s.jobsUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	if err := s.jobs.PauseJob(id); err != nil {
		if err == store.ErrNotFound {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "paused"})
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(w, r, "jobs:mutate"); !ok {
		return
	}
	if s.jobsUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	if err := s.jobs.CancelJob(id); err != nil {
		if err == store.ErrNotFound {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}
