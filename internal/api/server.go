package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
	"vram-governor/internal/jobs"
	"vram-governor/internal/safefile"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
)

// Server wires together the controller's HTTP API, the node<->controller
// websocket endpoint, the node registry (store), and the liveness monitor.
type Server struct {
	cfg   *Config
	log   *slog.Logger
	nodes store.NodeStore
	// Server keeps narrow interface views even though production injects one
	// aggregate PostgreSQL authority.
	engines  store.EngineStore
	profiles store.ProfileStore
	// jobs is the compatibility work-queue engine. Nil leaves those routes 501
	// for embedders that use only unified workloads.
	jobs                       *jobs.Manager
	workloads                  *workloads.Manager
	workloadStore              store.WorkloadStore
	incidentStore              store.IncidentStore
	artifacts                  artifacts.Store
	credentials                []storedCredential
	adminNets                  []*net.IPNet
	authSessions               store.BrowserSessionStore
	enrollments                store.NodeEnrollmentStore
	commandSecret              []byte
	checkpointProofMu          sync.Mutex
	checkpointProofNonces      map[string]string
	checkpointProofIssuedAt    map[string]time.Time
	checkpointProofSessions    map[string]string
	checkpointProofHighWater   map[string]uint64
	checkpointProofFences      map[string]uint64
	checkpointProofGenerations map[string]uint64
	checkpointProofNoncePath   string
	checkpointProofNonceErr    error
	// nodeCommandExpiry is a signed reconciliation window. It is independent
	// of the caller's cancellable observation deadline; zero uses production
	// defaults, while boundary tests may shorten it to exercise expiry.
	nodeCommandExpiry     time.Duration
	nodeConnMu            sync.RWMutex
	sessionMutationMu     sync.Mutex
	nodeSessionSeq        atomic.Uint64
	nodeRecoveryMu        sync.Mutex
	nodeRecoveryTimers    map[string]*nodeRecoveryTimer
	recoveryReadFailures  map[string]int
	recoveryTimerSeq      atomic.Uint64
	recoveryLifecycleMu   sync.Mutex
	recoveryClosed        bool
	recoveryCtx           context.Context
	recoveryCancel        context.CancelFunc
	checkpointRecovery    func() error
	recoveryWG            sync.WaitGroup
	connectionLifecycleMu sync.Mutex
	connectionsClosed     bool
	activeConnections     map[*nodeConnection]struct{}
	connectionWG          sync.WaitGroup
	plugMu                sync.Mutex
	nodeConnections       map[string]*nodeConnection
	telemetryMu           sync.RWMutex
	telemetryHistory      map[string][]telemetrySnapshot
	mux                   *http.ServeMux
}

func (s *Server) SetCheckpointRecovery(recover func() error) { s.checkpointRecovery = recover }

// NewServer wires the controller's HTTP+WS surface to a backing store.
// backing must implement store.Store (NodeStore + EngineStore +
// ProfileStore + JobStore) — store.MemoryStore does. jobsMgr may be nil if
// the caller doesn't want the Phase 3 jobs API mounted.
func NewServer(cfg *Config, log *slog.Logger, backing store.Store, jobsMgr *jobs.Manager, dashboardFS http.FileSystem) *Server {
	commandSecret := cfg.Auth.CommandSigningSecret
	if cfg.Auth.CommandSigningSecretEnv != "" {
		commandSecret = os.Getenv(cfg.Auth.CommandSigningSecretEnv)
	}
	recoveryCtx, recoveryCancel := context.WithCancel(context.Background())
	s := &Server{cfg: cfg, log: log, nodes: backing, engines: backing, profiles: backing, jobs: jobsMgr, workloadStore: backing, incidentStore: backing, authSessions: backing, enrollments: backing, commandSecret: []byte(commandSecret), checkpointProofNonces: make(map[string]string), checkpointProofIssuedAt: make(map[string]time.Time), checkpointProofSessions: make(map[string]string), checkpointProofHighWater: make(map[string]uint64), checkpointProofFences: make(map[string]uint64), checkpointProofGenerations: make(map[string]uint64), nodeConnections: make(map[string]*nodeConnection), nodeRecoveryTimers: make(map[string]*nodeRecoveryTimer), recoveryReadFailures: make(map[string]int), activeConnections: make(map[*nodeConnection]struct{}), recoveryCtx: recoveryCtx, recoveryCancel: recoveryCancel, telemetryHistory: make(map[string][]telemetrySnapshot), mux: http.NewServeMux()}
	if cfg.Workloads.Checkpoint.Enabled && cfg.Workloads.Checkpoint.Root != "" {
		s.checkpointProofNoncePath = filepath.Join(cfg.Workloads.Checkpoint.Root, ".proof-nonces.json")
		if err := s.loadCheckpointProofNonces(); err != nil {
			s.checkpointProofNonceErr = err
			log.Warn("checkpoint proof replay journal unavailable; proof admission will fail closed", "error", err)
		}
	}
	s.buildCredentials()
	for _, cidr := range cfg.Auth.AdminPrivateCIDRs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Warn("ignoring invalid admin CIDR", "cidr", cidr)
			continue
		}
		s.adminNets = append(s.adminNets, block)
	}
	s.routes(dashboardFS)
	s.recoveryWG.Add(1)
	go s.resumeNodeRecoveries()
	return s
}

// loadCheckpointProofNonces restores the single-use proof journal before any
// websocket can advertise a checkpoint capability. An unreadable journal is
// deliberately retained as a fail-closed condition by validateCheckpoint...
func (s *Server) loadCheckpointProofNonces() error {
	if s.checkpointProofNoncePath == "" {
		return nil
	}
	if dirInfo, dirErr := os.Lstat(filepath.Dir(s.checkpointProofNoncePath)); dirErr == nil {
		if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() || (goruntime.GOOS != "windows" && dirInfo.Mode().Perm()&0o077 != 0) {
			return fmt.Errorf("checkpoint proof replay journal parent is unsafe")
		}
	}
	// Open the journal through the shared descriptor boundary. The helper has
	// no ordinary-open fallback, while the descriptor checks below retain the
	// journal's private/type/size policy.
	file, err := safefile.OpenReadOnlyNoFollow(s.checkpointProofNoncePath)
	if err == nil {
		opened, statErr := file.Stat()
		if statErr != nil || !privateBoundedJournalInfo(opened, 1<<20) || opened.Size() < 0 {
			_ = file.Close()
			return fmt.Errorf("checkpoint proof replay journal descriptor is unsafe")
		}
		body, readErr := io.ReadAll(io.LimitReader(file, 1<<20+1))
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(body) > 1<<20 {
			return fmt.Errorf("checkpoint proof replay journal exceeds byte bound")
		}
		return s.loadCheckpointProofNonceBody(body)
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

type checkpointProofJournal struct {
	Version     string               `json:"version"`
	Nonces      map[string]string    `json:"nonces"`
	IssuedAt    map[string]time.Time `json:"issued_at"`
	HighWater   map[string]uint64    `json:"high_water"`
	Fences      map[string]uint64    `json:"fences"`
	Generations map[string]uint64    `json:"generations"`
}

func privateBoundedJournalInfo(info os.FileInfo, maxBytes int64) bool {
	if info == nil || maxBytes <= 0 || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maxBytes {
		return false
	}
	if goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return false
	}
	value := reflect.ValueOf(info.Sys())
	if value.IsValid() && value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	if value.IsValid() && value.Kind() == reflect.Struct {
		field := value.FieldByName("Nlink")
		if field.IsValid() && field.CanUint() && field.Uint() > 1 {
			return false
		}
	}
	return true
}

func (s *Server) loadCheckpointProofNonceBody(body []byte) error {
	// Parse and validate into private maps first.  A corrupt or partial file
	// must not leave a half-loaded replay journal that can admit a proof after
	// restart.  The top-level key check also keeps an unversioned/partial v2
	// envelope from being mistaken for the explicit legacy map format.
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		if err == nil {
			err = fmt.Errorf("checkpoint proof replay journal is not an object")
		}
		return err
	}
	const version = "llm-checkpoint-proof-journal-v2"
	reserved := map[string]struct{}{"version": {}, "nonces": {}, "issued_at": {}, "high_water": {}, "fences": {}, "generations": {}}
	if versionRaw, hasVersion := raw["version"]; hasVersion {
		var got string
		if err := json.Unmarshal(versionRaw, &got); err != nil || got != version {
			if err == nil {
				err = fmt.Errorf("unknown checkpoint proof replay journal version %q", got)
			}
			return err
		}
		for key := range raw {
			if _, ok := reserved[key]; !ok {
				return fmt.Errorf("checkpoint proof replay journal contains unknown field %q", key)
			}
		}
		for _, key := range []string{"nonces", "issued_at", "high_water", "fences", "generations"} {
			value, ok := raw[key]
			if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return fmt.Errorf("checkpoint proof replay journal v2 is missing %s", key)
			}
		}
	}

	var envelope checkpointProofJournal
	legacyFormat := false
	if _, hasVersion := raw["version"]; hasVersion {
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&envelope); err != nil {
			return fmt.Errorf("checkpoint proof replay journal v2 is malformed: %w", err)
		}
	} else {
		// The only supported legacy format is an explicit object whose every
		// value is a non-empty digest string.  It cannot coexist with any v2
		// field, and it is rejected if this server already has high-water state
		// that the legacy format cannot represent.
		for key := range raw {
			if _, ok := reserved[key]; ok {
				return fmt.Errorf("checkpoint proof replay journal is an unversioned or partial v2 envelope")
			}
		}
		if len(s.checkpointProofHighWater) != 0 || len(s.checkpointProofFences) != 0 || len(s.checkpointProofGenerations) != 0 {
			return fmt.Errorf("legacy checkpoint proof replay journal would discard high-water state")
		}
		legacyFormat = true
		envelope.Version = "legacy"
		envelope.Nonces = make(map[string]string, len(raw))
		for key, value := range raw {
			var digest string
			if key == "" || json.Unmarshal(value, &digest) != nil || digest == "" {
				return fmt.Errorf("checkpoint proof replay journal legacy entry is invalid")
			}
			envelope.Nonces[key] = digest
		}
		envelope.IssuedAt = make(map[string]time.Time, len(envelope.Nonces))
		envelope.HighWater = make(map[string]uint64)
		envelope.Fences = make(map[string]uint64)
		envelope.Generations = make(map[string]uint64)
	}
	if envelope.Nonces == nil || envelope.IssuedAt == nil || envelope.HighWater == nil || envelope.Fences == nil || envelope.Generations == nil {
		return fmt.Errorf("checkpoint proof replay journal contains nil v2 map")
	}
	if len(envelope.Nonces) > 10000 || len(envelope.HighWater) > 10000 || len(envelope.Fences) > 10000 || len(envelope.Generations) > 10000 {
		return fmt.Errorf("checkpoint proof replay journal exceeds entry bound")
	}
	for key, digest := range envelope.Nonces {
		if key == "" || digest == "" {
			return fmt.Errorf("checkpoint proof replay journal contains an invalid nonce entry")
		}
		if !legacyFormat {
			if issued, ok := envelope.IssuedAt[key]; !ok || issued.IsZero() {
				return fmt.Errorf("checkpoint proof replay journal nonce %q has no issued_at", key)
			}
		}
	}
	for key := range envelope.IssuedAt {
		if _, ok := envelope.Nonces[key]; !ok {
			return fmt.Errorf("checkpoint proof replay journal issued_at key %q has no nonce", key)
		}
	}
	for key, high := range envelope.HighWater {
		if key == "" || high == 0 {
			return fmt.Errorf("checkpoint proof replay journal contains an invalid high-water entry")
		}
		if _, ok := envelope.Fences[key]; !ok {
			return fmt.Errorf("checkpoint proof replay journal high-water key %q has no fence", key)
		}
		if _, ok := envelope.Generations[key]; !ok {
			return fmt.Errorf("checkpoint proof replay journal high-water key %q has no generation", key)
		}
	}
	for key, fence := range envelope.Fences {
		if key == "" || fence == 0 {
			return fmt.Errorf("checkpoint proof replay journal contains an invalid fence entry")
		}
		if _, ok := envelope.HighWater[key]; !ok {
			return fmt.Errorf("checkpoint proof replay journal fence key %q has no high-water identity", key)
		}
		if _, ok := envelope.Generations[key]; !ok {
			return fmt.Errorf("checkpoint proof replay journal fence key %q has no generation", key)
		}
	}
	for key, generation := range envelope.Generations {
		if key == "" || generation == 0 {
			return fmt.Errorf("checkpoint proof replay journal contains an invalid generation entry")
		}
		if _, ok := envelope.HighWater[key]; !ok {
			return fmt.Errorf("checkpoint proof replay journal generation key %q has no high-water identity", key)
		}
		if _, ok := envelope.Fences[key]; !ok {
			return fmt.Errorf("checkpoint proof replay journal generation key %q has no fence", key)
		}
	}
	// Reject a downgrade before mutating the live maps.  This matters when a
	// caller reloads a journal in-process and when a stale replacement survives
	// a crash between the file and directory fsyncs.
	for key, digest := range envelope.Nonces {
		if prior, ok := s.checkpointProofNonces[key]; ok && prior != digest {
			return fmt.Errorf("checkpoint proof replay journal nonce %q conflicts with resident state", key)
		}
	}
	for key, value := range envelope.HighWater {
		if prior := s.checkpointProofHighWater[key]; prior > value {
			return fmt.Errorf("checkpoint proof replay journal high-water rollback for %q", key)
		}
	}
	for key, value := range envelope.Fences {
		if prior := s.checkpointProofFences[key]; prior > value {
			return fmt.Errorf("checkpoint proof replay journal fence rollback for %q", key)
		}
	}
	for key, value := range envelope.Generations {
		if prior := s.checkpointProofGenerations[key]; prior > value {
			return fmt.Errorf("checkpoint proof replay journal generation rollback for %q", key)
		}
	}
	if s.checkpointProofNonces == nil {
		s.checkpointProofNonces = make(map[string]string)
	}
	if s.checkpointProofIssuedAt == nil {
		s.checkpointProofIssuedAt = make(map[string]time.Time)
	}
	if s.checkpointProofHighWater == nil {
		s.checkpointProofHighWater = make(map[string]uint64)
	}
	if s.checkpointProofFences == nil {
		s.checkpointProofFences = make(map[string]uint64)
	}
	if s.checkpointProofGenerations == nil {
		s.checkpointProofGenerations = make(map[string]uint64)
	}
	for key, value := range envelope.Nonces {
		s.checkpointProofNonces[key] = value
	}
	for key, value := range envelope.IssuedAt {
		s.checkpointProofIssuedAt[key] = value
	}
	for key, value := range envelope.HighWater {
		s.checkpointProofHighWater[key] = value
	}
	for key, value := range envelope.Fences {
		s.checkpointProofFences[key] = value
	}
	for key, value := range envelope.Generations {
		s.checkpointProofGenerations[key] = value
	}
	s.compactCheckpointProofJournalLocked(time.Now().UTC())
	return nil
}

// rejectDuplicateJSONKeys performs the structural part of journal parsing
// before json.Unmarshal.  encoding/json otherwise silently keeps the last
// value for duplicate object keys, which would make a signed replay journal
// ambiguous and could hide a downgrade or conflicting identity.  Walk every
// object recursively so duplicate keys in the envelope and any nested map are
// rejected consistently.
func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := walkJSONValue(decoder, "$", true); err != nil {
		return fmt.Errorf("checkpoint proof replay journal has duplicate or malformed JSON: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON token %v", token)
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, path string, root bool) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key at %s is not a string", path)
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate object key %q at %s", key, path)
				}
				seen[key] = struct{}{}
				if err := walkJSONValue(decoder, path+"."+key, false); err != nil {
					return err
				}
			}
			end, endErr := decoder.Token()
			if endErr != nil {
				return endErr
			}
			if end != json.Delim('}') {
				return fmt.Errorf("object at %s did not terminate", path)
			}
		case '[':
			index := 0
			for decoder.More() {
				if err := walkJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index), false); err != nil {
					return err
				}
				index++
			}
			end, endErr := decoder.Token()
			if endErr != nil {
				return endErr
			}
			if end != json.Delim(']') {
				return fmt.Errorf("array at %s did not terminate", path)
			}
		default:
			return fmt.Errorf("unexpected delimiter %q at %s", delimiter, path)
		}
	default:
		if root {
			return fmt.Errorf("journal root must be an object")
		}
	}
	return nil
}

func checkpointProofIssuedAt(key string) time.Time {
	separator := strings.LastIndexByte(key, '|')
	if separator < 0 || separator+1 >= len(key) {
		return time.Time{}
	}
	nonce := key[separator+1:]
	if len(nonce) < 20 {
		return time.Time{}
	}
	nanos, err := strconv.ParseInt(nonce[:20], 10, 64)
	if err != nil || nanos <= 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos).UTC()
}

func (s *Server) compactCheckpointProofJournalLocked(now time.Time) {
	if s.checkpointProofIssuedAt == nil {
		s.checkpointProofIssuedAt = make(map[string]time.Time)
	}
	journalRetention := 48 * time.Hour
	if s.cfg != nil && s.cfg.Workloads.Checkpoint.ProofJournalRetentionSeconds > 0 {
		journalRetention = time.Duration(s.cfg.Workloads.Checkpoint.ProofJournalRetentionSeconds) * time.Second
	}
	for key := range s.checkpointProofNonces {
		issued := s.checkpointProofIssuedAt[key]
		if issued.IsZero() {
			issued = checkpointProofIssuedAt(key)
		}
		if !issued.IsZero() && now.Sub(issued) > journalRetention {
			delete(s.checkpointProofNonces, key)
			delete(s.checkpointProofIssuedAt, key)
			for sessionKey := range s.checkpointProofSessions {
				if strings.HasSuffix(sessionKey, "|"+key) {
					delete(s.checkpointProofSessions, sessionKey)
				}
			}
		}
	}
}

func (s *Server) persistCheckpointProofNoncesLocked() error {
	if s.checkpointProofNoncePath == "" {
		return nil
	}
	if s.checkpointProofNonces == nil {
		s.checkpointProofNonces = make(map[string]string)
	}
	if s.checkpointProofIssuedAt == nil {
		s.checkpointProofIssuedAt = make(map[string]time.Time)
	}
	if s.checkpointProofHighWater == nil {
		s.checkpointProofHighWater = make(map[string]uint64)
	}
	if s.checkpointProofFences == nil {
		s.checkpointProofFences = make(map[string]uint64)
	}
	if s.checkpointProofGenerations == nil {
		s.checkpointProofGenerations = make(map[string]uint64)
	}
	s.compactCheckpointProofJournalLocked(time.Now().UTC())
	envelope := checkpointProofJournal{Version: "llm-checkpoint-proof-journal-v2", Nonces: s.checkpointProofNonces, IssuedAt: s.checkpointProofIssuedAt, HighWater: s.checkpointProofHighWater, Fences: s.checkpointProofFences, Generations: s.checkpointProofGenerations}
	body, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if len(s.checkpointProofNonces) > 10000 || len(s.checkpointProofHighWater) > 10000 || len(s.checkpointProofFences) > 10000 || len(s.checkpointProofGenerations) > 10000 || len(body) > 1<<20 {
		return fmt.Errorf("checkpoint proof replay journal exceeds configured bound")
	}
	dir := filepath.Dir(s.checkpointProofNoncePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return fmt.Errorf("checkpoint proof replay journal parent is unsafe")
	}
	tmp, err := os.CreateTemp(dir, ".proof-nonces-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.checkpointProofNoncePath); err != nil {
		return err
	}
	if goruntime.GOOS != "windows" {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		syncErr := d.Sync()
		closeErr := d.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	return nil
}

// Close stops bounded recovery timers and waits for any in-flight recovery
// callbacks before the backing controller is torn down.
func (s *Server) Close() {
	if s == nil || s.recoveryCancel == nil {
		return
	}
	s.recoveryLifecycleMu.Lock()
	if s.recoveryClosed {
		s.recoveryLifecycleMu.Unlock()
		return
	}
	s.recoveryClosed = true
	s.recoveryCancel()
	s.nodeRecoveryMu.Lock()
	for id, entry := range s.nodeRecoveryTimers {
		if entry != nil && entry.timer != nil && entry.timer.Stop() {
			s.recoveryWG.Done()
		}
		delete(s.nodeRecoveryTimers, id)
	}
	s.nodeRecoveryMu.Unlock()
	s.recoveryLifecycleMu.Unlock()
	s.connectionLifecycleMu.Lock()
	if !s.connectionsClosed {
		s.connectionsClosed = true
	}
	active := make([]*nodeConnection, 0, len(s.activeConnections))
	for connection := range s.activeConnections {
		active = append(active, connection)
	}
	s.connectionLifecycleMu.Unlock()
	s.sessionMutationMu.Lock()
	s.nodeConnMu.Lock()
	connections := make([]*nodeConnection, 0, len(s.nodeConnections))
	for nodeID, connection := range s.nodeConnections {
		connections = append(connections, connection)
		delete(s.nodeConnections, nodeID)
	}
	s.nodeConnMu.Unlock()
	s.sessionMutationMu.Unlock()
	for _, connection := range active {
		connection.close()
	}
	for _, connection := range connections {
		connection.close()
	}
	s.connectionWG.Wait()
	s.recoveryWG.Wait()
}

func (s *Server) resumeNodeRecoveries() {
	defer s.recoveryWG.Done()
	for attempt := 1; ; attempt++ {
		rows, err := s.workloadStore.ListNodeCommandRecovery(s.recoveryCtx, "", "")
		if err == nil {
			for _, row := range rows {
				if row == nil || !row.Uncertain {
					continue
				}
				s.scheduleNodeRecovery(row.ID)
			}
			return
		}
		timer := time.NewTimer(recoveryBackoff(attempt))
		select {
		case <-s.recoveryCtx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *Server) SetWorkloadManager(manager *workloads.Manager, backing ...store.WorkloadStore) {
	s.workloads = manager
	if manager != nil {
		manager.SetNodeControl(s.executeNodeCommand)
		manager.SetGPUPerformanceControl(s.executeNodeCommand)
	}
	if len(backing) > 0 && backing[0] != nil {
		s.workloadStore = backing[0]
		if incidents, ok := backing[0].(store.IncidentStore); ok {
			s.incidentStore = incidents
		}
	}
}
func (s *Server) SetArtifactStore(store artifacts.Store) { s.artifacts = store }

func (s *Server) SetAppFS(appFS fs.FS) {
	s.mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(appFS))))
	s.mux.HandleFunc("GET /studio", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/studio/", http.StatusPermanentRedirect)
	})
	s.mux.HandleFunc("GET /studio/", func(w http.ResponseWriter, r *http.Request) {
		s.serveAppHTML(w, r, appFS, "studio.html", false)
	})
	s.mux.HandleFunc("GET /chat", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/chat/", http.StatusPermanentRedirect)
	})
	s.mux.HandleFunc("GET /chat/", func(w http.ResponseWriter, r *http.Request) {
		s.serveAppHTML(w, r, appFS, "chat.html", false)
	})
	s.mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusPermanentRedirect)
	})
	s.mux.HandleFunc("GET /admin/", func(w http.ResponseWriter, r *http.Request) {
		s.serveAppHTML(w, r, appFS, "admin.html", true)
	})
}

func (s *Server) serveAppHTML(w http.ResponseWriter, r *http.Request, appFS fs.FS, name string, admin bool) {
	if admin {
		if !s.adminRemoteAllowed(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin_network_denied"})
			return
		}
	}
	data, err := fs.ReadFile(appFS, name)
	if err != nil {
		http.Error(w, "interface unavailable", http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

func (s *Server) Handler() http.Handler { return s.securityMiddleware(s.mux) }

// RunLivenessMonitor periodically scans the node registry and flips observed
// connectivity between connected/suspect/lost based on time since last
// heartbeat, per architecture.md §34A. It runs until ctx is cancelled.
func (s *Server) RunLivenessMonitor(ctx context.Context) {
	interval := time.Duration(s.cfg.Liveness.HeartbeatIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 2 * time.Second
	}
	suspectAfter := time.Duration(s.cfg.Liveness.SuspectAfterSeconds) * time.Second
	lostAfter := time.Duration(s.cfg.Liveness.LostAfterSeconds) * time.Second

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepLiveness(ctx, suspectAfter, lostAfter)
			s.reconcileIncidentAnalyses(ctx)
		}
	}
}

func (s *Server) reconcileIncidentAnalyses(ctx context.Context) {
	if s.incidentStore == nil || s.workloads == nil {
		return
	}
	incidents, err := s.incidentStore.ListIncidents(ctx, "")
	if err != nil {
		s.log.Warn("incident analysis reconciliation failed", "error", err)
		return
	}
	for _, incident := range incidents {
		s.syncIncidentAnalysis(ctx, incident)
	}
}

func (s *Server) sweepLiveness(ctx context.Context, suspectAfter, lostAfter time.Duration) {
	nodes, err := s.nodes.ListNodes(ctx)
	if err != nil {
		s.log.Error("liveness sweep: list nodes failed", "err", err)
		return
	}
	now := time.Now().UTC()
	for _, n := range nodes {
		if n.Observed.LastHeartbeat.IsZero() {
			continue
		}
		age := now.Sub(n.Observed.LastHeartbeat)
		s.nodeConnMu.RLock()
		_, transportConnected := s.nodeConnections[n.ID]
		s.nodeConnMu.RUnlock()
		hardLostAfter := 3 * lostAfter
		if hardLostAfter < lostAfter+30*time.Second {
			hardLostAfter = lostAfter + 30*time.Second
		}
		var want domain.ConnectivityState
		switch {
		case age >= lostAfter && (!transportConnected || age >= hardLostAfter):
			want = domain.ConnectivityLost
		case age >= suspectAfter:
			want = domain.ConnectivitySuspect
		default:
			want = domain.ConnectivityConnected
		}
		if want == n.Observed.Connectivity {
			continue
		}
		id := n.ID
		prev := n.Observed.Connectivity
		err := s.nodes.UpdateObserved(ctx, id, func(o *domain.Observed, _ *[]domain.Accelerator) {
			o.Connectivity = want
			if want == domain.ConnectivityLost {
				o.Ready = false
				o.Lifecycle = domain.LifecycleOffline
			}
		})
		if err != nil {
			s.log.Error("liveness sweep: update failed", "node", id, "err", err)
			continue
		}
		s.log.Info("node connectivity transition", "node", id, "from", prev, "to", want, "heartbeat_age_s", age.Seconds())
		s.reconcileNodeConnectivityIncident(ctx, n, prev, want)
	}
}

func (s *Server) nodeLossMonitoringEnabled() bool {
	return s.cfg.Agents.MonitorNodeLoss == nil || *s.cfg.Agents.MonitorNodeLoss
}

func (s *Server) reconcileNodeConnectivityIncident(ctx context.Context, node *domain.Node, previous, current domain.ConnectivityState) {
	if !s.nodeLossMonitoringEnabled() || s.incidentStore == nil || node == nil {
		return
	}
	evidenceRef := "node:" + node.ID
	incidents, err := s.incidentStore.ListIncidents(ctx, "system")
	if err != nil {
		s.log.Warn("node-loss incident reconciliation failed", "node", node.ID, "error", err)
		return
	}
	var active, recentlyRecovered *domain.Incident
	for _, incident := range incidents {
		if incident.Status == "closed" {
			continue
		}
		if incident.Status == "recovered" {
			// A node that drops again within half an hour reopens the same
			// incident: a flapping link made ~75 new incidents an hour.
			if time.Since(incident.UpdatedAt) < 30*time.Minute && (recentlyRecovered == nil || incident.UpdatedAt.After(recentlyRecovered.UpdatedAt)) {
				for _, evidence := range incident.EvidenceRefs {
					if evidence == evidenceRef {
						recentlyRecovered = incident
					}
				}
			}
			continue
		}
		for _, evidence := range incident.EvidenceRefs {
			if evidence == evidenceRef {
				active = incident
				break
			}
		}
		if active != nil {
			break
		}
	}
	now := time.Now().UTC()
	if current == domain.ConnectivityLost {
		if active != nil {
			return
		}
		if recentlyRecovered != nil {
			recentlyRecovered.Status = "open"
			recentlyRecovered.UpdatedAt = now
			if !strings.Contains(recentlyRecovered.Summary, "(repeated)") {
				recentlyRecovered.Summary += " (repeated)"
			}
			if _, err := s.incidentStore.UpdateIncident(ctx, recentlyRecovered); err != nil {
				s.log.Warn("node-loss incident reopen failed", "node", node.ID, "error", err)
			}
			return
		}
		name := node.Name
		if name == "" {
			name = node.ID
		}
		incident := &domain.Incident{ID: "inc-" + randomSecret()[:24], OwnerID: "system", Severity: "S2", Confidence: .99, Summary: "Node lost: " + name, EvidenceRefs: []string{evidenceRef}, Status: "open", CreatedAt: now, UpdatedAt: now}
		if _, err := s.incidentStore.CreateIncident(ctx, incident); err != nil {
			s.log.Warn("node-loss incident creation failed", "node", node.ID, "error", err)
			return
		}
		payload, _ := json.Marshal(map[string]any{"node_id": node.ID, "previous": previous, "current": current})
		_ = s.workloadStore.AppendAuditEvent(ctx, &domain.AuditEvent{ID: "evt-" + randomSecret()[:24], Timestamp: now, OwnerID: "system", Type: "incident.node_lost", Severity: "warn", Payload: payload})
		return
	}
	if current == domain.ConnectivityConnected && active != nil {
		active.Status = "recovered"
		active.UpdatedAt = now
		if _, err := s.incidentStore.UpdateIncident(ctx, active); err != nil {
			s.log.Warn("node-loss incident recovery update failed", "node", node.ID, "error", err)
			return
		}
		payload, _ := json.Marshal(map[string]any{"node_id": node.ID, "previous": previous, "current": current, "incident_id": active.ID})
		_ = s.workloadStore.AppendAuditEvent(ctx, &domain.AuditEvent{ID: "evt-" + randomSecret()[:24], Timestamp: now, OwnerID: "system", Type: "incident.node_recovered", Severity: "info", Payload: payload})
	}
}
