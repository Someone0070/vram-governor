package workloads

// Production LLM checkpointing is intentionally a separate path from the
// runtime capability probe.  The probe may establish that llama.cpp accepts a
// slot save/restore request; this coordinator is the only code that may turn
// that fact into an admission/preemption promise.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	goruntime "runtime"
	"strings"
	"sync"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/runtime"
	"vram-governor/internal/safefile"
	"vram-governor/internal/store"
	"vram-governor/internal/wsproto"
)

var ErrCheckpointUnavailable = errors.New("llm checkpoint capability is not proven")
var ErrCheckpointConflict = errors.New("llm checkpoint command is stale or fenced")
var ErrCheckpointNotFound = errors.New("llm checkpoint state not_found")
var ErrSnapshotActiveReferences = errors.New("snapshot has active references")
var ErrSnapshotNotTerminalized = errors.New("snapshot is not terminalized")
var ErrSnapshotDeleteExpectation = errors.New("snapshot delete expectation does not match")

type CheckpointPolicy struct {
	Locked           bool
	Pinned           bool
	Manual           bool
	Off              bool
	NoConsent        bool
	Priority         int
	PreemptionBudget int
}

func (p CheckpointPolicy) EligibleForUrgent(newPriority int) bool {
	if p.Locked || p.Pinned || p.Manual || p.Off || p.NoConsent || p.PreemptionBudget <= 0 {
		return false
	}
	return p.Priority < newPriority
}

type CheckpointCommand struct {
	ID                         string `json:"id"`
	IdempotencyKey             string `json:"idempotency_key"`
	OwnerID                    string `json:"owner_id"`
	WorkloadID                 string `json:"workload_id"`
	Generation                 uint64 `json:"generation"`
	RuntimeIdentity            string `json:"runtime_identity"`
	ModelFingerprint           string `json:"model_fingerprint"`
	ProfileFingerprint         string `json:"profile_fingerprint"`
	ContextLimit               int    `json:"context_limit"`
	Fence                      uint64 `json:"fence"`
	Signature                  string `json:"signature"`
	ConversationID             string `json:"conversation_id,omitempty"`
	ContinuationConversationID string `json:"continuation_conversation_id,omitempty"`
	SnapshotName               string `json:"snapshot_name,omitempty"`
	SnapshotDigest             string `json:"snapshot_digest,omitempty"`
	CompensationOf             string `json:"compensation_of,omitempty"`
	WorkloadRevision           uint64 `json:"workload_revision,omitempty"`
}

// SignedCommandHandler is the narrow in-process seam used by production
// adapters and faithful node fixtures. It preserves the same signed envelope
// and commandProcessor boundary as the websocket transport.
type SignedCommandHandler interface {
	Handle(context.Context, wsproto.CommandPayload) wsproto.CommandResultPayload
}

func NewSignedNodeCommandControl(handler SignedCommandHandler, nodeID string, secret []byte) NodeControl {
	return func(ctx context.Context, _ string, command string, args map[string]any, idempotencyKey string) (map[string]any, error) {
		if handler == nil || nodeID == "" || len(secret) < 16 || idempotencyKey == "" {
			return nil, ErrCheckpointUnavailable
		}
		now := time.Now().UTC()
		payload := wsproto.CommandPayload{ID: idempotencyKey, IdempotencyKey: idempotencyKey, NodeID: nodeID, Command: command, Args: args, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
		signature, err := wsproto.SignCommand(payload, secret)
		if err != nil {
			return nil, err
		}
		payload.Signature = signature
		result := handler.Handle(ctx, payload)
		if !result.OK {
			return nil, errors.New(result.Error)
		}
		return result.Result, nil
	}
}

func (c CheckpointCommand) valid() error {
	if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.IdempotencyKey) == "" ||
		strings.TrimSpace(c.OwnerID) == "" || strings.TrimSpace(c.WorkloadID) == "" ||
		strings.TrimSpace(c.RuntimeIdentity) == "" || strings.TrimSpace(c.ModelFingerprint) == "" ||
		strings.TrimSpace(c.ProfileFingerprint) == "" || c.ContextLimit <= 0 {
		return fmt.Errorf("checkpoint command has incomplete identity")
	}
	if c.WorkloadRevision == 0 {
		return fmt.Errorf("checkpoint command workload revision is required")
	}
	if c.Fence == 0 {
		return fmt.Errorf("checkpoint command fence is required")
	}
	return nil
}

// checkpointConversationID is derived from the immutable operation envelope,
// never from a backend response.  The value is deterministic so an HTTP
// retry, controller restart, and node reconnect all carry the same
// conversation identity before the first durable create.
func checkpointConversationID(command CheckpointCommand) string {
	if strings.TrimSpace(command.ConversationID) != "" {
		return command.ConversationID
	}
	seed := sha256.Sum256([]byte(command.OwnerID + "|" + command.WorkloadID + "|" + fmt.Sprint(command.Generation) + "|" + fmt.Sprint(command.Fence) + "|" + command.ID))
	return "conv-" + hex.EncodeToString(seed[:12])
}

func withCheckpointConversation(command CheckpointCommand) CheckpointCommand {
	command.ConversationID = checkpointConversationID(command)
	// Bind the continuation identity before the managed stream operation is
	// durably created.  Checkpointing an in-flight stream later reuses this
	// immutable operation row; inventing the continuation only at preemption
	// would look like an identity/fence rewrite to CAS recovery.
	if strings.TrimSpace(command.ContinuationConversationID) == "" && strings.TrimSpace(command.ID) != "" {
		command.ContinuationConversationID = "continuation-" + command.ID
	}
	return command
}

type SlotLease struct {
	TargetID      string
	NodeID        string
	AcceleratorID string
	SlotID        int
	// SlotAssigned is set only after the signed node slot_assign command has
	// returned the authoritative slot. It prevents the coordinator from
	// assigning the same physical slot a second time during checkpoint.
	SlotAssigned       bool
	OwnerID            string
	WorkloadID         string
	Generation         uint64
	Fence              uint64
	RuntimeIdentity    string
	ModelFingerprint   string
	ProfileFingerprint string
	ContextLimit       int
	Signature          string
}

type PartialOutput struct {
	Prefix           []byte `json:"prefix,omitempty"`
	AssistantContent []byte `json:"assistant_content,omitempty"`
	TokenCount       int    `json:"token_count"`
	Complete         bool   `json:"complete"`
	UnsafeToolCall   bool   `json:"unsafe_tool_call,omitempty"`
}

// Stitch preserves already-delivered stream bytes when a resumed backend
// returns only the suffix. If a backend repeats the prefix, it is not doubled.
func (p PartialOutput) Stitch(resumed []byte) []byte {
	if len(p.Prefix) == 0 {
		return append([]byte(nil), resumed...)
	}
	if len(resumed) >= len(p.Prefix) && string(resumed[:len(p.Prefix)]) == string(p.Prefix) {
		return append([]byte(nil), resumed...)
	}
	out := make([]byte, 0, len(p.Prefix)+len(resumed))
	out = append(out, p.Prefix...)
	out = append(out, resumed...)
	return out
}

type KVSnapshot struct {
	Bytes         []byte
	Tokens        int
	RuntimeDigest string
	Ref           string
	SizeBytes     int64
}

// CheckpointRuntime is the production boundary. Implementations must bind
// every call to the lease returned by AssignSlot; a slot number alone is not
// authority. ConfirmStopped must observe the backend stopped before Release.
type CheckpointRuntime interface {
	AssignSlot(context.Context, SlotLease) (SlotLease, error)
	PauseAtTokenBoundary(context.Context, SlotLease) (PartialOutput, error)
	SaveKV(context.Context, SlotLease) (KVSnapshot, error)
	ConfirmBackendStopped(context.Context, SlotLease) error
	ReleaseSlot(context.Context, SlotLease) error
	Reload(context.Context, SlotLease) error
	RestoreKV(context.Context, SlotLease, KVSnapshot) error
	VerifyKVReuse(context.Context, SlotLease, int) (int, error)
	Resume(context.Context, SlotLease, PartialOutput) error
}

// checkpointCompensationRuntime is implemented by the signed node runtime.
// It gives rollback commands an explicit durable identity instead of
// masquerading as a forward resume phase.
type checkpointCompensationRuntime interface {
	SetCheckpointCompensation(string)
}

// checkpointPhysicalRestoreRuntime lets the native adapter split restore
// from continuation. A physical restore is durable, but it cannot claim KV
// reuse/resumed until the actual client-owned stream has started and reported
// usage for its exact conversation.
type checkpointPhysicalRestoreRuntime interface {
	DeferRestoreContinuation() bool
	SetRestoreLease(SlotLease)
}

type SnapshotMetadata struct {
	Version          string                     `json:"version"`
	Identity         runtime.CheckpointIdentity `json:"identity"`
	Fence            uint64                     `json:"fence"`
	OldFence         uint64                     `json:"old_fence"`
	NewFence         uint64                     `json:"new_fence"`
	SnapshotName     string                     `json:"snapshot_name"`
	NodeID           string                     `json:"node_id"`
	KVBytes          int64                      `json:"kv_bytes"`
	KVTokens         int                        `json:"kv_tokens"`
	KVRuntimeDigest  string                     `json:"kv_runtime_digest"`
	KVDigest         string                     `json:"kv_digest"`
	KVRef            string                     `json:"kv_ref,omitempty"`
	KVExternal       bool                       `json:"kv_external,omitempty"`
	Output           PartialOutput              `json:"output"`
	ActiveReferences int                        `json:"active_references,omitempty"`
	Terminalized     bool                       `json:"terminalized,omitempty"`
	CreatedAt        time.Time                  `json:"created_at"`
	CommandID        string                     `json:"command_id"`
	// WorkloadRevision is part of the immutable operation identity. Keeping it
	// in the sidecar prevents a same-path/same-command retry from being treated
	// as idempotent after a workload projection has advanced.
	WorkloadRevision uint64 `json:"workload_revision,omitempty"`
}

// SnapshotDeleteExpectation is the privileged cleanup proof for a snapshot.
// Ordinary Delete has no force mode: the operation must first be terminalized
// and the manifest must still belong to the expected operation.
type SnapshotDeleteExpectation struct {
	OwnerID          string
	OperationID      string
	ActiveReferences int
	Terminalized     bool
}

var safeSnapshotComponent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var safeSnapshotFile = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.kv$`)

// checkedSnapshotAdd/Sub are deliberately limited to non-negative byte
// accounting.  Snapshot quotas are logical sizes, so a negative operand is
// malformed state rather than a value that can be clamped away.  In
// particular, do not compute a replacement as `used+incoming-old`: the
// intermediate addition can overflow even when the final result is valid.
func checkedSnapshotAdd(left, right int64) (int64, error) {
	if left < 0 || right < 0 {
		return 0, fmt.Errorf("snapshot quota accounting has a negative size")
	}
	if right > math.MaxInt64-left {
		return 0, fmt.Errorf("snapshot quota accounting overflow")
	}
	return left + right, nil
}

func checkedSnapshotSub(left, right int64) (int64, error) {
	if left < 0 || right < 0 || right > left {
		return 0, fmt.Errorf("snapshot quota accounting underflow")
	}
	return left - right, nil
}

func checkedSnapshotReplacement(used, incoming, replaced int64) (int64, error) {
	withoutReplacement, err := checkedSnapshotSub(used, replaced)
	if err != nil {
		return 0, err
	}
	return checkedSnapshotAdd(withoutReplacement, incoming)
}

func checkedSnapshotLengthSum(parts ...[]byte) (int64, error) {
	var total int64
	for _, part := range parts {
		var err error
		total, err = checkedSnapshotAdd(total, int64(len(part)))
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

// checkedSnapshotFileCount keeps quota accounting fail-closed even on a
// platform where an int-sized walk counter could otherwise wrap.  A wrapped
// count could make a full store appear empty and admit one more bundle.
func checkedSnapshotFileCount(count int) (int, error) {
	if count < 0 || count == int(^uint(0)>>1) {
		return 0, fmt.Errorf("snapshot quota file count overflow")
	}
	return count + 1, nil
}

// readSnapshotMetadataForAccounting treats an existing sidecar as
// authoritative.  A corrupt/unreadable sidecar must never be silently
// ignored, especially when it declares an external KV size: charging the
// physical placeholder size would under-account the store.
func readSnapshotMetadataForAccounting(path string, maxBytes int64) (SnapshotMetadata, bool, error) {
	var metadata SnapshotMetadata
	_, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		return metadata, false, nil
	}
	if statErr != nil {
		return metadata, false, statErr
	}
	body, _, err := readSnapshotDescriptor(path, maxBytes)
	if err != nil {
		return metadata, true, fmt.Errorf("snapshot metadata sidecar is unsafe: %w", err)
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return metadata, true, fmt.Errorf("snapshot metadata sidecar is invalid: %w", err)
	}
	if metadata.Version != "llm-checkpoint-v1" || metadata.SnapshotName == "" || !safeSnapshotFile.MatchString(metadata.SnapshotName) {
		return metadata, true, fmt.Errorf("snapshot metadata sidecar identity is invalid")
	}
	if metadata.KVExternal && (metadata.KVBytes <= 0 || metadata.KVRef == "" || metadata.KVRuntimeDigest == "") {
		return metadata, true, fmt.Errorf("external snapshot sidecar has an invalid declared size or reference")
	}
	return metadata, true, nil
}

// SnapshotStore is a canonical, owner-scoped, bounded store. It is used by
// both the production adapter and deterministic tests; no probe snapshot can
// be consumed unless it has a matching metadata sidecar.
type SnapshotStore struct {
	root                             string
	maxBytes, maxOwnerBytes          int64
	maxFiles, maxOwnerFiles          int
	maxMetadataBytes, maxOutputBytes int64
	expiry                           time.Duration
	lockStale                        time.Duration
	mu                               sync.Mutex
}

func (s *SnapshotStore) acquireFileLock() (*os.File, error) {
	lockPath := filepath.Join(s.root, ".checkpoint.lock")
	if info, err := os.Lstat(lockPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("snapshot lock is not a regular file")
		}
		// A controller crash must not permanently disable checkpointing, but a
		// fresh lock is never removed while another process could own it.
		staleAfter := s.lockStale
		if staleAfter <= 0 {
			staleAfter = 10 * time.Minute
		}
		if time.Since(info.ModTime()) > staleAfter {
			if err := os.Remove(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("stale snapshot lock cannot be removed: %w", err)
			}
		}
	}
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("snapshot store is locked: %w", err)
	}
	return lock, nil
}

func releaseFileLock(lock *os.File, root string) error {
	if lock == nil {
		return nil
	}
	closeErr := lock.Close()
	removeErr := os.Remove(filepath.Join(root, ".checkpoint.lock"))
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	if closeErr != nil {
		return closeErr
	}
	return removeErr
}

func NewSnapshotStore(root string, maxBytes int64, maxFiles int) (*SnapshotStore, error) {
	if strings.TrimSpace(root) == "" || maxBytes <= 0 || maxFiles <= 0 {
		return nil, fmt.Errorf("snapshot root and positive quotas are required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(canonical); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("snapshot root is not a directory")
	}
	_ = os.Chmod(canonical, 0o700)
	if info, err := os.Lstat(canonical); err != nil || info.Mode()&os.ModeSymlink != 0 || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, fmt.Errorf("snapshot root permissions are not private")
	}
	s := &SnapshotStore{root: canonical, maxBytes: maxBytes, maxOwnerBytes: maxBytes, maxFiles: maxFiles, maxOwnerFiles: maxFiles, maxMetadataBytes: 1 << 20, maxOutputBytes: 1 << 20}
	// Crash recovery removes only bundle-shaped files that prove their own
	// ownership. Complete snapshots and arbitrary .kv files are never guessed at
	// or rewritten on startup.
	_ = filepath.WalkDir(canonical, func(path string, entry os.DirEntry, e error) error {
		if e != nil || entry.IsDir() {
			return e
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".kv") && filepath.Base(path) == name {
			commit := path + ".commit"
			if _, commitErr := os.Lstat(commit); errors.Is(commitErr, os.ErrNotExist) {
				metaPath := strings.TrimSuffix(path, ".kv") + ".kv.json"
				if body, _, readErr := readSnapshotDescriptor(metaPath, 1<<20); readErr == nil {
					var metadata SnapshotMetadata
					if json.Unmarshal(body, &metadata) == nil && metadata.Version == "llm-checkpoint-v1" && metadata.SnapshotName == name {
						_ = os.Remove(path)
						_ = os.Remove(metaPath)
					}
				}
			}
		}
		if strings.Contains(name, ".partial-") && (strings.HasSuffix(name, ".kv") || strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".commit")) {
			_ = os.Remove(path)
		}
		return nil
	})
	s.lockStale = 10 * time.Minute
	s.expiry = 24 * time.Hour
	return s, nil
}

// ConfigureQuotas applies node/controller configuration without changing the
// compatibility constructor used by older callers.
func (s *SnapshotStore) ConfigureQuotas(maxBytes int64, maxFiles int, ownerBytes int64, ownerFiles int, metadataBytes int64, outputBytes int64) error {
	if s == nil || maxBytes <= 0 || maxFiles <= 0 || ownerBytes <= 0 || ownerFiles <= 0 || metadataBytes <= 0 || outputBytes <= 0 || ownerBytes > maxBytes || ownerFiles > maxFiles {
		return fmt.Errorf("invalid checkpoint quotas")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxBytes, s.maxFiles, s.maxOwnerBytes, s.maxOwnerFiles, s.maxMetadataBytes, s.maxOutputBytes = maxBytes, maxFiles, ownerBytes, ownerFiles, metadataBytes, outputBytes
	return nil
}

func (s *SnapshotStore) ConfigureStorage(expirySeconds, lockStaleSeconds int) error {
	if s == nil || expirySeconds <= 0 || lockStaleSeconds <= 0 {
		return fmt.Errorf("invalid checkpoint expiry/lock bounds")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expiry = time.Duration(expirySeconds) * time.Second
	s.lockStale = time.Duration(lockStaleSeconds) * time.Second
	return nil
}

// CleanupExpired removes only committed bundles whose manifest proves expiry;
// arbitrary .kv files are never deleted as a recovery heuristic.
func (s *SnapshotStore) CleanupExpired() error {
	if s == nil {
		return ErrCheckpointUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.acquireFileLock()
	if err != nil {
		return err
	}
	defer releaseFileLock(lock, s.root)
	if s.expiry <= 0 {
		return nil
	}
	cutoff := time.Now().Add(-s.expiry)
	return filepath.WalkDir(s.root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".kv.commit") {
			return walkErr
		}
		base := strings.TrimSuffix(path, ".commit")
		metaPath := base + ".json"
		body, _, readErr := readSnapshotDescriptor(metaPath, s.maxMetadataBytes)
		if readErr != nil {
			return nil
		}
		var metadata SnapshotMetadata
		owner := filepath.Base(filepath.Dir(base))
		if json.Unmarshal(body, &metadata) != nil || metadata.Identity.OwnerID == "" || metadata.Identity.OwnerID != owner || metadata.CreatedAt.IsZero() || !metadata.CreatedAt.Before(cutoff) || metadata.ActiveReferences > 0 || !metadata.Terminalized {
			return nil
		}
		if _, _, markerErr := readSnapshotDescriptor(path, 4096); markerErr != nil {
			return nil
		}
		for _, candidate := range []string{base, metaPath, path} {
			if removeErr := os.Remove(candidate); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return removeErr
			}
		}
		if goruntime.GOOS != "windows" {
			if dir, openErr := os.Open(filepath.Dir(base)); openErr == nil {
				if syncErr := dir.Sync(); syncErr != nil {
					_ = dir.Close()
					return syncErr
				}
				if closeErr := dir.Close(); closeErr != nil {
					return closeErr
				}
			}
		}
		return nil
	})
}

func (s *SnapshotStore) Root() string { return s.root }

func (s *SnapshotStore) ownerDir(owner string) (string, error) {
	if !safeSnapshotComponent.MatchString(owner) {
		return "", fmt.Errorf("invalid snapshot owner")
	}
	dir := filepath.Join(s.root, owner)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(dir, 0o700)
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil || canonical != dir {
		return "", fmt.Errorf("snapshot owner path escaped root")
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return "", fmt.Errorf("snapshot owner path is not a directory")
	}
	if info, err := os.Lstat(dir); err != nil || info.Mode()&os.ModeSymlink != 0 || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return "", fmt.Errorf("snapshot owner path permissions are not private")
	}
	return dir, nil
}

func (s *SnapshotStore) snapshotPath(owner, name string) (string, string, error) {
	if !safeSnapshotFile.MatchString(name) || filepath.Base(name) != name || strings.Contains(name, "..") {
		return "", "", fmt.Errorf("invalid snapshot name")
	}
	dir, err := s.ownerDir(owner)
	if err != nil {
		return "", "", err
	}
	path := filepath.Join(dir, name)
	if canonical, e := filepath.EvalSymlinks(dir); e != nil || canonical != dir {
		return "", "", fmt.Errorf("snapshot directory is not canonical")
	}
	if info, e := os.Lstat(path); e == nil && (info.Mode()&os.ModeSymlink != 0 || info.IsDir()) {
		return "", "", fmt.Errorf("snapshot target is not a regular file")
	}
	return path, path + ".json", nil
}

func (s *SnapshotStore) usageLocked() (int64, int, error) {
	var bytes int64
	files := 0
	err := filepath.WalkDir(s.root, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".kv") {
			return nil
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in snapshot store")
		}
		if !singleLink(info) {
			return fmt.Errorf("hardlink in snapshot store")
		}
		var countErr error
		files, countErr = checkedSnapshotFileCount(files)
		if countErr != nil {
			return countErr
		}
		logicalBytes := info.Size()
		if logicalBytes < 0 {
			return fmt.Errorf("snapshot file has a negative size")
		}
		metaPath := strings.TrimSuffix(path, ".kv") + ".kv.json"
		metadata, present, metadataErr := readSnapshotMetadataForAccounting(metaPath, s.maxMetadataBytes)
		if metadataErr != nil {
			return metadataErr
		}
		if present && metadata.KVExternal {
			logicalBytes = metadata.KVBytes
		}
		var addErr error
		bytes, addErr = checkedSnapshotAdd(bytes, logicalBytes)
		if addErr != nil {
			return addErr
		}
		return nil
	})
	return bytes, files, err
}

func singleLink(info os.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	v := reflect.ValueOf(info.Sys())
	if v.IsValid() && v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.IsValid() && v.Kind() == reflect.Struct {
		field := v.FieldByName("Nlink")
		if field.IsValid() && field.CanUint() {
			return field.Uint() <= 1
		}
	}
	return true
}

// readSnapshotDescriptor compares pre-open and descriptor stats, so a
// last-component path swap cannot turn the earlier Lstat into a false safety
// check. The shared safefile helper also rejects final-component symlinks on
// Unix before this descriptor is returned.
func readSnapshotDescriptor(path string, maxBytes int64) ([]byte, os.FileInfo, error) {
	if maxBytes <= 0 {
		return nil, nil, fmt.Errorf("snapshot size bound is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleLink(info) || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, nil, fmt.Errorf("snapshot file is unsafe")
	}
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode()&os.ModeSymlink != 0 || !singleLink(opened) || (goruntime.GOOS != "windows" && opened.Mode().Perm()&0o077 != 0) {
		return nil, nil, fmt.Errorf("snapshot descriptor is unsafe")
	}
	if opened.Size() < 0 || opened.Size() > maxBytes {
		return nil, nil, fmt.Errorf("snapshot exceeds configured bound")
	}
	// Avoid maxBytes+1 wrapping when a quota is intentionally set to
	// MaxInt64.  The descriptor stat above already proves the file is within
	// that bound, so there is no sentinel byte left to read in that case.
	readLimit := maxBytes
	if maxBytes < math.MaxInt64 {
		readLimit = maxBytes + 1
	}
	body, err := io.ReadAll(io.LimitReader(f, readLimit))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, nil, fmt.Errorf("snapshot exceeds configured bound")
	}
	return body, opened, nil
}

// snapshotPayloadMatches verifies that a retry really is the same immutable
// bundle before Put treats it as an idempotent no-op. Matching only owner and
// operation would let a caller replace the bytes/digest behind a stable
// pathname; matching only size would permit same-length corruption.
func snapshotPayloadMatches(data []byte, incoming, existing SnapshotMetadata) bool {
	if incoming.KVExternal != existing.KVExternal {
		return false
	}
	if incoming.KVRuntimeDigest != existing.KVRuntimeDigest || incoming.KVRef != existing.KVRef || incoming.KVTokens != existing.KVTokens {
		return false
	}
	if incoming.KVExternal {
		return incoming.KVBytes == existing.KVBytes && incoming.KVRef == existing.KVRef && incoming.KVRuntimeDigest == existing.KVRuntimeDigest
	}
	if existing.KVBytes != int64(len(data)) || existing.KVDigest == "" {
		return false
	}
	digest := sha256.Sum256(data)
	return existing.KVDigest == "sha256:"+hex.EncodeToString(digest[:])
}

func (s *SnapshotStore) Put(owner, name string, data []byte, metadata SnapshotMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, lockErr := s.acquireFileLock()
	if lockErr != nil {
		return lockErr
	}
	defer releaseFileLock(lock, s.root)
	path, metaPath, err := s.snapshotPath(owner, name)
	if err != nil {
		return err
	}
	if len(data) == 0 && !(metadata.KVExternal && metadata.KVRef != "" && metadata.KVRuntimeDigest != "" && metadata.KVBytes > 0) {
		return fmt.Errorf("empty KV snapshot")
	}
	if metadata.Identity.OwnerID == "" {
		metadata.Identity.OwnerID = owner
	}
	if metadata.Identity.OwnerID != "" && metadata.Identity.OwnerID != owner {
		return fmt.Errorf("snapshot metadata owner mismatch")
	}
	usedBytes, files, err := s.usageLocked()
	if err != nil {
		return err
	}
	var replacementBytes int64
	if existingInfo, statErr := os.Lstat(path); statErr == nil {
		if existingInfo.Mode()&os.ModeSymlink != 0 || !existingInfo.Mode().IsRegular() || !singleLink(existingInfo) {
			return fmt.Errorf("snapshot replacement target is unsafe")
		}
		replacementBytes = existingInfo.Size()
		if replacementBytes < 0 {
			return fmt.Errorf("snapshot replacement target has a negative size")
		}
		// An existing bundle is replaceable only after its previous operation
		// has released the restore reference and terminalized its lifecycle. Do
		// not overwrite an active/nonterminal bundle, a different operation, or
		// a different immutable execution identity merely because the pathname
		// matches. Same-owner/same-operation retries remain idempotent.
		metaBody, _, metaReadErr := readSnapshotDescriptor(metaPath, s.maxMetadataBytes)
		if metaReadErr != nil {
			return fmt.Errorf("snapshot replacement metadata is unsafe: %w", metaReadErr)
		}
		var existing SnapshotMetadata
		if json.Unmarshal(metaBody, &existing) != nil || existing.Version != "llm-checkpoint-v1" || existing.SnapshotName != name || existing.Identity.OwnerID != owner {
			return ErrSnapshotDeleteExpectation
		}
		if existing.KVExternal {
			if existing.KVBytes <= 0 {
				return fmt.Errorf("external snapshot replacement has an invalid declared size")
			}
			replacementBytes = existing.KVBytes
		}
		if existing.CommandID == metadata.CommandID && existing.WorkloadRevision == metadata.WorkloadRevision && existing.Identity == metadata.Identity && existing.Fence == metadata.Fence && existing.OldFence == metadata.OldFence && existing.NewFence == metadata.NewFence && snapshotPayloadMatches(data, metadata, existing) {
			// Idempotence must not bless a pathname whose physical bundle was
			// swapped or corrupted after the original Put.  Re-open the exact
			// descriptor (including the commit marker) before treating this as a
			// no-op; inline KV bytes are additionally checked against the stored
			// digest.  External KV data is validated by its immutable runtime
			// digest/reference metadata, while the local descriptor is still
			// required to be safe and bounded.
			existingData, _, dataReadErr := readSnapshotDescriptor(path, s.maxBytes)
			if dataReadErr != nil {
				return fmt.Errorf("snapshot replacement data is unsafe: %w", dataReadErr)
			}
			marker, _, markerReadErr := readSnapshotDescriptor(path+".commit", 4096)
			if markerReadErr != nil || string(marker) != existing.KVRuntimeDigest {
				return ErrSnapshotDeleteExpectation
			}
			if !existing.KVExternal {
				if existing.KVBytes != int64(len(existingData)) || existing.KVDigest == "" {
					return ErrSnapshotDeleteExpectation
				}
				digest := sha256.Sum256(existingData)
				if existing.KVDigest != "sha256:"+hex.EncodeToString(digest[:]) {
					return ErrSnapshotDeleteExpectation
				}
			}
			// A retry of the same owner/operation and exact payload is safe even
			// while the original bundle is active: no replacement occurs, so its
			// existing reference state remains authoritative.
			return nil
		}
		if existing.ActiveReferences > 0 {
			return ErrSnapshotActiveReferences
		}
		if !existing.Terminalized {
			return ErrSnapshotNotTerminalized
		}
		if existing.CommandID != metadata.CommandID || existing.Identity != metadata.Identity {
			return ErrSnapshotDeleteExpectation
		}
		// A terminalized bundle may only be retried as the exact same payload;
		// the branch above already returned for that case. Keep this explicit so
		// future metadata fields cannot silently permit a content rewrite.
		return ErrSnapshotDeleteExpectation
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	} else {
		files, err = checkedSnapshotFileCount(files)
		if err != nil {
			return err
		}
	}
	logicalBytes := int64(len(data))
	if metadata.KVExternal {
		if metadata.KVBytes <= 0 {
			return fmt.Errorf("external snapshot has an invalid declared size")
		}
		logicalBytes = metadata.KVBytes
	}
	if logicalBytes <= 0 {
		return fmt.Errorf("invalid KV snapshot size")
	}
	newBytes, accountingErr := checkedSnapshotReplacement(usedBytes, logicalBytes, replacementBytes)
	if accountingErr != nil {
		return accountingErr
	}
	if files > s.maxFiles || newBytes > s.maxBytes {
		return fmt.Errorf("snapshot quota exceeded")
	}
	ownerBytes, ownerFiles := int64(0), 0
	ownerDir, dirErr := s.ownerDir(owner)
	if dirErr != nil {
		return dirErr
	}
	ownerWalkErr := filepath.WalkDir(ownerDir, func(candidate string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".kv") {
			return walkErr
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return statErr
		}
		var countErr error
		ownerFiles, countErr = checkedSnapshotFileCount(ownerFiles)
		if countErr != nil {
			return countErr
		}
		logical := info.Size()
		if logical < 0 {
			return fmt.Errorf("snapshot file has a negative size")
		}
		metaPath := strings.TrimSuffix(candidate, ".kv") + ".kv.json"
		existing, present, metadataErr := readSnapshotMetadataForAccounting(metaPath, s.maxMetadataBytes)
		if metadataErr != nil {
			return metadataErr
		}
		if present && existing.KVExternal {
			logical = existing.KVBytes
		}
		var addErr error
		ownerBytes, addErr = checkedSnapshotAdd(ownerBytes, logical)
		if addErr != nil {
			return addErr
		}
		return nil
	})
	if ownerWalkErr != nil {
		return ownerWalkErr
	}
	var replacementOwnerBytes int64
	if existingInfo, statErr := os.Lstat(path); statErr == nil {
		replacementOwnerBytes = existingInfo.Size()
		if replacementOwnerBytes < 0 {
			return fmt.Errorf("snapshot replacement target has a negative size")
		}
		existing, present, metadataErr := readSnapshotMetadataForAccounting(metaPath, s.maxMetadataBytes)
		if metadataErr != nil {
			return metadataErr
		}
		if present && existing.KVExternal {
			replacementOwnerBytes = existing.KVBytes
		}
	} else if errors.Is(statErr, os.ErrNotExist) {
		ownerFiles, err = checkedSnapshotFileCount(ownerFiles)
		if err != nil {
			return err
		}
	} else {
		return statErr
	}
	ownerNewBytes, accountingErr := checkedSnapshotReplacement(ownerBytes, logicalBytes, replacementOwnerBytes)
	if accountingErr != nil {
		return accountingErr
	}
	if ownerFiles > s.maxOwnerFiles || ownerNewBytes > s.maxOwnerBytes {
		return fmt.Errorf("snapshot owner quota exceeded")
	}
	metadata.Version = "llm-checkpoint-v1"
	metadata.SnapshotName = name
	if metadata.ActiveReferences == 0 {
		// Direct store users have no separate lifecycle callback; treating an
		// unreferenced write as terminal preserves the old expiry behavior. The
		// coordinator sets ActiveReferences=1 for a live checkpoint operation.
		metadata.Terminalized = true
	}
	if metadata.NodeID == "" {
		metadata.NodeID = metadata.Identity.NodeID
	}
	if !metadata.KVExternal {
		metadata.KVBytes = int64(len(data))
		dataDigest := sha256.Sum256(data)
		metadata.KVDigest = "sha256:" + hex.EncodeToString(dataDigest[:])
	} else if metadata.KVDigest == "" {
		metadata.KVDigest = metadata.KVRuntimeDigest
	}
	outputBytes, outputErr := checkedSnapshotLengthSum(metadata.Output.Prefix, metadata.Output.AssistantContent)
	if outputErr != nil {
		return outputErr
	}
	if outputBytes > s.maxOutputBytes {
		return fmt.Errorf("snapshot output exceeds configured bound")
	}
	body, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	if int64(len(body)) > s.maxMetadataBytes {
		return fmt.Errorf("snapshot metadata exceeds configured bound")
	}
	tmp := path + fmt.Sprintf(".partial-%d", time.Now().UnixNano())
	metaTmp := metaPath + fmt.Sprintf(".partial-%d", time.Now().UnixNano())
	cleanup := func() { _ = os.Remove(tmp); _ = os.Remove(metaTmp) }
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		cleanup()
		return err
	}
	m, err := os.OpenFile(metaTmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		cleanup()
		return err
	}
	if _, err = m.Write(body); err == nil {
		err = m.Sync()
	}
	closeErr = m.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		cleanup()
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	if err = os.Rename(metaTmp, metaPath); err != nil {
		_ = os.Remove(path)
		cleanup()
		return err
	}
	commit := path + ".commit"
	markerTmp := commit + fmt.Sprintf(".partial-%d", time.Now().UnixNano())
	markerFile, markerOpenErr := os.OpenFile(markerTmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if markerOpenErr != nil {
		err = markerOpenErr
	} else if _, err = markerFile.Write([]byte(metadata.KVRuntimeDigest)); err == nil {
		err = markerFile.Sync()
		closeErr := markerFile.Close()
		if err == nil {
			err = closeErr
		}
	} else {
		_ = markerFile.Close()
	}
	if err != nil {
		_ = os.Remove(path)
		_ = os.Remove(metaPath)
		_ = os.Remove(markerTmp)
		return err
	}
	if err = os.Rename(markerTmp, commit); err != nil {
		_ = os.Remove(path)
		_ = os.Remove(metaPath)
		_ = os.Remove(markerTmp)
		return err
	}
	if goruntime.GOOS != "windows" {
		if dir, openErr := os.Open(filepath.Dir(path)); openErr == nil {
			syncErr := dir.Sync()
			_ = dir.Close()
			if syncErr != nil {
				_ = os.Remove(path)
				_ = os.Remove(metaPath)
				_ = os.Remove(commit)
				return syncErr
			}
		} else {
			_ = os.Remove(path)
			_ = os.Remove(metaPath)
			_ = os.Remove(commit)
			return openErr
		}
	}
	return nil
}

func (s *SnapshotStore) Get(owner, name string) ([]byte, SnapshotMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, lockErr := s.acquireFileLock()
	if lockErr != nil {
		return nil, SnapshotMetadata{}, lockErr
	}
	defer releaseFileLock(lock, s.root)
	path, metaPath, err := s.snapshotPath(owner, name)
	if err != nil {
		return nil, SnapshotMetadata{}, err
	}
	if info, err := os.Lstat(path + ".commit"); err != nil {
		return nil, SnapshotMetadata{}, fmt.Errorf("snapshot commit marker missing: %w", err)
	} else if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleLink(info) {
		return nil, SnapshotMetadata{}, fmt.Errorf("snapshot commit marker is unsafe")
	}
	data, _, err := readSnapshotDescriptor(path, s.maxBytes)
	if err != nil {
		return nil, SnapshotMetadata{}, err
	}
	body, _, err := readSnapshotDescriptor(metaPath, s.maxMetadataBytes)
	if err != nil {
		return nil, SnapshotMetadata{}, fmt.Errorf("snapshot metadata missing: %w", err)
	}
	if int64(len(body)) > s.maxMetadataBytes {
		return nil, SnapshotMetadata{}, fmt.Errorf("snapshot metadata exceeds configured bound")
	}
	var metadata SnapshotMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, SnapshotMetadata{}, fmt.Errorf("invalid snapshot metadata: %w", err)
	}
	if metadata.Version != "llm-checkpoint-v1" || metadata.SnapshotName != name || (!metadata.KVExternal && metadata.KVBytes != int64(len(data))) || (metadata.KVExternal && (metadata.KVBytes <= 0 || metadata.KVRef == "")) {
		return nil, SnapshotMetadata{}, fmt.Errorf("snapshot metadata is stale or partial")
	}
	if metadata.Identity.OwnerID != owner {
		return nil, SnapshotMetadata{}, fmt.Errorf("snapshot owner mismatch")
	}
	if metadata.Identity.NodeID != "" && (metadata.NodeID == "" || metadata.NodeID != metadata.Identity.NodeID) {
		return nil, SnapshotMetadata{}, fmt.Errorf("snapshot node identity mismatch")
	}
	if s.expiry > 0 && !metadata.CreatedAt.IsZero() && time.Now().After(metadata.CreatedAt.Add(s.expiry)) {
		return nil, SnapshotMetadata{}, fmt.Errorf("snapshot expired")
	}
	if metadata.KVRef != "" && (!safeSnapshotFile.MatchString(filepath.Base(metadata.KVRef)) || filepath.Base(metadata.KVRef) != metadata.KVRef) {
		return nil, SnapshotMetadata{}, fmt.Errorf("snapshot runtime reference is unsafe")
	}
	outputBytes, outputErr := checkedSnapshotLengthSum(metadata.Output.Prefix, metadata.Output.AssistantContent)
	if outputErr != nil {
		return nil, SnapshotMetadata{}, outputErr
	}
	if outputBytes > s.maxOutputBytes {
		return nil, SnapshotMetadata{}, fmt.Errorf("snapshot output exceeds configured bound")
	}
	if metadata.KVExternal {
		if metadata.KVDigest == "" || metadata.KVDigest != metadata.KVRuntimeDigest {
			return nil, SnapshotMetadata{}, fmt.Errorf("external snapshot digest mismatch")
		}
	} else {
		dataDigest := sha256.Sum256(data)
		if metadata.KVDigest == "" || metadata.KVDigest != "sha256:"+hex.EncodeToString(dataDigest[:]) {
			return nil, SnapshotMetadata{}, fmt.Errorf("snapshot KV digest mismatch")
		}
	}
	marker, _, err := readSnapshotDescriptor(path+".commit", 4096)
	if err != nil || string(marker) != metadata.KVRuntimeDigest {
		return nil, SnapshotMetadata{}, fmt.Errorf("snapshot commit marker is stale")
	}
	return data, metadata, nil
}

func (s *SnapshotStore) deleteLocked(owner, name string, expected *SnapshotDeleteExpectation) error {
	path, meta, err := s.snapshotPath(owner, name)
	if err != nil {
		return err
	}
	pathInfo, pathErr := os.Lstat(path)
	metaInfo, metaErr := os.Lstat(meta)
	commitInfo, commitErr := os.Lstat(path + ".commit")
	if errors.Is(pathErr, os.ErrNotExist) && errors.Is(metaErr, os.ErrNotExist) && errors.Is(commitErr, os.ErrNotExist) {
		return nil
	}
	if pathErr != nil || metaErr != nil || commitErr != nil || pathInfo == nil || metaInfo == nil || commitInfo == nil {
		return fmt.Errorf("snapshot bundle is incomplete")
	}
	body, _, readErr := readSnapshotDescriptor(meta, s.maxMetadataBytes)
	if readErr != nil {
		return readErr
	}
	var metadata SnapshotMetadata
	if err := json.Unmarshal(body, &metadata); err != nil || metadata.Version != "llm-checkpoint-v1" || metadata.SnapshotName != name || metadata.Identity.OwnerID != owner {
		return fmt.Errorf("snapshot metadata is invalid")
	}
	if metadata.ActiveReferences > 0 {
		return ErrSnapshotActiveReferences
	}
	if !metadata.Terminalized {
		return ErrSnapshotNotTerminalized
	}
	if expected != nil {
		if expected.OwnerID == "" || expected.OwnerID != owner || expected.OperationID == "" || expected.OperationID != metadata.CommandID || expected.ActiveReferences != metadata.ActiveReferences || expected.Terminalized != metadata.Terminalized {
			return ErrSnapshotDeleteExpectation
		}
	}
	if e := os.Remove(meta); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e := os.Remove(path + ".commit"); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e := os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if goruntime.GOOS != "windows" {
		if dir, openErr := os.Open(filepath.Dir(path)); openErr == nil {
			syncErr := dir.Sync()
			_ = dir.Close()
			if syncErr != nil {
				return syncErr
			}
		}
	}
	return nil
}

func (s *SnapshotStore) Delete(owner, name string) error {
	if s == nil {
		return ErrCheckpointUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, lockErr := s.acquireFileLock()
	if lockErr != nil {
		return lockErr
	}
	defer releaseFileLock(lock, s.root)
	return s.deleteLocked(owner, name, nil)
}

// DeletePrivileged is reserved for a controller path that has already
// terminalized the exact operation. The expected operation/reference state is
// checked while the snapshot lock is held, so a late release cannot race a
// deletion and remove the only restore artifact.
func (s *SnapshotStore) DeletePrivileged(owner, name string, expected SnapshotDeleteExpectation) error {
	if s == nil {
		return ErrCheckpointUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, lockErr := s.acquireFileLock()
	if lockErr != nil {
		return lockErr
	}
	defer releaseFileLock(lock, s.root)
	return s.deleteLocked(owner, name, &expected)
}

// MarkInactive is the lifecycle handoff used by terminal operation paths.
// Only the owner-scoped metadata sidecar is changed; cleanup can later remove
// the bundle after expiry without guessing at unrelated raw KV files.
func (s *SnapshotStore) MarkInactive(owner, name string) error {
	if s == nil {
		return ErrCheckpointUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, lockErr := s.acquireFileLock()
	if lockErr != nil {
		return lockErr
	}
	defer releaseFileLock(lock, s.root)
	path, metaPath, err := s.snapshotPath(owner, name)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(path + ".commit"); err != nil {
		return err
	} else if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleLink(info) {
		return fmt.Errorf("snapshot commit marker is unsafe")
	}
	body, _, err := readSnapshotDescriptor(metaPath, s.maxMetadataBytes)
	if err != nil {
		return err
	}
	var metadata SnapshotMetadata
	if err := json.Unmarshal(body, &metadata); err != nil || metadata.Identity.OwnerID != owner || metadata.SnapshotName != name {
		return fmt.Errorf("snapshot metadata is invalid")
	}
	metadata.ActiveReferences = 0
	metadata.Terminalized = true
	updated, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil || int64(len(updated)) > s.maxMetadataBytes {
		if err == nil {
			err = fmt.Errorf("snapshot metadata exceeds configured bound")
		}
		return err
	}
	tmp := metaPath + fmt.Sprintf(".partial-%d", time.Now().UnixNano())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(updated); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err = os.Rename(tmp, metaPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if goruntime.GOOS != "windows" {
		dir, openErr := os.Open(filepath.Dir(metaPath))
		if openErr != nil {
			return openErr
		}
		syncErr := dir.Sync()
		_ = dir.Close()
		return syncErr
	}
	return nil
}

// MarkInactiveForOperation is the strict terminalization handoff used by
// production operation cleanup. It proves the manifest still belongs to the
// operation being finalized before changing its reference state.
func (s *SnapshotStore) MarkInactiveForOperation(owner, name, operationID string) error {
	if s == nil {
		return ErrCheckpointUnavailable
	}
	if strings.TrimSpace(operationID) == "" {
		return ErrSnapshotDeleteExpectation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, lockErr := s.acquireFileLock()
	if lockErr != nil {
		return lockErr
	}
	defer releaseFileLock(lock, s.root)
	path, metaPath, err := s.snapshotPath(owner, name)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(path + ".commit"); err != nil {
		return err
	} else if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleLink(info) {
		return fmt.Errorf("snapshot commit marker is unsafe")
	}
	body, _, err := readSnapshotDescriptor(metaPath, s.maxMetadataBytes)
	if err != nil {
		return err
	}
	var metadata SnapshotMetadata
	if err := json.Unmarshal(body, &metadata); err != nil || metadata.Identity.OwnerID != owner || metadata.SnapshotName != name || metadata.CommandID != operationID {
		return ErrSnapshotDeleteExpectation
	}
	metadata.ActiveReferences = 0
	metadata.Terminalized = true
	updated, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil || int64(len(updated)) > s.maxMetadataBytes {
		if err == nil {
			err = fmt.Errorf("snapshot metadata exceeds configured bound")
		}
		return err
	}
	tmp := metaPath + fmt.Sprintf(".partial-%d", time.Now().UnixNano())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(updated); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err = os.Rename(tmp, metaPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if goruntime.GOOS != "windows" {
		dir, openErr := os.Open(filepath.Dir(metaPath))
		if openErr != nil {
			return openErr
		}
		syncErr := dir.Sync()
		_ = dir.Close()
		return syncErr
	}
	return nil
}

type CheckpointCoordinator struct {
	Runtime               CheckpointRuntime
	RuntimeFactory        func(context.Context, CheckpointCommand, SlotLease) (CheckpointRuntime, error)
	Store                 *SnapshotStore
	Proof                 runtime.CheckpointCapabilityProof
	Authorize             func(CheckpointCommand) error
	Operations            store.LLMCheckpointOperationStore
	mu                    sync.Mutex
	active                map[string]CheckpointMetadataState
	inflight              map[string]struct{}
	targetProofs          map[string]runtime.CheckpointCapabilityProof
	targetRecoveryErr     map[string]error
	recoveryErr           error
	recoveryQuery         func(context.Context, *store.LLMCheckpointOperation) error
	recoveryEvidenceQuery func(context.Context, *store.LLMCheckpointOperation) (RecoveryObservation, error)
	recoveryCorrection    func(context.Context, *store.LLMCheckpointOperation, RecoveryObservation, string) error
}

type RecoveryObservation struct {
	NodeID                     string
	TargetID                   string
	AcceleratorID              string
	OperationID                string
	Phase                      string
	PhaseOrdinal               int
	SlotID                     int
	SnapshotName               string
	ConversationID             string
	ContinuationConversationID string
	SnapshotDigest             string
	RuntimeIdentity            string
	ModelFingerprint           string
	ProfileFingerprint         string
	ContextFingerprint         string
}

func (c *CheckpointCoordinator) persistOperation(ctx context.Context, command CheckpointCommand, lease SlotLease, phase string, snapshot string, partial PartialOutput, saved, reused int, op **store.LLMCheckpointOperation) error {
	if c.Operations == nil {
		return nil
	}
	if c.Store != nil {
		outputBytes, outputErr := checkedSnapshotLengthSum(partial.Prefix, partial.AssistantContent)
		if outputErr != nil {
			return outputErr
		}
		if outputBytes > c.Store.maxOutputBytes {
			return fmt.Errorf("checkpoint partial output exceeds configured bound")
		}
	}
	command = withCheckpointConversation(command)
	phaseOrdinal := checkpointRecoveryOrdinal(phase)
	if phaseOrdinal <= 0 {
		return fmt.Errorf("checkpoint phase %q has no durable ordinal", phase)
	}
	current := *op
	if current == nil {
		created, _, err := c.Operations.CreateLLMCheckpointOperation(ctx, &store.LLMCheckpointOperation{ID: command.ID, IdempotencyKey: command.IdempotencyKey, OwnerID: command.OwnerID, WorkloadID: command.WorkloadID, NodeID: lease.NodeID, AcceleratorID: lease.AcceleratorID, TargetID: lease.TargetID, SlotID: lease.SlotID, Generation: command.Generation, Fence: command.Fence, RuntimeIdentity: command.RuntimeIdentity, Model: command.ModelFingerprint, ModelFingerprint: command.ModelFingerprint, ProfileFingerprint: command.ProfileFingerprint, ContextFingerprint: fmt.Sprintf("ctx:%d", command.ContextLimit), ConversationID: command.ConversationID, ContinuationConversationID: command.ContinuationConversationID, CompensationOf: command.CompensationOf, WorkloadRevision: command.WorkloadRevision, SnapshotName: snapshot, SnapshotDigest: command.SnapshotDigest, Phase: phase, PhaseOrdinal: phaseOrdinal, PartialOutputHash: DigestOutput(partial.Prefix), PartialOutputOffset: len(partial.Prefix), PartialOutputContent: append([]byte(nil), partial.Prefix...), PartialOutputUnsafeToolCall: partial.UnsafeToolCall, SavedTokens: saved, ReusedTokens: reused})
		if err != nil {
			return err
		}
		*op = created
		return nil
	}
	// The manager records cleanup and recovery identity on the same row while
	// a save or restore is in flight; a stale revision is retried against the
	// fresh row instead of failing the restore (and its failure record).
	for attempt := 0; ; attempt++ {
		// Every update must carry the complete immutable command identity.  A
		// replay with a changed conversation/compensation binding is a conflict,
		// not an opportunity to rewrite the original operation.
		if current.ID != command.ID || current.IdempotencyKey != command.IdempotencyKey || current.OwnerID != command.OwnerID || current.WorkloadID != command.WorkloadID || current.WorkloadRevision != command.WorkloadRevision || current.Generation != command.Generation || current.Fence != command.Fence || current.RuntimeIdentity != command.RuntimeIdentity || current.ModelFingerprint != command.ModelFingerprint || current.ProfileFingerprint != command.ProfileFingerprint || current.ContextFingerprint != fmt.Sprintf("ctx:%d", command.ContextLimit) || current.ConversationID != command.ConversationID || current.ContinuationConversationID != command.ContinuationConversationID || current.CompensationOf != command.CompensationOf {
			return ErrCheckpointConflict
		}
		// PrepareOperation may have run before a node slot was assigned.  Its
		// planned write is an idempotent assertion once the row has advanced and
		// must never regress the durable lifecycle.
		if phase == "planned" && current.Phase != "planned" {
			return nil
		}
		// A live checkpointable stream records assigned/start before the scheduler
		// later asks the coordinator to checkpoint that same operation. Reasserting
		// the already durable assignment must not regress a started row back to the
		// assignment ordinal; the node pause is the next physical phase.
		if phase == "assigned" && current.Phase != "planned" && current.PhaseOrdinal >= phaseOrdinal {
			return nil
		}
		if current.Phase == phase && current.PhaseOrdinal == phaseOrdinal && current.SnapshotName == snapshot && current.SavedTokens == saved && current.ReusedTokens == reused {
			return nil
		}
		next := *current
		next.Phase = phase
		next.PhaseOrdinal = phaseOrdinal
		next.ContinuationConversationID = command.ContinuationConversationID
		next.Model = command.ModelFingerprint
		next.NodeID = lease.NodeID
		next.AcceleratorID = lease.AcceleratorID
		next.TargetID = lease.TargetID
		next.SlotID = lease.SlotID
		next.SnapshotName = snapshot
		if command.SnapshotDigest != "" {
			next.SnapshotDigest = command.SnapshotDigest
		}
		next.PartialOutputHash = DigestOutput(partial.Prefix)
		next.PartialOutputOffset = len(partial.Prefix)
		next.PartialOutputContent = append([]byte(nil), partial.Prefix...)
		next.PartialOutputUnsafeToolCall = partial.UnsafeToolCall
		next.SavedTokens = saved
		next.ReusedTokens = reused
		next.WorkloadRevision = current.WorkloadRevision
		updated, err := c.Operations.UpdateLLMCheckpointOperation(ctx, &next, current.Revision)
		if err == nil {
			*op = updated
			return nil
		}
		if attempt >= 3 || !errors.Is(err, store.ErrLLMCheckpointConflict) {
			return err
		}
		fresh, getErr := c.Operations.GetLLMCheckpointOperation(ctx, current.ID)
		if getErr != nil || fresh.Revision == current.Revision {
			return err
		}
		current = fresh
		*op = fresh
	}
}

type CheckpointMetadataState struct {
	Lease    SlotLease
	Snapshot string
	Output   PartialOutput
	Command  CheckpointCommand
}

func NewCheckpointCoordinator(rt CheckpointRuntime, store *SnapshotStore, proof runtime.CheckpointCapabilityProof) *CheckpointCoordinator {
	return &CheckpointCoordinator{Runtime: rt, Store: store, Proof: proof, active: make(map[string]CheckpointMetadataState), inflight: make(map[string]struct{}), targetProofs: make(map[string]runtime.CheckpointCapabilityProof), targetRecoveryErr: make(map[string]error)}
}

// SetRecoveryQuery wires restart reconciliation to the same signed node
// command channel used by live checkpoint mutations.
func (c *CheckpointCoordinator) SetRecoveryQuery(query func(context.Context, *store.LLMCheckpointOperation) error) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.recoveryQuery = query
	c.mu.Unlock()
}

func (c *CheckpointCoordinator) SetRecoveryEvidenceQuery(query func(context.Context, *store.LLMCheckpointOperation) (RecoveryObservation, error)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.recoveryEvidenceQuery = query
	c.mu.Unlock()
}

// SetRecoveryCorrection installs the phase-specific corrective action used
// when a reconnect observes a valid node that is ahead/behind its durable row.
// The correction runs with the same operation identity and must perform its
// own signed stop/idle/release or restore sequence before returning success.
func (c *CheckpointCoordinator) SetRecoveryCorrection(query func(context.Context, *store.LLMCheckpointOperation, RecoveryObservation, string) error) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.recoveryCorrection = query
	c.mu.Unlock()
}

func (c *CheckpointCoordinator) SetTargetProof(targetID string, proof runtime.CheckpointCapabilityProof) {
	if c == nil || targetID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.targetProofs == nil {
		c.targetProofs = make(map[string]runtime.CheckpointCapabilityProof)
	}
	if proof.Complete() && proof.TargetID == targetID {
		c.targetProofs[targetID] = proof
	} else {
		delete(c.targetProofs, targetID)
	}
}

func (c *CheckpointCoordinator) ReadyForTarget(target Target, model, profile string, contextLimit int, generation uint64) bool {
	if c == nil || c.Store == nil {
		return false
	}
	c.mu.Lock()
	proof, ok := c.targetProofs[target.ID]
	targetRecoveryErr := c.targetRecoveryErr[target.ID]
	c.mu.Unlock()
	// Recovery is target-scoped: an offline node must not make an otherwise
	// reconciled target unusable. Ready() remains conservative for global
	// status/reporting, while this admission predicate follows the exact target.
	if targetRecoveryErr != nil {
		return false
	}
	if !ok || !proof.Complete() || proof.TargetID != target.ID {
		return false
	}
	if target.NodeID != "" && proof.NodeID != target.NodeID || target.AcceleratorID != "" && proof.AcceleratorID != target.AcceleratorID || target.RuntimeIdentity != "" && proof.RuntimeIdentity != target.RuntimeIdentity || target.ModelFingerprint != "" && proof.ModelFingerprint != target.ModelFingerprint || target.ContextLimit > 0 && proof.ContextLimit != target.ContextLimit || target.CapabilityGeneration > 0 && proof.Generation != target.CapabilityGeneration {
		return false
	}
	if model != "" && proof.ModelFingerprint != model || profile != "" && proof.ProfileFingerprint != profile || contextLimit > 0 && proof.ContextLimit != contextLimit || generation > 0 && proof.Generation != generation {
		return false
	}
	return true
}

func checkpointRecoveryOrdinal(phase string) int {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "planned":
		return 1
	case "assigned":
		return 1
	case "started":
		return 2
	case "paused":
		return 3
	case "saved":
		return 4
	case "stopped":
		return 5
	case "released":
		return 6
	case "restore_planned":
		return 6
	case "restore_assigned":
		return 8
	case "reloaded":
		return 9
	case "restored":
		return 10
	case "resumed":
		return 11
	case "continued":
		return 12
	case "reused":
		return 13
	case "completed", "failed", "cancelled", "restore_failed":
		return 15
	default:
		return -1
	}
}

func llmCheckpointTerminalTransitionForSuccess(from, to string) bool {
	switch {
	case from == "started" && to == "stopped":
		return true
	case from == "paused" && to == "stopped":
		return false
	case from == "saved" && to == "stopped":
		return true
	case from == "stopped" && to == "released":
		return true
	case from == "started" && to == "released":
		return false
	}
	return false
}

func checkpointRecoveryPhaseMatches(row, observed string) bool {
	if strings.TrimSpace(observed) == "" {
		return false
	}
	row = strings.ToLower(strings.TrimSpace(row))
	observed = strings.ToLower(strings.TrimSpace(observed))
	if row == observed {
		return true
	}
	aliases := map[string]map[string]struct{}{
		"planned":          {"planned": {}},
		"assigned":         {"slot_assign": {}, "assigned": {}},
		"started":          {"start": {}, "started": {}},
		"paused":           {"pause": {}, "paused": {}},
		"saved":            {"save": {}, "saved": {}},
		"stopped":          {"stop_confirm": {}, "stopped": {}},
		"released":         {"release": {}, "released": {}},
		"restore_planned":  {"restore_planned": {}, "release": {}, "released": {}},
		"restore_assigned": {"slot_assign": {}, "assigned": {}, "restore_assigned": {}},
		"reloaded":         {"reload": {}, "reloaded": {}},
		"restored":         {"restore": {}, "restored": {}},
		"resumed":          {"resume": {}, "resumed": {}},
		"continued":        {"continue": {}, "continued": {}},
		"reused":           {"reuse_verify": {}, "reused": {}},
		"completed":        {"completed": {}, "release": {}},
		"failed":           {"failed": {}, "release": {}, "cancel": {}},
		"cancelled":        {"cancelled": {}, "cancel": {}, "release": {}},
		"restore_failed":   {"restore_failed": {}, "release": {}, "cancel": {}},
	}
	allowed := aliases[row]
	_, ok := allowed[observed]
	return ok
}

// Recover rebuilds idempotency/ownership state after controller restart from
// durable operation rows. Node reconciliation is deliberately target-scoped:
// an unavailable node fences only its own target while a reconciled target may
// continue admitting work. Snapshotless rows are still queried and corrected;
// they are never silently treated as resumable snapshots.
func (c *CheckpointCoordinator) Recover(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if c.Operations == nil || c.Store == nil {
		c.mu.Lock()
		c.recoveryErr = ErrCheckpointUnavailable
		if c.targetRecoveryErr == nil {
			c.targetRecoveryErr = make(map[string]error)
		}
		c.targetRecoveryErr[""] = ErrCheckpointUnavailable
		c.mu.Unlock()
		return ErrCheckpointUnavailable
	}
	rows, err := c.Operations.ListLLMCheckpointOperations(ctx, "")
	if err != nil {
		c.mu.Lock()
		c.recoveryErr = err
		c.mu.Unlock()
		return err
	}
	c.mu.Lock()
	evidenceQuery := c.recoveryEvidenceQuery
	recoveryQuery := c.recoveryQuery
	correction := c.recoveryCorrection
	if c.targetRecoveryErr == nil {
		c.targetRecoveryErr = make(map[string]error)
	}
	// Rebuild from the latest durable rows only. A row that was released or
	// terminalized must not leave stale in-memory ownership from an earlier
	// process incarnation.
	c.active = make(map[string]CheckpointMetadataState)
	c.mu.Unlock()
	// Stores return rows in implementation-defined order.  Reconciliation must
	// select the newest durable revision per operation before filtering terminal
	// rows; otherwise an older active phase can resurrect ownership after a
	// later released/completed phase.
	latestRows := make(map[string]*store.LLMCheckpointOperation)
	for _, candidate := range rows {
		if candidate == nil {
			continue
		}
		key := candidate.ID
		if key == "" {
			key = candidate.IdempotencyKey
		}
		prior := latestRows[key]
		if prior == nil || candidate.Revision > prior.Revision || (candidate.Revision == prior.Revision && candidate.UpdatedAt.After(prior.UpdatedAt)) {
			latestRows[key] = candidate
		}
	}
	var unresolved []string
	targetErrors := make(map[string][]string)
	for _, op := range latestRows {
		if op == nil {
			continue
		}
		targetID := op.TargetID
		if op.PhaseOrdinal <= 0 || checkpointRecoveryOrdinal(op.Phase) <= 0 || op.PhaseOrdinal != checkpointRecoveryOrdinal(op.Phase) || strings.TrimSpace(op.ConversationID) == "" || strings.TrimSpace(op.ID) == "" || strings.TrimSpace(op.IdempotencyKey) == "" || strings.TrimSpace(op.OwnerID) == "" || strings.TrimSpace(op.WorkloadID) == "" || op.Generation == 0 || op.Fence == 0 {
			message := op.ID + ": durable phase/identity is missing or invalid"
			unresolved = append(unresolved, message)
			targetErrors[targetID] = append(targetErrors[targetID], message)
			continue
		}
		if op.Phase == "failed" || op.Phase == "cancelled" || op.Phase == "completed" || op.Phase == "restore_failed" {
			continue
		}
		if op.SnapshotName != "" && strings.TrimSpace(op.SnapshotDigest) == "" {
			message := op.ID + ": snapshot digest is missing from durable operation"
			unresolved = append(unresolved, message)
			targetErrors[targetID] = append(targetErrors[targetID], message)
			continue
		}
		var observation RecoveryObservation
		hasObservation := false
		if evidenceQuery != nil {
			observation, err = evidenceQuery(ctx, op)
			if err != nil {
				// An authoritative not_found is a node fact, not a transport
				// failure. Give the installed correction hook a chance to
				// terminalize or otherwise fence the exact operation. Other errors
				// are retried by the signed controller query path before reaching
				// this branch.
				if correction != nil && errors.Is(err, ErrCheckpointNotFound) {
					if correctionErr := correction(ctx, op, RecoveryObservation{}, "not_found"); correctionErr == nil {
						continue
					} else {
						err = fmt.Errorf("%w: correction: %v", err, correctionErr)
					}
				}
				message := op.ID + ": node reconciliation: " + err.Error()
				unresolved = append(unresolved, message)
				targetErrors[targetID] = append(targetErrors[targetID], message)
				continue
			}
			hasObservation = true
			mismatch := observation.NodeID != op.NodeID || observation.TargetID != op.TargetID || observation.AcceleratorID != op.AcceleratorID || observation.OperationID != op.ID || (op.SlotID >= 0 && observation.SlotID != op.SlotID) || observation.SnapshotName != op.SnapshotName || observation.SnapshotDigest != op.SnapshotDigest || observation.ConversationID != op.ConversationID || observation.ContinuationConversationID != op.ContinuationConversationID || observation.RuntimeIdentity != op.RuntimeIdentity || observation.ModelFingerprint != op.ModelFingerprint || observation.ProfileFingerprint != op.ProfileFingerprint || observation.ContextFingerprint != op.ContextFingerprint || !checkpointRecoveryPhaseMatches(op.Phase, observation.Phase) || observation.PhaseOrdinal <= 0 || observation.PhaseOrdinal != checkpointRecoveryOrdinal(op.Phase)
			if mismatch {
				message := op.ID + ": node evidence identity/phase mismatch"
				if correction == nil {
					unresolved = append(unresolved, message)
					targetErrors[targetID] = append(targetErrors[targetID], message)
					continue
				}
				if correctionErr := correction(ctx, op, observation, op.Phase); correctionErr != nil {
					message += ": correction: " + correctionErr.Error()
					unresolved = append(unresolved, message)
					targetErrors[targetID] = append(targetErrors[targetID], message)
					continue
				}
				// A successful phase-specific correction is authoritative for this
				// reconciliation pass.  Do not re-evaluate the stale pre-correction
				// observation as an unresolved snapshotless row.
				observation.Phase = op.Phase
				observation.PhaseOrdinal = checkpointRecoveryOrdinal(op.Phase)
			}
		} else if recoveryQuery != nil {
			if err := recoveryQuery(ctx, op); err != nil {
				message := op.ID + ": node reconciliation: " + err.Error()
				unresolved = append(unresolved, message)
				targetErrors[targetID] = append(targetErrors[targetID], message)
				continue
			}
			hasObservation = true
		} else {
			message := op.ID + ": node reconciliation query is unavailable"
			unresolved = append(unresolved, message)
			targetErrors[targetID] = append(targetErrors[targetID], message)
			continue
		}
		if op.SnapshotName == "" {
			// A snapshotless row has been queried above. A terminal/released
			// observation proves that no resumable owner remains; an active row
			// requires an explicit correction hook before it can be cleared.
			terminalObservation := hasObservation && (observation.Phase == "release" || observation.Phase == "released" || observation.Phase == "cancel" || observation.Phase == "cancelled" || observation.Phase == "completed")
			if terminalObservation {
				continue
			}
			if correction != nil {
				if correctionErr := correction(ctx, op, observation, "snapshotless"); correctionErr == nil {
					continue
				} else {
					message := op.ID + ": missing snapshot reference: correction: " + correctionErr.Error()
					unresolved = append(unresolved, message)
					targetErrors[targetID] = append(targetErrors[targetID], message)
					continue
				}
			}
			message := op.ID + ": missing snapshot reference"
			unresolved = append(unresolved, message)
			targetErrors[targetID] = append(targetErrors[targetID], message)
			continue
		}
		_, metadata, getErr := c.Store.Get(op.OwnerID, op.SnapshotName)
		if getErr != nil {
			if correction != nil {
				if correctionErr := correction(ctx, op, observation, "snapshot_missing"); correctionErr == nil {
					continue
				} else {
					getErr = fmt.Errorf("%w: correction: %v", getErr, correctionErr)
				}
			}
			message := op.ID + ": " + getErr.Error()
			unresolved = append(unresolved, message)
			targetErrors[targetID] = append(targetErrors[targetID], message)
			continue
		}
		contextLimit := 0
		if strings.HasPrefix(op.ContextFingerprint, "ctx:") {
			_, _ = fmt.Sscanf(op.ContextFingerprint, "ctx:%d", &contextLimit)
		}
		command := CheckpointCommand{ID: op.ID, IdempotencyKey: op.IdempotencyKey, OwnerID: op.OwnerID, WorkloadID: op.WorkloadID, WorkloadRevision: op.WorkloadRevision, Generation: op.Generation, Fence: op.Fence, RuntimeIdentity: op.RuntimeIdentity, ModelFingerprint: op.ModelFingerprint, ProfileFingerprint: op.ProfileFingerprint, ContextLimit: contextLimit, ConversationID: op.ConversationID, ContinuationConversationID: op.ContinuationConversationID}
		if metadata.Identity.TargetID != "" && op.TargetID != "" && metadata.Identity.TargetID != op.TargetID {
			message := op.ID + ": snapshot target identity mismatch"
			unresolved = append(unresolved, message)
			targetErrors[targetID] = append(targetErrors[targetID], message)
			continue
		}
		if op.SnapshotDigest != "" && metadata.KVRuntimeDigest != "" && op.SnapshotDigest != metadata.KVRuntimeDigest {
			message := op.ID + ": snapshot digest identity mismatch"
			unresolved = append(unresolved, message)
			targetErrors[targetID] = append(targetErrors[targetID], message)
			continue
		}
		output := metadata.Output
		if len(op.PartialOutputContent) > 0 {
			output.Prefix = append([]byte(nil), op.PartialOutputContent...)
			output.TokenCount = op.PartialOutputOffset
		}
		output.UnsafeToolCall = op.PartialOutputUnsafeToolCall
		c.mu.Lock()
		// The entry is resumable metadata only. It does not recreate a physical
		// node owner; ownership is re-established by the signed restore lease.
		c.active[op.IdempotencyKey] = CheckpointMetadataState{Lease: SlotLease{TargetID: op.TargetID, NodeID: op.NodeID, AcceleratorID: op.AcceleratorID, SlotID: op.SlotID, OwnerID: op.OwnerID, WorkloadID: op.WorkloadID, Generation: op.Generation, Fence: op.Fence, RuntimeIdentity: op.RuntimeIdentity, ModelFingerprint: op.ModelFingerprint, ProfileFingerprint: op.ProfileFingerprint}, Snapshot: op.SnapshotName, Output: output, Command: command}
		c.mu.Unlock()
	}
	c.mu.Lock()
	c.targetRecoveryErr = make(map[string]error, len(targetErrors))
	for targetID, messages := range targetErrors {
		c.targetRecoveryErr[targetID] = fmt.Errorf("checkpoint recovery unresolved: %s", strings.Join(messages, "; "))
	}
	if len(unresolved) > 0 {
		c.recoveryErr = fmt.Errorf("checkpoint recovery unresolved: %s", strings.Join(unresolved, "; "))
	} else {
		c.recoveryErr = nil
	}
	result := c.recoveryErr
	c.mu.Unlock()
	return result
}

func (c *CheckpointCoordinator) OutputForSnapshot(owner, snapshot string) PartialOutput {
	if c == nil {
		return PartialOutput{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, state := range c.active {
		if state.Snapshot == snapshot && state.Command.OwnerID == owner {
			return PartialOutput{Prefix: append([]byte(nil), state.Output.Prefix...), AssistantContent: append([]byte(nil), state.Output.AssistantContent...), TokenCount: state.Output.TokenCount, Complete: state.Output.Complete, UnsafeToolCall: state.Output.UnsafeToolCall}
		}
	}
	return PartialOutput{}
}

func (c *CheckpointCoordinator) Ready() bool {
	// The controller coordinator is immutable and may intentionally have no
	// shared runtime.  HTTPAdapter supplies a per-operation NodeCheckpointRuntime
	// after resolving the authoritative target/channel; requiring Runtime here
	// would make that production path unreachable during bootstrap.
	if c == nil || c.Store == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recoveryErr == nil
}

func (c *CheckpointCoordinator) Checkpoint(ctx context.Context, command CheckpointCommand, lease SlotLease) (string, error) {
	if c == nil {
		return "", ErrCheckpointUnavailable
	}
	rt := c.Runtime
	if c.RuntimeFactory != nil {
		var err error
		rt, err = c.RuntimeFactory(ctx, command, lease)
		if err != nil {
			return "", err
		}
	}
	if rt == nil {
		return "", ErrCheckpointUnavailable
	}
	return c.checkpoint(ctx, command, lease, rt, c.Proof)
}

func (c *CheckpointCoordinator) CheckpointWithRuntime(ctx context.Context, command CheckpointCommand, lease SlotLease, rt CheckpointRuntime) (string, error) {
	return c.checkpoint(ctx, command, lease, rt, c.Proof)
}

func (c *CheckpointCoordinator) CheckpointWithRuntimeProof(ctx context.Context, command CheckpointCommand, lease SlotLease, rt CheckpointRuntime, proof runtime.CheckpointCapabilityProof) (string, error) {
	return c.checkpoint(ctx, command, lease, rt, proof)
}

// PrepareOperation durably reserves the operation identity before a managed
// stream sends any physical slot command. The later checkpoint phases replay
// this exact idempotency record rather than creating a second ownership row.
func (c *CheckpointCoordinator) PrepareOperation(ctx context.Context, command CheckpointCommand, lease SlotLease) error {
	if c == nil || c.Operations == nil {
		return ErrCheckpointUnavailable
	}
	command = withCheckpointConversation(command)
	if err := command.valid(); err != nil {
		return err
	}
	var op *store.LLMCheckpointOperation
	return c.persistOperation(ctx, command, lease, "planned", "", PartialOutput{}, 0, 0, &op)
}

// RecordOperationPhase mirrors the signed node journal in the controller
// operation row.  It is intentionally a small explicit API rather than a
// generic phase setter so callers cannot manufacture a phase without first
// completing the node action that produced it.
func (c *CheckpointCoordinator) RecordOperationPhase(ctx context.Context, command CheckpointCommand, lease SlotLease, phase string) error {
	if c == nil || c.Operations == nil {
		return ErrCheckpointUnavailable
	}
	command = withCheckpointConversation(command)
	current, err := c.Operations.GetLLMCheckpointOperationByIdempotency(ctx, command.OwnerID, command.IdempotencyKey)
	if err != nil {
		return err
	}
	partial := PartialOutput{}
	if current.PartialOutputContent != nil {
		partial.Prefix = append([]byte(nil), current.PartialOutputContent...)
		partial.TokenCount = current.PartialOutputOffset
		partial.UnsafeToolCall = current.PartialOutputUnsafeToolCall
	}
	return c.persistOperation(ctx, command, lease, phase, current.SnapshotName, partial, current.SavedTokens, current.ReusedTokens, &current)
}

func (c *CheckpointCoordinator) checkpoint(ctx context.Context, command CheckpointCommand, lease SlotLease, rt CheckpointRuntime, proof runtime.CheckpointCapabilityProof) (string, error) {
	if c == nil || rt == nil || c.Store == nil || !proof.Complete() {
		return "", ErrCheckpointUnavailable
	}
	command = withCheckpointConversation(command)
	if err := command.valid(); err != nil {
		return "", err
	}
	if c.Authorize != nil {
		if err := c.Authorize(command); err != nil {
			return "", err
		}
	}
	if lease.OwnerID != command.OwnerID || lease.WorkloadID != command.WorkloadID || lease.Generation != command.Generation || lease.Fence != command.Fence || lease.RuntimeIdentity != command.RuntimeIdentity || lease.ModelFingerprint != command.ModelFingerprint || lease.ProfileFingerprint != command.ProfileFingerprint || lease.ContextLimit != command.ContextLimit {
		return "", ErrCheckpointConflict
	}
	lease.Signature = command.Signature
	c.mu.Lock()
	if c.active == nil {
		c.active = make(map[string]CheckpointMetadataState)
	}
	if c.inflight == nil {
		c.inflight = make(map[string]struct{})
	}
	if prior, ok := c.active[command.IdempotencyKey]; ok {
		c.mu.Unlock()
		if prior.Command.ID == command.ID {
			return prior.Snapshot, nil
		}
		return "", ErrCheckpointConflict
	}
	if _, ok := c.inflight[command.IdempotencyKey]; ok {
		c.mu.Unlock()
		return "", ErrCheckpointConflict
	}
	c.inflight[command.IdempotencyKey] = struct{}{}
	c.mu.Unlock()
	completed := false
	assignedHardware := false
	compensationAttempted := false
	physicalSnapshot := false
	slotReleased := false
	var compensationOperation *store.LLMCheckpointOperation
	var compensationCommand CheckpointCommand
	var assigned SlotLease
	var partial PartialOutput
	var savedKV KVSnapshot
	var err error
	// A checkpoint has two distinct rollback cases. Before a durable snapshot
	// exists, the original assigned conversation can be resumed directly. After
	// the snapshot is committed, the node may already have accepted release;
	// compensation must therefore reacquire/reload/restore before resuming. The
	// linked rollback_resume phase lets a real command processor authorize that
	// recovery without pretending the released owner still owns the slot.
	restoreOriginal := func(restoreCtx context.Context) error {
		cleanupAssigned := func(activeLease SlotLease, cause error) error {
			cleanupErrs := []error{cause}
			// ConfirmStopped is the signed stop/idle boundary.  If the node is
			// already beyond that phase, ReleaseSlot is still attempted below;
			// the processor treats the exact release key as idempotent.
			if stopErr := rt.ConfirmBackendStopped(restoreCtx, activeLease); stopErr != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("stop confirmation during compensation cleanup: %w", stopErr))
			}
			if releaseErr := rt.ReleaseSlot(restoreCtx, activeLease); releaseErr != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("release during compensation cleanup: %w", releaseErr))
			}
			return errors.Join(cleanupErrs...)
		}
		if !physicalSnapshot {
			if resumeErr := rt.Resume(restoreCtx, assigned, partial); resumeErr != nil {
				return cleanupAssigned(assigned, resumeErr)
			}
			return nil
		}
		// A release error has no authoritative outcome. Preserve the original
		// direct rollback attempt for that ambiguous boundary; a confirmed
		// release (the only state in which ownership is known to be gone) takes
		// the reacquire/reload/restore path below.
		if !slotReleased {
			if resumeErr := rt.Resume(restoreCtx, assigned, partial); resumeErr != nil {
				return cleanupAssigned(assigned, resumeErr)
			}
			if inactiveErr := c.Store.MarkInactiveForOperation(command.OwnerID, savedKV.Ref, command.ID); inactiveErr != nil {
				return inactiveErr
			}
			return c.Store.DeletePrivileged(command.OwnerID, savedKV.Ref, SnapshotDeleteExpectation{OwnerID: command.OwnerID, OperationID: command.ID, ActiveReferences: 0, Terminalized: true})
		}
		var restoreErrs []error
		restoredLease := assigned
		if slotReleased {
			reacquired, reacquireErr := rt.AssignSlot(restoreCtx, assigned)
			if reacquireErr != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("reacquire: %w", reacquireErr))
			} else {
				restoredLease = reacquired
				assigned = reacquired
			}
		}
		if len(restoreErrs) == 0 && slotReleased && compensationOperation != nil {
			if phaseErr := c.persistOperation(context.WithoutCancel(restoreCtx), compensationCommand, restoredLease, "restore_assigned", savedKV.Ref, partial, savedKV.Tokens, 0, &compensationOperation); phaseErr != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("durable restore assignment: %w", phaseErr))
			}
		}
		if len(restoreErrs) == 0 && slotReleased {
			if reloadErr := rt.Reload(restoreCtx, restoredLease); reloadErr != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("reload: %w", reloadErr))
			}
		}
		if len(restoreErrs) == 0 && slotReleased && compensationOperation != nil {
			if phaseErr := c.persistOperation(context.WithoutCancel(restoreCtx), compensationCommand, restoredLease, "reloaded", savedKV.Ref, partial, savedKV.Tokens, 0, &compensationOperation); phaseErr != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("durable reload: %w", phaseErr))
			}
		}
		if len(restoreErrs) == 0 {
			if restoreErr := rt.RestoreKV(restoreCtx, restoredLease, savedKV); restoreErr != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("restore: %w", restoreErr))
			}
		}
		if len(restoreErrs) == 0 && slotReleased && compensationOperation != nil {
			if phaseErr := c.persistOperation(context.WithoutCancel(restoreCtx), compensationCommand, restoredLease, "restored", savedKV.Ref, partial, savedKV.Tokens, 0, &compensationOperation); phaseErr != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("durable restore evidence: %w", phaseErr))
			}
		}
		if len(restoreErrs) == 0 {
			if resumeErr := rt.Resume(restoreCtx, restoredLease, partial); resumeErr != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("resume: %w", resumeErr))
			}
		}
		if len(restoreErrs) == 0 && slotReleased && compensationOperation != nil {
			if phaseErr := c.persistOperation(context.WithoutCancel(restoreCtx), compensationCommand, restoredLease, "resumed", savedKV.Ref, partial, savedKV.Tokens, 0, &compensationOperation); phaseErr != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("durable compensation resume: %w", phaseErr))
			}
		}
		if len(restoreErrs) > 0 {
			// Reacquire/reload/restore can fail at any boundary. Release the
			// fresh assignment before surfacing an unresolved compensation.
			if cleanupErr := rt.ReleaseSlot(restoreCtx, restoredLease); cleanupErr != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("compensation slot cleanup: %w", cleanupErr))
			}
		} else if c.Store != nil && savedKV.Ref != "" {
			if inactiveErr := c.Store.MarkInactiveForOperation(command.OwnerID, savedKV.Ref, command.ID); inactiveErr != nil && !errors.Is(inactiveErr, os.ErrNotExist) {
				restoreErrs = append(restoreErrs, fmt.Errorf("snapshot terminalization: %w", inactiveErr))
			} else if cleanupErr := c.Store.DeletePrivileged(command.OwnerID, savedKV.Ref, SnapshotDeleteExpectation{OwnerID: command.OwnerID, OperationID: command.ID, ActiveReferences: 0, Terminalized: true}); cleanupErr != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("snapshot cleanup: %w", cleanupErr))
			}
		}
		if len(restoreErrs) > 0 {
			return errors.Join(restoreErrs...)
		}
		return nil
	}
	beginCompensation := func() (CheckpointCommand, error) {
		compCommand := command
		compCommand.ID = command.ID + ":compensate"
		compCommand.IdempotencyKey = command.IdempotencyKey + ":compensate"
		compCommand.CompensationOf = command.ID
		compCommand = withCheckpointConversation(compCommand)
		compensationCommand = compCommand
		if c.Operations != nil && compensationOperation == nil {
			compLease := assigned
			// The main operation may still own the original slot.  The
			// compensation intent therefore starts slotless and obtains its
			// own assignment in the signed rollback sequence.
			compLease.SlotID = -1
			if err := c.persistOperation(ctx, compCommand, compLease, "restore_planned", savedKV.Ref, partial, savedKV.Tokens, 0, &compensationOperation); err != nil {
				return CheckpointCommand{}, err
			}
		}
		if setter, ok := rt.(interface{ SetCheckpointCommand(CheckpointCommand) }); ok {
			setter.SetCheckpointCommand(compCommand)
		} else if setter, ok := rt.(checkpointCompensationRuntime); ok {
			setter.SetCheckpointCompensation(command.ID)
		}
		return compCommand, nil
	}
	finishCompensation := func(compCommand CheckpointCommand, phase string, cause error) error {
		if compensationOperation == nil || c.Operations == nil {
			return cause
		}
		compLease := assigned
		if compLease.SlotID < 0 {
			compLease.SlotID = assigned.SlotID
		}
		message := ""
		if cause != nil {
			message = cause.Error()
		}
		if err := c.persistOperation(context.Background(), compCommand, compLease, phase, compensationOperation.SnapshotName, partial, compensationOperation.SavedTokens, compensationOperation.ReusedTokens, &compensationOperation); err != nil {
			return err
		}
		if message != "" {
			next := *compensationOperation
			next.Error = message
			updated, updateErr := c.Operations.UpdateLLMCheckpointOperation(context.Background(), &next, compensationOperation.Revision)
			if updateErr != nil {
				return updateErr
			}
			compensationOperation = updated
		}
		return nil
	}
	compensate := func(cause error) (string, error) {
		if compensationAttempted {
			return "", cause
		}
		compensationAttempted = true
		compCommand, compErr := beginCompensation()
		if compErr != nil {
			c.mu.Lock()
			c.recoveryErr = fmt.Errorf("checkpoint compensation intent could not be persisted: %w", compErr)
			c.mu.Unlock()
			return "", fmt.Errorf("%w; compensation intent failed: %v", cause, compErr)
		}
		if restoreErr := restoreOriginal(context.WithoutCancel(ctx)); restoreErr != nil {
			_ = finishCompensation(compCommand, "failed", restoreErr)
			c.mu.Lock()
			c.recoveryErr = fmt.Errorf("checkpoint compensation unresolved: %w", restoreErr)
			c.mu.Unlock()
			return "", fmt.Errorf("%w; victim restore failed: %v", cause, restoreErr)
		}
		_ = finishCompensation(compCommand, "completed", nil)
		return "", cause
	}
	var operation *store.LLMCheckpointOperation
	// StartStreamWithLease prepares the durable operation before the first
	// backend phase. Reuse that exact row here; creating a second row would
	// make a physical slot mutation look like a new operation after restart.
	if c.Operations != nil {
		if existing, getErr := c.Operations.GetLLMCheckpointOperationByIdempotency(ctx, command.OwnerID, command.IdempotencyKey); getErr == nil {
			operation = existing
		} else if !errors.Is(getErr, store.ErrNotFound) {
			return "", getErr
		}
	}
	if err := c.persistOperation(ctx, command, lease, "planned", "", PartialOutput{}, 0, 0, &operation); err != nil {
		return "", err
	}
	defer func() {
		if !completed {
			if assignedHardware && !compensationAttempted {
				compensationAttempted = true
				compCommand, compErr := beginCompensation()
				if compErr != nil {
					c.mu.Lock()
					c.recoveryErr = fmt.Errorf("checkpoint compensation intent could not be persisted: %w", compErr)
					c.mu.Unlock()
				} else if restoreErr := restoreOriginal(context.Background()); restoreErr != nil {
					_ = finishCompensation(compCommand, "failed", restoreErr)
					c.mu.Lock()
					c.recoveryErr = fmt.Errorf("checkpoint compensation failed: %w", restoreErr)
					c.mu.Unlock()
				} else {
					_ = finishCompensation(compCommand, "completed", nil)
				}
			}
			if operation != nil && c.Operations != nil {
				failed := *operation
				failed.Phase = "failed"
				failed.PhaseOrdinal = checkpointRecoveryOrdinal("failed")
				failed.Error = "checkpoint lifecycle failed; victim retained or restore failure surfaced"
				if updateErr := func() error {
					_, err := c.Operations.UpdateLLMCheckpointOperation(context.Background(), &failed, operation.Revision)
					return err
				}(); updateErr != nil {
					c.mu.Lock()
					c.recoveryErr = fmt.Errorf("checkpoint failure record could not be persisted: %w", updateErr)
					c.mu.Unlock()
				}
			}
			c.mu.Lock()
			delete(c.inflight, command.IdempotencyKey)
			c.mu.Unlock()
		}
	}()
	if lease.SlotAssigned && lease.SlotID >= 0 {
		assigned = lease
	} else {
		assigned, err = rt.AssignSlot(ctx, lease)
		if err != nil {
			return "", err
		}
	}
	assignedHardware = true
	if assigned.SlotID < 0 || assigned.OwnerID != command.OwnerID || assigned.WorkloadID != command.WorkloadID || assigned.Generation != command.Generation || assigned.Fence != command.Fence || assigned.RuntimeIdentity != command.RuntimeIdentity || assigned.ModelFingerprint != command.ModelFingerprint || assigned.ProfileFingerprint != command.ProfileFingerprint || assigned.ContextLimit != command.ContextLimit {
		return compensate(ErrCheckpointConflict)
	}
	if err := c.persistOperation(ctx, command, assigned, "assigned", "", PartialOutput{}, 0, 0, &operation); err != nil {
		return compensate(err)
	}
	partial, err = rt.PauseAtTokenBoundary(ctx, assigned)
	if err != nil {
		return compensate(err)
	}
	if err := c.persistOperation(ctx, command, assigned, "paused", "", partial, 0, 0, &operation); err != nil {
		return compensate(err)
	}
	kv, err := rt.SaveKV(ctx, assigned)
	if err != nil {
		return compensate(err)
	}
	if len(kv.Bytes) == 0 && strings.TrimSpace(kv.Ref) == "" {
		return compensate(fmt.Errorf("runtime returned empty KV snapshot"))
	}
	if operation != nil {
		operation.SnapshotBytes = kv.SizeBytes
		operation.SnapshotDigest = kv.RuntimeDigest
	}
	command.SnapshotDigest = kv.RuntimeDigest
	if err := c.persistOperation(ctx, command, assigned, "saved", kv.Ref, partial, kv.Tokens, 0, &operation); err != nil {
		return compensate(err)
	}
	if err := rt.ConfirmBackendStopped(ctx, assigned); err != nil {
		return compensate(fmt.Errorf("backend stop not confirmed: %w", err))
	}
	if err := c.persistOperation(ctx, command, assigned, "stopped", kv.Ref, partial, kv.Tokens, 0, &operation); err != nil {
		return compensate(err)
	}
	identity := runtime.CheckpointIdentity{NodeID: lease.NodeID, TargetID: lease.TargetID, AcceleratorID: lease.AcceleratorID, OwnerID: command.OwnerID, WorkloadID: command.WorkloadID, Generation: command.Generation, RuntimeIdentity: command.RuntimeIdentity, ModelFingerprint: command.ModelFingerprint, ProfileFingerprint: command.ProfileFingerprint, ContextLimit: command.ContextLimit, SlotID: assigned.SlotID}
	name := ""
	if kv.Ref != "" {
		if !safeSnapshotFile.MatchString(filepath.Base(kv.Ref)) || filepath.Base(kv.Ref) != kv.Ref {
			return compensate(fmt.Errorf("runtime returned an unsafe KV reference"))
		}
		name = kv.Ref
	}
	material, _ := json.Marshal(identity)
	digest := sha256.Sum256(material)
	if name == "" {
		name = "owner-" + hex.EncodeToString(digest[:16]) + ".kv"
	}
	metadata := SnapshotMetadata{Identity: identity, Fence: command.Fence, OldFence: command.Fence - 1, NewFence: command.Fence, KVTokens: kv.Tokens, KVBytes: kv.SizeBytes, KVRuntimeDigest: kv.RuntimeDigest, KVRef: kv.Ref, Output: partial, ActiveReferences: 1, Terminalized: false, CreatedAt: time.Now().UTC(), CommandID: command.ID, WorkloadRevision: command.WorkloadRevision}
	data := kv.Bytes
	if len(data) == 0 {
		metadata.KVExternal = true
		metadata.KVDigest = kv.RuntimeDigest
	}
	if err := c.Store.Put(command.OwnerID, name, data, metadata); err != nil {
		return compensate(err)
	}
	savedKV = kv
	savedKV.Ref = name
	physicalSnapshot = true
	if err := rt.ReleaseSlot(ctx, assigned); err != nil {
		// The release result is ambiguous: the node may have accepted the
		// command and lost only its response. Never delete the sole restore
		// artifact here. Compensation first reconciles/resumes the exact lease;
		// an unreconciled artifact remains durable for restart recovery.
		return compensate(fmt.Errorf("slot release outcome is ambiguous: %w", err))
	}
	slotReleased = true
	if err := c.persistOperation(ctx, command, assigned, "released", name, partial, kv.Tokens, 0, &operation); err != nil {
		return compensate(err)
	}
	c.mu.Lock()
	c.active[command.IdempotencyKey] = CheckpointMetadataState{Lease: assigned, Snapshot: name, Output: partial, Command: command}
	delete(c.inflight, command.IdempotencyKey)
	c.mu.Unlock()
	completed = true
	return name, nil
}

func (c *CheckpointCoordinator) Restore(ctx context.Context, command CheckpointCommand, lease SlotLease, snapshotName string) error {
	if c == nil {
		return ErrCheckpointUnavailable
	}
	rt := c.Runtime
	if c.RuntimeFactory != nil {
		var err error
		rt, err = c.RuntimeFactory(ctx, command, lease)
		if err != nil {
			return err
		}
	}
	if rt == nil {
		return ErrCheckpointUnavailable
	}
	return c.restore(ctx, command, lease, snapshotName, rt, c.Proof)
}

func (c *CheckpointCoordinator) RestoreWithRuntime(ctx context.Context, command CheckpointCommand, lease SlotLease, snapshotName string, rt CheckpointRuntime) error {
	return c.restore(ctx, command, lease, snapshotName, rt, c.Proof)
}

func (c *CheckpointCoordinator) RestoreWithRuntimeProof(ctx context.Context, command CheckpointCommand, lease SlotLease, snapshotName string, rt CheckpointRuntime, proof runtime.CheckpointCapabilityProof) error {
	return c.restore(ctx, command, lease, snapshotName, rt, proof)
}

func (c *CheckpointCoordinator) restore(ctx context.Context, command CheckpointCommand, lease SlotLease, snapshotName string, rt CheckpointRuntime, proof runtime.CheckpointCapabilityProof) error {
	if c == nil || rt == nil || c.Store == nil || !proof.Complete() {
		return ErrCheckpointUnavailable
	}
	command = withCheckpointConversation(command)
	if err := command.valid(); err != nil {
		return err
	}
	if c.Authorize != nil {
		if err := c.Authorize(command); err != nil {
			return err
		}
	}
	if lease.OwnerID != command.OwnerID || lease.WorkloadID != command.WorkloadID || lease.Generation != command.Generation || lease.Fence != command.Fence || lease.RuntimeIdentity != command.RuntimeIdentity || lease.ModelFingerprint != command.ModelFingerprint || lease.ProfileFingerprint != command.ProfileFingerprint || lease.ContextLimit != command.ContextLimit {
		return ErrCheckpointConflict
	}
	data, metadata, err := c.Store.Get(command.OwnerID, snapshotName)
	if err != nil {
		return err
	}
	// The first controller lease legitimately has an old fence of zero.  The
	// new restore fence must still be strictly newer than both the snapshot's
	// durable fence and its non-zero new-fence marker.
	if metadata.Identity.OwnerID != command.OwnerID || metadata.Identity.WorkloadID != command.WorkloadID || metadata.Identity.TargetID != lease.TargetID || metadata.Identity.AcceleratorID != lease.AcceleratorID || (metadata.Identity.NodeID != "" && lease.NodeID != "" && metadata.Identity.NodeID != lease.NodeID) || (metadata.NodeID != "" && metadata.NodeID != metadata.Identity.NodeID) || metadata.Identity.Generation != command.Generation || metadata.Identity.RuntimeIdentity != command.RuntimeIdentity || metadata.Identity.ModelFingerprint != command.ModelFingerprint || metadata.Identity.ProfileFingerprint != command.ProfileFingerprint || metadata.Identity.ContextLimit != command.ContextLimit || metadata.Fence == 0 || command.Fence <= metadata.Fence || metadata.NewFence == 0 || command.Fence <= metadata.NewFence {
		return ErrCheckpointConflict
	}
	lease.Signature = command.Signature
	// Bind the restore operation to the digest recorded by the snapshot
	// manifest before the first durable restore phase. State queries must be
	// able to compare the node journal's digest with the controller row even
	// after a restart.
	command.SnapshotDigest = metadata.KVRuntimeDigest
	// A restore is authorized by the new lease and may use a different idle
	// slot. The snapshot slot is provenance only; do not force it after urgent
	// work has taken that physical slot.
	var operation *store.LLMCheckpointOperation
	if c.Operations != nil {
		if existing, getErr := c.Operations.GetLLMCheckpointOperationByIdempotency(ctx, command.OwnerID, command.IdempotencyKey); getErr == nil {
			operation = existing
		}
	}
	if err := c.persistOperation(ctx, command, lease, "restore_planned", snapshotName, metadata.Output, metadata.KVTokens, 0, &operation); err != nil {
		return err
	}
	markRestoreFailure := func(cause error) error {
		if operation == nil || c.Operations == nil {
			return cause
		}
		var updateErr error
		for attempt := 0; attempt < 4; attempt++ {
			failed := *operation
			failed.Phase = "restore_failed"
			failed.PhaseOrdinal = checkpointRecoveryOrdinal("restore_failed")
			failed.Error = cause.Error()
			if _, updateErr = c.Operations.UpdateLLMCheckpointOperation(context.Background(), &failed, operation.Revision); updateErr == nil || !errors.Is(updateErr, store.ErrLLMCheckpointConflict) {
				break
			}
			fresh, getErr := c.Operations.GetLLMCheckpointOperation(context.Background(), operation.ID)
			if getErr != nil || fresh.Revision == operation.Revision {
				break
			}
			operation = fresh
		}
		if updateErr != nil {
			c.mu.Lock()
			c.recoveryErr = fmt.Errorf("%w; restore failure record could not be persisted: %v", cause, updateErr)
			c.mu.Unlock()
			return c.recoveryErr
		}
		return cause
	}
	releaseOrVisible := func(cause error) error {
		if releaseErr := rt.ReleaseSlot(ctx, lease); releaseErr != nil {
			return markRestoreFailure(fmt.Errorf("%w; restore cleanup failed: %v", cause, releaseErr))
		}
		return markRestoreFailure(cause)
	}
	assigned, err := rt.AssignSlot(ctx, lease)
	if err != nil {
		return markRestoreFailure(err)
	}
	// The node is authoritative for the actual idle slot; a faithful driver
	// may select another safe idle slot for this newly authorized restore.
	if assigned.SlotID < 0 || assigned.OwnerID != command.OwnerID || assigned.WorkloadID != command.WorkloadID || assigned.Generation != command.Generation || assigned.Fence != command.Fence {
		if releaseErr := rt.ReleaseSlot(ctx, assigned); releaseErr != nil {
			return markRestoreFailure(fmt.Errorf("%w; assigned restore slot cleanup failed: %v", ErrCheckpointConflict, releaseErr))
		}
		return markRestoreFailure(ErrCheckpointConflict)
	}
	releaseOrVisible = func(cause error) error {
		if releaseErr := rt.ReleaseSlot(ctx, assigned); releaseErr != nil {
			return markRestoreFailure(fmt.Errorf("%w; restore cleanup failed: %v", cause, releaseErr))
		}
		return markRestoreFailure(cause)
	}
	if err := c.persistOperation(ctx, command, assigned, "restore_assigned", snapshotName, metadata.Output, metadata.KVTokens, 0, &operation); err != nil {
		return releaseOrVisible(err)
	}
	if err := rt.Reload(ctx, assigned); err != nil {
		return releaseOrVisible(err)
	}
	if err := c.persistOperation(ctx, command, assigned, "reloaded", snapshotName, metadata.Output, metadata.KVTokens, 0, &operation); err != nil {
		return releaseOrVisible(err)
	}
	if err := rt.RestoreKV(ctx, assigned, KVSnapshot{Bytes: data, Ref: metadata.KVRef, SizeBytes: metadata.KVBytes, Tokens: metadata.KVTokens, RuntimeDigest: metadata.KVRuntimeDigest}); err != nil {
		return releaseOrVisible(err)
	}
	if err := c.persistOperation(ctx, command, assigned, "restored", snapshotName, metadata.Output, metadata.KVTokens, 0, &operation); err != nil {
		return releaseOrVisible(err)
	}
	if deferred, ok := rt.(checkpointPhysicalRestoreRuntime); ok && deferred.DeferRestoreContinuation() {
		deferred.SetRestoreLease(assigned)
		return nil
	}
	// Resume binds the authorized continuation conversation before measuring
	// reuse. Measuring an idle slot (or stale pre-restore counters) is not
	// evidence for this resumed generation.
	if err := rt.Resume(ctx, assigned, metadata.Output); err != nil {
		return releaseOrVisible(err)
	}
	if err := c.persistOperation(ctx, command, assigned, "resumed", snapshotName, metadata.Output, metadata.KVTokens, 0, &operation); err != nil {
		return releaseOrVisible(err)
	}
	// Non-deferred runtimes establish the controller continuation as part of
	// Resume itself. Record the same explicit continued boundary used by the
	// native deferred stream before accepting a reuse measurement.
	if err := c.persistOperation(ctx, command, assigned, "continued", snapshotName, metadata.Output, metadata.KVTokens, 0, &operation); err != nil {
		return releaseOrVisible(err)
	}
	// The node-side Resume operation establishes the exact continuation
	// identity. Its reuse measurement is therefore attributable to this
	// operation rather than to an unrelated idle-slot counter.
	reused, err := rt.VerifyKVReuse(ctx, assigned, metadata.KVTokens)
	if err != nil || reused >= metadata.KVTokens {
		if err == nil {
			err = fmt.Errorf("restore performed full prefill")
		}
		return releaseOrVisible(err)
	}
	if err := c.persistOperation(ctx, command, assigned, "reused", snapshotName, metadata.Output, metadata.KVTokens, reused, &operation); err != nil {
		return releaseOrVisible(err)
	}
	c.mu.Lock()
	for key, prior := range c.active {
		if prior.Snapshot == snapshotName && prior.Command.OwnerID == command.OwnerID && prior.Command.WorkloadID == command.WorkloadID {
			delete(c.active, key)
		}
	}
	c.active[command.IdempotencyKey] = CheckpointMetadataState{Lease: assigned, Snapshot: snapshotName, Output: metadata.Output, Command: command}
	c.mu.Unlock()
	return nil
}

// FinalizeRestoreContinuation records reuse only after the real resumed
// conversation has supplied attributable cached-token evidence.
func (c *CheckpointCoordinator) FinalizeRestoreContinuation(ctx context.Context, command CheckpointCommand, lease SlotLease, snapshotName string, partial PartialOutput, reused int) error {
	if c == nil || c.Operations == nil || reused <= 0 {
		return ErrCheckpointUnavailable
	}
	op, err := c.Operations.GetLLMCheckpointOperationByIdempotency(ctx, command.OwnerID, command.IdempotencyKey)
	if err != nil {
		return err
	}
	if op.Phase != "restored" && op.Phase != "resumed" && op.Phase != "continued" {
		return ErrCheckpointConflict
	}
	if op.Phase == "restored" {
		if err := c.persistOperation(ctx, command, lease, "resumed", snapshotName, partial, op.SavedTokens, 0, &op); err != nil {
			return err
		}
	}
	if op.Phase == "resumed" {
		if err := c.persistOperation(ctx, command, lease, "continued", snapshotName, partial, op.SavedTokens, 0, &op); err != nil {
			return err
		}
	}
	if err := c.persistOperation(ctx, command, lease, "reused", snapshotName, partial, op.SavedTokens, reused, &op); err != nil {
		return err
	}
	c.mu.Lock()
	c.active[command.IdempotencyKey] = CheckpointMetadataState{Lease: lease, Snapshot: snapshotName, Output: partial, Command: command}
	c.mu.Unlock()
	return nil
}

func (c *CheckpointCoordinator) TerminalizeOperation(ctx context.Context, operationID, phase, message string) error {
	if c == nil || c.Operations == nil || operationID == "" {
		return nil
	}
	op, err := c.Operations.GetLLMCheckpointOperation(ctx, operationID)
	if err != nil {
		return err
	}
	if checkpointRecoveryOrdinal(phase) <= 0 || phase == "planned" || phase == "assigned" || phase == "started" || phase == "paused" || phase == "saved" || phase == "stopped" || phase == "released" || phase == "restore_planned" || phase == "restore_assigned" || phase == "reloaded" || phase == "restored" || phase == "reused" || phase == "resumed" || phase == "continued" {
		return fmt.Errorf("invalid checkpoint terminal phase %q", phase)
	}

	// A resumed stream has two durable operation rows: the original stream
	// owns the saved snapshot, while the restore operation owns the resumed
	// conversation.  The node-side reuse proof completes the latter, but the
	// original row must be completed in the same terminal transition or it
	// would retain a released uniqueness/manifest hold forever.  Prefer the
	// explicit compensation link when one exists; normal restores predate that
	// link, so resolve their source by the immutable owner/workload/snapshot
	// identity and the released phase.
	terminalize := func(row *store.LLMCheckpointOperation) error {
		if row == nil || row.Phase == "completed" || row.Phase == "failed" || row.Phase == "cancelled" || row.Phase == "restore_failed" {
			return nil
		}
		current := row
		// A successful managed stream has no snapshot, but it still owns a
		// started slot. Persist the authoritative stop/release boundaries before
		// writing completed. This is also used for a normal stream whose client
		// never asked for preemption.
		if phase == "completed" {
			for _, nextPhase := range []string{"stopped", "released"} {
				if current.Phase == nextPhase || current.Phase == "released" {
					continue
				}
				if !llmCheckpointTerminalTransitionForSuccess(current.Phase, nextPhase) {
					break
				}
				next := *current
				next.Phase = nextPhase
				next.PhaseOrdinal = checkpointRecoveryOrdinal(nextPhase)
				updated, updateErr := c.Operations.UpdateLLMCheckpointOperation(ctx, &next, current.Revision)
				if updateErr != nil {
					return updateErr
				}
				current = updated
			}
		}
		next := *current
		next.Phase = phase
		next.PhaseOrdinal = checkpointRecoveryOrdinal(phase)
		next.Error = message
		updated, updateErr := c.Operations.UpdateLLMCheckpointOperation(ctx, &next, current.Revision)
		if updateErr != nil {
			return updateErr
		}
		*row = *updated
		return nil
	}

	var source *store.LLMCheckpointOperation
	if op.CompensationOf != "" {
		candidate, getErr := c.Operations.GetLLMCheckpointOperation(ctx, op.CompensationOf)
		if getErr != nil {
			return getErr
		}
		if candidate.ID != op.ID && candidate.OwnerID == op.OwnerID && candidate.WorkloadID == op.WorkloadID && candidate.SnapshotName == op.SnapshotName {
			source = candidate
		}
	} else if op.SnapshotName != "" {
		rows, listErr := c.Operations.ListLLMCheckpointOperations(ctx, op.OwnerID)
		if listErr != nil {
			return listErr
		}
		for _, candidate := range rows {
			if candidate == nil || candidate.ID == op.ID || candidate.Phase != "released" {
				continue
			}
			if candidate.OwnerID == op.OwnerID && candidate.WorkloadID == op.WorkloadID && candidate.SnapshotName == op.SnapshotName {
				source = candidate
				break
			}
		}
	}
	// Update the source first.  If the primary update loses a CAS race, a
	// retry is safe: the source is already terminal and the primary remains
	// eligible for the same transition.
	if err := terminalize(source); err != nil {
		return err
	}
	if err := terminalize(op); err != nil {
		return err
	}
	if c.Store != nil && op.SnapshotName != "" {
		snapshotOwner := op.OwnerID
		snapshotOperation := op.ID
		if source != nil {
			snapshotOperation = source.ID
		}
		if inactiveErr := c.Store.MarkInactiveForOperation(snapshotOwner, op.SnapshotName, snapshotOperation); inactiveErr != nil && !errors.Is(inactiveErr, os.ErrNotExist) {
			return inactiveErr
		}
	}
	return nil
}

// ProbeCapabilityProof is intentionally never sufficient for admission.
func ProbeCapabilityProof() runtime.CheckpointCapabilityProof {
	return runtime.CheckpointCapabilityProof{ProbeOnly: true, Reason: "probe result is not production checkpoint proof"}
}

// DigestOutput is used by adapters to bind buffered partial output to the
// same owner/generation envelope as the KV snapshot.
func DigestOutput(output []byte) string {
	sum := sha256.Sum256(output)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type checkpointExecution struct {
	Request        domain.WorkloadRequest
	Plan           *domain.ExecutionPlan
	Target         Target
	Lease          SlotLease
	OperationID    string
	SnapshotName   string
	Emit           func([]byte) error
	Resumed        bool
	ConversationID string
	// OperationConversationID is the immutable conversation identity journaled
	// by the node. ConversationID becomes the live continuation conversation
	// after restore, so recovery queries must retain both values.
	OperationConversationID string
}

// SetLLMCheckpointCoordinator is the explicit production wiring point. A
// plain HTTPAdapter remains cancelable but never becomes checkpointable by
// configuration or by the probe result alone.
func (a *HTTPAdapter) SetLLMCheckpointCoordinator(coordinator *CheckpointCoordinator) {
	a.checkpointMu.Lock()
	a.checkpoint = coordinator
	if a.checkpointProofs == nil {
		a.checkpointProofs = make(map[string]runtime.CheckpointCapabilityProof)
	}
	a.checkpointMu.Unlock()
}

// SetCheckpointProof consumes target-scoped node evidence delivered by the
// advertisement. A controller-global proof file is never consulted.
func (a *HTTPAdapter) SetCheckpointProof(proof runtime.CheckpointCapabilityProof) {
	a.checkpointMu.Lock()
	defer a.checkpointMu.Unlock()
	if proof.Complete() {
		a.checkpointProofs[proof.TargetID] = proof
	}
}

func (a *HTTPAdapter) SetTargetCheckpointProof(targetID string, proof runtime.CheckpointCapabilityProof) {
	a.checkpointMu.Lock()
	defer a.checkpointMu.Unlock()
	if a.checkpointProofs == nil {
		a.checkpointProofs = make(map[string]runtime.CheckpointCapabilityProof)
	}
	if proof.Complete() {
		a.checkpointProofs[targetID] = proof
	} else {
		delete(a.checkpointProofs, targetID)
	}
	coordinator := a.checkpoint
	if coordinator != nil {
		coordinator.SetTargetProof(targetID, proof)
	}
}

func (a *HTTPAdapter) LeaseStreamingEnabled() bool {
	a.checkpointMu.Lock()
	defer a.checkpointMu.Unlock()
	return a.checkpoint != nil && a.checkpointResolver != nil && len(a.checkpointProofs) > 0
}

func (a *HTTPAdapter) LeaseStreamingEnabledForTarget(target Target) bool {
	a.checkpointMu.Lock()
	coordinator := a.checkpoint
	proof := a.checkpointProofs[target.ID]
	a.checkpointMu.Unlock()
	return a.kind == "llama" && coordinator != nil && proof.Complete() && coordinator.ReadyForTarget(target, "", "", 0, 0)
}

func (a *HTTPAdapter) recordCheckpointExecution(h *domain.ExecutionHandle, req domain.WorkloadRequest, plan *domain.ExecutionPlan, target Target) {
	if a.kind != "llama" || h == nil {
		return
	}
	a.checkpointMu.Lock()
	a.checkpointRuns[h.ExternalID] = checkpointExecution{Request: req, Plan: plan, Target: target}
	a.checkpointMu.Unlock()
}

func (a *HTTPAdapter) CheckpointProof() runtime.CheckpointCapabilityProof {
	a.checkpointMu.Lock()
	defer a.checkpointMu.Unlock()
	if a.checkpoint == nil {
		return ProbeCapabilityProof()
	}
	for _, proof := range a.checkpointProofs {
		return proof
	}
	return ProbeCapabilityProof()
}

// NodeCheckpointRuntime is the production boundary. It never opens a
// controller-to-runtime HTTP connection: NodeControl persists, signs,
// fences, delivers, and waits for each command through the existing node
// command channel.
type NodeCheckpointRuntime struct {
	Control          NodeControl
	NodeID           string
	Target           Target
	Command          CheckpointCommand
	LastResumeID     string
	OutputPrefix     []byte
	AssistantContent []byte
	AssignedSlotID   int
	compensationOf   string
	OutputSnapshot   func() (prefix, assistant []byte)
	UnsafeToolCall   func() bool
}

func (r *NodeCheckpointRuntime) DeferRestoreContinuation() bool { return true }

func (r *NodeCheckpointRuntime) SetRestoreLease(lease SlotLease) {
	if r != nil {
		r.AssignedSlotID = lease.SlotID
	}
}

func (r *NodeCheckpointRuntime) SetCheckpointCompensation(operationID string) {
	if r != nil {
		r.compensationOf = operationID
	}
}

// SetCheckpointCommand switches the signed operation envelope for a durable
// compensation.  The compensation gets its own operation/idempotency key and
// links back to the immutable main operation through CompensationOf.
func (r *NodeCheckpointRuntime) SetCheckpointCommand(command CheckpointCommand) {
	if r != nil {
		r.Command = command
		r.compensationOf = command.CompensationOf
	}
}

func (r *NodeCheckpointRuntime) call(ctx context.Context, action string, lease SlotLease, extra map[string]any) (map[string]any, error) {
	if r == nil || r.Control == nil || strings.TrimSpace(r.NodeID) == "" {
		return nil, ErrCheckpointUnavailable
	}
	model := r.Command.ModelFingerprint
	if strings.TrimSpace(model) == "" {
		return nil, ErrCheckpointConflict
	}
	args := map[string]any{
		"target_kind": "llamacpp", "target_id": r.Target.ID, "accelerator_id": lease.AcceleratorID, "model": model,
		"runtime_identity": lease.RuntimeIdentity, "capability_version": r.Target.CapabilityVersion,
		"capability_revision": r.Target.CapabilityRevision, "profile_fingerprint": lease.ProfileFingerprint,
		"context_fingerprint": fmt.Sprintf("ctx:%d", lease.ContextLimit), "owner_id": lease.OwnerID,
		"workload_id": lease.WorkloadID, "generation": lease.Generation, "fencing_token": lease.Fence,
		"context_limit": lease.ContextLimit, "checkpoint_action": action, "checkpoint_operation_id": r.Command.ID,
	}
	if conversationID := r.Command.ConversationID; conversationID != "" {
		args["conversation_id"] = conversationID
	}
	if continuationID := r.Command.ContinuationConversationID; continuationID != "" {
		args["continuation_conversation_id"] = continuationID
	}
	if r.Command.IdempotencyKey != "" {
		args["idempotency_key"] = r.Command.IdempotencyKey + ":" + action
	}
	for k, v := range extra {
		args[k] = v
	}
	result, err := r.Control(ctx, r.NodeID, "checkpoint_"+action, args, r.Command.IdempotencyKey+":"+action)
	return result, err
}

func (r *NodeCheckpointRuntime) AssignSlot(ctx context.Context, lease SlotLease) (SlotLease, error) {
	result, err := r.call(ctx, "slot_assign", lease, map[string]any{"slot_id": lease.SlotID})
	if err != nil {
		return SlotLease{}, err
	}
	slot := -1
	switch n := result["slot_id"].(type) {
	case int:
		slot = n
	case float64:
		slot = int(n)
	}
	if slot < 0 {
		return SlotLease{}, ErrCheckpointConflict
	}
	lease.SlotID = slot
	r.AssignedSlotID = slot
	return lease, nil
}
func (r *NodeCheckpointRuntime) PauseAtTokenBoundary(ctx context.Context, lease SlotLease) (PartialOutput, error) {
	result, err := r.call(ctx, "pause", lease, map[string]any{"slot_id": lease.SlotID})
	if err != nil {
		return PartialOutput{}, err
	}
	var out PartialOutput
	b, _ := json.Marshal(result)
	_ = json.Unmarshal(b, &out)
	if len(out.Prefix) == 0 && len(r.OutputPrefix) > 0 {
		out.Prefix = append([]byte(nil), r.OutputPrefix...)
	}
	if r.OutputSnapshot != nil {
		prefix, assistant := r.OutputSnapshot()
		out.Prefix = prefix
		if len(assistant) > 0 {
			out.AssistantContent = assistant
		}
	}
	if r.UnsafeToolCall != nil && r.UnsafeToolCall() {
		out.UnsafeToolCall = true
	}
	if len(r.AssistantContent) > 0 {
		out.AssistantContent = append([]byte(nil), r.AssistantContent...)
	}
	return out, nil
}
func (r *NodeCheckpointRuntime) SaveKV(ctx context.Context, lease SlotLease) (KVSnapshot, error) {
	name := r.Command.SnapshotName
	if name == "" {
		return KVSnapshot{}, fmt.Errorf("production snapshot name is required")
	}
	result, err := r.call(ctx, "save", lease, map[string]any{"slot_id": lease.SlotID, "snapshot_name": name})
	if err != nil {
		return KVSnapshot{}, err
	}
	var out KVSnapshot
	b, _ := json.Marshal(result)
	_ = json.Unmarshal(b, &out)
	if value, ok := result["snapshot_bytes"].(float64); ok {
		out.SizeBytes = int64(value)
	} else if value, ok := result["snapshot_bytes"].(int64); ok {
		out.SizeBytes = value
	} else if value, ok := result["snapshot_bytes"].(int); ok {
		out.SizeBytes = int64(value)
	}
	if value, ok := result["saved_tokens"].(float64); ok {
		out.Tokens = int(value)
	} else if value, ok := result["saved_tokens"].(int); ok {
		out.Tokens = value
	} else if value, ok := result["saved_tokens"].(int64); ok {
		out.Tokens = int(value)
	}
	if out.Ref == "" {
		out.Ref, _ = result["snapshot_ref"].(string)
		if out.Ref == "" {
			out.Ref, _ = result["ref"].(string)
		}
		if out.Ref == "" {
			out.Ref, _ = result["snapshot_name"].(string)
		}
	}
	if out.RuntimeDigest == "" {
		out.RuntimeDigest, _ = result["snapshot_digest"].(string)
		if out.RuntimeDigest == "" {
			out.RuntimeDigest, _ = result["runtime_digest"].(string)
		}
	}
	if out.SizeBytes <= 0 && len(out.Bytes) > 0 {
		out.SizeBytes = int64(len(out.Bytes))
	}
	if out.Ref == "" || out.RuntimeDigest == "" || out.SizeBytes <= 0 || out.Tokens <= 0 {
		return KVSnapshot{}, fmt.Errorf("node omitted authoritative KV snapshot evidence")
	}
	return out, nil
}
func (r *NodeCheckpointRuntime) ConfirmBackendStopped(ctx context.Context, lease SlotLease) error {
	_, err := r.call(ctx, "stop_confirm", lease, map[string]any{"slot_id": lease.SlotID})
	return err
}
func (r *NodeCheckpointRuntime) ReleaseSlot(ctx context.Context, lease SlotLease) error {
	extra := map[string]any{"slot_id": lease.SlotID}
	if r.Command.SnapshotName != "" {
		extra["snapshot_name"] = r.Command.SnapshotName
	}
	_, err := r.call(ctx, "release", lease, extra)
	return err
}
func (r *NodeCheckpointRuntime) Reload(ctx context.Context, lease SlotLease) error {
	_, err := r.call(ctx, "reload", lease, map[string]any{"slot_id": lease.SlotID})
	return err
}
func (r *NodeCheckpointRuntime) RestoreKV(ctx context.Context, lease SlotLease, snapshot KVSnapshot) error {
	_, err := r.call(ctx, "restore", lease, map[string]any{"slot_id": lease.SlotID, "snapshot_name": snapshot.Ref, "snapshot_digest": snapshot.RuntimeDigest, "saved_tokens": snapshot.Tokens})
	return err
}
func (r *NodeCheckpointRuntime) VerifyKVReuse(ctx context.Context, lease SlotLease, saved int) (int, error) {
	result, err := r.call(ctx, "reuse_verify", lease, map[string]any{"slot_id": lease.SlotID, "saved_tokens": saved})
	if err != nil {
		return 0, err
	}
	for _, key := range []string{"reused_tokens", "prefilled_tokens"} {
		switch n := result[key].(type) {
		case int:
			return n, nil
		case float64:
			return int(n), nil
		}
	}
	return 0, fmt.Errorf("node omitted KV reuse measurement")
}
func (r *NodeCheckpointRuntime) Resume(ctx context.Context, lease SlotLease, output PartialOutput) error {
	action := "resume"
	if r.compensationOf != "" {
		action = "rollback_resume"
	}
	extra := map[string]any{"slot_id": lease.SlotID, "partial_output_hash": DigestOutput(output.Prefix), "partial_output_offset": len(output.Prefix), "continuation_conversation_id": r.Command.ContinuationConversationID}
	if r.compensationOf != "" {
		extra["compensation_of"] = r.compensationOf
	}
	result, err := r.call(ctx, action, lease, extra)
	if err == nil {
		if id, ok := result["external_id"].(string); ok {
			r.LastResumeID = id
		}
	}
	return err
}

// Cancel is the signed cleanup boundary for a resumed handle whose controller
// publication or continuation CAS failed.  It is intentionally distinct from
// ReleaseSlot: the node must first drain the exact resumed conversation before
// dropping ownership.
func (r *NodeCheckpointRuntime) Cancel(ctx context.Context, lease SlotLease) error {
	if r == nil {
		return ErrCheckpointUnavailable
	}
	extra := map[string]any{"slot_id": lease.SlotID, "compensation_of": r.Command.ID}
	if r.Command.ContinuationConversationID != "" {
		extra["continuation_conversation_id"] = r.Command.ContinuationConversationID
	}
	_, err := r.call(ctx, "cancel", lease, extra)
	return err
}

// ContinueControllerStream records the signed continuation phase for a
// response that the controller has already opened against the restored slot.
// The node processor validates the phase and conversation ownership but does
// not issue a second HTTP generation.
func (r *NodeCheckpointRuntime) ContinueControllerStream(ctx context.Context, lease SlotLease, conversationID string, assistantPrefix []byte) error {
	if strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("checkpoint continuation requires conversation id")
	}
	if r != nil {
		r.Command.ContinuationConversationID = conversationID
	}
	_, err := r.call(ctx, "continue", lease, map[string]any{
		"slot_id":                      lease.SlotID,
		"continuation_conversation_id": conversationID,
		"assistant_prefix":             string(assistantPrefix),
		"controller_stream":            true,
	})
	return err
}
