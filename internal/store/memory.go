package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"vram-governor/internal/domain"
)

// MemoryStore is the concurrency-safe development implementation of the full
// controller store. Production uses PostgresWorkloadStore.
type MemoryStore struct {
	mu       sync.RWMutex
	nodes    map[string]*domain.Node
	engines  map[string]*domain.EngineInstance       // by engine ID
	profiles map[string][]*domain.PerformanceProfile // by node ID

	jobs                  map[string]*domain.Job                            // by job ID
	workItems             map[string]map[string]map[string]*domain.WorkItem // job -> item -> operation version
	workloads             map[string]*domain.Workload
	idempotency           map[string]string
	leases                map[string]*domain.AcceleratorLease
	leaseFences           map[string]int64
	leaseCleanupIntents   map[string]*domain.AcceleratorLeaseCleanupIntent
	promptMappings        map[string]*domain.PromptMapping
	auditEvents           []*domain.AuditEvent
	incidents             map[string]*domain.Incident
	residencies           map[string]*domain.ModelResidency
	transitions           map[string]*domain.ResidencyTransition
	transitionKeys        map[string]string
	notifications         map[string]*domain.NotificationDelivery
	notificationKeys      map[string]string
	nodeCommands          map[string]*domain.NodeCommand
	nodeCommandKeys       map[string]string
	budgets               map[string]*domain.BudgetReservation
	transformApprovals    map[string]*domain.TransformationApproval
	learningSamples       []*domain.SchedulerLearningSample
	interferenceProfiles  map[string]*domain.InterferenceProfile
	transitionPlans       map[string]*domain.TransitionPlan
	targetPolicyOverrides map[string]*domain.TargetPolicyOverride
	browserSessions       map[string]*domain.BrowserSession
	nodeEnrollments       map[string]*domain.NodeEnrollment
	runtimeProfiles       map[string]*domain.RuntimeProfile
	workingSets           map[string]*domain.WorkingSet
	modelCapacities       map[string]*ModelCapacity
	llmCheckpointOps      map[string]*LLMCheckpointOperation
	llmCheckpointKeys     map[string]string
	llmDisplacementOps    map[string]*LLMDisplacementOperation
	llmDisplacementKeys   map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		nodes:               make(map[string]*domain.Node),
		engines:             make(map[string]*domain.EngineInstance),
		profiles:            make(map[string][]*domain.PerformanceProfile),
		jobs:                make(map[string]*domain.Job),
		workItems:           make(map[string]map[string]map[string]*domain.WorkItem),
		workloads:           make(map[string]*domain.Workload),
		idempotency:         make(map[string]string),
		leases:              make(map[string]*domain.AcceleratorLease),
		leaseFences:         make(map[string]int64),
		leaseCleanupIntents: make(map[string]*domain.AcceleratorLeaseCleanupIntent),
		promptMappings:      make(map[string]*domain.PromptMapping),
		incidents:           make(map[string]*domain.Incident),
		residencies:         make(map[string]*domain.ModelResidency),
		transitions:         make(map[string]*domain.ResidencyTransition),
		transitionKeys:      make(map[string]string),
		notifications:       make(map[string]*domain.NotificationDelivery), notificationKeys: make(map[string]string),
		nodeCommands: make(map[string]*domain.NodeCommand), nodeCommandKeys: make(map[string]string),
		budgets:               make(map[string]*domain.BudgetReservation),
		transformApprovals:    make(map[string]*domain.TransformationApproval),
		interferenceProfiles:  make(map[string]*domain.InterferenceProfile),
		transitionPlans:       make(map[string]*domain.TransitionPlan),
		targetPolicyOverrides: make(map[string]*domain.TargetPolicyOverride),
		browserSessions:       make(map[string]*domain.BrowserSession),
		nodeEnrollments:       make(map[string]*domain.NodeEnrollment),
		runtimeProfiles:       make(map[string]*domain.RuntimeProfile),
		workingSets:           make(map[string]*domain.WorkingSet),
		modelCapacities:       make(map[string]*ModelCapacity),
		llmCheckpointOps:      make(map[string]*LLMCheckpointOperation),
		llmCheckpointKeys:     make(map[string]string),
		llmDisplacementOps:    make(map[string]*LLMDisplacementOperation),
		llmDisplacementKeys:   make(map[string]string),
	}
}

func cloneLLMCheckpointOperation(op *LLMCheckpointOperation) *LLMCheckpointOperation {
	if op == nil {
		return nil
	}
	copy := *op
	copy.PartialOutputContent = append([]byte(nil), op.PartialOutputContent...)
	if op.RecoveryHandle != nil {
		handle := *op.RecoveryHandle
		handle.Opaque = append([]byte(nil), op.RecoveryHandle.Opaque...)
		if op.RecoveryHandle.Performance != nil {
			performance := *op.RecoveryHandle.Performance
			handle.Performance = &performance
		}
		copy.RecoveryHandle = &handle
	}
	if op.CleanupHandle != nil {
		handle := *op.CleanupHandle
		handle.Opaque = append([]byte(nil), op.CleanupHandle.Opaque...)
		if op.CleanupHandle.Performance != nil {
			performance := *op.CleanupHandle.Performance
			handle.Performance = &performance
		}
		copy.CleanupHandle = &handle
	}
	return &copy
}

func (m *MemoryStore) CreateLLMCheckpointOperation(_ context.Context, op *LLMCheckpointOperation) (*LLMCheckpointOperation, bool, error) {
	prepared, err := prepareLLMCheckpointCreate(op)
	if err != nil {
		return nil, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing := m.llmCheckpointOps[prepared.ID]; existing != nil {
		if sameLLMCheckpointIdentity(existing, prepared) {
			return cloneLLMCheckpointOperation(existing), false, nil
		}
		return nil, false, fmt.Errorf("%w: id exists with another identity", ErrLLMCheckpointConflict)
	}
	key := prepared.OwnerID + "\x00" + prepared.IdempotencyKey
	if id := m.llmCheckpointKeys[key]; id != "" {
		existing := m.llmCheckpointOps[id]
		if sameLLMCheckpointIdentity(existing, prepared) {
			return cloneLLMCheckpointOperation(existing), false, nil
		}
		return nil, false, fmt.Errorf("%w: idempotency key used by another operation", ErrLLMCheckpointConflict)
	}
	for _, existing := range m.llmCheckpointOps {
		if existing.TargetID == prepared.TargetID && existing.AcceleratorID == prepared.AcceleratorID && existing.SlotID >= 0 && existing.SlotID == prepared.SlotID && llmCheckpointHoldsSlot(existing.Phase) && llmCheckpointHoldsSlot(prepared.Phase) {
			return nil, false, fmt.Errorf("%w: slot %d held by operation %s (%s)", ErrLLMCheckpointConflict, existing.SlotID, existing.ID, existing.Phase)
		}
	}
	m.llmCheckpointOps[prepared.ID] = prepared
	m.llmCheckpointKeys[key] = prepared.ID
	return cloneLLMCheckpointOperation(prepared), true, nil
}
func (m *MemoryStore) GetLLMCheckpointOperation(_ context.Context, id string) (*LLMCheckpointOperation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if op := m.llmCheckpointOps[id]; op != nil {
		return cloneLLMCheckpointOperation(op), nil
	}
	return nil, ErrNotFound
}
func (m *MemoryStore) GetLLMCheckpointOperationByIdempotency(_ context.Context, owner, key string) (*LLMCheckpointOperation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id := m.llmCheckpointKeys[owner+"\x00"+key]
	if id == "" {
		return nil, ErrNotFound
	}
	op := m.llmCheckpointOps[id]
	if op == nil {
		return nil, ErrNotFound
	}
	return cloneLLMCheckpointOperation(op), nil
}
func (m *MemoryStore) UpdateLLMCheckpointOperation(_ context.Context, op *LLMCheckpointOperation, expected uint64) (*LLMCheckpointOperation, error) {
	if op != nil {
		op = cloneLLMCheckpointOperation(op)
		if op.ConversationID == "" {
			seed := sha256.Sum256([]byte(op.OwnerID + "|" + op.WorkloadID + "|" + fmt.Sprint(op.Generation) + "|" + fmt.Sprint(op.Fence) + "|" + op.ID))
			op.ConversationID = "conv-" + hex.EncodeToString(seed[:12])
		}
	}
	if err := validateLLMCheckpointRequiredIdentity(op); err != nil {
		return nil, err
	}
	if expected == 0 {
		return nil, ErrLLMCheckpointConflict
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.llmCheckpointOps[op.ID]
	if current == nil {
		return nil, ErrNotFound
	}
	if current.Revision != expected {
		return nil, fmt.Errorf("%w: revision %d, expected %d", ErrLLMCheckpointConflict, current.Revision, expected)
	}
	if !llmCheckpointImmutableIdentityEqual(current, op) {
		return nil, fmt.Errorf("%w: immutable identity changed", ErrLLMCheckpointConflict)
	}
	if !llmCheckpointTransitionAllowedFor(current, op) {
		return nil, fmt.Errorf("%w: transition %s -> %s not allowed", ErrLLMCheckpointConflict, current.Phase, op.Phase)
	}
	for id, existing := range m.llmCheckpointOps {
		if id == op.ID || existing.TargetID != op.TargetID || existing.AcceleratorID != op.AcceleratorID || existing.SlotID < 0 || op.SlotID < 0 || existing.SlotID != op.SlotID {
			continue
		}
		if llmCheckpointHoldsSlot(existing.Phase) && llmCheckpointHoldsSlot(op.Phase) {
			return nil, fmt.Errorf("%w: slot %d held by operation %s (%s)", ErrLLMCheckpointConflict, existing.SlotID, existing.ID, existing.Phase)
		}
	}
	copy := cloneLLMCheckpointOperation(op)
	copy.CreatedAt = current.CreatedAt
	copy.Revision = current.Revision + 1
	copy.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
	m.llmCheckpointOps[op.ID] = copy
	return cloneLLMCheckpointOperation(copy), nil
}
func (m *MemoryStore) ListLLMCheckpointOperations(_ context.Context, owner string) ([]*LLMCheckpointOperation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*LLMCheckpointOperation, 0)
	for _, op := range m.llmCheckpointOps {
		if owner == "" || op.OwnerID == owner {
			out = append(out, cloneLLMCheckpointOperation(op))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt.Equal(out[j].UpdatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].UpdatedAt.Before(out[j].UpdatedAt)
	})
	return out, nil
}

func cloneModelCapacity(capacity *ModelCapacity) *ModelCapacity {
	if capacity == nil {
		return nil
	}
	copy := *capacity
	return &copy
}

func (m *MemoryStore) UpsertModelCapacity(_ context.Context, capacity *ModelCapacity) (*ModelCapacity, error) {
	if capacity == nil || capacity.TargetID == "" || capacity.Model == "" {
		return nil, errors.New("model capacity requires target and model")
	}
	if capacity.FootprintBytes() < 0 || capacity.VRAMReserveBytes < 0 || capacity.RuntimeHardCapBytes < 0 || capacity.RAMBytes < 0 || capacity.RAMReserveBytes < 0 || capacity.VRAMTotalBytes < 0 || capacity.RAMTotalBytes < 0 {
		return nil, errors.New("model capacity bytes may not be negative or overflow")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := modelCapacityKey(capacity.TargetID, capacity.Model, capacity.ProfileID)
	stored := cloneModelCapacity(capacity)
	if previous := m.modelCapacities[key]; previous != nil {
		stored.Revision = previous.Revision + 1
	} else if stored.Revision == 0 {
		stored.Revision = 1
	}
	if stored.UpdatedAt.IsZero() {
		stored.UpdatedAt = time.Now().UTC()
	}
	if stored.ObservedAt.IsZero() {
		stored.ObservedAt = stored.UpdatedAt
	}
	stored.ID = modelCapacityID(stored.TargetID, stored.Model, stored.ProfileID)
	m.modelCapacities[key] = stored
	return cloneModelCapacity(stored), nil
}

func (m *MemoryStore) GetModelCapacity(_ context.Context, targetID, model, profileID string) (*ModelCapacity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	capacity := m.modelCapacities[modelCapacityKey(targetID, model, profileID)]
	if capacity == nil {
		return nil, ErrNotFound
	}
	return cloneModelCapacity(capacity), nil
}

func (m *MemoryStore) ListModelCapacities(_ context.Context, targetID, model string) ([]*ModelCapacity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*ModelCapacity, 0)
	for _, capacity := range m.modelCapacities {
		if targetID != "" && capacity.TargetID != targetID || model != "" && capacity.Model != model {
			continue
		}
		result = append(result, cloneModelCapacity(capacity))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].TargetID != result[j].TargetID {
			return result[i].TargetID < result[j].TargetID
		}
		if result[i].Model != result[j].Model {
			return result[i].Model < result[j].Model
		}
		return result[i].ProfileID < result[j].ProfileID
	})
	return result, nil
}

func cloneRuntimeProfile(profile *domain.RuntimeProfile) *domain.RuntimeProfile {
	if profile == nil {
		return nil
	}
	copy := *profile
	copy.Operations = append([]string(nil), profile.Operations...)
	copy.Features = append([]string(nil), profile.Features...)
	copy.InputSchema = cloneJSONSchema(profile.InputSchema)
	copy.OutputSchema = cloneJSONSchema(profile.OutputSchema)
	copy.AcceptedArtifactTypes = append([]string(nil), profile.AcceptedArtifactTypes...)
	copy.ProducedArtifactTypes = append([]string(nil), profile.ProducedArtifactTypes...)
	copy.CompatibilityOperations = append([]string(nil), profile.CompatibilityOperations...)
	if profile.Availability != nil {
		availability := *profile.Availability
		copy.Availability = &availability
	}
	return &copy
}

func cloneJSONSchema(schema domain.JSONSchema) domain.JSONSchema {
	if schema == nil {
		return nil
	}
	raw, _ := json.Marshal(schema)
	var clone domain.JSONSchema
	_ = json.Unmarshal(raw, &clone)
	return clone
}

func runtimeProfileKey(profileID, version string) string { return profileID + "\x00" + version }

func sameRuntimeProfileMeaning(left, right *domain.RuntimeProfile) bool {
	return left != nil && right != nil && left.ProfileID == right.ProfileID && left.Version == right.Version && left.Digest == right.Digest && left.CapabilityRevision == right.CapabilityRevision && left.CapabilityDefinitionHash == right.CapabilityDefinitionHash && left.Adapter == right.Adapter && left.Model == right.Model && left.Workflow == right.Workflow && left.Modality == right.Modality && left.ExecutionLocality == right.ExecutionLocality && slices.Equal(left.Operations, right.Operations) && slices.Equal(left.Features, right.Features) && slices.Equal(left.AcceptedArtifactTypes, right.AcceptedArtifactTypes) && slices.Equal(left.ProducedArtifactTypes, right.ProducedArtifactTypes) && slices.Equal(left.CompatibilityOperations, right.CompatibilityOperations) && sameJSONSchemaMeaning(left.InputSchema, right.InputSchema) && sameJSONSchemaMeaning(left.OutputSchema, right.OutputSchema)
}

// sameJSONSchemaMeaning compares the stable JSON document rather than Go's
// in-memory map types. YAML decoding can retain nested domain.JSONSchema values
// while PostgreSQL's JSON round trip decodes those same objects as map[string]any.
// JSON encoding sorts map keys, so equal bytes here are a deterministic semantic
// comparison. A marshal failure is deliberately a mismatch: immutable identities
// must fail closed rather than accepting an unrepresentable schema.
func sameJSONSchemaMeaning(left, right domain.JSONSchema) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func legacyRuntimeProfileMeaning(left, right *domain.RuntimeProfile) bool {
	return left != nil && right != nil && left.CapabilityDefinitionHash == "" && left.ProfileID == right.ProfileID && left.Version == right.Version && left.Digest == right.Digest && left.Adapter == right.Adapter && left.Model == right.Model && slices.Equal(left.Operations, right.Operations) && slices.Equal(left.Features, right.Features)
}

func (m *MemoryStore) UpsertRuntimeProfile(_ context.Context, profile *domain.RuntimeProfile) (*domain.RuntimeProfile, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := runtimeProfileKey(profile.ProfileID, profile.Version)
	if existing, found := m.runtimeProfiles[key]; found {
		if legacyRuntimeProfileMeaning(existing, profile) {
			stored := cloneRuntimeProfile(profile)
			m.runtimeProfiles[key] = stored
			return cloneRuntimeProfile(stored), false, nil
		}
		if !sameRuntimeProfileMeaning(existing, profile) {
			return nil, false, errors.New("runtime profile identity already exists with a different digest")
		}
		return cloneRuntimeProfile(existing), false, nil
	}
	stored := cloneRuntimeProfile(profile)
	m.runtimeProfiles[key] = stored
	return cloneRuntimeProfile(stored), true, nil
}

func (m *MemoryStore) ListRuntimeProfiles(_ context.Context) ([]*domain.RuntimeProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	profiles := make([]*domain.RuntimeProfile, 0, len(m.runtimeProfiles))
	for _, profile := range m.runtimeProfiles {
		profiles = append(profiles, cloneRuntimeProfile(profile))
	}
	sort.Slice(profiles, func(i, j int) bool {
		if profiles[i].ProfileID == profiles[j].ProfileID {
			return profiles[i].Version < profiles[j].Version
		}
		return profiles[i].ProfileID < profiles[j].ProfileID
	})
	return profiles, nil
}

func cloneWorkingSet(workingSet *domain.WorkingSet) *domain.WorkingSet {
	if workingSet == nil {
		return nil
	}
	copy := *workingSet
	copy.DesiredProfiles = append([]string(nil), workingSet.DesiredProfiles...)
	copy.LikelyNextProfiles = append([]string(nil), workingSet.LikelyNextProfiles...)
	copy.UnlikelyProfiles = append([]string(nil), workingSet.UnlikelyProfiles...)
	return &copy
}

func workingSetKey(ownerID, sessionID, phaseID string) string {
	return ownerID + "\x00" + sessionID + "\x00" + phaseID
}

func (m *MemoryStore) UpsertWorkingSet(_ context.Context, workingSet *domain.WorkingSet) (*domain.WorkingSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := workingSetKey(workingSet.OwnerID, workingSet.SessionID, workingSet.PhaseID)
	if existing, found := m.workingSets[key]; found {
		workingSet.CreatedAt = existing.CreatedAt
	}
	stored := cloneWorkingSet(workingSet)
	m.workingSets[key] = stored
	return cloneWorkingSet(stored), nil
}

func (m *MemoryStore) ReleaseWorkingSet(_ context.Context, ownerID, sessionID, phaseID string, releasedAt time.Time) (*domain.WorkingSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := workingSetKey(ownerID, sessionID, phaseID)
	workingSet, found := m.workingSets[key]
	if !found {
		return nil, ErrNotFound
	}
	copy := cloneWorkingSet(workingSet)
	copy.ReleasedAt = &releasedAt
	copy.UpdatedAt = releasedAt
	m.workingSets[key] = copy
	return cloneWorkingSet(copy), nil
}

func (m *MemoryStore) ListWorkingSets(_ context.Context, ownerID, sessionID string, includeReleased bool) ([]*domain.WorkingSet, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sets := make([]*domain.WorkingSet, 0)
	for _, workingSet := range m.workingSets {
		if ownerID != "" && workingSet.OwnerID != ownerID || sessionID != "" && workingSet.SessionID != sessionID || !includeReleased && workingSet.ReleasedAt != nil {
			continue
		}
		sets = append(sets, cloneWorkingSet(workingSet))
	}
	sort.Slice(sets, func(i, j int) bool {
		if sets[i].SessionID == sets[j].SessionID {
			return sets[i].PhaseID < sets[j].PhaseID
		}
		return sets[i].SessionID < sets[j].SessionID
	})
	return sets, nil
}

func cloneTargetPolicyOverride(policy *domain.TargetPolicyOverride) *domain.TargetPolicyOverride {
	if policy == nil {
		return nil
	}
	copy := *policy
	return &copy
}

func (m *MemoryStore) UpsertTargetPolicyOverride(_ context.Context, policy *domain.TargetPolicyOverride) (*domain.TargetPolicyOverride, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.targetPolicyOverrides[policy.TargetID] = cloneTargetPolicyOverride(policy)
	return cloneTargetPolicyOverride(policy), nil
}

func (m *MemoryStore) ListTargetPolicyOverrides(_ context.Context) ([]*domain.TargetPolicyOverride, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*domain.TargetPolicyOverride, 0, len(m.targetPolicyOverrides))
	for _, policy := range m.targetPolicyOverrides {
		result = append(result, cloneTargetPolicyOverride(policy))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TargetID < result[j].TargetID })
	return result, nil
}

func cloneBrowserSession(session *domain.BrowserSession) *domain.BrowserSession {
	cp := *session
	cp.Scopes = append([]string(nil), session.Scopes...)
	cp.Adapters = append([]string(nil), session.Adapters...)
	return &cp
}

func (m *MemoryStore) CreateBrowserSession(_ context.Context, session *domain.BrowserSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.browserSessions[session.IDHash]; exists {
		return errors.New("browser session already exists")
	}
	m.browserSessions[session.IDHash] = cloneBrowserSession(session)
	return nil
}

func (m *MemoryStore) GetBrowserSession(_ context.Context, idHash string) (*domain.BrowserSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	session, exists := m.browserSessions[idHash]
	if !exists {
		return nil, ErrNotFound
	}
	return cloneBrowserSession(session), nil
}

func (m *MemoryStore) DeleteBrowserSession(_ context.Context, idHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.browserSessions, idHash)
	return nil
}

func cloneNode(n *domain.Node) *domain.Node {
	cp := *n
	cp.Observed.System.NetworkAddresses = append([]string(nil), n.Observed.System.NetworkAddresses...)
	cp.Observed.AgentLogs = append([]domain.LogEntry(nil), n.Observed.AgentLogs...)
	for index := range cp.Observed.AgentLogs {
		if n.Observed.AgentLogs[index].Attributes != nil {
			cp.Observed.AgentLogs[index].Attributes = make(map[string]any, len(n.Observed.AgentLogs[index].Attributes))
			for key, value := range n.Observed.AgentLogs[index].Attributes {
				cp.Observed.AgentLogs[index].Attributes[key] = value
			}
		}
	}
	cp.Accelerators = append([]domain.Accelerator(nil), n.Accelerators...)
	for index := range cp.Accelerators {
		if n.Accelerators[index].RuntimeCapabilities != nil {
			capabilities := *n.Accelerators[index].RuntimeCapabilities
			cp.Accelerators[index].RuntimeCapabilities = &capabilities
		}
	}
	return &cp
}

func (m *MemoryStore) UpsertNode(ctx context.Context, n *domain.Node) (*domain.Node, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	existing, ok := m.nodes[n.ID]
	if !ok {
		n.RegisteredAt = now
	} else {
		n.RegisteredAt = existing.RegisteredAt
	}
	n.UpdatedAt = now
	stored := cloneNode(n)
	m.nodes[n.ID] = stored
	return cloneNode(stored), nil
}

func (m *MemoryStore) GetNode(ctx context.Context, id string) (*domain.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.nodes[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneNode(n), nil
}

func (m *MemoryStore) ListNodes(ctx context.Context) ([]*domain.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*domain.Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		out = append(out, cloneNode(n))
	}
	return out, nil
}

func (m *MemoryStore) UpdateObserved(ctx context.Context, id string, fn func(o *domain.Observed, accels *[]domain.Accelerator)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[id]
	if !ok {
		return ErrNotFound
	}
	fn(&n.Observed, &n.Accelerators)
	n.UpdatedAt = time.Now().UTC()
	return nil
}

func (m *MemoryStore) UpdateDesired(ctx context.Context, id string, fn func(d *domain.Desired, scheduling *domain.SchedulingState)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, ok := m.nodes[id]
	if !ok {
		return ErrNotFound
	}
	fn(&node.Desired, &node.SchedulingState)
	node.UpdatedAt = time.Now().UTC()
	return nil
}

func (m *MemoryStore) DeleteNode(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nodes[id]; !ok {
		return ErrNotFound
	}
	delete(m.nodes, id)
	return nil
}

// ---- EngineStore ----

func (m *MemoryStore) UpsertEngine(ctx context.Context, e *domain.EngineInstance) (*domain.EngineInstance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *e
	m.engines[e.ID] = &cp
	out := cp
	return &out, nil
}

func (m *MemoryStore) ListEnginesForNode(ctx context.Context, nodeID string) ([]*domain.EngineInstance, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*domain.EngineInstance, 0)
	for _, e := range m.engines {
		if e.NodeID == nodeID {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *MemoryStore) DeleteEngine(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.engines[id]; !ok {
		return ErrNotFound
	}
	delete(m.engines, id)
	return nil
}

// ---- ProfileStore ----

func (m *MemoryStore) SaveProfile(ctx context.Context, nodeID string, p *domain.PerformanceProfile) (*domain.PerformanceProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *p
	m.profiles[nodeID] = append(m.profiles[nodeID], &cp)
	out := cp
	return &out, nil
}

func (m *MemoryStore) ListProfilesForNode(ctx context.Context, nodeID string) ([]*domain.PerformanceProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	src := m.profiles[nodeID]
	out := make([]*domain.PerformanceProfile, 0, len(src))
	for _, p := range src {
		cp := *p
		out = append(out, &cp)
	}
	return out, nil
}

func (m *MemoryStore) ListAllProfiles(ctx context.Context) ([]*domain.PerformanceProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*domain.PerformanceProfile, 0)
	for _, src := range m.profiles {
		for _, p := range src {
			cp := *p
			out = append(out, &cp)
		}
	}
	return out, nil
}

// ---- JobStore ----

func cloneJob(j *domain.Job) *domain.Job {
	cp := *j
	return &cp
}

func cloneWorkItem(wi *domain.WorkItem) *domain.WorkItem {
	cp := *wi
	cp.TriedWorkers = append([]string(nil), wi.TriedWorkers...)
	if wi.Payload != nil {
		p := make(map[string]any, len(wi.Payload))
		for k, v := range wi.Payload {
			p[k] = v
		}
		cp.Payload = p
	}
	return &cp
}

func (m *MemoryStore) UpsertJob(ctx context.Context, j *domain.Job) (*domain.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored := cloneJob(j)
	m.jobs[j.ID] = stored
	return cloneJob(stored), nil
}

func (m *MemoryStore) GetJob(ctx context.Context, id string) (*domain.Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneJob(j), nil
}

func (m *MemoryStore) ListJobs(ctx context.Context) ([]*domain.Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*domain.Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		out = append(out, cloneJob(j))
	}
	return out, nil
}

func (m *MemoryStore) UpsertWorkItem(ctx context.Context, wi *domain.WorkItem) (*domain.WorkItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byItem, ok := m.workItems[wi.JobID]
	if !ok {
		byItem = make(map[string]map[string]*domain.WorkItem)
		m.workItems[wi.JobID] = byItem
	}
	byVersion, ok := byItem[wi.ItemID]
	if !ok {
		byVersion = make(map[string]*domain.WorkItem)
		byItem[wi.ItemID] = byVersion
	}
	stored := cloneWorkItem(wi)
	byVersion[wi.OperationVersion] = stored
	return cloneWorkItem(stored), nil
}

func (m *MemoryStore) GetWorkItem(ctx context.Context, jobID, itemID, operationVersion string) (*domain.WorkItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	byItem, ok := m.workItems[jobID]
	if !ok {
		return nil, ErrNotFound
	}
	byVersion, ok := byItem[itemID]
	if !ok {
		return nil, ErrNotFound
	}
	wi, ok := byVersion[operationVersion]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneWorkItem(wi), nil
}

func (m *MemoryStore) ListWorkItemsForJob(ctx context.Context, jobID string) ([]*domain.WorkItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	byItem := m.workItems[jobID]
	out := make([]*domain.WorkItem, 0, len(byItem))
	for _, byVersion := range byItem {
		for _, wi := range byVersion {
			out = append(out, cloneWorkItem(wi))
		}
	}
	return out, nil
}

func cloneWorkload(w *domain.Workload) *domain.Workload {
	cp := *w
	if w.StartedAt != nil {
		startedAt := *w.StartedAt
		cp.StartedAt = &startedAt
	}
	cp.Request.Payload = append(json.RawMessage(nil), w.Request.Payload...)
	cp.Request.ArtifactRefs = append([]string(nil), w.Request.ArtifactRefs...)
	cp.Request.CapabilityRequirements.Features = append([]string(nil), w.Request.CapabilityRequirements.Features...)
	cp.Request.ProfilePreferences.Preferred = append([]string(nil), w.Request.ProfilePreferences.Preferred...)
	cp.Request.ProfilePreferences.Acceptable = append([]string(nil), w.Request.ProfilePreferences.Acceptable...)
	cp.Request.Dependencies = append([]string(nil), w.Request.Dependencies...)
	cp.Request.Notifications.Webhooks = append([]string(nil), w.Request.Notifications.Webhooks...)
	cp.Request.Transformations = append([]string(nil), w.Request.Transformations...)
	cp.Request.TransformationParameters = append(json.RawMessage(nil), w.Request.TransformationParameters...)
	cp.Decision.Alternatives = append([]string(nil), w.Decision.Alternatives...)
	cp.OutputRefs = append([]string(nil), w.OutputRefs...)
	cp.TransitionPlanIDs = append([]string(nil), w.TransitionPlanIDs...)
	cp.InlineOutput = append(json.RawMessage(nil), w.InlineOutput...)
	if w.TargetRetryAfter != nil {
		cp.TargetRetryAfter = make(map[string]time.Time, len(w.TargetRetryAfter))
		for targetID, retryAt := range w.TargetRetryAfter {
			cp.TargetRetryAfter[targetID] = retryAt
		}
	}
	if w.Plan != nil {
		plan := *w.Plan
		plan.Transformations = append([]string(nil), w.Plan.Transformations...)
		plan.ResidencyTransitionIDs = append([]string(nil), w.Plan.ResidencyTransitionIDs...)
		plan.Material = append(json.RawMessage(nil), w.Plan.Material...)
		cp.Plan = &plan
	}
	if w.Execution != nil {
		execution := *w.Execution
		execution.Opaque = append(json.RawMessage(nil), w.Execution.Opaque...)
		cp.Execution = &execution
	}
	return &cp
}

// ---- WorkloadStore ----

func (m *MemoryStore) CreateWorkload(ctx context.Context, w *domain.Workload) (*domain.Workload, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w = cloneWorkload(w)
	w.Revision = 1
	if w.Request.IdempotencyKey != "" {
		key := w.Request.OwnerID + "\x00" + w.Request.IdempotencyKey
		if id, ok := m.idempotency[key]; ok {
			return cloneWorkload(m.workloads[id]), false, nil
		}
		m.idempotency[key] = w.Request.ID
	}
	if existing, ok := m.workloads[w.Request.ID]; ok {
		return cloneWorkload(existing), false, nil
	}
	m.workloads[w.Request.ID] = cloneWorkload(w)
	return cloneWorkload(w), true, nil
}

func (m *MemoryStore) UpdateWorkload(ctx context.Context, w *domain.Workload) (*domain.Workload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if w == nil || w.Revision == 0 {
		return nil, ErrWorkloadConflict
	}
	current, ok := m.workloads[w.Request.ID]
	if !ok {
		return nil, ErrNotFound
	}
	if current.Revision != w.Revision {
		return nil, ErrWorkloadConflict
	}
	if current.CancellationOwner != w.CancellationOwner {
		return nil, ErrWorkloadConflict
	}
	updated := cloneWorkload(w)
	updated.Revision = current.Revision + 1
	m.workloads[w.Request.ID] = updated
	return cloneWorkload(updated), nil
}

func (m *MemoryStore) CompareAndSwapWorkload(ctx context.Context, w *domain.Workload, expectedRevision uint64, expectedStatus domain.WorkloadStatus, expectedCancellationOwner string) (*domain.Workload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.workloads[w.Request.ID]
	if !ok {
		return nil, ErrNotFound
	}
	if workloadRequiresSettlementIntent(w) && !(current.BudgetSettlementPending && current.BudgetReservationToken == w.BudgetReservationToken && current.BudgetSettlementAttempt == w.BudgetReservationAttempt) {
		return nil, ErrWorkloadConflict
	}
	if current.Revision != expectedRevision || current.Status != expectedStatus || current.CancellationOwner != expectedCancellationOwner {
		return nil, ErrWorkloadConflict
	}
	updated := cloneWorkload(w)
	updated.Revision = current.Revision + 1
	m.workloads[w.Request.ID] = updated
	return cloneWorkload(updated), nil
}

func (m *MemoryStore) GetWorkload(ctx context.Context, id string) (*domain.Workload, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	w, ok := m.workloads[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneWorkload(w), nil
}

func (m *MemoryStore) ListWorkloads(ctx context.Context) ([]*domain.Workload, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*domain.Workload, 0, len(m.workloads))
	for _, w := range m.workloads {
		out = append(out, cloneWorkload(w))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) AcquireAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, ttl time.Duration) (*domain.AcceleratorLease, bool, error) {
	return m.acquireAcceleratorLease(ctx, acceleratorID, workloadID, "", ttl)
}

// AcquireAcceleratorLeaseForCheckpointRecovery is the only exception to the
// ordinary unresolved-cleanup admission fence.  The caller must name the
// exact armed recovery operation; the store advances that row to pending with
// the new fence while holding the same mutex as lease allocation, closing the
// reacquire-to-journal crash seam.
func (m *MemoryStore) AcquireAcceleratorLeaseForCheckpointRecovery(ctx context.Context, acceleratorID, workloadID, operationID string, ttl time.Duration) (*domain.AcceleratorLease, bool, error) {
	return m.acquireAcceleratorLease(ctx, acceleratorID, workloadID, operationID, ttl)
}

func (m *MemoryStore) acquireAcceleratorLease(_ context.Context, acceleratorID, workloadID, recoveryOperationID string, ttl time.Duration) (*domain.AcceleratorLease, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	// Displacement custody blocks every lease path, including the pre-existing
	// checkpoint-recovery seam. An expired or absent lease does not settle it.
	for _, op := range m.llmDisplacementOps {
		if op != nil && op.AcceleratorID == acceleratorID && displacementRecordRetainsCustody(op) {
			lease := op.OriginalLease
			if lease == nil {
				lease = &domain.AcceleratorLease{AcceleratorID: acceleratorID, WorkloadID: op.VictimWorkloadID, FencingToken: int64(op.Fence)}
			}
			copy := *lease
			return &copy, false, nil
		}
	}
	var recoveryOp *LLMCheckpointOperation
	// Find the exact authorized recovery row before evaluating blockers. Map
	// iteration is intentionally unordered; returning on the first unrelated
	// row would make a valid compensation reacquire depend on row order and
	// diverge from PostgreSQL's ordered scan.
	for _, op := range m.llmCheckpointOps {
		if op != nil && op.CleanupAcceleratorID == acceleratorID && op.CleanupState == "armed" && op.WorkloadID == workloadID && recoveryOperationID != "" && (op.ID == recoveryOperationID || op.CleanupOperationID == recoveryOperationID) {
			recoveryOp = op
			break
		}
	}
	for _, op := range m.llmCheckpointOps {
		if op == nil || op.CleanupAcceleratorID != acceleratorID || (op.CleanupState != "armed" && op.CleanupState != "owned" && op.CleanupState != "pending" && op.CleanupState != "failed" && op.CleanupState != "stopped") || op == recoveryOp {
			continue
		}
		fence := int64(op.CleanupFence)
		if fence == 0 {
			fence = int64(op.Fence)
		}
		return &domain.AcceleratorLease{AcceleratorID: acceleratorID, WorkloadID: op.WorkloadID, FencingToken: fence, ExpiresAt: now.Add(ttl)}, false, nil
	}
	if cur := m.leases[acceleratorID]; cur != nil && cur.ExpiresAt.After(now) {
		cp := *cur
		return &cp, false, nil
	}
	if recoveryOp != nil && m.leaseFences[acceleratorID] < int64(recoveryOp.CleanupFence) {
		// A controller restart may have lost the lease row while the durable
		// cleanup row still records the last physical fence.  Never issue a
		// recovery token at or below that fence: the node would reject the
		// compensation, while a future owner could otherwise appear newer.
		m.leaseFences[acceleratorID] = int64(recoveryOp.CleanupFence)
	}
	m.leaseFences[acceleratorID]++
	lease := &domain.AcceleratorLease{AcceleratorID: acceleratorID, WorkloadID: workloadID, FencingToken: m.leaseFences[acceleratorID], ExpiresAt: now.Add(ttl)}
	m.leases[acceleratorID] = lease
	if recoveryOp != nil {
		recoveryOp.CleanupState = "pending"
		recoveryOp.CleanupOperationID = firstNonEmptyMemory(recoveryOp.CleanupOperationID, recoveryOperationID, recoveryOp.ID)
		recoveryOp.CleanupAcceleratorID = acceleratorID
		recoveryOp.CleanupFence = uint64(lease.FencingToken)
		if recoveryOp.CleanupGeneration == 0 {
			recoveryOp.CleanupGeneration = recoveryOp.Generation
		}
		recoveryOp.Revision++
		recoveryOp.UpdatedAt = now
	}
	cp := *lease
	return &cp, true, nil
}

func firstNonEmptyMemory(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (m *MemoryStore) RenewAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	lease := m.leases[acceleratorID]
	if lease == nil || lease.WorkloadID != workloadID || lease.FencingToken != fencingToken {
		return ErrNotFound
	}
	lease.ExpiresAt = time.Now().UTC().Add(ttl)
	return nil
}

func (m *MemoryStore) ReleaseAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	lease := m.leases[acceleratorID]
	if lease == nil {
		return nil
	}
	if lease.WorkloadID != workloadID || lease.FencingToken != fencingToken {
		return ErrNotFound
	}
	delete(m.leases, acceleratorID)
	return nil
}

func (m *MemoryStore) GetAcceleratorLease(_ context.Context, acceleratorID string) (*domain.AcceleratorLease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	lease := m.leases[acceleratorID]
	if lease == nil {
		return nil, ErrNotFound
	}
	cp := *lease
	return &cp, nil
}

func leaseCleanupKey(acceleratorID, owner string, fencingToken int64) string {
	return acceleratorID + "\x00" + owner + "\x00" + fmt.Sprint(fencingToken)
}

func leaseCleanupRecordKey(intent *domain.AcceleratorLeaseCleanupIntent) string {
	key := leaseCleanupKey(intent.AcceleratorID, intent.Owner, intent.FencingToken)
	if intent.WorkloadID != "" {
		key += "\x00" + intent.WorkloadID
	}
	return key
}

func cloneLeaseCleanupIntent(intent *domain.AcceleratorLeaseCleanupIntent) *domain.AcceleratorLeaseCleanupIntent {
	if intent == nil {
		return nil
	}
	cp := *intent
	if intent.NextRetryAt != nil {
		next := *intent.NextRetryAt
		cp.NextRetryAt = &next
	}
	return &cp
}

func (m *MemoryStore) RecordAcceleratorLeaseCleanupIntent(_ context.Context, intent *domain.AcceleratorLeaseCleanupIntent) (*domain.AcceleratorLeaseCleanupIntent, error) {
	if err := validateLeaseCleanupIntent(intent); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := leaseCleanupRecordKey(intent)
	now := time.Now().UTC()
	stored := cloneLeaseCleanupIntent(intent)
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = now
	}
	if stored.UpdatedAt.IsZero() {
		stored.UpdatedAt = now
	}
	if stored.Attempts <= 0 {
		stored.Attempts = 1
	}
	if existing := m.leaseCleanupIntents[key]; existing != nil {
		if existing.WorkloadID != intent.WorkloadID || existing.ExpectedWorkloadRevision != intent.ExpectedWorkloadRevision || existing.TerminalDisposition != intent.TerminalDisposition || existing.TerminalErrorCode != intent.TerminalErrorCode {
			return nil, ErrAcceleratorLeaseCleanupConflict
		}
		if stored.Attempts < existing.Attempts {
			stored.Attempts = existing.Attempts
		}
		stored.CreatedAt = existing.CreatedAt
		stored.ReleaseConfirmed = existing.ReleaseConfirmed || stored.ReleaseConfirmed
		stored.TerminalPublished = existing.TerminalPublished || stored.TerminalPublished
		stored.AuditPublished = existing.AuditPublished || stored.AuditPublished
		stored.NotificationPublished = existing.NotificationPublished || stored.NotificationPublished
		stored.BudgetSettled = existing.BudgetSettled || stored.BudgetSettled
	}
	m.leaseCleanupIntents[key] = stored
	return cloneLeaseCleanupIntent(stored), nil
}

func (m *MemoryStore) ListAcceleratorLeaseCleanupIntents(_ context.Context, now time.Time, limit int) ([]*domain.AcceleratorLeaseCleanupIntent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows := make([]*domain.AcceleratorLeaseCleanupIntent, 0)
	for _, intent := range m.leaseCleanupIntents {
		if intent.NextRetryAt != nil && intent.NextRetryAt.After(now) {
			continue
		}
		rows = append(rows, cloneLeaseCleanupIntent(intent))
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].UpdatedAt.Equal(rows[j].UpdatedAt) {
			return leaseCleanupKey(rows[i].AcceleratorID, rows[i].Owner, rows[i].FencingToken) < leaseCleanupKey(rows[j].AcceleratorID, rows[j].Owner, rows[j].FencingToken)
		}
		return rows[i].UpdatedAt.Before(rows[j].UpdatedAt)
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func (m *MemoryStore) DeleteAcceleratorLeaseCleanupIntent(_ context.Context, acceleratorID, owner string, fencingToken int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := leaseCleanupKey(acceleratorID, owner, fencingToken)
	for key := range m.leaseCleanupIntents {
		if key == prefix || strings.HasPrefix(key, prefix+"\x00") {
			delete(m.leaseCleanupIntents, key)
		}
	}
	return nil
}

func (m *MemoryStore) DeleteAcceleratorLeaseCleanupIntentForWorkload(_ context.Context, acceleratorID, owner string, fencingToken int64, workloadID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.leaseCleanupIntents, leaseCleanupKey(acceleratorID, owner, fencingToken)+"\x00"+workloadID)
	return nil
}

func (m *MemoryStore) SavePromptMapping(ctx context.Context, mapping *domain.PromptMapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *mapping
	if existing := m.promptMappings[mapping.PublicPromptID]; existing != nil {
		if cp.WorkloadID == "" {
			cp.WorkloadID = existing.WorkloadID
		}
		if cp.TargetID == "" {
			cp.TargetID = existing.TargetID
		}
		if cp.BackendPromptID == "" {
			cp.BackendPromptID = existing.BackendPromptID
		}
		if cp.ClientID == "" {
			cp.ClientID = existing.ClientID
		}
	}
	m.promptMappings[mapping.PublicPromptID] = &cp
	return nil
}

func (m *MemoryStore) GetPromptMapping(ctx context.Context, publicPromptID string) (*domain.PromptMapping, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	mapping, ok := m.promptMappings[publicPromptID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *mapping
	return &cp, nil
}

func (m *MemoryStore) AppendAuditEvent(ctx context.Context, event *domain.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.auditEvents {
		if existing.ID == event.ID {
			return nil
		}
	}
	cp := *event
	cp.Payload = append(json.RawMessage(nil), event.Payload...)
	m.auditEvents = append(m.auditEvents, &cp)
	return nil
}

func (m *MemoryStore) ListAuditEvents(ctx context.Context, ownerID string, limit int) ([]*domain.AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	out := make([]*domain.AuditEvent, 0, limit)
	for i := len(m.auditEvents) - 1; i >= 0 && len(out) < limit; i-- {
		event := m.auditEvents[i]
		if ownerID != "" && event.OwnerID != ownerID {
			continue
		}
		cp := *event
		cp.Payload = append(json.RawMessage(nil), event.Payload...)
		out = append(out, &cp)
	}
	return out, nil
}

func residencyKey(targetID, model string) string { return targetID + "\x00" + model }

func cloneResidency(value *domain.ModelResidency) *domain.ModelResidency {
	cp := *value
	return &cp
}

func residencyGenerationCompatible(existing, incoming *domain.ModelResidency) bool {
	if existing == nil || incoming == nil {
		return true
	}
	if incoming.TargetGeneration < existing.TargetGeneration {
		return false
	}
	if incoming.TargetGeneration == existing.TargetGeneration {
		return existing.ExecutionFingerprint != "" && incoming.ExecutionFingerprint != "" && existing.ExecutionFingerprint == incoming.ExecutionFingerprint
	}
	// A new generation must carry a canonical fingerprint. This is also the
	// only legal upgrade path for legacy generation-zero rows with no fence.
	return incoming.ExecutionFingerprint != ""
}

func cloneTransition(value *domain.ResidencyTransition) *domain.ResidencyTransition {
	cp := *value
	return &cp
}

func cloneNotification(value *domain.NotificationDelivery) *domain.NotificationDelivery {
	cp := *value
	cp.Payload = append(json.RawMessage(nil), value.Payload...)
	return &cp
}

func (m *MemoryStore) UpsertModelResidency(ctx context.Context, residency *domain.ModelResidency) (*domain.ModelResidency, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := residencyKey(residency.TargetID, residency.Model)
	if existing := m.residencies[key]; existing != nil {
		if !residencyGenerationCompatible(existing, residency) {
			return nil, fmt.Errorf("%w existing_generation=%d incoming_generation=%d existing_fingerprint=%q incoming_fingerprint=%q", ErrModelResidencyGenerationConflict, existing.TargetGeneration, residency.TargetGeneration, existing.ExecutionFingerprint, residency.ExecutionFingerprint)
		}
		if residency.Revision <= existing.Revision {
			residency.Revision = existing.Revision + 1
		}
	} else if residency.Revision == 0 {
		residency.Revision = 1
	}
	stored := cloneResidency(residency)
	m.residencies[key] = stored
	return cloneResidency(stored), nil
}

func (m *MemoryStore) CreateModelResidency(ctx context.Context, residency *domain.ModelResidency) (*domain.ModelResidency, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := residencyKey(residency.TargetID, residency.Model)
	if existing := m.residencies[key]; existing != nil {
		if !residencyGenerationCompatible(existing, residency) {
			return nil, false, fmt.Errorf("%w existing_generation=%d incoming_generation=%d existing_fingerprint=%q incoming_fingerprint=%q", ErrModelResidencyGenerationConflict, existing.TargetGeneration, residency.TargetGeneration, existing.ExecutionFingerprint, residency.ExecutionFingerprint)
		}
		return cloneResidency(existing), false, nil
	}
	created := cloneResidency(residency)
	if created.Revision == 0 {
		created.Revision = 1
	}
	m.residencies[key] = created
	return cloneResidency(created), true, nil
}

func (m *MemoryStore) CompareAndSwapModelResidency(ctx context.Context, residency *domain.ModelResidency, expectedRevision uint64) (*domain.ModelResidency, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := residencyKey(residency.TargetID, residency.Model)
	current := m.residencies[key]
	if current == nil || current.Revision != expectedRevision {
		return nil, ErrModelResidencyConflict
	}
	if !residencyGenerationCompatible(current, residency) {
		return nil, fmt.Errorf("%w existing_generation=%d incoming_generation=%d existing_fingerprint=%q incoming_fingerprint=%q", ErrModelResidencyGenerationConflict, current.TargetGeneration, residency.TargetGeneration, current.ExecutionFingerprint, residency.ExecutionFingerprint)
	}
	updated := cloneResidency(residency)
	updated.Revision = expectedRevision + 1
	m.residencies[key] = updated
	return cloneResidency(updated), nil
}

func (m *MemoryStore) GetModelResidency(ctx context.Context, targetID, model string) (*domain.ModelResidency, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	residency := m.residencies[residencyKey(targetID, model)]
	if residency == nil {
		return nil, ErrNotFound
	}
	return cloneResidency(residency), nil
}

func (m *MemoryStore) ListModelResidencies(ctx context.Context) ([]*domain.ModelResidency, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*domain.ModelResidency, 0, len(m.residencies))
	for _, residency := range m.residencies {
		out = append(out, cloneResidency(residency))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetID != out[j].TargetID {
			return out[i].TargetID < out[j].TargetID
		}
		return out[i].Model < out[j].Model
	})
	return out, nil
}

func (m *MemoryStore) CreateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, bool, error) {
	if err := validateResidencyTransitionStoredOrigin(transition); err != nil || residencyTransitionHasLeaseOrigin(transition) {
		if err != nil { return nil, false, err }
		return nil, false, fmt.Errorf("%w: CreateResidencyTransition cannot issue or accept lease-origin provenance", ErrResidencyTransitionConflict)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if id := m.transitionKeys[transition.IdempotencyKey]; id != "" {
		existing := m.transitions[id]
		if err := verifyResidencyTransitionReplay(existing, transition); err != nil {
			return nil, false, err
		}
		return cloneTransition(existing), false, nil
	}
	if existing := m.transitions[transition.ID]; existing != nil {
		if err := verifyResidencyTransitionReplay(existing, transition); err != nil {
			return nil, false, err
		}
		return cloneTransition(existing), false, nil
	}
	stored := cloneTransition(transition)
	m.transitions[transition.ID] = stored
	m.transitionKeys[transition.IdempotencyKey] = transition.ID
	return cloneTransition(stored), true, nil
}

func (m *MemoryStore) AllocateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, bool, error) {
	if err := validateResidencyTransitionStoredOrigin(transition); err != nil || residencyTransitionHasLeaseOrigin(transition) {
		if err != nil { return nil, false, err }
		return nil, false, fmt.Errorf("%w: unleased allocation cannot issue or accept lease-origin provenance", ErrResidencyTransitionConflict)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if id := m.transitionKeys[transition.IdempotencyKey]; id != "" {
		existing := m.transitions[id]
		if err := verifyResidencyTransitionReplay(existing, transition); err != nil {
			return nil, false, err
		}
		return cloneTransition(existing), false, nil
	}
	if existing := m.transitions[transition.ID]; existing != nil {
		if err := verifyResidencyTransitionReplay(existing, transition); err != nil {
			return nil, false, err
		}
		return cloneTransition(existing), false, nil
	}
	allocated := cloneTransition(transition)
	if allocated.Revision == 0 {
		allocated.Revision = 1
	}
	var highwater int64
	for _, row := range m.transitions {
		if row.TargetID == allocated.TargetID && row.Model == allocated.Model && row.FencingToken > highwater {
			highwater = row.FencingToken
		}
	}
	if highwater == math.MaxInt64 {
		return nil, false, fmt.Errorf("%w: residency transition model fence exhausted", ErrResidencyTransitionConflict)
	}
	if allocated.FencingToken <= highwater {
		allocated.FencingToken = highwater + 1
	}
	m.transitions[allocated.ID] = allocated
	m.transitionKeys[allocated.IdempotencyKey] = allocated.ID
	return cloneTransition(allocated), true, nil
}

func (m *MemoryStore) AllocateResidencyTransitionWithLease(ctx context.Context, transition *domain.ResidencyTransition, lease *domain.AcceleratorLease) (*domain.ResidencyTransition, bool, error) {
	resource, err := validateResidencyTransitionLeaseOriginRequest(transition, lease)
	if err != nil { return nil, false, err }
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	currentLease := m.leases[resource]
	if err := validateCurrentResidencyLeaseOrigin(currentLease, lease, now); err != nil { return nil, false, err }
	byKeyID := m.transitionKeys[transition.IdempotencyKey]
	byID := m.transitions[transition.ID]
	if byKeyID != "" {
		byKey := m.transitions[byKeyID]
		if byKey == nil || (byID != nil && byID.ID != byKey.ID) {
			return nil, false, fmt.Errorf("%w: transition id and idempotency key identify different rows", ErrResidencyTransitionConflict)
		}
		if err := verifyResidencyTransitionLeaseReplay(byKey, transition, lease); err != nil { return nil, false, err }
		return cloneTransition(byKey), false, nil
	}
	if byID != nil {
		if err := verifyResidencyTransitionLeaseReplay(byID, transition, lease); err != nil { return nil, false, err }
		return cloneTransition(byID), false, nil
	}
	allocated := cloneTransition(transition)
	if allocated.Revision == 0 { allocated.Revision = 1 }
	var highwater int64
	for _, row := range m.transitions {
		if row.TargetID == allocated.TargetID && row.Model == allocated.Model && row.FencingToken > highwater { highwater = row.FencingToken }
	}
	if highwater == math.MaxInt64 { return nil, false, fmt.Errorf("%w: residency transition model fence exhausted", ErrResidencyTransitionConflict) }
	if allocated.FencingToken <= highwater { allocated.FencingToken = highwater + 1 }
	allocated.LeaseOriginAcceleratorID = resource
	allocated.LeaseOriginWorkloadID = lease.WorkloadID
	allocated.LeaseOriginFencingToken = lease.FencingToken
	allocated.LeaseOriginAllocated = true
	m.transitions[allocated.ID] = allocated
	m.transitionKeys[allocated.IdempotencyKey] = allocated.ID
	return cloneTransition(allocated), true, nil
}

func (m *MemoryStore) GetResidencyTransitionByIdempotencyForLease(ctx context.Context, idempotencyKey string, lease *domain.AcceleratorLease) (*domain.ResidencyTransition, error) {
	if idempotencyKey == "" || lease == nil || lease.AcceleratorID == "" { return nil, ErrNotFound }
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validateCurrentResidencyLeaseOrigin(m.leases[lease.AcceleratorID], lease, time.Now().UTC()); err != nil { return nil, err }
	id := m.transitionKeys[idempotencyKey]
	if id == "" { return nil, ErrNotFound }
	transition := m.transitions[id]
	if transition == nil { return nil, ErrNotFound }
	if transition.LeaseOriginAcceleratorID != lease.AcceleratorID || transition.LeaseOriginWorkloadID != lease.WorkloadID ||
		transition.LeaseOriginFencingToken != lease.FencingToken || !transition.LeaseOriginAllocated || transition.FencingToken < lease.FencingToken {
		return nil, fmt.Errorf("%w: transition replay has no exact allocated lease origin", ErrResidencyTransitionConflict)
	}
	return cloneTransition(transition), nil
}

func (m *MemoryStore) CompareAndSwapResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition, expectedRevision uint64, expectedStatus domain.ResidencyTransitionStatus, expectedFence int64) (*domain.ResidencyTransition, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.transitions[transition.ID]
	if current == nil {
		return nil, ErrNotFound
	}
	if err := validateResidencyTransitionStoredOrigin(current); err != nil { return nil, err }
	if err := validateResidencyTransitionStoredOrigin(transition); err != nil { return nil, err }
	if current.Revision != expectedRevision || current.Status != expectedStatus || current.FencingToken != expectedFence {
		return nil, ErrResidencyTransitionConflict
	}
	if err := verifyResidencyTransitionReplay(current, transition); err != nil {
		return nil, err
	}
	updated := cloneTransition(transition)
	updated.Revision = expectedRevision + 1
	m.transitions[updated.ID] = updated
	return cloneTransition(updated), nil
}

func (m *MemoryStore) UpdateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.transitions[transition.ID]
	if current == nil {
		return nil, ErrNotFound
	}
	if err := validateResidencyTransitionStoredOrigin(current); err != nil { return nil, err }
	if err := validateResidencyTransitionStoredOrigin(transition); err != nil { return nil, err }
	if !sameResidencyTransitionLeaseOrigin(current, transition) {
		return nil, fmt.Errorf("%w: UpdateResidencyTransition cannot change lease-origin provenance", ErrResidencyTransitionConflict)
	}
	if current.LeaseOriginAllocated {
		if err := verifyResidencyTransitionCanonical(current, transition, true); err != nil {
			return nil, fmt.Errorf("%w: UpdateResidencyTransition cannot change allocated transition identity", ErrResidencyTransitionConflict)
		}
	}
	stored := cloneTransition(transition)
	m.transitions[transition.ID] = stored
	return cloneTransition(stored), nil
}

func (m *MemoryStore) GetResidencyTransitionByIdempotency(ctx context.Context, idempotencyKey string) (*domain.ResidencyTransition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if idempotencyKey == "" {
		return nil, ErrNotFound
	}
	id := m.transitionKeys[idempotencyKey]
	if id == "" || m.transitions[id] == nil {
		return nil, ErrNotFound
	}
	return cloneTransition(m.transitions[id]), nil
}

func (m *MemoryStore) GetResidencyTransition(ctx context.Context, id string) (*domain.ResidencyTransition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	transition := m.transitions[id]
	if transition == nil {
		return nil, ErrNotFound
	}
	return cloneTransition(transition), nil
}

func (m *MemoryStore) MaxResidencyFencingToken(ctx context.Context, targetID, model string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var max int64
	for _, transition := range m.transitions {
		if transition.TargetID == targetID && transition.Model == model && transition.FencingToken > max {
			max = transition.FencingToken
		}
	}
	return max, nil
}

func (m *MemoryStore) ListActiveResidencyTransitions(ctx context.Context, targetID, model string) ([]*domain.ResidencyTransition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*domain.ResidencyTransition, 0)
	for _, transition := range m.transitions {
		if transition.TargetID != targetID || transition.Model != model || (transition.Status != domain.ResidencyTransitionPlanned && transition.Status != domain.ResidencyTransitionRunning && !(transition.Status == domain.ResidencyTransitionSucceeded && transition.ProjectionRepairPending)) {
			continue
		}
		out = append(out, cloneTransition(transition))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) ListResidencyTransitions(ctx context.Context, limit int) ([]*domain.ResidencyTransition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	all := limit < 0
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	out := make([]*domain.ResidencyTransition, 0, len(m.transitions))
	for _, transition := range m.transitions {
		out = append(out, cloneTransition(transition))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if !all && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemoryStore) CreateNotification(ctx context.Context, delivery *domain.NotificationDelivery) (*domain.NotificationDelivery, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id := m.notificationKeys[delivery.IdempotencyKey]; id != "" {
		return cloneNotification(m.notifications[id]), false, nil
	}
	if existing := m.notifications[delivery.ID]; existing != nil {
		return cloneNotification(existing), false, nil
	}
	stored := cloneNotification(delivery)
	m.notifications[delivery.ID] = stored
	m.notificationKeys[delivery.IdempotencyKey] = delivery.ID
	return cloneNotification(stored), true, nil
}

func (m *MemoryStore) UpdateNotification(ctx context.Context, delivery *domain.NotificationDelivery) (*domain.NotificationDelivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.notifications[delivery.ID] == nil {
		return nil, ErrNotFound
	}
	stored := cloneNotification(delivery)
	m.notifications[delivery.ID] = stored
	return cloneNotification(stored), nil
}

func (m *MemoryStore) ListPendingNotifications(ctx context.Context, now time.Time, limit int) ([]*domain.NotificationDelivery, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var out []*domain.NotificationDelivery
	for _, delivery := range m.notifications {
		if delivery.DeliveredAt == nil && delivery.FailedAt == nil && !delivery.NextAttemptAt.After(now) {
			out = append(out, cloneNotification(delivery))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NextAttemptAt.Before(out[j].NextAttemptAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemoryStore) ListNotifications(ctx context.Context, ownerID string, limit int) ([]*domain.NotificationDelivery, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var out []*domain.NotificationDelivery
	for _, delivery := range m.notifications {
		if ownerID == "" || delivery.OwnerID == ownerID {
			out = append(out, cloneNotification(delivery))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func cloneNodeCommand(value *domain.NodeCommand) *domain.NodeCommand {
	cp := *value
	if value.Args != nil {
		cp.Args = make(map[string]any, len(value.Args))
		for key, item := range value.Args {
			cp.Args[key] = item
		}
	}
	cp.Result = append(json.RawMessage(nil), value.Result...)
	return &cp
}

func (m *MemoryStore) CreateNodeCommand(ctx context.Context, command *domain.NodeCommand) (*domain.NodeCommand, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := command.NodeID + "\x00" + command.IdempotencyKey
	if id := m.nodeCommandKeys[key]; id != "" {
		existing := m.nodeCommands[id]
		if err := verifyNodeCommandReplay(existing, command); err != nil {
			return nil, false, err
		}
		return cloneNodeCommand(existing), false, nil
	}
	if existing := m.nodeCommands[command.ID]; existing != nil {
		if err := verifyNodeCommandReplay(existing, command); err != nil {
			return nil, false, err
		}
		return cloneNodeCommand(existing), false, nil
	}
	stored := cloneNodeCommand(command)
	if stored.Revision == 0 {
		stored.Revision = 1
	}
	m.nodeCommands[command.ID] = stored
	m.nodeCommandKeys[key] = command.ID
	return cloneNodeCommand(stored), true, nil
}

func (m *MemoryStore) UpdateNodeCommand(ctx context.Context, command *domain.NodeCommand) (*domain.NodeCommand, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nodeCommands[command.ID] == nil {
		return nil, ErrNotFound
	}
	stored := cloneNodeCommand(command)
	m.nodeCommands[command.ID] = stored
	return cloneNodeCommand(stored), nil
}

func (m *MemoryStore) CompareAndSwapNodeCommand(ctx context.Context, command *domain.NodeCommand, expectedAttempts int, expected ...domain.NodeCommandStatus) (*domain.NodeCommand, error) {
	m.mu.RLock()
	current := m.nodeCommands[command.ID]
	m.mu.RUnlock()
	if current == nil {
		return nil, ErrNotFound
	}
	return m.CompareAndSwapNodeCommandRevision(ctx, command, current.Revision, expectedAttempts, current.Uncertain, expected...)
}

func (m *MemoryStore) CompareAndSwapNodeCommandRevision(ctx context.Context, command *domain.NodeCommand, expectedRevision uint64, expectedAttempts int, expectedUncertain bool, expected ...domain.NodeCommandStatus) (*domain.NodeCommand, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.nodeCommands[command.ID]
	if current == nil {
		return nil, ErrNotFound
	}
	allowed := false
	for _, status := range expected {
		if current.Status == status {
			allowed = true
			break
		}
	}
	if !allowed || current.Revision != expectedRevision || current.Attempts != expectedAttempts || current.Uncertain != expectedUncertain {
		return nil, ErrNodeCommandConflict
	}
	if err := verifyNodeCommandDelivery(current, command); err != nil {
		return nil, err
	}
	stored := cloneNodeCommand(command)
	stored.Revision = current.Revision + 1
	m.nodeCommands[command.ID] = stored
	return cloneNodeCommand(stored), nil
}

func (m *MemoryStore) AdvanceNodeCommandRecovery(ctx context.Context, id string) (*domain.NodeCommand, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.nodeCommands[id]
	if current == nil {
		return nil, ErrNotFound
	}
	if !current.Uncertain || current.EvidenceKind == "authoritative_observation" {
		return cloneNodeCommand(current), nil
	}
	updated := cloneNodeCommand(current)
	updated.RecoveryAttempts++
	next := time.Now().UTC().Add(nodeCommandRecoveryBackoff(updated.RecoveryAttempts))
	updated.RecoveryNextAt = &next
	updated.UpdatedAt = time.Now().UTC()
	updated.Revision = current.Revision + 1
	m.nodeCommands[id] = updated
	return cloneNodeCommand(updated), nil
}

func nodeCommandRecoveryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 9 {
		attempt = 9
	}
	delay := 100 * time.Millisecond
	for i := 1; i < attempt; i++ {
		delay *= 2
	}
	if delay > 5*time.Second {
		return 5 * time.Second
	}
	return delay
}

func (m *MemoryStore) PromoteNodeCommandUncertain(ctx context.Context, id, nodeID string, result json.RawMessage, commandError string) (*domain.NodeCommand, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.nodeCommands[id]
	if current == nil || current.NodeID != nodeID {
		return nil, ErrNotFound
	}
	if !current.Uncertain && (current.Status == domain.NodeCommandSucceeded || current.Status == domain.NodeCommandFailed) && current.EvidenceKind == "authoritative_observation" {
		return nil, ErrNodeCommandConflict
	}
	updated := cloneNodeCommand(current)
	updated.Status = domain.NodeCommandSent
	updated.Uncertain = true
	updated.Result = append(json.RawMessage(nil), result...)
	updated.Error = commandError
	updated.UpdatedAt = time.Now().UTC()
	updated.Revision = current.Revision + 1
	m.nodeCommands[id] = updated
	return cloneNodeCommand(updated), nil
}

func (m *MemoryStore) ListNodeCommandRecovery(ctx context.Context, nodeID, reconcilesCommandID string) ([]*domain.NodeCommand, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*domain.NodeCommand, 0)
	for _, command := range m.nodeCommands {
		if nodeID != "" && command.NodeID != nodeID {
			continue
		}
		if reconcilesCommandID != "" && command.ReconcilesCommandID != reconcilesCommandID {
			continue
		}
		out = append(out, cloneNodeCommand(command))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryStore) GetNodeCommand(ctx context.Context, id string) (*domain.NodeCommand, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	command := m.nodeCommands[id]
	if command == nil {
		return nil, ErrNotFound
	}
	return cloneNodeCommand(command), nil
}

func (m *MemoryStore) ListNodeCommands(ctx context.Context, nodeID string, limit int) ([]*domain.NodeCommand, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var out []*domain.NodeCommand
	for _, command := range m.nodeCommands {
		if nodeID == "" || command.NodeID == nodeID {
			out = append(out, cloneNodeCommand(command))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func cloneBudget(value *domain.BudgetReservation) *domain.BudgetReservation {
	cp := *value
	return &cp
}

func (m *MemoryStore) ReserveBudget(ctx context.Context, principalID, workloadID string, amountCents, limitCents int64) (*domain.BudgetReservation, bool, error) {
	reservation, allowed, _, err := m.ReserveBudgetClaim(ctx, principalID, workloadID, amountCents, limitCents, "budget:"+workloadID+":legacy")
	return reservation, allowed, err
}

func (m *MemoryStore) ReserveBudgetClaim(ctx context.Context, principalID, workloadID string, amountCents, limitCents int64, attemptToken string) (*domain.BudgetReservation, bool, bool, error) {
	if strings.TrimSpace(attemptToken) == "" {
		return nil, false, false, fmt.Errorf("%w: empty budget attempt token", ErrWorkloadConflict)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing := m.budgets[workloadID]; existing != nil && existing.Status != domain.BudgetReleased {
		if existing.Revision == 0 {
			existing.Revision = 1
		}
		if existing.Attempt == 0 {
			existing.Attempt = 1
		}
		if existing.OwnershipToken == "" {
			existing.OwnershipToken = fmt.Sprintf("budget:%s:%d", workloadID, existing.Attempt)
		}
		if existing.Status != domain.BudgetReserved || existing.WorkloadID != workloadID || existing.PrincipalID != principalID || existing.OwnershipToken != attemptToken || existing.ReservedCents != amountCents || existing.LimitCents != limitCents || existing.Currency != defaultBudgetCurrency {
			return cloneBudget(existing), false, false, fmt.Errorf("%w: active budget reservation belongs to another attempt", ErrWorkloadConflict)
		}
		return cloneBudget(existing), true, false, nil
	}
	var committed int64
	for _, reservation := range m.budgets {
		if reservation.PrincipalID != principalID {
			continue
		}
		if reservation.Status == domain.BudgetReserved {
			committed += reservation.ReservedCents
		} else if reservation.Status == domain.BudgetSettled {
			committed += reservation.ActualCents
		}
	}
	if limitCents > 0 && committed+amountCents > limitCents {
		return nil, false, false, nil
	}
	now := time.Now().UTC()
	attempt := uint64(1)
	if existing := m.budgets[workloadID]; existing != nil {
		attempt = existing.Attempt + 1
	}
	reservation := &domain.BudgetReservation{WorkloadID: workloadID, PrincipalID: principalID, Revision: 1, Attempt: attempt, OwnershipToken: attemptToken, ReservedCents: amountCents, LimitCents: limitCents, Currency: defaultBudgetCurrency, Status: domain.BudgetReserved, CreatedAt: now, UpdatedAt: now}
	if existing := m.budgets[workloadID]; existing != nil {
		reservation.CreatedAt = existing.CreatedAt
	}
	m.budgets[workloadID] = reservation
	return cloneBudget(reservation), true, true, nil
}

// ReserveAndLinkBudgetClaim holds the workload/budget mutex across both
// ownership decisions and publication of the token. A caller can therefore
// never observe a newly reserved claim without its exact workload linkage.
func (m *MemoryStore) ReserveAndLinkBudgetClaim(ctx context.Context, principalID, workloadID string, amountCents, limitCents int64, attemptToken string, expectedRevision uint64, expectedStatus domain.WorkloadStatus, expectedCancellationOwner string) (*domain.BudgetReservation, *domain.Workload, bool, bool, error) {
	if strings.TrimSpace(attemptToken) == "" {
		return nil, nil, false, false, fmt.Errorf("%w: empty budget attempt token", ErrWorkloadConflict)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	workload := m.workloads[workloadID]
	if workload == nil || workload.Revision != expectedRevision || workload.Status != expectedStatus || workload.CancellationOwner != expectedCancellationOwner || (workload.Request.PrincipalID != "" && workload.Request.PrincipalID != principalID) {
		return nil, nil, false, false, ErrWorkloadConflict
	}
	if workload.BudgetReservationToken != "" && (workload.BudgetReservationToken != attemptToken || (workload.BudgetReservationCents != 0 && workload.BudgetReservationCents != amountCents) || (workload.BudgetReservationLimitCents != 0 && workload.BudgetReservationLimitCents != limitCents) || (workload.BudgetReservationCurrency != "" && workload.BudgetReservationCurrency != defaultBudgetCurrency)) {
		return nil, nil, false, false, ErrWorkloadConflict
	}
	if existing := m.budgets[workloadID]; existing != nil && existing.Status != domain.BudgetReleased {
		if existing.Revision == 0 {
			existing.Revision = 1
		}
		if existing.Attempt == 0 {
			existing.Attempt = 1
		}
		if existing.OwnershipToken == "" {
			existing.OwnershipToken = fmt.Sprintf("budget:%s:%d", workloadID, existing.Attempt)
		}
		if existing.Status != domain.BudgetReserved || existing.WorkloadID != workloadID || existing.PrincipalID != principalID || existing.OwnershipToken != attemptToken || existing.ReservedCents != amountCents || existing.LimitCents != limitCents || existing.Currency != defaultBudgetCurrency || (workload.BudgetReservationAttempt != 0 && workload.BudgetReservationAttempt != existing.Attempt) {
			return cloneBudget(existing), nil, false, false, fmt.Errorf("%w: active budget reservation belongs to another attempt", ErrWorkloadConflict)
		}
		updated := cloneWorkload(workload)
		updated.BudgetReservationToken = existing.OwnershipToken
		updated.BudgetReservationAttempt = existing.Attempt
		updated.BudgetReservationCents = existing.ReservedCents
		updated.BudgetReservationLimitCents = existing.LimitCents
		updated.BudgetReservationCurrency = existing.Currency
		updated.Revision++
		updated.UpdatedAt = time.Now().UTC()
		m.workloads[workloadID] = updated
		return cloneBudget(existing), cloneWorkload(updated), true, false, nil
	}
	var committed int64
	for _, reservation := range m.budgets {
		if reservation.PrincipalID != principalID {
			continue
		}
		if reservation.Status == domain.BudgetReserved {
			committed += reservation.ReservedCents
		} else if reservation.Status == domain.BudgetSettled {
			committed += reservation.ActualCents
		}
	}
	if limitCents > 0 && committed+amountCents > limitCents {
		return nil, cloneWorkload(workload), false, false, nil
	}
	now := time.Now().UTC()
	attempt := uint64(1)
	if existing := m.budgets[workloadID]; existing != nil {
		attempt = existing.Attempt + 1
	}
	reservation := &domain.BudgetReservation{WorkloadID: workloadID, PrincipalID: principalID, Revision: 1, Attempt: attempt, OwnershipToken: attemptToken, ReservedCents: amountCents, LimitCents: limitCents, Currency: defaultBudgetCurrency, Status: domain.BudgetReserved, CreatedAt: now, UpdatedAt: now}
	if existing := m.budgets[workloadID]; existing != nil {
		reservation.CreatedAt = existing.CreatedAt
	}
	updated := cloneWorkload(workload)
	updated.BudgetReservationToken = reservation.OwnershipToken
	updated.BudgetReservationAttempt = reservation.Attempt
	updated.BudgetReservationCents = reservation.ReservedCents
	updated.BudgetReservationLimitCents = reservation.LimitCents
	updated.BudgetReservationCurrency = reservation.Currency
	updated.Revision++
	updated.UpdatedAt = now
	m.budgets[workloadID] = reservation
	m.workloads[workloadID] = updated
	return cloneBudget(reservation), cloneWorkload(updated), true, true, nil
}

func (m *MemoryStore) SettleBudget(ctx context.Context, workloadID string, actualCents int64) (*domain.BudgetReservation, error) {
	return nil, errors.New("budget settlement requires ownership token")
}

func (m *MemoryStore) SettleBudgetClaim(ctx context.Context, workloadID, ownershipToken string, attempt uint64, actualCents int64) (*domain.BudgetReservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	reservation := m.budgets[workloadID]
	if reservation == nil {
		return nil, ErrNotFound
	}
	if ownershipToken == "" || reservation.OwnershipToken != ownershipToken || attempt == 0 || reservation.Attempt != attempt {
		return nil, ErrWorkloadConflict
	}
	if actualCents < 0 {
		actualCents = 0
	}
	if reservation.Status == domain.BudgetSettled {
		if reservation.ActualCents == actualCents {
			return cloneBudget(reservation), nil
		}
		return nil, ErrWorkloadConflict
	}
	if reservation.Status != domain.BudgetReserved {
		return nil, ErrWorkloadConflict
	}
	reservation.ActualCents = actualCents
	reservation.Status = domain.BudgetSettled
	reservation.Revision++
	reservation.UpdatedAt = time.Now().UTC()
	return cloneBudget(reservation), nil
}

func (m *MemoryStore) ReleaseBudget(ctx context.Context, workloadID string) error {
	return errors.New("budget release requires ownership token")
}

func (m *MemoryStore) ReleaseBudgetClaim(ctx context.Context, workloadID, ownershipToken string, attempt uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	reservation := m.budgets[workloadID]
	if reservation == nil {
		return nil
	}
	if ownershipToken == "" || reservation.OwnershipToken != ownershipToken || attempt == 0 || reservation.Attempt != attempt {
		return ErrWorkloadConflict
	}
	if reservation.Status == domain.BudgetReleased {
		return nil
	}
	if reservation.Status != domain.BudgetReserved {
		return ErrWorkloadConflict
	}
	reservation.Revision++
	if reservation.Status == domain.BudgetReserved {
		reservation.Status = domain.BudgetReleased
		reservation.UpdatedAt = time.Now().UTC()
	}
	return nil
}

func (m *MemoryStore) ListBudgetReservations(ctx context.Context, principalID string) ([]*domain.BudgetReservation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*domain.BudgetReservation
	for _, reservation := range m.budgets {
		if principalID == "" || reservation.PrincipalID == principalID {
			out = append(out, cloneBudget(reservation))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func cloneTransformationApproval(value *domain.TransformationApproval) *domain.TransformationApproval {
	cp := *value
	return &cp
}

func transformationApprovalKey(workloadID, planHash string) string {
	return workloadID + "::" + planHash
}

func (m *MemoryStore) CreateTransformationApproval(ctx context.Context, approval *domain.TransformationApproval) (*domain.TransformationApproval, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := transformationApprovalKey(approval.WorkloadID, approval.PlanHash)
	if existing := m.transformApprovals[key]; existing != nil {
		return cloneTransformationApproval(existing), false, nil
	}
	m.transformApprovals[key] = cloneTransformationApproval(approval)
	return cloneTransformationApproval(approval), true, nil
}

func (m *MemoryStore) GetTransformationApproval(ctx context.Context, workloadID, planHash string) (*domain.TransformationApproval, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	approval := m.transformApprovals[transformationApprovalKey(workloadID, planHash)]
	if approval == nil {
		return nil, ErrNotFound
	}
	return cloneTransformationApproval(approval), nil
}

func (m *MemoryStore) ListTransformationApprovals(ctx context.Context, workloadID string) ([]*domain.TransformationApproval, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*domain.TransformationApproval
	for _, approval := range m.transformApprovals {
		if workloadID == "" || approval.WorkloadID == workloadID {
			out = append(out, cloneTransformationApproval(approval))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func cloneLearningSample(value *domain.SchedulerLearningSample) *domain.SchedulerLearningSample {
	cp := *value
	cp.Predicted = append(json.RawMessage(nil), value.Predicted...)
	cp.Observed = append(json.RawMessage(nil), value.Observed...)
	return &cp
}

func (m *MemoryStore) SaveSchedulerLearningSample(ctx context.Context, sample *domain.SchedulerLearningSample) (*domain.SchedulerLearningSample, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sample.ID == 0 {
		sample.ID = int64(len(m.learningSamples) + 1)
	}
	m.learningSamples = append(m.learningSamples, cloneLearningSample(sample))
	return cloneLearningSample(sample), nil
}

func (m *MemoryStore) ListSchedulerLearningSamples(ctx context.Context, acceleratorID string, limit int) ([]*domain.SchedulerLearningSample, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var out []*domain.SchedulerLearningSample
	for i := len(m.learningSamples) - 1; i >= 0 && len(out) < limit; i-- {
		if acceleratorID == "" || m.learningSamples[i].AcceleratorID == acceleratorID {
			out = append(out, cloneLearningSample(m.learningSamples[i]))
		}
	}
	return out, nil
}

func cloneInterferenceProfile(value *domain.InterferenceProfile) *domain.InterferenceProfile {
	cp := *value
	cp.WorkloadClasses = append([]string(nil), value.WorkloadClasses...)
	return &cp
}

func (m *MemoryStore) UpsertInterferenceProfile(ctx context.Context, profile *domain.InterferenceProfile) (*domain.InterferenceProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing := m.interferenceProfiles[profile.Key]; existing != nil && profile.Version <= existing.Version {
		return nil, ErrInterferenceProfileConflict
	}
	m.interferenceProfiles[profile.Key] = cloneInterferenceProfile(profile)
	return cloneInterferenceProfile(profile), nil
}

func (m *MemoryStore) GetInterferenceProfile(ctx context.Context, key string) (*domain.InterferenceProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	profile := m.interferenceProfiles[key]
	if profile == nil {
		return nil, ErrNotFound
	}
	return cloneInterferenceProfile(profile), nil
}

func (m *MemoryStore) ListInterferenceProfiles(ctx context.Context) ([]*domain.InterferenceProfile, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*domain.InterferenceProfile, 0, len(m.interferenceProfiles))
	for _, profile := range m.interferenceProfiles {
		result = append(result, cloneInterferenceProfile(profile))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

func cloneTransitionPlan(value *domain.TransitionPlan) *domain.TransitionPlan {
	copy := *value
	copy.Steps = append([]domain.TransitionStep(nil), value.Steps...)
	copy.Rollback = append([]domain.TransitionStep(nil), value.Rollback...)
	return &copy
}

func (m *MemoryStore) CreateTransitionPlan(ctx context.Context, plan *domain.TransitionPlan) (*domain.TransitionPlan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.transitionPlans[plan.ID] != nil {
		return nil, errors.New("store: transition plan already exists")
	}
	m.transitionPlans[plan.ID] = cloneTransitionPlan(plan)
	return cloneTransitionPlan(plan), nil
}

func (m *MemoryStore) UpdateTransitionPlan(ctx context.Context, plan *domain.TransitionPlan) (*domain.TransitionPlan, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.transitionPlans[plan.ID] == nil {
		return nil, ErrNotFound
	}
	m.transitionPlans[plan.ID] = cloneTransitionPlan(plan)
	return cloneTransitionPlan(plan), nil
}

func (m *MemoryStore) ListTransitionPlans(ctx context.Context, workloadID string, limit int) ([]*domain.TransitionPlan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var result []*domain.TransitionPlan
	for _, plan := range m.transitionPlans {
		if workloadID == "" || plan.WorkloadID == workloadID || plan.VictimWorkloadID == workloadID {
			result = append(result, cloneTransitionPlan(plan))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func cloneIncident(incident *domain.Incident) *domain.Incident {
	cp := *incident
	cp.EvidenceRefs = append([]string(nil), incident.EvidenceRefs...)
	cp.Proposal = append(json.RawMessage(nil), incident.Proposal...)
	return &cp
}

func (m *MemoryStore) CreateIncident(ctx context.Context, incident *domain.Incident) (*domain.Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.incidents[incident.ID]; exists {
		return nil, errors.New("store: incident already exists")
	}
	m.incidents[incident.ID] = cloneIncident(incident)
	return cloneIncident(incident), nil
}

func (m *MemoryStore) UpdateIncident(ctx context.Context, incident *domain.Incident) (*domain.Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.incidents[incident.ID]; !exists {
		return nil, ErrNotFound
	}
	m.incidents[incident.ID] = cloneIncident(incident)
	return cloneIncident(incident), nil
}

func (m *MemoryStore) GetIncident(ctx context.Context, id string) (*domain.Incident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	incident, exists := m.incidents[id]
	if !exists {
		return nil, ErrNotFound
	}
	return cloneIncident(incident), nil
}

func (m *MemoryStore) ListIncidents(ctx context.Context, ownerID string) ([]*domain.Incident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*domain.Incident
	for _, incident := range m.incidents {
		if ownerID == "" || incident.OwnerID == ownerID {
			out = append(out, cloneIncident(incident))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
