package store

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
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
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		nodes:          make(map[string]*domain.Node),
		engines:        make(map[string]*domain.EngineInstance),
		profiles:       make(map[string][]*domain.PerformanceProfile),
		jobs:           make(map[string]*domain.Job),
		workItems:      make(map[string]map[string]map[string]*domain.WorkItem),
		workloads:      make(map[string]*domain.Workload),
		idempotency:    make(map[string]string),
		leases:         make(map[string]*domain.AcceleratorLease),
		leaseFences:    make(map[string]int64),
		promptMappings: make(map[string]*domain.PromptMapping),
		incidents:      make(map[string]*domain.Incident),
		residencies:    make(map[string]*domain.ModelResidency),
		transitions:    make(map[string]*domain.ResidencyTransition),
		transitionKeys: make(map[string]string),
		notifications:  make(map[string]*domain.NotificationDelivery), notificationKeys: make(map[string]string),
		nodeCommands: make(map[string]*domain.NodeCommand), nodeCommandKeys: make(map[string]string),
		budgets:               make(map[string]*domain.BudgetReservation),
		transformApprovals:    make(map[string]*domain.TransformationApproval),
		interferenceProfiles:  make(map[string]*domain.InterferenceProfile),
		transitionPlans:       make(map[string]*domain.TransitionPlan),
		targetPolicyOverrides: make(map[string]*domain.TargetPolicyOverride),
		browserSessions:       make(map[string]*domain.BrowserSession),
	}
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
	if _, ok := m.workloads[w.Request.ID]; !ok {
		return nil, ErrNotFound
	}
	m.workloads[w.Request.ID] = cloneWorkload(w)
	return cloneWorkload(w), nil
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
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	if cur := m.leases[acceleratorID]; cur != nil && cur.ExpiresAt.After(now) && cur.WorkloadID != workloadID {
		cp := *cur
		return &cp, false, nil
	}
	m.leaseFences[acceleratorID]++
	lease := &domain.AcceleratorLease{AcceleratorID: acceleratorID, WorkloadID: workloadID, FencingToken: m.leaseFences[acceleratorID], ExpiresAt: now.Add(ttl)}
	m.leases[acceleratorID] = lease
	cp := *lease
	return &cp, true, nil
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
	stored := cloneResidency(residency)
	m.residencies[residencyKey(residency.TargetID, residency.Model)] = stored
	return cloneResidency(stored), nil
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if id := m.transitionKeys[transition.IdempotencyKey]; id != "" {
		return cloneTransition(m.transitions[id]), false, nil
	}
	if existing := m.transitions[transition.ID]; existing != nil {
		return cloneTransition(existing), false, nil
	}
	stored := cloneTransition(transition)
	m.transitions[transition.ID] = stored
	m.transitionKeys[transition.IdempotencyKey] = transition.ID
	return cloneTransition(stored), true, nil
}

func (m *MemoryStore) UpdateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.transitions[transition.ID] == nil {
		return nil, ErrNotFound
	}
	stored := cloneTransition(transition)
	m.transitions[transition.ID] = stored
	return cloneTransition(stored), nil
}

func (m *MemoryStore) ListResidencyTransitions(ctx context.Context, limit int) ([]*domain.ResidencyTransition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	out := make([]*domain.ResidencyTransition, 0, len(m.transitions))
	for _, transition := range m.transitions {
		out = append(out, cloneTransition(transition))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
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
		return cloneNodeCommand(m.nodeCommands[id]), false, nil
	}
	if existing := m.nodeCommands[command.ID]; existing != nil {
		return cloneNodeCommand(existing), false, nil
	}
	stored := cloneNodeCommand(command)
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing := m.budgets[workloadID]; existing != nil && existing.Status != domain.BudgetReleased {
		return cloneBudget(existing), true, nil
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
		return nil, false, nil
	}
	now := time.Now().UTC()
	reservation := &domain.BudgetReservation{WorkloadID: workloadID, PrincipalID: principalID, ReservedCents: amountCents, Status: domain.BudgetReserved, CreatedAt: now, UpdatedAt: now}
	if existing := m.budgets[workloadID]; existing != nil {
		reservation.CreatedAt = existing.CreatedAt
	}
	m.budgets[workloadID] = reservation
	return cloneBudget(reservation), true, nil
}

func (m *MemoryStore) SettleBudget(ctx context.Context, workloadID string, actualCents int64) (*domain.BudgetReservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	reservation := m.budgets[workloadID]
	if reservation == nil {
		return nil, ErrNotFound
	}
	if actualCents < 0 {
		actualCents = 0
	}
	reservation.ActualCents = actualCents
	reservation.Status = domain.BudgetSettled
	reservation.UpdatedAt = time.Now().UTC()
	return cloneBudget(reservation), nil
}

func (m *MemoryStore) ReleaseBudget(ctx context.Context, workloadID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	reservation := m.budgets[workloadID]
	if reservation == nil {
		return nil
	}
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
