package store

import (
	"context"
	"errors"
	"sort"

	"vram-governor/internal/domain"
)

var ErrAlreadyExists = errors.New("store: already exists")

func cloneNodeEnrollment(value *domain.NodeEnrollment) *domain.NodeEnrollment {
	copy := *value
	return &copy
}

func (m *MemoryStore) CreateNodeEnrollment(_ context.Context, value *domain.NodeEnrollment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.nodeEnrollments[value.NodeID]; exists {
		return ErrAlreadyExists
	}
	for _, existing := range m.nodeEnrollments {
		if existing.TokenHash == value.TokenHash {
			return ErrAlreadyExists
		}
	}
	m.nodeEnrollments[value.NodeID] = cloneNodeEnrollment(value)
	return nil
}

func (m *MemoryStore) GetNodeEnrollmentByHash(_ context.Context, hash string) (*domain.NodeEnrollment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, value := range m.nodeEnrollments {
		if value.TokenHash == hash {
			return cloneNodeEnrollment(value), nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) GetNodeEnrollment(_ context.Context, nodeID string) (*domain.NodeEnrollment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, exists := m.nodeEnrollments[nodeID]
	if !exists {
		return nil, ErrNotFound
	}
	return cloneNodeEnrollment(value), nil
}

func (m *MemoryStore) ListNodeEnrollments(_ context.Context) ([]*domain.NodeEnrollment, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	values := make([]*domain.NodeEnrollment, 0, len(m.nodeEnrollments))
	for _, value := range m.nodeEnrollments {
		values = append(values, cloneNodeEnrollment(value))
	}
	sort.Slice(values, func(i, j int) bool { return values[i].NodeID < values[j].NodeID })
	return values, nil
}

func (m *MemoryStore) RevokeNodeEnrollment(_ context.Context, nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, exists := m.nodeEnrollments[nodeID]
	if !exists {
		return ErrNotFound
	}
	value.Status = "revoked"
	return nil
}
