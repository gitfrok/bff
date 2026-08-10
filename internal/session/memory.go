package session

import (
	"context"
	"sync"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
)

// Memory is an in-process session store for environments without a shared
// store. It is the dev posture: a BFF restart logs everyone out, which is the
// correct failure mode for sessions whose loss is an inconvenience, not a
// correctness break (ADR-0049 decision 5).
type Memory struct {
	mu   sync.Mutex
	byID map[string]memoryEntry
	now  func() time.Time
}

type memoryEntry struct {
	read      aggregate.ReadContext
	expiresAt time.Time
}

// NewMemory builds an empty in-process store.
func NewMemory() *Memory {
	return &Memory{byID: make(map[string]memoryEntry), now: time.Now}
}

func (m *Memory) Create(ctx context.Context, read aggregate.ReadContext, ttl time.Duration) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictLocked()
	m.byID[id] = memoryEntry{read: read, expiresAt: m.now().Add(ttl)}
	return id, nil
}

func (m *Memory) Load(ctx context.Context, id string) (aggregate.ReadContext, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.byID[id]
	if !ok {
		return aggregate.ReadContext{}, ErrNoSession
	}
	if !m.now().Before(entry.expiresAt) {
		delete(m.byID, id)
		return aggregate.ReadContext{}, ErrNoSession
	}
	return entry.read, nil
}

func (m *Memory) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id)
	return nil
}

func (m *Memory) evictLocked() {
	for id, entry := range m.byID {
		if !m.now().Before(entry.expiresAt) {
			delete(m.byID, id)
		}
	}
}

var _ Store = (*Memory)(nil)
