package requestlog

import (
	"context"
	"sync"
	"testing"
	"time"
)

type mockStore struct {
	mu            sync.Mutex
	logs          []Event
	deletedBefore []time.Time
	cleared       bool
}

func (m *mockStore) InsertRequestLogs(ctx context.Context, logs []Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, logs...)
	return nil
}

func (m *mockStore) DeleteExpiredRequestLogs(ctx context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletedBefore = append(m.deletedBefore, before)
	var kept []Event
	count := int64(0)
	for _, l := range m.logs {
		if l.Timestamp.Before(before) {
			count++
		} else {
			kept = append(kept, l)
		}
	}
	m.logs = kept
	return count, nil
}

func (m *mockStore) ClearAllRequestLogs(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleared = true
	m.logs = nil
	return nil
}

func TestLogger_BatchFlush(t *testing.T) {
	store := &mockStore{}
	logger := New(store, 24*time.Hour, true)
	logger.flushInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger.Start(ctx)

	logger.Emit(Event{
		ClientIP:    "1.2.3.4",
		RequestType: TypeDNS,
		Domain:      "example.com",
		Port:        53,
		Status:      "resolved",
	})

	time.Sleep(150 * time.Millisecond)

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(store.logs))
	}
	if store.logs[0].Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", store.logs[0].Domain)
	}
}

func TestLogger_Disabled(t *testing.T) {
	store := &mockStore{}
	logger := New(store, 24*time.Hour, false)
	logger.flushInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger.Start(ctx)

	logger.Emit(Event{
		ClientIP:    "1.2.3.4",
		RequestType: TypeDNS,
		Domain:      "example.com",
	})

	time.Sleep(100 * time.Millisecond)

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.logs) != 0 {
		t.Fatalf("expected 0 logs when disabled, got %d", len(store.logs))
	}
}

func TestLogger_QueueFullDrop(t *testing.T) {
	store := &mockStore{}
	logger := New(store, 24*time.Hour, true)
	logger.queue = make(chan Event, 2) // small buffer for testing

	// Emit 3 events without starting worker
	logger.Emit(Event{Domain: "1.com"})
	logger.Emit(Event{Domain: "2.com"})
	logger.Emit(Event{Domain: "3.com"}) // should drop

	if logger.DroppedCount() != 1 {
		t.Errorf("expected 1 dropped event, got %d", logger.DroppedCount())
	}
}
