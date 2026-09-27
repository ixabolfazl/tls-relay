package reqstats_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/reqstats"
)

type mockStatsStore struct {
	mu    sync.Mutex
	calls []mockCall
}

type mockCall struct {
	date        time.Time
	requestType string
	category    string
	count       int64
}

func (m *mockStatsStore) IncrementRequestStat(_ context.Context, date time.Time, requestType, category string, count int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, mockCall{
		date:        date,
		requestType: requestType,
		category:    category,
		count:       count,
	})
	return nil
}

func (m *mockStatsStore) totalCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

func TestCollector_AccumulatesAndFlushes(t *testing.T) {
	store := &mockStatsStore{}
	c := reqstats.New()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.StartWriter(ctx, store)

	c.Emit("DNS", "authorized")
	c.Emit("DNS", "authorized")
	c.Emit("DNS", "unauthorized_passthrough")
	c.Emit("TLS", "registered")

	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if store.totalCalls() >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.calls) != 3 {
		t.Fatalf("expected 3 distinct stat calls, got %d", len(store.calls))
	}

	var dnsAuthCount int64
	for _, call := range store.calls {
		if call.requestType == "DNS" && call.category == "authorized" {
			dnsAuthCount += call.count
		}
	}
	if dnsAuthCount != 2 {
		t.Errorf("DNS authorized count got %d, want 2", dnsAuthCount)
	}
}

func TestCollector_NonBlockingWhenFull(t *testing.T) {
	c := reqstats.New()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			c.Emit("DNS", "total")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Emit blocked when channel full")
	}

	if c.DroppedCount() == 0 {
		t.Error("expected drops when channel is full")
	}
}
