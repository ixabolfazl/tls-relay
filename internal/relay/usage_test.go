package relay_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/relay"
)

// ---------------------------------------------------------------------------
// Mock UsageStore
// ---------------------------------------------------------------------------

type mockUsageStore struct {
	mu              sync.Mutex
	userCalls       []mockUsageCall
	domainCalls     []mockDomainCall
	userDomainCalls []mockUserDomainCall
	dnsCalls        []mockDNSCall
	errFn           func() error
}

type mockUsageCall struct {
	userID        int64
	bytesSent     int64
	bytesReceived int64
	date          time.Time
}

type mockDomainCall struct {
	domain        string
	bytesSent     int64
	bytesReceived int64
	date          time.Time
}

type mockUserDomainCall struct {
	userID        int64
	domain        string
	bytesSent     int64
	bytesReceived int64
	date          time.Time
}

func (m *mockUsageStore) IncrementUserUsage(_ context.Context, userID, bytesSent, bytesReceived int64, date time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userCalls = append(m.userCalls, mockUsageCall{
		userID:        userID,
		bytesSent:     bytesSent,
		bytesReceived: bytesReceived,
		date:          date,
	})
	if m.errFn != nil {
		return m.errFn()
	}
	return nil
}

func (m *mockUsageStore) IncrementDomainUsage(_ context.Context, domain string, bytesSent, bytesReceived int64, date time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.domainCalls = append(m.domainCalls, mockDomainCall{
		domain:        domain,
		bytesSent:     bytesSent,
		bytesReceived: bytesReceived,
		date:          date,
	})
	if m.errFn != nil {
		return m.errFn()
	}
	return nil
}

func (m *mockUsageStore) IncrementUserDomainUsage(_ context.Context, userID int64, domain string, bytesSent, bytesReceived int64, date time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userDomainCalls = append(m.userDomainCalls, mockUserDomainCall{
		userID:        userID,
		domain:        domain,
		bytesSent:     bytesSent,
		bytesReceived: bytesReceived,
		date:          date,
	})
	if m.errFn != nil {
		return m.errFn()
	}
	return nil
}

type mockDNSCall struct {
	userID int64
	count  int64
	date   time.Time
}

func (m *mockUsageStore) IncrementUserDNSUsage(_ context.Context, userID int64, date time.Time, count int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dnsCalls = append(m.dnsCalls, mockDNSCall{
		userID: userID,
		count:  count,
		date:   date,
	})
	if m.errFn != nil {
		return m.errFn()
	}
	return nil
}

func (m *mockUsageStore) IncrementProtocolUsage(_ context.Context, _ string, _, _ int64, _ time.Time) error {
	if m.errFn != nil {
		return m.errFn()
	}
	return nil
}

func (m *mockUsageStore) callsFor(userID int64) []mockUsageCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []mockUsageCall
	for _, c := range m.userCalls {
		if c.userID == userID {
			out = append(out, c)
		}
	}
	return out
}

func (m *mockUsageStore) totalUserCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.userCalls)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestUsageTracker_BatchesMultipleEmitsForSameUser(t *testing.T) {
	store := &mockUsageStore{}
	ut := relay.NewUsageTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ut.StartWriter(ctx, store)

	const userID = int64(42)
	const calls = 5

	for i := 0; i < calls; i++ {
		ut.Emit(userID, "", 100, 200) // 100 sent, 200 received each time, no domain
	}

	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if store.totalUserCalls() >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	calls42 := store.callsFor(userID)
	if len(calls42) == 0 {
		t.Fatal("expected at least one store call for userID 42, got none")
	}

	var totalSent, totalReceived int64
	for _, c := range calls42 {
		totalSent += c.bytesSent
		totalReceived += c.bytesReceived
	}

	wantSent := int64(calls * 100)
	wantReceived := int64(calls * 200)
	if totalSent != wantSent {
		t.Errorf("total sent: got %d, want %d", totalSent, wantSent)
	}
	if totalReceived != wantReceived {
		t.Errorf("total received: got %d, want %d", totalReceived, wantReceived)
	}
}

func TestUsageTracker_FlushCallsStorePerUser(t *testing.T) {
	store := &mockUsageStore{}
	ut := relay.NewUsageTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ut.StartWriter(ctx, store)

	ut.Emit(1, "", 1000, 2000)
	ut.Emit(2, "", 3000, 4000)

	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if store.totalUserCalls() >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if store.totalUserCalls() < 2 {
		t.Fatalf("expected at least 2 store calls (one per user), got %d", store.totalUserCalls())
	}

	calls1 := store.callsFor(1)
	calls2 := store.callsFor(2)

	var sent1, recv1, sent2, recv2 int64
	for _, c := range calls1 {
		sent1 += c.bytesSent
		recv1 += c.bytesReceived
	}
	for _, c := range calls2 {
		sent2 += c.bytesSent
		recv2 += c.bytesReceived
	}

	if sent1 != 1000 || recv1 != 2000 {
		t.Errorf("user1: got sent=%d recv=%d, want 1000/2000", sent1, recv1)
	}
	if sent2 != 3000 || recv2 != 4000 {
		t.Errorf("user2: got sent=%d recv=%d, want 3000/4000", sent2, recv2)
	}
}

func TestUsageTracker_PublicUserWithDomain(t *testing.T) {
	store := &mockUsageStore{}
	ut := relay.NewUsageTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ut.StartWriter(ctx, store)

	// Public connection (userID = 0) with a matched domain
	ut.Emit(0, "example.com", 500, 600)

	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		dCalls := len(store.domainCalls)
		store.mu.Unlock()
		if dCalls >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.userCalls) != 0 {
		t.Errorf("expected 0 userCalls for public user, got %d", len(store.userCalls))
	}
	if len(store.userDomainCalls) != 0 {
		t.Errorf("expected 0 userDomainCalls for public user, got %d", len(store.userDomainCalls))
	}
	if len(store.domainCalls) != 1 {
		t.Fatalf("expected 1 domainCall, got %d", len(store.domainCalls))
	}
	dc := store.domainCalls[0]
	if dc.domain != "example.com" || dc.bytesSent != 500 || dc.bytesReceived != 600 {
		t.Errorf("domainCall got %+v, want example.com (500/600)", dc)
	}
}

func TestUsageTracker_RegisteredUserUnmatchedDomain(t *testing.T) {
	store := &mockUsageStore{}
	ut := relay.NewUsageTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ut.StartWriter(ctx, store)

	// Registered user hitting unmatched domain (domain = "")
	ut.Emit(10, "", 700, 800)

	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if store.totalUserCalls() >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.domainCalls) != 0 {
		t.Errorf("expected 0 domainCalls for empty domain, got %d", len(store.domainCalls))
	}
	if len(store.userDomainCalls) != 0 {
		t.Errorf("expected 0 userDomainCalls for empty domain, got %d", len(store.userDomainCalls))
	}
	if len(store.userCalls) != 1 {
		t.Fatalf("expected 1 userCall, got %d", len(store.userCalls))
	}
	uc := store.userCalls[0]
	if uc.userID != 10 || uc.bytesSent != 700 || uc.bytesReceived != 800 {
		t.Errorf("userCall got %+v, want user 10 (700/800)", uc)
	}
}

func TestUsageTracker_RegisteredUserMultipleDomains(t *testing.T) {
	store := &mockUsageStore{}
	ut := relay.NewUsageTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ut.StartWriter(ctx, store)

	// Registered user 5 visits domain A and domain B
	ut.Emit(5, "domainA.com", 100, 200)
	ut.Emit(5, "domainB.com", 300, 400)

	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		store.mu.Lock()
		udCalls := len(store.userDomainCalls)
		store.mu.Unlock()
		if udCalls >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	// Should produce 2 userCalls (one for each key), 2 domainCalls, and 2 userDomainCalls
	if len(store.userDomainCalls) != 2 {
		t.Errorf("expected 2 userDomainCalls, got %d", len(store.userDomainCalls))
	}
	if len(store.domainCalls) != 2 {
		t.Errorf("expected 2 domainCalls, got %d", len(store.domainCalls))
	}
	if len(store.userCalls) != 2 {
		t.Errorf("expected 2 userCalls (one per key), got %d", len(store.userCalls))
	}

	// Verify combined user total sent is 100+300 = 400, received 200+400 = 600
	var totSent, totRec int64
	for _, uc := range store.userCalls {
		if uc.userID == 5 {
			totSent += uc.bytesSent
			totRec += uc.bytesReceived
		}
	}
	if totSent != 400 || totRec != 600 {
		t.Errorf("combined user calls sent/rec got %d/%d, want 400/600", totSent, totRec)
	}
}

func TestUsageTracker_NonBlockingWhenChannelFull(t *testing.T) {
	ut := relay.NewUsageTracker()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			ut.Emit(1, "example.com", 100, 200)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Emit blocked or was extremely slow — it must be non-blocking")
	}

	if ut.DroppedCount() == 0 {
		t.Error("expected some drops when channel is full, got 0")
	}
}

func TestUsageTracker_UnregisteredUserNoDomainIgnored(t *testing.T) {
	store := &mockUsageStore{}
	ut := relay.NewUsageTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ut.StartWriter(ctx, store)

	ut.Emit(0, "", 100, 200)
	ut.Emit(-1, "", 100, 200)

	cancel()
	time.Sleep(50 * time.Millisecond)

	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.userCalls) != 0 || len(store.domainCalls) != 0 || len(store.userDomainCalls) != 0 {
		t.Errorf("expected 0 store calls for invalid userIDs with empty domain, got user=%d domain=%d userDomain=%d",
			len(store.userCalls), len(store.domainCalls), len(store.userDomainCalls))
	}
}

func TestUsageTracker_FlushesDNSQueryEventsWithoutTLSBytes(t *testing.T) {
	store := &mockUsageStore{}
	ut := relay.NewUsageTracker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ut.StartWriter(ctx, store)

	ut.EmitDNSQuery(42)
	ut.EmitDNSQuery(42)
	ut.EmitDNSQuery(42)

	cancel()
	time.Sleep(50 * time.Millisecond)

	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.dnsCalls) != 1 {
		t.Fatalf("expected 1 batched DNS call for user 42, got %d", len(store.dnsCalls))
	}
	if store.dnsCalls[0].userID != 42 {
		t.Errorf("expected userID 42, got %d", store.dnsCalls[0].userID)
	}
	if store.dnsCalls[0].count != 3 {
		t.Errorf("expected DNS count 3, got %d", store.dnsCalls[0].count)
	}
}
