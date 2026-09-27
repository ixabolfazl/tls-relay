package relay_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/relay"
)

// fakeConn is a minimal net.Conn used for testing ConnTracker without real
// network sockets.  Only Close() needs to work; the rest panic if called.
type fakeConn struct {
	mu     sync.Mutex
	closed bool
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Satisfy net.Conn interface (unused in tests).
func (c *fakeConn) Read(_ []byte) (int, error)         { panic("not implemented") }
func (c *fakeConn) Write(_ []byte) (int, error)        { panic("not implemented") }
func (c *fakeConn) LocalAddr() net.Addr                { return nil }
func (c *fakeConn) RemoteAddr() net.Addr               { return nil }
func (c *fakeConn) SetDeadline(_ time.Time) error      { panic("not implemented") }
func (c *fakeConn) SetReadDeadline(_ time.Time) error  { panic("not implemented") }
func (c *fakeConn) SetWriteDeadline(_ time.Time) error { panic("not implemented") }

// ---------------------------------------------------------------------------
// ConnTracker tests
// ---------------------------------------------------------------------------

func TestConnTracker_RegisterUnregister(t *testing.T) {
	ct := relay.NewConnTracker()
	conn := &fakeConn{}

	ct.Register("1.2.3.4", conn)
	if ct.ActiveCount() != 1 {
		t.Fatalf("expected 1 active connection after Register, got %d", ct.ActiveCount())
	}

	ct.Unregister("1.2.3.4", conn)
	if ct.ActiveCount() != 0 {
		t.Fatalf("expected 0 active connections after Unregister, got %d", ct.ActiveCount())
	}
}

func TestConnTracker_EvictNotAllowed_ClosesRevokedConns(t *testing.T) {
	ct := relay.NewConnTracker()

	connA := &fakeConn{}
	connB := &fakeConn{}
	connC := &fakeConn{}

	ct.Register("1.1.1.1", connA)
	ct.Register("2.2.2.2", connB)
	ct.Register("3.3.3.3", connC)

	// Only 2.2.2.2 remains allowed.
	allowed := map[string]struct{}{
		"2.2.2.2": {},
	}
	ct.EvictNotAllowed(allowed)

	if !connA.isClosed() {
		t.Error("connA (1.1.1.1 — revoked) should have been closed")
	}
	if connB.isClosed() {
		t.Error("connB (2.2.2.2 — still allowed) should NOT have been closed")
	}
	if !connC.isClosed() {
		t.Error("connC (3.3.3.3 — revoked) should have been closed")
	}
}

func TestConnTracker_EvictNotAllowed_NilAllowed_ClosesAll(t *testing.T) {
	ct := relay.NewConnTracker()

	conn1 := &fakeConn{}
	conn2 := &fakeConn{}
	ct.Register("10.0.0.1", conn1)
	ct.Register("10.0.0.2", conn2)

	// Passing nil map → evict everything.
	ct.EvictNotAllowed(nil)

	if !conn1.isClosed() || !conn2.isClosed() {
		t.Error("all connections should be closed when allowed map is nil")
	}
}

func TestConnTracker_MultipleConnsPerIP(t *testing.T) {
	ct := relay.NewConnTracker()

	c1 := &fakeConn{}
	c2 := &fakeConn{}
	ct.Register("5.5.5.5", c1)
	ct.Register("5.5.5.5", c2)

	if ct.ActiveCount() != 2 {
		t.Fatalf("expected 2 connections for same IP, got %d", ct.ActiveCount())
	}

	ct.EvictNotAllowed(nil) // evict all

	if !c1.isClosed() || !c2.isClosed() {
		t.Error("both connections for the same IP should be closed")
	}
}

func TestConnTracker_UnregisterAfterEvict_NoDataRace(t *testing.T) {
	// Ensure Unregister on an already-evicted conn doesn't panic or race.
	ct := relay.NewConnTracker()
	conn := &fakeConn{}

	ct.Register("9.9.9.9", conn)
	ct.EvictNotAllowed(nil)        // closes conn and internal map cleaned up lazily
	ct.Unregister("9.9.9.9", conn) // must be a safe no-op

	if ct.ActiveCount() != 0 {
		t.Errorf("expected 0 active connections, got %d", ct.ActiveCount())
	}
}

// ---------------------------------------------------------------------------
// Online User Presence & Last Seen Tests
// ---------------------------------------------------------------------------

type mockStore struct {
	mu        sync.Mutex
	lastSeens map[int64]time.Time
}

func (m *mockStore) UpdateUserLastSeen(_ context.Context, userID int64, lastSeen time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastSeens[userID] = lastSeen
	return nil
}

func TestConnTracker_UserPresenceLifecycle(t *testing.T) {
	ct := relay.NewConnTracker()

	// Map IP 203.0.113.10 to User 1 ("alice")
	ct.SetUserMappings([]relay.UserMappingInfo{
		{
			UserID:   1,
			Username: "alice",
			IPs:      []string{"203.0.113.10"},
		},
	})

	stats := ct.GetPresenceStats()
	if stats.TotalUsers != 1 {
		t.Fatalf("expected 1 user, got %d", stats.TotalUsers)
	}
	if stats.Users[0].Status != "Offline" {
		t.Fatalf("expected initial status Offline, got %s", stats.Users[0].Status)
	}
	if stats.Users[0].ActiveConnections != 0 {
		t.Fatalf("expected 0 active connections, got %d", stats.Users[0].ActiveConnections)
	}

	conn1 := &fakeConn{}
	conn2 := &fakeConn{}

	// Connection 1 opened -> Online
	ct.Register("203.0.113.10", conn1)
	stats = ct.GetPresenceStats()
	if stats.TotalOnline != 1 {
		t.Errorf("expected TotalOnline 1, got %d", stats.TotalOnline)
	}
	if stats.Users[0].Status != "Online" {
		t.Errorf("expected status Online after conn1, got %s", stats.Users[0].Status)
	}
	if stats.Users[0].ActiveConnections != 1 {
		t.Errorf("expected 1 active connection, got %d", stats.Users[0].ActiveConnections)
	}
	if stats.Users[0].FirstActiveAt == "" {
		t.Error("expected FirstActiveAt to be set when user becomes Online")
	}

	// Connection 2 opened -> ActiveConnections = 2, still Online
	ct.Register("203.0.113.10", conn2)
	stats = ct.GetPresenceStats()
	if stats.Users[0].Status != "Online" {
		t.Errorf("expected status Online after conn2, got %s", stats.Users[0].Status)
	}
	if stats.Users[0].ActiveConnections != 2 {
		t.Errorf("expected 2 active connections, got %d", stats.Users[0].ActiveConnections)
	}

	// Connection 1 closed -> ActiveConnections = 1, still Online
	ct.Unregister("203.0.113.10", conn1)
	stats = ct.GetPresenceStats()
	if stats.Users[0].Status != "Online" {
		t.Errorf("expected status Online after conn1 closed, got %s", stats.Users[0].Status)
	}
	if stats.Users[0].ActiveConnections != 1 {
		t.Errorf("expected 1 active connection remaining, got %d", stats.Users[0].ActiveConnections)
	}

	// Connection 2 closed -> ActiveConnections = 0, Offline
	ct.Unregister("203.0.113.10", conn2)
	stats = ct.GetPresenceStats()
	if stats.TotalOnline != 0 {
		t.Errorf("expected TotalOnline 0, got %d", stats.TotalOnline)
	}
	if stats.Users[0].Status != "Offline" {
		t.Errorf("expected status Offline after final connection closed, got %s", stats.Users[0].Status)
	}
	if stats.Users[0].ActiveConnections != 0 {
		t.Errorf("expected 0 active connections, got %d", stats.Users[0].ActiveConnections)
	}
	if stats.Users[0].LastSeenAt == "" {
		t.Error("expected LastSeenAt to be recorded when final connection closes")
	}
}

func TestConnTracker_LastSeenAsyncDBWorker(t *testing.T) {
	ct := relay.NewConnTracker()

	ct.SetUserMappings([]relay.UserMappingInfo{
		{
			UserID:   42,
			Username: "bob",
			IPs:      []string{"198.51.100.50"},
		},
	})

	store := &mockStore{lastSeens: make(map[int64]time.Time)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ct.StartLastSeenWriter(ctx, store)

	conn := &fakeConn{}
	ct.Register("198.51.100.50", conn)
	ct.Unregister("198.51.100.50", conn)

	// Wait briefly for worker goroutine to process channel message
	time.Sleep(50 * time.Millisecond)

	store.mu.Lock()
	lastSeen, ok := store.lastSeens[42]
	store.mu.Unlock()

	if !ok {
		t.Fatal("expected last seen event for user 42 to be written to DB store")
	}
	if lastSeen.IsZero() {
		t.Error("lastSeen timestamp should not be zero")
	}
}

func TestConnTracker_UnregisteredIP_DoesNotAffectUserTracking(t *testing.T) {
	ct := relay.NewConnTracker()
	conn := &fakeConn{}

	// IP 1.1.1.1 is not registered to any user
	ct.Register("1.1.1.1", conn)
	if ct.ActiveCount() != 1 {
		t.Errorf("expected ActiveCount 1, got %d", ct.ActiveCount())
	}

	stats := ct.GetPresenceStats()
	if stats.TotalUsers != 0 {
		t.Errorf("expected 0 registered users, got %d", stats.TotalUsers)
	}

	ct.Unregister("1.1.1.1", conn)
	if ct.ActiveCount() != 0 {
		t.Errorf("expected ActiveCount 0, got %d", ct.ActiveCount())
	}
}

func TestConnTracker_LookupUser_CanonicalIP(t *testing.T) {
	ct := relay.NewConnTracker()
	ct.SetUserMappings([]relay.UserMappingInfo{
		{
			UserID:   10,
			Username: "alice",
			IPs:      []string{"  192.168.1.100  "},
		},
	})

	// Standard lookup
	uid, uname, ok := ct.LookupUser("192.168.1.100")
	if !ok || uid != 10 || uname != "alice" {
		t.Errorf("expected (10, alice, true), got (%d, %s, %v)", uid, uname, ok)
	}

	// IPv4-mapped IPv6 lookup
	uid2, uname2, ok2 := ct.LookupUser("::ffff:192.168.1.100")
	if !ok2 || uid2 != 10 || uname2 != "alice" {
		t.Errorf("expected mapped IPv6 to match (10, alice, true), got (%d, %s, %v)", uid2, uname2, ok2)
	}
}
