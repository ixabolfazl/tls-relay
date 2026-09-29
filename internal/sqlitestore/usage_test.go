package sqlitestore_test

import (
	"context"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

// newUsageTestUser creates a user for usage tests and returns their ID.
func newUsageTestUser(t *testing.T, s *sqlitestore.Store, username string) int64 {
	t.Helper()
	u, err := s.CreateUser(context.Background(), username, 3)
	if err != nil {
		t.Fatalf("CreateUser(%q): %v", username, err)
	}
	return u.ID
}

// ---------------------------------------------------------------------------
// IncrementUserUsage tests
// ---------------------------------------------------------------------------

func TestIncrementUserUsage_AccumulatesCorrectly(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	uid := newUsageTestUser(t, s, "usage_alice")

	day1 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)

	// Two increments on day1.
	if err := s.IncrementUserUsage(ctx, uid, 100, 200, day1); err != nil {
		t.Fatalf("IncrementUserUsage day1 first: %v", err)
	}
	if err := s.IncrementUserUsage(ctx, uid, 50, 75, day1); err != nil {
		t.Fatalf("IncrementUserUsage day1 second: %v", err)
	}

	// One increment on day2.
	if err := s.IncrementUserUsage(ctx, uid, 1000, 2000, day2); err != nil {
		t.Fatalf("IncrementUserUsage day2: %v", err)
	}

	// Check total usage map.
	totals, err := s.GetUsersTotalUsage(ctx, time.Time{})
	if err != nil {
		t.Fatalf("GetUsersTotalUsage: %v", err)
	}
	tu, ok := totals[uid]
	if !ok {
		t.Fatal("user not found in GetUsersTotalUsage")
	}
	wantSent := int64(100 + 50 + 1000)
	wantReceived := int64(200 + 75 + 2000)
	if tu.Sent != wantSent {
		t.Errorf("total sent: got %d, want %d", tu.Sent, wantSent)
	}
	if tu.Received != wantReceived {
		t.Errorf("total received: got %d, want %d", tu.Received, wantReceived)
	}
}

func TestIncrementUserUsage_ZeroBytesNoOp(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	uid := newUsageTestUser(t, s, "usage_bob")

	// Zero-byte increment should be a no-op.
	if err := s.IncrementUserUsage(ctx, uid, 0, 0, time.Now()); err != nil {
		t.Fatalf("IncrementUserUsage(0,0): %v", err)
	}

	// Check no daily rows were created.
	rows, err := s.GetUserUsageDaily(ctx, uid, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("GetUserUsageDaily: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected no daily rows after zero-byte increment, got %d", len(rows))
	}
}

// ---------------------------------------------------------------------------
// Daily row upsert tests (no duplicate rows on same date)
// ---------------------------------------------------------------------------

func TestIncrementUserUsage_DailyRowUpsertNoDuplicates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	uid := newUsageTestUser(t, s, "usage_carol")

	day := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)

	// Three increments on the same calendar day (different times).
	for i := 0; i < 3; i++ {
		if err := s.IncrementUserUsage(ctx, uid, 10, 20, day.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatalf("IncrementUserUsage #%d: %v", i, err)
		}
	}

	rows, err := s.GetUserUsageDaily(ctx, uid, day)
	if err != nil {
		t.Fatalf("GetUserUsageDaily: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 daily row, got %d", len(rows))
	}
	if rows[0].Date != "2026-03-15" {
		t.Errorf("date: got %q, want %q", rows[0].Date, "2026-03-15")
	}
	if rows[0].BytesSent != 30 {
		t.Errorf("bytes_sent: got %d, want 30", rows[0].BytesSent)
	}
	if rows[0].BytesReceived != 60 {
		t.Errorf("bytes_received: got %d, want 60", rows[0].BytesReceived)
	}
}

// ---------------------------------------------------------------------------
// ResetUserUsage tests
// ---------------------------------------------------------------------------

func TestResetUserUsage_WipesBothTotalAndDailyHistory(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	uid := newUsageTestUser(t, s, "usage_dave")

	// Accumulate some usage across multiple days.
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if err := s.IncrementUserUsage(ctx, uid, 500, 1000, base.Add(time.Duration(i)*24*time.Hour)); err != nil {
			t.Fatalf("IncrementUserUsage day %d: %v", i, err)
		}
	}

	_ = s.IncrementUserDNSUsage(ctx, uid, base, 15)

	// Confirm rows exist.
	rows, err := s.GetUserUsageDaily(ctx, uid, base)
	if err != nil {
		t.Fatalf("GetUserUsageDaily before reset: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("expected 5 daily rows before reset, got %d", len(rows))
	}

	// Reset.
	if err := s.ResetUserUsage(ctx, uid); err != nil {
		t.Fatalf("ResetUserUsage: %v", err)
	}

	// Daily rows should be empty.
	rows, err = s.GetUserUsageDaily(ctx, uid, base)
	if err != nil {
		t.Fatalf("GetUserUsageDaily after reset: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 daily rows after reset, got %d", len(rows))
	}

	// DNS usage total after reset should be zero.
	dnsTotal, err := s.GetUserDNSUsageTotal(ctx, uid, time.Time{})
	if err != nil {
		t.Fatalf("GetUserDNSUsageTotal after reset: %v", err)
	}
	if dnsTotal != 0 {
		t.Errorf("expected 0 DNS queries after reset, got %d", dnsTotal)
	}

	// Total should be zero.
	totals, err := s.GetUsersTotalUsage(ctx, time.Time{})
	if err != nil {
		t.Fatalf("GetUsersTotalUsage after reset: %v", err)
	}
	tu := totals[uid]
	if tu.Sent != 0 || tu.Received != 0 {
		t.Errorf("totals after reset: sent=%d received=%d (want 0,0)", tu.Sent, tu.Received)
	}
}

// ---------------------------------------------------------------------------
// GetGlobalUsageDaily tests
// ---------------------------------------------------------------------------

func TestGetGlobalUsageDaily_SumsAcrossUsers(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	uid1 := newUsageTestUser(t, s, "usage_global1")
	uid2 := newUsageTestUser(t, s, "usage_global2")

	day := time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC)

	// user1: 100 sent, 200 received on that day.
	if err := s.IncrementUserUsage(ctx, uid1, 100, 200, day); err != nil {
		t.Fatal(err)
	}
	// user2: 300 sent, 400 received on that day.
	if err := s.IncrementUserUsage(ctx, uid2, 300, 400, day); err != nil {
		t.Fatal(err)
	}

	rows, err := s.GetGlobalUsageDaily(ctx, day)
	if err != nil {
		t.Fatalf("GetGlobalUsageDaily: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 aggregated row, got %d", len(rows))
	}
	r := rows[0]
	if r.Date != "2026-06-10" {
		t.Errorf("date: got %q, want %q", r.Date, "2026-06-10")
	}
	if r.BytesSent != 400 {
		t.Errorf("bytes_sent: got %d, want 400", r.BytesSent)
	}
	if r.BytesReceived != 600 {
		t.Errorf("bytes_received: got %d, want 600", r.BytesReceived)
	}
}

func TestGetGlobalUsageDaily_SinceFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	uid := newUsageTestUser(t, s, "usage_filter")

	day1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	day3 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

	for _, d := range []time.Time{day1, day2, day3} {
		if err := s.IncrementUserUsage(ctx, uid, 1, 1, d); err != nil {
			t.Fatal(err)
		}
	}

	// Query from day2 — should exclude day1.
	rows, err := s.GetGlobalUsageDaily(ctx, day2)
	if err != nil {
		t.Fatalf("GetGlobalUsageDaily: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("expected 2 rows (day2, day3), got %d", len(rows))
	}
	if len(rows) > 0 && rows[0].Date != "2026-01-05" {
		t.Errorf("first row date: got %q, want %q", rows[0].Date, "2026-01-05")
	}
}

func TestGetUsersTotalUsage_MultipleUsers(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	uid1 := newUsageTestUser(t, s, "usage_total1")
	uid2 := newUsageTestUser(t, s, "usage_total2")

	day := time.Now().UTC()
	_ = s.IncrementUserUsage(ctx, uid1, 111, 222, day)
	_ = s.IncrementUserUsage(ctx, uid2, 333, 444, day)

	totals, err := s.GetUsersTotalUsage(ctx, time.Time{})
	if err != nil {
		t.Fatalf("GetUsersTotalUsage: %v", err)
	}

	if t1, ok := totals[uid1]; !ok || t1.Sent != 111 || t1.Received != 222 {
		t.Errorf("uid1 totals: got sent=%d received=%d, want 111/222", totals[uid1].Sent, totals[uid1].Received)
	}
	if t2, ok := totals[uid2]; !ok || t2.Sent != 333 || t2.Received != 444 {
		t.Errorf("uid2 totals: got sent=%d received=%d, want 333/444", totals[uid2].Sent, totals[uid2].Received)
	}
}

func TestGlobalUsageTotals_AfterUserReset(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	uid := newUsageTestUser(t, s, "user_reset_test")
	day := time.Now().UTC()

	// Record protocol usage (e.g. 500 sent, 600 received for TLS)
	if err := s.IncrementProtocolUsage(ctx, "TLS", 500, 600, day); err != nil {
		t.Fatalf("IncrementProtocolUsage failed: %v", err)
	}

	// Record user usage (300 sent, 400 received)
	if err := s.IncrementUserUsage(ctx, uid, 300, 400, day); err != nil {
		t.Fatalf("IncrementUserUsage failed: %v", err)
	}

	// Check global totals - should reflect protocol usage
	sent, recv, err := s.GetGlobalUsageTotals(ctx, day.Add(-time.Hour))
	if err != nil {
		t.Fatalf("GetGlobalUsageTotals failed: %v", err)
	}
	if sent != 500 || recv != 600 {
		t.Fatalf("expected 500 sent, 600 recv from protocol usage; got %d, %d", sent, recv)
	}

	// Reset user usage
	if err := s.ResetUserUsage(ctx, uid); err != nil {
		t.Fatalf("ResetUserUsage failed: %v", err)
	}

	// Global totals must NOT change after user reset
	sentAfter, recvAfter, err := s.GetGlobalUsageTotals(ctx, day.Add(-time.Hour))
	if err != nil {
		t.Fatalf("GetGlobalUsageTotals after reset failed: %v", err)
	}
	if sentAfter != 500 || recvAfter != 600 {
		t.Fatalf("expected global totals to remain 500/600 after user reset; got %d/%d", sentAfter, recvAfter)
	}

	// Delete user
	if err := s.DeleteUser(ctx, uid); err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	// Global totals must still NOT change after user deletion
	sentAfterDelete, recvAfterDelete, err := s.GetGlobalUsageTotals(ctx, day.Add(-time.Hour))
	if err != nil {
		t.Fatalf("GetGlobalUsageTotals after delete failed: %v", err)
	}
	if sentAfterDelete != 500 || recvAfterDelete != 600 {
		t.Fatalf("expected global totals to remain 500/600 after user delete; got %d/%d", sentAfterDelete, recvAfterDelete)
	}
}
