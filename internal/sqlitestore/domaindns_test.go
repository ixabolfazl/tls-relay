package sqlitestore_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

func TestDomainDNSUsage_IncrementAndQueries(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	day1 := time.Date(2026, 2, 10, 10, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 2, 11, 14, 0, 0, 0, time.UTC)

	// Increment queries for example.com and api.example.com
	if err := s.IncrementDomainDNSUsage(ctx, "example.com", day1, 5); err != nil {
		t.Fatalf("IncrementDomainDNSUsage day1: %v", err)
	}
	if err := s.IncrementDomainDNSUsage(ctx, "example.com", day1, 3); err != nil {
		t.Fatalf("IncrementDomainDNSUsage day1 2nd: %v", err)
	}
	if err := s.IncrementDomainDNSUsage(ctx, "example.com", day2, 12); err != nil {
		t.Fatalf("IncrementDomainDNSUsage day2: %v", err)
	}
	if err := s.IncrementDomainDNSUsage(ctx, "api.example.com", day1, 7); err != nil {
		t.Fatalf("IncrementDomainDNSUsage api day1: %v", err)
	}

	// 1. GetDomainDNSUsageDaily for example.com
	daily, err := s.GetDomainDNSUsageDaily(ctx, "example.com", day1)
	if err != nil {
		t.Fatalf("GetDomainDNSUsageDaily: %v", err)
	}
	if len(daily) != 2 {
		t.Fatalf("expected 2 daily rows, got %d", len(daily))
	}
	if daily[0].Date != "2026-02-10" || daily[0].QueryCount != 8 {
		t.Errorf("day 1 got %+v, want date 2026-02-10 count 8", daily[0])
	}
	if daily[1].Date != "2026-02-11" || daily[1].QueryCount != 12 {
		t.Errorf("day 2 got %+v, want date 2026-02-11 count 12", daily[1])
	}

	// Range filter: only day2
	dailyDay2, err := s.GetDomainDNSUsageDaily(ctx, "example.com", day2)
	if err != nil {
		t.Fatalf("GetDomainDNSUsageDaily day2: %v", err)
	}
	if len(dailyDay2) != 1 || dailyDay2[0].QueryCount != 12 {
		t.Errorf("expected 1 row with 12 queries for day2, got %+v", dailyDay2)
	}

	// 2. GetDomainDNSUsageTotal
	totAll, err := s.GetDomainDNSUsageTotal(ctx, "example.com", time.Time{})
	if err != nil {
		t.Fatalf("GetDomainDNSUsageTotal: %v", err)
	}
	if totAll != 20 {
		t.Errorf("expected total 20 queries, got %d", totAll)
	}

	totSinceDay2, err := s.GetDomainDNSUsageTotal(ctx, "example.com", day2)
	if err != nil {
		t.Fatalf("GetDomainDNSUsageTotal day2: %v", err)
	}
	if totSinceDay2 != 12 {
		t.Errorf("expected total 12 queries for day2, got %d", totSinceDay2)
	}

	// 3. ListDomainsDNSTotals
	allTotals, err := s.ListDomainsDNSTotals(ctx, time.Time{})
	if err != nil {
		t.Fatalf("ListDomainsDNSTotals: %v", err)
	}
	if allTotals["example.com"] != 20 {
		t.Errorf("expected 20 queries for example.com, got %d", allTotals["example.com"])
	}
	if allTotals["api.example.com"] != 7 {
		t.Errorf("expected 7 queries for api.example.com, got %d", allTotals["api.example.com"])
	}

	// Filtered ListDomainsDNSTotals
	sinceTotals, err := s.ListDomainsDNSTotals(ctx, day2)
	if err != nil {
		t.Fatalf("ListDomainsDNSTotals filtered: %v", err)
	}
	if sinceTotals["example.com"] != 12 {
		t.Errorf("expected 12 for example.com since day2, got %d", sinceTotals["example.com"])
	}
	if _, ok := sinceTotals["api.example.com"]; ok {
		t.Errorf("api.example.com should not be in sinceTotals for day2")
	}
}

func TestDomainDNSUsage_MigrationIdempotency(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migrate.db")
	s, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("first sqlitestore.New: %v", err)
	}
	ctx := context.Background()

	day := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if err := s.IncrementDomainDNSUsage(ctx, "test.org", day, 42); err != nil {
		t.Fatalf("IncrementDomainDNSUsage: %v", err)
	}
	_ = s.Close()

	// Reopen same DB: calls migrate() again
	s2, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("second sqlitestore.New: %v", err)
	}
	defer s2.Close()

	tot, err := s2.GetDomainDNSUsageTotal(ctx, "test.org", time.Time{})
	if err != nil {
		t.Fatalf("GetDomainDNSUsageTotal after reopen: %v", err)
	}
	if tot != 42 {
		t.Errorf("expected 42 queries after reopen, got %d", tot)
	}
}

func TestDomainDNSUsage_PreservedOnDomainRuleDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.AddDomainRule(ctx, "ephemeral.com", "", "[443]", "default", "proxy"); err != nil {
		t.Fatalf("AddDomainRule: %v", err)
	}

	day := time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)
	if err := s.IncrementDomainDNSUsage(ctx, "ephemeral.com", day, 100); err != nil {
		t.Fatalf("IncrementDomainDNSUsage: %v", err)
	}

	// Delete domain rule
	if err := s.DeleteDomainRule(ctx, "ephemeral.com"); err != nil {
		t.Fatalf("DeleteDomainRule: %v", err)
	}

	// Historical usage must still exist
	tot, err := s.GetDomainDNSUsageTotal(ctx, "ephemeral.com", time.Time{})
	if err != nil {
		t.Fatalf("GetDomainDNSUsageTotal after delete: %v", err)
	}
	if tot != 100 {
		t.Errorf("expected 100 queries after rule deletion, got %d", tot)
	}
}
