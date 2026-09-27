package sqlitestore_test

import (
	"context"
	"testing"
	"time"
)

func TestDomainUsage_IncrementAndQueries(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Add domain rule for test
	err := s.AddDomainRule(ctx, "example.com", "", "[443]", "default", "proxy")
	if err != nil {
		t.Fatalf("AddDomainRule: %v", err)
	}

	day1 := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 1, 16, 12, 0, 0, 0, time.UTC)

	// Increment domain usage on day1
	if err := s.IncrementDomainUsage(ctx, "example.com", 100, 200, day1); err != nil {
		t.Fatalf("IncrementDomainUsage day1: %v", err)
	}
	if err := s.IncrementDomainUsage(ctx, "example.com", 50, 50, day1); err != nil {
		t.Fatalf("IncrementDomainUsage day1 second: %v", err)
	}

	// Increment on day2
	if err := s.IncrementDomainUsage(ctx, "example.com", 500, 1000, day2); err != nil {
		t.Fatalf("IncrementDomainUsage day2: %v", err)
	}

	// Check domain_rules total usage
	totals, err := s.ListDomainsTotalUsage(ctx, time.Time{})
	if err != nil {
		t.Fatalf("ListDomainsTotalUsage: %v", err)
	}
	tot, ok := totals["example.com"]
	if !ok {
		t.Fatal("example.com not found in totals")
	}
	if tot.BytesSent != 650 || tot.BytesReceived != 1250 {
		t.Errorf("domain total usage got sent=%d received=%d, want 650/1250", tot.BytesSent, tot.BytesReceived)
	}

	// Check daily usage
	dailyRows, err := s.GetDomainUsageDaily(ctx, "example.com", day1)
	if err != nil {
		t.Fatalf("GetDomainUsageDaily: %v", err)
	}
	if len(dailyRows) != 2 {
		t.Fatalf("expected 2 daily rows, got %d", len(dailyRows))
	}
	if dailyRows[0].Date != "2026-01-15" || dailyRows[0].BytesSent != 150 || dailyRows[0].BytesReceived != 250 {
		t.Errorf("dailyRow 0 got %+v, want date 2026-01-15, sent 150, received 250", dailyRows[0])
	}
	if dailyRows[1].Date != "2026-01-16" || dailyRows[1].BytesSent != 500 || dailyRows[1].BytesReceived != 1000 {
		t.Errorf("dailyRow 1 got %+v, want date 2026-01-16, sent 500, received 1000", dailyRows[1])
	}
}

func TestDomainUsage_NonExistentRuleToleratedAndSurvivesDeletion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	day := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)

	// Increment usage for a domain that doesn't exist in domain_rules
	if err := s.IncrementDomainUsage(ctx, "nonexistent.com", 300, 400, day); err != nil {
		t.Fatalf("IncrementDomainUsage on non-existent domain: %v", err)
	}

	daily, err := s.GetDomainUsageDaily(ctx, "nonexistent.com", day)
	if err != nil {
		t.Fatalf("GetDomainUsageDaily: %v", err)
	}
	if len(daily) != 1 || daily[0].BytesSent != 300 || daily[0].BytesReceived != 400 {
		t.Errorf("daily usage for nonexistent domain got %+v", daily)
	}

	// Now create a rule, increment usage, then delete the rule
	if err := s.AddDomainRule(ctx, "to-delete.com", "", "[443]", "default", "proxy"); err != nil {
		t.Fatalf("AddDomainRule: %v", err)
	}
	if err := s.IncrementDomainUsage(ctx, "to-delete.com", 1000, 2000, day); err != nil {
		t.Fatalf("IncrementDomainUsage: %v", err)
	}

	// Delete rule
	if err := s.DeleteDomainRule(ctx, "to-delete.com"); err != nil {
		t.Fatalf("DeleteDomainRule: %v", err)
	}

	// Verify historical daily usage still queryable
	daily, err = s.GetDomainUsageDaily(ctx, "to-delete.com", day)
	if err != nil {
		t.Fatalf("GetDomainUsageDaily after deletion: %v", err)
	}
	if len(daily) != 1 || daily[0].BytesSent != 1000 || daily[0].BytesReceived != 2000 {
		t.Errorf("historical usage after deletion got %+v, want 1000/2000", daily)
	}
}

func TestUserDomainUsage_IncrementAndAggregations(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u1 := newUsageTestUser(t, s, "user1")
	u2 := newUsageTestUser(t, s, "user2")

	day1 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)

	// User 1 visits domain A and B
	if err := s.IncrementUserDomainUsage(ctx, u1, "domainA.com", 100, 200, day1); err != nil {
		t.Fatalf("IncrementUserDomainUsage u1 A day1: %v", err)
	}
	if err := s.IncrementUserDomainUsage(ctx, u1, "domainA.com", 50, 50, day1); err != nil {
		t.Fatalf("IncrementUserDomainUsage u1 A day1 second: %v", err)
	}
	if err := s.IncrementUserDomainUsage(ctx, u1, "domainB.com", 300, 400, day2); err != nil {
		t.Fatalf("IncrementUserDomainUsage u1 B day2: %v", err)
	}

	// User 2 visits domain A
	if err := s.IncrementUserDomainUsage(ctx, u2, "domainA.com", 1000, 2000, day1); err != nil {
		t.Fatalf("IncrementUserDomainUsage u2 A day1: %v", err)
	}

	// GetUserDomainUsageDaily for u1 on domainA.com
	daily, err := s.GetUserDomainUsageDaily(ctx, u1, "domainA.com", day1)
	if err != nil {
		t.Fatalf("GetUserDomainUsageDaily: %v", err)
	}
	if len(daily) != 1 || daily[0].BytesSent != 150 || daily[0].BytesReceived != 250 {
		t.Errorf("GetUserDomainUsageDaily got %+v, want sent 150, received 250", daily)
	}

	// GetUserDomainUsageTotal
	sSent, sRec, err := s.GetUserDomainUsageTotal(ctx, u1, "domainA.com")
	if err != nil {
		t.Fatalf("GetUserDomainUsageTotal: %v", err)
	}
	if sSent != 150 || sRec != 250 {
		t.Errorf("GetUserDomainUsageTotal got %d/%d, want 150/250", sSent, sRec)
	}

	// ListUserUsageByDomain for u1
	byDom, err := s.ListUserUsageByDomain(ctx, u1)
	if err != nil {
		t.Fatalf("ListUserUsageByDomain: %v", err)
	}
	if len(byDom) != 2 {
		t.Fatalf("expected 2 domain rows for u1, got %d", len(byDom))
	}
	// Ordered by total bytes DESC (domainB = 700, domainA = 400)
	if byDom[0].Domain != "domainB.com" || byDom[0].BytesSent != 300 || byDom[0].BytesReceived != 400 {
		t.Errorf("byDom[0] got %+v, want domainB.com (300/400)", byDom[0])
	}
	if byDom[1].Domain != "domainA.com" || byDom[1].BytesSent != 150 || byDom[1].BytesReceived != 250 {
		t.Errorf("byDom[1] got %+v, want domainA.com (150/250)", byDom[1])
	}

	// ListDomainUsageByUser for domainA.com
	byUser, err := s.ListDomainUsageByUser(ctx, "domainA.com")
	if err != nil {
		t.Fatalf("ListDomainUsageByUser: %v", err)
	}
	if len(byUser) != 2 {
		t.Fatalf("expected 2 user rows for domainA.com, got %d", len(byUser))
	}
	// Ordered by total DESC (u2 total 3000, u1 total 400)
	if byUser[0].UserID != u2 || byUser[0].Username != "user2" || byUser[0].BytesSent != 1000 || byUser[0].BytesReceived != 2000 {
		t.Errorf("byUser[0] got %+v, want user2 (1000/2000)", byUser[0])
	}
	if byUser[1].UserID != u1 || byUser[1].Username != "user1" || byUser[1].BytesSent != 150 || byUser[1].BytesReceived != 250 {
		t.Errorf("byUser[1] got %+v, want user1 (150/250)", byUser[1])
	}
}

func TestDomainUsage_MonthlyAggregationAcrossMonthBoundary(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	d1 := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	d2 := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	d3 := time.Date(2026, 2, 5, 0, 0, 0, 0, time.UTC)

	_ = s.IncrementDomainUsage(ctx, "monthly.com", 100, 100, d1)
	_ = s.IncrementDomainUsage(ctx, "monthly.com", 200, 200, d2)
	_ = s.IncrementDomainUsage(ctx, "monthly.com", 500, 500, d3)

	monthly, err := s.GetDomainUsageMonthly(ctx, "monthly.com", d1)
	if err != nil {
		t.Fatalf("GetDomainUsageMonthly: %v", err)
	}
	if len(monthly) != 2 {
		t.Fatalf("expected 2 monthly rows, got %d", len(monthly))
	}
	if monthly[0].Month != "2026-01" || monthly[0].BytesSent != 300 || monthly[0].BytesReceived != 300 {
		t.Errorf("month 0 got %+v, want 2026-01 (300/300)", monthly[0])
	}
	if monthly[1].Month != "2026-02" || monthly[1].BytesSent != 500 || monthly[1].BytesReceived != 500 {
		t.Errorf("month 1 got %+v, want 2026-02 (500/500)", monthly[1])
	}
}

func TestUserDomainUsage_SinceDateFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u1 := newUsageTestUser(t, s, "filterUser")

	dayOld := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dayToday := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

	_ = s.IncrementUserDomainUsage(ctx, u1, "old-domain.com", 1000, 1000, dayOld)
	_ = s.IncrementUserDomainUsage(ctx, u1, "today-domain.com", 500, 500, dayToday)

	// All time (no filter)
	allDomains, err := s.ListUserUsageByDomain(ctx, u1)
	if err != nil {
		t.Fatalf("ListUserUsageByDomain all: %v", err)
	}
	if len(allDomains) != 2 {
		t.Fatalf("expected 2 domains all-time, got %d", len(allDomains))
	}

	// Filtered by today
	todayDomains, err := s.ListUserUsageByDomain(ctx, u1, dayToday)
	if err != nil {
		t.Fatalf("ListUserUsageByDomain filtered: %v", err)
	}
	if len(todayDomains) != 1 {
		t.Fatalf("expected 1 domain for today filter, got %d", len(todayDomains))
	}
	if todayDomains[0].Domain != "today-domain.com" {
		t.Errorf("expected today-domain.com, got %s", todayDomains[0].Domain)
	}
}
