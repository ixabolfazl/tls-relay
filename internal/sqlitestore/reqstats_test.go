package sqlitestore_test

import (
	"context"
	"testing"
	"time"
)

func TestRequestStats_AccumulateAndTotals(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	day1 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)

	_ = s.IncrementRequestStat(ctx, day1, "DNS", "authorized", 10)
	_ = s.IncrementRequestStat(ctx, day1, "DNS", "authorized", 5)
	_ = s.IncrementRequestStat(ctx, day1, "DNS", "unauthorized_passthrough", 3)
	_ = s.IncrementRequestStat(ctx, day2, "DNS", "authorized", 20)

	_ = s.IncrementRequestStat(ctx, day1, "TLS", "registered", 50)
	_ = s.IncrementRequestStat(ctx, day2, "TLS", "unregistered", 30)

	dnsTotals, err := s.GetRequestStatsTotals(ctx, "DNS")
	if err != nil {
		t.Fatalf("GetRequestStatsTotals DNS: %v", err)
	}
	if dnsTotals["authorized"] != 35 {
		t.Errorf("DNS authorized total got %d, want 35", dnsTotals["authorized"])
	}
	if dnsTotals["unauthorized_passthrough"] != 3 {
		t.Errorf("DNS passthrough total got %d, want 3", dnsTotals["unauthorized_passthrough"])
	}
	if dnsTotals["total"] != 38 {
		t.Errorf("DNS overall total got %d, want 38", dnsTotals["total"])
	}

	dailyDNS, err := s.GetRequestStatsDaily(ctx, "DNS", day1)
	if err != nil {
		t.Fatalf("GetRequestStatsDaily DNS: %v", err)
	}
	if len(dailyDNS) != 3 {
		t.Fatalf("expected 3 daily stat rows for DNS, got %d", len(dailyDNS))
	}
}

func TestRequestStats_IgnoreLegacyTotalCategory(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	day := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

	// Simulate legacy data with "total" category row inserted
	_ = s.IncrementRequestStat(ctx, day, "DNS", "authorized", 20)
	_ = s.IncrementRequestStat(ctx, day, "DNS", "blocked", 5)
	_ = s.IncrementRequestStat(ctx, day, "DNS", "total", 25) // legacy row

	totals, err := s.GetRequestStatsTotals(ctx, "DNS")
	if err != nil {
		t.Fatalf("GetRequestStatsTotals: %v", err)
	}

	// Grand total should be 20 + 5 = 25, not 50
	if totals["total"] != 25 {
		t.Errorf("expected grand total 25 without double-counting legacy 'total' row, got %d", totals["total"])
	}

	daily, err := s.GetRequestStatsDaily(ctx, "DNS", day)
	if err != nil {
		t.Fatalf("GetRequestStatsDaily: %v", err)
	}
	for _, row := range daily {
		if row.Category == "total" {
			t.Errorf("GetRequestStatsDaily should filter out 'total' category, but found row: %+v", row)
		}
	}
}
