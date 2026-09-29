package updatecheck_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/updatecheck"
)

func TestSemverComparison(t *testing.T) {
	tests := []struct {
		current  string
		latest   string
		expected bool
	}{
		{"v1.3.0", "v1.4.0", true},
		{"1.3.0", "v1.4.0", true},
		{"v1.3.0", "1.3.1", true},
		{"v1.3.0", "v1.3.0", false},
		{"v1.4.0", "v1.3.0", false},
		{"1.4.0", "1.4.0", false},
		{"v2.0.0", "v1.9.9", false},
		{"v1.3.0-rc1", "v1.3.1", true},
		{"dev", "v1.4.0", false},
		{"none", "v1.4.0", false},
		{"unknown", "v1.4.0", false},
		{"", "v1.4.0", false},
		{"v1.3.0", "invalid", false},
		{"custom", "v1.4.0", false},
	}

	for _, tt := range tests {
		got := updatecheck.IsNewer(tt.current, tt.latest)
		if got != tt.expected {
			t.Errorf("IsNewer(%q, %q) = %v; want %v", tt.current, tt.latest, got, tt.expected)
		}
	}
}

func TestChecker_ReportsUpdateWhenNewerReleaseExists(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("expected Accept application/vnd.github+json, got %q", r.Header.Get("Accept"))
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tag_name": "v1.4.0",
			"html_url": "https://github.com/ixabolfazl/tls-relay/releases/tag/v1.4.0",
		})
	}))
	defer server.Close()

	checker := updatecheck.NewChecker("v1.3.0",
		updatecheck.WithBaseURL(server.URL),
		updatecheck.WithHTTPClient(server.Client()),
	)

	info, err := checker.Latest(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !info.UpdateAvailable {
		t.Errorf("expected UpdateAvailable = true, got false")
	}
	if info.LatestVersion != "v1.4.0" {
		t.Errorf("expected LatestVersion = v1.4.0, got %q", info.LatestVersion)
	}
	if info.CurrentVersion != "v1.3.0" {
		t.Errorf("expected CurrentVersion = v1.3.0, got %q", info.CurrentVersion)
	}
	if info.ReleaseURL != "https://github.com/ixabolfazl/tls-relay/releases/tag/v1.4.0" {
		t.Errorf("unexpected ReleaseURL: %q", info.ReleaseURL)
	}
}

func TestChecker_UpToDateDoesNotReportUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tag_name": "v1.3.0",
			"html_url": "https://github.com/ixabolfazl/tls-relay/releases/tag/v1.3.0",
		})
	}))
	defer server.Close()

	checker := updatecheck.NewChecker("v1.3.0",
		updatecheck.WithBaseURL(server.URL),
		updatecheck.WithHTTPClient(server.Client()),
	)

	info, err := checker.Latest(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.UpdateAvailable {
		t.Errorf("expected UpdateAvailable = false when on same version, got true")
	}
}

func TestChecker_DevVersionNeverReportsUpdate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tag_name": "v99.0.0",
			"html_url": "https://github.com/ixabolfazl/tls-relay/releases/tag/v99.0.0",
		})
	}))
	defer server.Close()

	checker := updatecheck.NewChecker("dev",
		updatecheck.WithBaseURL(server.URL),
		updatecheck.WithHTTPClient(server.Client()),
	)

	info, err := checker.Latest(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.UpdateAvailable {
		t.Errorf("expected UpdateAvailable = false for dev version, got true")
	}
}

func TestChecker_CachesSuccessfulResult(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tag_name": "v1.4.0",
			"html_url": "https://github.com/example/release",
		})
	}))
	defer server.Close()

	checker := updatecheck.NewChecker("v1.3.0",
		updatecheck.WithBaseURL(server.URL),
		updatecheck.WithHTTPClient(server.Client()),
		updatecheck.WithCacheTTL(1*time.Hour),
	)

	// Multiple calls in parallel
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := checker.Latest(context.Background())
			if err != nil || !info.UpdateAvailable {
				t.Errorf("call failed or not available: %v, %v", info, err)
			}
		}()
	}
	wg.Wait()

	if count := requestCount.Load(); count != 1 {
		t.Errorf("expected exactly 1 outbound request due to caching/singleflight, got %d", count)
	}
}

func TestChecker_FallsBackToStaleOnFailure(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tag_name": "v1.4.0",
			"html_url": "https://github.com/example/release",
		})
	}))
	defer server.Close()

	checker := updatecheck.NewChecker("v1.3.0",
		updatecheck.WithBaseURL(server.URL),
		updatecheck.WithHTTPClient(server.Client()),
		updatecheck.WithCacheTTL(10*time.Millisecond),
		updatecheck.WithFailureTTL(10*time.Minute),
	)

	// Initial good call
	info1, err := checker.Latest(context.Background())
	if err != nil || !info1.UpdateAvailable {
		t.Fatalf("first call failed: %v", err)
	}

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

	// Now fail network
	fail.Store(true)

	// Second call should return the stale good result without error
	info2, err := checker.Latest(context.Background())
	if err != nil {
		t.Fatalf("expected stale fallback without error, got %v", err)
	}
	if info2.LatestVersion != "v1.4.0" {
		t.Errorf("expected stale version v1.4.0, got %q", info2.LatestVersion)
	}
}
