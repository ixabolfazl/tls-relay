package catalog

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestChecker_SuccessAndCache(t *testing.T) {
	var hits atomic.Int64
	validJSON := `{
		"version": 2,
		"updated_at": "2026-10-01",
		"categories": [
			{
				"id": "cat1",
				"name": "Cat 1",
				"subcategories": [
					{
						"id": "cat1.sub1",
						"name": "Sub 1",
						"domains": [{"domain": "example.com"}]
					}
				]
			}
		]
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validJSON))
	}))
	defer ts.Close()

	c := NewChecker(
		WithURL(ts.URL),
		WithHTTPClient(ts.Client()),
		WithCacheTTL(1*time.Hour),
	)

	ctx := context.Background()
	cat1, err := c.Latest(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cat1.Version != 2 {
		t.Errorf("expected version 2, got %d", cat1.Version)
	}
	if hits.Load() != 1 {
		t.Errorf("expected 1 hit, got %d", hits.Load())
	}

	// Immediate second call should hit cache
	cat2, err := c.Latest(ctx)
	if err != nil {
		t.Fatalf("unexpected error on cached call: %v", err)
	}
	if cat2.Version != 2 {
		t.Errorf("expected version 2, got %d", cat2.Version)
	}
	if hits.Load() != 1 {
		t.Errorf("expected still 1 hit due to cache, got %d", hits.Load())
	}

	// Force refresh should bypass cache
	cat3, err := c.ForceRefresh(ctx)
	if err != nil {
		t.Fatalf("unexpected error on force refresh: %v", err)
	}
	if cat3.Version != 2 {
		t.Errorf("expected version 2, got %d", cat3.Version)
	}
	if hits.Load() != 2 {
		t.Errorf("expected 2 hits after force refresh, got %d", hits.Load())
	}
}

func TestChecker_Non200AndStaleFallback(t *testing.T) {
	var statusCode atomic.Int32
	statusCode.Store(http.StatusOK)

	validJSON := `{
		"version": 1,
		"categories": [
			{
				"id": "cat1",
				"name": "Cat 1",
				"subcategories": [
					{
						"id": "cat1.sub1",
						"name": "Sub 1",
						"domains": [{"domain": "example.com"}]
					}
				]
			}
		]
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := int(statusCode.Load())
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(validJSON))
		} else {
			_, _ = w.Write([]byte("error"))
		}
	}))
	defer ts.Close()

	c := NewChecker(
		WithURL(ts.URL),
		WithHTTPClient(ts.Client()),
		WithCacheTTL(10*time.Millisecond),
		WithFailureTTL(10*time.Millisecond),
	)

	ctx := context.Background()
	// First fetch succeeds
	cat1, err := c.Latest(ctx)
	if err != nil {
		t.Fatalf("initial fetch failed: %v", err)
	}
	if cat1.Version != 1 {
		t.Fatalf("expected version 1, got %d", cat1.Version)
	}

	// Now make server fail
	statusCode.Store(http.StatusInternalServerError)
	time.Sleep(15 * time.Millisecond) // expire cache

	// Should fallback to stale catalog
	cat2, err := c.Latest(ctx)
	if cat2 == nil {
		t.Fatalf("expected stale catalog fallback, got nil")
	}
	if cat2.Version != 1 {
		t.Errorf("expected stale version 1, got %d", cat2.Version)
	}
}

func TestChecker_OversizeBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write more than 5 MB
		big := strings.Repeat("x", MaxInputBytes+100)
		_, _ = fmt.Fprint(w, big)
	}))
	defer ts.Close()

	c := NewChecker(
		WithURL(ts.URL),
		WithHTTPClient(ts.Client()),
	)

	_, err := c.Latest(context.Background())
	if err == nil {
		t.Fatalf("expected error for oversize response, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestChecker_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer ts.Close()

	c := NewChecker(
		WithURL(ts.URL),
		WithHTTPClient(ts.Client()),
	)

	_, err := c.Latest(context.Background())
	if err == nil {
		t.Fatalf("expected error for invalid json, got nil")
	}
}
