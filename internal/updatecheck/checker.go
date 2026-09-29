// Package updatecheck provides release checking against GitHub releases with caching and semver comparison.
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Info holds version update status and release metadata.
type Info struct {
	CurrentVersion  string    `json:"current_version"`
	LatestVersion   string    `json:"latest_version"`
	UpdateAvailable bool      `json:"update_available"`
	ReleaseURL      string    `json:"release_url"`
	ReleaseNotesURL string    `json:"release_notes_url"`
	CheckedAt       time.Time `json:"checked_at"`
}

// Option configures Checker instances.
type Option func(*Checker)

// WithBaseURL overrides the GitHub API releases URL.
func WithBaseURL(url string) Option {
	return func(c *Checker) {
		c.apiURL = url
	}
}

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Checker) {
		c.httpClient = client
	}
}

// WithCacheTTL configures the success cache duration.
func WithCacheTTL(d time.Duration) Option {
	return func(c *Checker) {
		c.cacheTTL = d
	}
}

// WithFailureTTL configures the failure cache duration.
func WithFailureTTL(d time.Duration) Option {
	return func(c *Checker) {
		c.failureTTL = d
	}
}

// Checker manages cached queries for GitHub releases.
type Checker struct {
	mu             sync.RWMutex
	currentVersion string
	apiURL         string
	httpClient     *http.Client
	cacheTTL       time.Duration
	failureTTL     time.Duration

	lastSuccess time.Time
	cachedInfo  Info
	lastFailure time.Time
	lastErr     error

	sfg singleflight.Group
}

// NewChecker creates a new update checker.
func NewChecker(currentVersion string, opts ...Option) *Checker {
	c := &Checker{
		currentVersion: currentVersion,
		apiURL:         "https://api.github.com/repos/ixabolfazl/tls-relay/releases/latest",
		httpClient:     &http.Client{Timeout: 5 * time.Second},
		cacheTTL:       1 * time.Hour,
		failureTTL:     10 * time.Minute,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SetCurrentVersion updates the current running version string.
func (c *Checker) SetCurrentVersion(v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.currentVersion = v
}

// Latest returns the cached or freshly fetched update info.
func (c *Checker) Latest(ctx context.Context) (Info, error) {
	c.mu.RLock()
	now := time.Now()
	if !c.lastSuccess.IsZero() && now.Sub(c.lastSuccess) < c.cacheTTL {
		info := c.cachedInfo
		c.mu.RUnlock()
		return info, nil
	}
	if !c.lastFailure.IsZero() && now.Sub(c.lastFailure) < c.failureTTL {
		if !c.lastSuccess.IsZero() {
			info := c.cachedInfo
			c.mu.RUnlock()
			return info, nil
		}
		err := c.lastErr
		info := Info{CurrentVersion: c.currentVersion}
		c.mu.RUnlock()
		return info, err
	}
	c.mu.RUnlock()

	res, err, _ := c.sfg.Do("latest_release", func() (interface{}, error) {
		c.mu.RLock()
		if !c.lastSuccess.IsZero() && time.Since(c.lastSuccess) < c.cacheTTL {
			info := c.cachedInfo
			c.mu.RUnlock()
			return info, nil
		}
		c.mu.RUnlock()

		info, fetchErr := c.fetch(ctx)
		c.mu.Lock()
		defer c.mu.Unlock()
		if fetchErr != nil {
			c.lastFailure = time.Now()
			c.lastErr = fetchErr
			if !c.lastSuccess.IsZero() {
				return c.cachedInfo, nil
			}
			return Info{CurrentVersion: c.currentVersion}, fetchErr
		}

		c.lastSuccess = time.Now()
		c.cachedInfo = info
		c.lastFailure = time.Time{}
		c.lastErr = nil
		return info, nil
	})

	if err != nil {
		if info, ok := res.(Info); ok && info.CurrentVersion != "" {
			return info, err
		}
		return Info{CurrentVersion: c.currentVersion}, err
	}
	return res.(Info), nil
}

func (c *Checker) fetch(ctx context.Context) (Info, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL, nil)
	if err != nil {
		return Info{}, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("User-Agent", "tls-relay/"+c.currentVersion)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Info{}, fmt.Errorf("fetching latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Info{}, fmt.Errorf("unexpected status %d from github releases", resp.StatusCode)
	}

	var ghRelease struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ghRelease); err != nil {
		return Info{}, fmt.Errorf("decoding github release response: %w", err)
	}

	c.mu.RLock()
	curVer := c.currentVersion
	c.mu.RUnlock()

	updateAvailable := IsNewer(curVer, ghRelease.TagName)

	return Info{
		CurrentVersion:  curVer,
		LatestVersion:   ghRelease.TagName,
		UpdateAvailable: updateAvailable,
		ReleaseURL:      ghRelease.HTMLURL,
		ReleaseNotesURL: ghRelease.HTMLURL,
		CheckedAt:       time.Now().UTC(),
	}, nil
}

// ParseSemver parses a semver string like "v1.4.0" or "1.4.0" into major, minor, patch.
// Returns ok=false for "dev", invalid formats, or non-numeric components.
func ParseSemver(s string) (major, minor, patch int, ok bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" || strings.EqualFold(s, "dev") || strings.EqualFold(s, "none") || strings.EqualFold(s, "unknown") {
		return 0, 0, 0, false
	}

	// Strip pre-release or build metadata (-rc1, +build)
	if idx := strings.IndexAny(s, "-+"); idx != -1 {
		s = s[:idx]
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}

	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	pat, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || maj < 0 || min < 0 || pat < 0 {
		return 0, 0, 0, false
	}

	return maj, min, pat, true
}

// IsNewer compares current and latest semver strings.
// Returns true if latest is strictly newer than current.
// Returns false if current or latest is unparsable (e.g. "dev").
func IsNewer(current, latest string) bool {
	curMaj, curMin, curPat, okCur := ParseSemver(current)
	if !okCur {
		return false
	}
	latMaj, latMin, latPat, okLat := ParseSemver(latest)
	if !okLat {
		return false
	}

	if latMaj > curMaj {
		return true
	}
	if latMaj < curMaj {
		return false
	}
	if latMin > curMin {
		return true
	}
	if latMin < curMin {
		return false
	}
	return latPat > curPat
}
