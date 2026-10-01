package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	DefaultCatalogURL = "https://raw.githubusercontent.com/ixabolfazl/tls-relay/main/data/default-domains.json"
	DefaultTimeout    = 10 * time.Second
)

// Option configures Checker instances.
type Option func(*Checker)

// WithURL overrides the remote catalog URL.
func WithURL(url string) Option {
	return func(c *Checker) {
		c.url = url
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

// Checker manages cached queries for the remote default domains catalog.
type Checker struct {
	mu         sync.RWMutex
	url        string
	httpClient *http.Client
	cacheTTL   time.Duration
	failureTTL time.Duration

	lastSuccess   time.Time
	cachedCatalog *Catalog
	lastFailure   time.Time
	lastErr       error

	sfg singleflight.Group
}

// NewChecker creates a new catalog update checker.
func NewChecker(opts ...Option) *Checker {
	c := &Checker{
		url:        DefaultCatalogURL,
		httpClient: &http.Client{Timeout: DefaultTimeout},
		cacheTTL:   1 * time.Hour,
		failureTTL: 10 * time.Minute,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SetHTTPClient updates the HTTP client (e.g. when egress proxy configuration changes).
func (c *Checker) SetHTTPClient(client *http.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.httpClient = client
}

// Cached returns the currently cached catalog and error without network calls.
func (c *Checker) Cached() (*Catalog, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cachedCatalog, c.lastErr
}

// Latest returns the cached or freshly fetched remote catalog.
func (c *Checker) Latest(ctx context.Context) (*Catalog, error) {
	return c.get(ctx, false)
}

// ForceRefresh bypasses the cache and forces a fetch from GitHub.
func (c *Checker) ForceRefresh(ctx context.Context) (*Catalog, error) {
	return c.get(ctx, true)
}

func (c *Checker) get(ctx context.Context, force bool) (*Catalog, error) {
	now := time.Now()
	if !force {
		c.mu.RLock()
		if c.cachedCatalog != nil && !c.lastSuccess.IsZero() && now.Sub(c.lastSuccess) < c.cacheTTL {
			cat := c.cachedCatalog
			c.mu.RUnlock()
			return cat, nil
		}
		if !c.lastFailure.IsZero() && now.Sub(c.lastFailure) < c.failureTTL {
			if c.cachedCatalog != nil {
				cat := c.cachedCatalog
				c.mu.RUnlock()
				return cat, nil
			}
			err := c.lastErr
			c.mu.RUnlock()
			return nil, err
		}
		c.mu.RUnlock()
	}

	key := "fetch_catalog"
	if force {
		key = fmt.Sprintf("fetch_catalog_force_%d", now.UnixNano())
	}

	res, err, _ := c.sfg.Do(key, func() (interface{}, error) {
		if !force {
			c.mu.RLock()
			if c.cachedCatalog != nil && !c.lastSuccess.IsZero() && time.Since(c.lastSuccess) < c.cacheTTL {
				cat := c.cachedCatalog
				c.mu.RUnlock()
				return cat, nil
			}
			c.mu.RUnlock()
		}

		cat, fetchErr := c.fetch(ctx)
		c.mu.Lock()
		defer c.mu.Unlock()
		if fetchErr != nil {
			c.lastFailure = time.Now()
			c.lastErr = fetchErr
			if c.cachedCatalog != nil {
				// Stale fallback
				return c.cachedCatalog, nil
			}
			return nil, fetchErr
		}

		c.lastSuccess = time.Now()
		c.cachedCatalog = cat
		c.lastFailure = time.Time{}
		c.lastErr = nil
		return cat, nil
	})

	if err != nil {
		if cat, ok := res.(*Catalog); ok && cat != nil {
			return cat, err
		}
		return nil, err
	}
	if cat, ok := res.(*Catalog); ok {
		return cat, nil
	}
	return nil, errors.New("unexpected result from catalog fetch")
}

func (c *Checker) fetch(ctx context.Context) (*Catalog, error) {
	c.mu.RLock()
	client := c.httpClient
	fetchURL := c.url
	c.mu.RUnlock()

	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}

	reqCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("User-Agent", "tls-relay-catalog-checker")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d from catalog source", resp.StatusCode)
	}

	lr := io.LimitReader(resp.Body, MaxInputBytes+1)
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("reading catalog body: %w", err)
	}

	if len(body) > MaxInputBytes {
		return nil, fmt.Errorf("remote catalog exceeds maximum size of %d bytes", MaxInputBytes)
	}

	cat, err := Parse(body)
	if err != nil {
		return nil, fmt.Errorf("parsing remote catalog: %w", err)
	}

	return cat, nil
}
