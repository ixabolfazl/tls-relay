package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/ixabolfazl/tls-relay/data"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

const (
	MaxInputBytes = 5 * 1024 * 1024 // 5 MB
	MaxDomains    = 20000
	MaxNameRunes  = 64
)

var idRegex = regexp.MustCompile(`^[a-z0-9._-]+$`)

// DomainItem represents a single domain entry in a subcategory.
type DomainItem struct {
	Domain   string          `json:"domain"`
	Wildcard bool            `json:"wildcard,omitempty"`
	Mode     string          `json:"mode,omitempty"`
	Ports    json.RawMessage `json:"ports,omitempty"`
}

// Subcategory represents a subcategory under a category.
type Subcategory struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	DefaultEnabled *bool        `json:"default_enabled,omitempty"`
	Domains        []DomainItem `json:"domains"`
}

// Category represents a top-level category in the catalog.
type Category struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	DefaultEnabled *bool         `json:"default_enabled,omitempty"`
	Subcategories  []Subcategory `json:"subcategories"`
}

// Catalog represents the full default domains catalog.
type Catalog struct {
	Version    int        `json:"version"`
	UpdatedAt  string     `json:"updated_at,omitempty"`
	Categories []Category `json:"categories"`
}

// ExpandedDomain represents a single domain rule expanded from the catalog.
type ExpandedDomain struct {
	Domain          string
	SubcategoryID   string
	SubcategoryName string
	CategoryID      string
	CategoryName    string
	Mode            string
	Ports           string // JSON string representation, e.g. "[443]" or "\"all\""
	DefaultEnabled  bool
}

// SanitizeName strips control characters (<0x20, 0x7f), trims whitespace,
// and limits the name to at most 64 runes (matching sqlitestore.SanitizeGroupName semantics).
func SanitizeName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	cleaned := strings.TrimSpace(b.String())
	runes := []rune(cleaned)
	if len(runes) > MaxNameRunes {
		runes = runes[:MaxNameRunes]
	}
	return string(runes)
}

// IsDefaultEnabled returns the boolean value of b, defaulting to true if b is nil.
func IsDefaultEnabled(b *bool) bool {
	if b == nil {
		return true
	}
	return *b
}

// ParsePorts validates and formats raw ports JSON into canonical JSON ("[443]" or "\"all\"").
func ParsePorts(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "[443]", nil
	}
	// Try parsing as string (e.g. "all", "443", "[443]")
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		ps, err := rules.ParsePorts(s)
		if err != nil {
			return "", err
		}
		b, err := ps.MarshalJSON()
		return string(b), err
	}
	// Try parsing as []int
	var ports []int
	if err := json.Unmarshal(raw, &ports); err == nil {
		if len(ports) == 0 {
			return "", errors.New("ports array cannot be empty")
		}
		for _, p := range ports {
			if p <= 0 || p > 65535 {
				return "", fmt.Errorf("invalid port %d", p)
			}
		}
		ps := rules.PortsSpec{Ports: ports}
		b, err := ps.MarshalJSON()
		return string(b), err
	}
	return "", errors.New("invalid ports format: expected array of ints or \"all\"")
}

// Parse parses and strictly validates catalog JSON data.
func Parse(data []byte) (*Catalog, error) {
	if len(data) > MaxInputBytes {
		return nil, fmt.Errorf("catalog exceeds maximum size of %d bytes", MaxInputBytes)
	}

	var cat Catalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil, fmt.Errorf("decoding catalog JSON: %w", err)
	}

	if cat.Version <= 0 {
		return nil, fmt.Errorf("version must be a positive integer, got %d", cat.Version)
	}

	categoryIDs := make(map[string]struct{})
	subcategoryIDs := make(map[string]struct{})
	seenDomains := make(map[string]string) // normalized domain -> subcategory id
	totalDomains := 0

	for i := range cat.Categories {
		category := &cat.Categories[i]
		if !idRegex.MatchString(category.ID) {
			return nil, fmt.Errorf("invalid category id %q", category.ID)
		}
		if _, exists := categoryIDs[category.ID]; exists {
			return nil, fmt.Errorf("duplicate category id %q", category.ID)
		}
		categoryIDs[category.ID] = struct{}{}

		if utf8.RuneCountInString(category.Name) > MaxNameRunes {
			return nil, fmt.Errorf("category name %q exceeds maximum length of %d runes", category.Name, MaxNameRunes)
		}
		category.Name = SanitizeName(category.Name)
		if category.Name == "" {
			return nil, fmt.Errorf("category %q has empty name", category.ID)
		}

		for j := range category.Subcategories {
			subcategory := &category.Subcategories[j]
			expectedPrefix := category.ID + "."
			if !strings.HasPrefix(subcategory.ID, expectedPrefix) {
				return nil, fmt.Errorf("subcategory id %q must start with prefix %q", subcategory.ID, expectedPrefix)
			}
			slug := strings.TrimPrefix(subcategory.ID, expectedPrefix)
			if !idRegex.MatchString(slug) || slug == "" {
				return nil, fmt.Errorf("invalid subcategory slug in %q", subcategory.ID)
			}
			if _, exists := subcategoryIDs[subcategory.ID]; exists {
				return nil, fmt.Errorf("duplicate subcategory id %q", subcategory.ID)
			}
			subcategoryIDs[subcategory.ID] = struct{}{}

			if utf8.RuneCountInString(subcategory.Name) > MaxNameRunes {
				return nil, fmt.Errorf("subcategory name %q exceeds maximum length of %d runes", subcategory.Name, MaxNameRunes)
			}
			subcategory.Name = SanitizeName(subcategory.Name)
			if subcategory.Name == "" {
				return nil, fmt.Errorf("subcategory %q has empty name", subcategory.ID)
			}

			for k := range subcategory.Domains {
				item := &subcategory.Domains[k]
				totalDomains++
				if totalDomains > MaxDomains {
					return nil, fmt.Errorf("catalog exceeds maximum domain limit of %d", MaxDomains)
				}

				normDomain, err := rules.NormalizeDomainInput(item.Domain)
				if err != nil {
					return nil, fmt.Errorf("invalid domain %q in subcategory %q: %w", item.Domain, subcategory.ID, err)
				}

				normBase := strings.TrimPrefix(normDomain, "*.")
				if prevSub, exists := seenDomains[normBase]; exists {
					return nil, fmt.Errorf("domain %q in subcategory %q is duplicated from %q", normBase, subcategory.ID, prevSub)
				}
				seenDomains[normBase] = subcategory.ID

				mode, err := rules.NormalizeMode(item.Mode)
				if err != nil {
					return nil, fmt.Errorf("invalid mode %q for domain %q in subcategory %q: %w", item.Mode, item.Domain, subcategory.ID, err)
				}
				item.Mode = mode

				if _, err := ParsePorts(item.Ports); err != nil {
					return nil, fmt.Errorf("invalid ports for domain %q in subcategory %q: %w", item.Domain, subcategory.ID, err)
				}
			}
		}
	}

	return &cat, nil
}

// Expand flattens the catalog into a slice of ExpandedDomain entries.
// Domains with wildcard: true produce both the base domain and "*.baseDomain".
func Expand(cat *Catalog) []ExpandedDomain {
	if cat == nil {
		return nil
	}
	var out []ExpandedDomain
	for _, c := range cat.Categories {
		cEnabled := IsDefaultEnabled(c.DefaultEnabled)
		for _, s := range c.Subcategories {
			sEnabled := IsDefaultEnabled(s.DefaultEnabled)
			effectiveEnabled := cEnabled && sEnabled

			for _, d := range s.Domains {
				normDomain, err := rules.NormalizeDomainInput(d.Domain)
				if err != nil {
					continue
				}
				mode, err := rules.NormalizeMode(d.Mode)
				if err != nil {
					mode = "proxy"
				}
				ports, err := ParsePorts(d.Ports)
				if err != nil {
					ports = "[443]"
				}

				baseDomain := strings.TrimPrefix(normDomain, "*.")
				if d.Wildcard {
					out = append(out, ExpandedDomain{
						Domain:          baseDomain,
						SubcategoryID:   s.ID,
						SubcategoryName: s.Name,
						CategoryID:      c.ID,
						CategoryName:    c.Name,
						Mode:            mode,
						Ports:           ports,
						DefaultEnabled:  effectiveEnabled,
					})
					out = append(out, ExpandedDomain{
						Domain:          "*." + baseDomain,
						SubcategoryID:   s.ID,
						SubcategoryName: s.Name,
						CategoryID:      c.ID,
						CategoryName:    c.Name,
						Mode:            mode,
						Ports:           ports,
						DefaultEnabled:  effectiveEnabled,
					})
				} else {
					out = append(out, ExpandedDomain{
						Domain:          normDomain,
						SubcategoryID:   s.ID,
						SubcategoryName: s.Name,
						CategoryID:      c.ID,
						CategoryName:    c.Name,
						Mode:            mode,
						Ports:           ports,
						DefaultEnabled:  effectiveEnabled,
					})
				}
			}
		}
	}
	return out
}

var (
	embeddedCatalog *Catalog
	embeddedErr     error
	embeddedOnce    sync.Once
)

// Embedded returns the parsed embedded catalog, parsing it once and caching the result.
func Embedded() (*Catalog, error) {
	embeddedOnce.Do(func() {
		embeddedCatalog, embeddedErr = Parse(data.DefaultDomainsJSON)
	})
	return embeddedCatalog, embeddedErr
}
