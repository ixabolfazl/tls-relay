package catalog

import (
	"strings"
	"testing"
)

func TestEmbeddedIsValid(t *testing.T) {
	cat, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded() returned error: %v", err)
	}
	if cat.Version <= 0 {
		t.Errorf("expected Version > 0, got %d", cat.Version)
	}
	if len(cat.Categories) == 0 {
		t.Errorf("expected at least 1 category, got %d", len(cat.Categories))
	}
	expanded := Expand(cat)
	if len(expanded) == 0 {
		t.Errorf("expected expanded domains, got 0")
	}
}

func TestParse_Validation(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string
	}{
		{
			name:    "version zero",
			json:    `{"version": 0, "categories": []}`,
			wantErr: "version must be a positive integer",
		},
		{
			name: "invalid category id",
			json: `{
				"version": 1,
				"categories": [
					{"id": "Bad_Cat!", "name": "Bad", "subcategories": []}
				]
			}`,
			wantErr: "invalid category id",
		},
		{
			name: "duplicate category id",
			json: `{
				"version": 1,
				"categories": [
					{"id": "cat1", "name": "Cat 1", "subcategories": []},
					{"id": "cat1", "name": "Cat 2", "subcategories": []}
				]
			}`,
			wantErr: "duplicate category id",
		},
		{
			name: "subcategory missing parent prefix",
			json: `{
				"version": 1,
				"categories": [
					{"id": "cat1", "name": "Cat 1", "subcategories": [
						{"id": "sub1", "name": "Sub 1", "domains": []}
					]}
				]
			}`,
			wantErr: "must start with prefix",
		},
		{
			name: "duplicate subcategory id",
			json: `{
				"version": 1,
				"categories": [
					{"id": "cat1", "name": "Cat 1", "subcategories": [
						{"id": "cat1.sub1", "name": "Sub 1", "domains": []},
						{"id": "cat1.sub1", "name": "Sub 2", "domains": []}
					]}
				]
			}`,
			wantErr: "duplicate subcategory id",
		},
		{
			name: "duplicate domain across nodes",
			json: `{
				"version": 1,
				"categories": [
					{"id": "cat1", "name": "Cat 1", "subcategories": [
						{"id": "cat1.sub1", "name": "Sub 1", "domains": [
							{"domain": "example.com"}
						]},
						{"id": "cat1.sub2", "name": "Sub 2", "domains": [
							{"domain": "EXAMPLE.COM"}
						]}
					]}
				]
			}`,
			wantErr: "is duplicated from",
		},
		{
			name: "invalid domain",
			json: `{
				"version": 1,
				"categories": [
					{"id": "cat1", "name": "Cat 1", "subcategories": [
						{"id": "cat1.sub1", "name": "Sub 1", "domains": [
							{"domain": "bad..domain"}
						]}
					]}
				]
			}`,
			wantErr: "invalid domain",
		},
		{
			name: "invalid mode",
			json: `{
				"version": 1,
				"categories": [
					{"id": "cat1", "name": "Cat 1", "subcategories": [
						{"id": "cat1.sub1", "name": "Sub 1", "domains": [
							{"domain": "example.com", "mode": "unsupported"}
						]}
					]}
				]
			}`,
			wantErr: "invalid mode",
		},
		{
			name: "invalid port",
			json: `{
				"version": 1,
				"categories": [
					{"id": "cat1", "name": "Cat 1", "subcategories": [
						{"id": "cat1.sub1", "name": "Sub 1", "domains": [
							{"domain": "example.com", "ports": [99999]}
						]}
					]}
				]
			}`,
			wantErr: "invalid port",
		},
		{
			name: "name exceeds 64 runes",
			json: `{
				"version": 1,
				"categories": [
					{"id": "cat1", "name": "` + strings.Repeat("A", 65) + `", "subcategories": []}
				]
			}`,
			wantErr: "exceeds maximum length of 64 runes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.json))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestExpand(t *testing.T) {
	f := false
	tr := true
	raw := `{
		"version": 1,
		"categories": [
			{
				"id": "social",
				"name": "Social",
				"default_enabled": true,
				"subcategories": [
					{
						"id": "social.telegram",
						"name": "Telegram",
						"default_enabled": true,
						"domains": [
							{"domain": "telegram.org", "wildcard": true},
							{"domain": "t.me", "mode": "direct", "ports": "all"}
						]
					},
					{
						"id": "social.disabled",
						"name": "Disabled Sub",
						"default_enabled": false,
						"domains": [
							{"domain": "disabled.com"}
						]
					}
				]
			},
			{
				"id": "discat",
				"name": "Disabled Cat",
				"default_enabled": false,
				"subcategories": [
					{
						"id": "discat.sub",
						"name": "Sub",
						"default_enabled": true,
						"domains": [
							{"domain": "discat.org"}
						]
					}
				]
			}
		]
	}`

	_ = f
	_ = tr
	cat, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	expanded := Expand(cat)
	// Expected:
	// 1. telegram.org (exact)
	// 2. *.telegram.org (wildcard)
	// 3. t.me
	// 4. disabled.com (enabled = false because sub is false)
	// 5. discat.org (enabled = false because cat is false)
	if len(expanded) != 5 {
		t.Fatalf("expected 5 expanded domains, got %d", len(expanded))
	}

	m := make(map[string]ExpandedDomain)
	for _, e := range expanded {
		m[e.Domain] = e
	}

	tg, ok := m["telegram.org"]
	if !ok || !tg.DefaultEnabled || tg.Mode != "proxy" || tg.Ports != "[443]" || tg.SubcategoryID != "social.telegram" {
		t.Errorf("unexpected tg: %+v", tg)
	}

	tgWc, ok := m["*.telegram.org"]
	if !ok || !tgWc.DefaultEnabled || tgWc.Mode != "proxy" {
		t.Errorf("unexpected tg wildcard: %+v", tgWc)
	}

	tme, ok := m["t.me"]
	if !ok || !tme.DefaultEnabled || tme.Mode != "direct" || tme.Ports != "\"all\"" {
		t.Errorf("unexpected t.me: %+v", tme)
	}

	dis, ok := m["disabled.com"]
	if !ok || dis.DefaultEnabled {
		t.Errorf("expected disabled.com to have DefaultEnabled=false, got %+v", dis)
	}

	disCat, ok := m["discat.org"]
	if !ok || disCat.DefaultEnabled {
		t.Errorf("expected discat.org to have DefaultEnabled=false, got %+v", disCat)
	}
}
