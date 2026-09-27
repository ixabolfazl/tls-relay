package rules_test

import (
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/rules"
)

func TestLookupWithMatchInfo(t *testing.T) {
	rs := rules.NewRuleStore([]int{443, 8443}, "reject")
	err := rs.Swap(map[string]string{
		"exact.com":        `{"ports":[443]}`,
		"*.wildcard.com":   `{"ports":[8443]}`,
		"*.sub.nested.com": `{"ports":[443]}`,
	})
	if err != nil {
		t.Fatalf("Swap error: %v", err)
	}

	tests := []struct {
		name        string
		host        string
		port        int
		wantAllowed bool
		wantMatched bool
		wantKind    string
		wantRule    string
	}{
		{
			name:        "exact match allowed",
			host:        "exact.com",
			port:        443,
			wantAllowed: true,
			wantMatched: true,
			wantKind:    "exact",
			wantRule:    "",
		},
		{
			name:        "exact match wrong port",
			host:        "exact.com",
			port:        80,
			wantAllowed: false,
			wantMatched: true,
			wantKind:    "exact",
			wantRule:    "",
		},
		{
			name:        "wildcard match allowed",
			host:        "api.wildcard.com",
			port:        8443,
			wantAllowed: true,
			wantMatched: true,
			wantKind:    "wildcard",
			wantRule:    "*.wildcard.com",
		},
		{
			name:        "wildcard match wrong port",
			host:        "api.wildcard.com",
			port:        443,
			wantAllowed: false,
			wantMatched: true,
			wantKind:    "wildcard",
			wantRule:    "*.wildcard.com",
		},
		{
			name:        "no match",
			host:        "unknown.com",
			port:        443,
			wantAllowed: false,
			wantMatched: false,
			wantKind:    "none",
			wantRule:    "",
		},
		{
			name:        "apex does not match wildcard",
			host:        "wildcard.com",
			port:        8443,
			wantAllowed: false,
			wantMatched: false,
			wantKind:    "none",
			wantRule:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowedLookup, matchedLookup := rs.Lookup(tt.host, tt.port)
			allowedMatchInfo, info := rs.LookupWithMatchInfo(tt.host, tt.port)
			allowedDetailed, detailedRule, detailedInfo := rs.LookupDetailed(tt.host, tt.port)

			// Equivalence check between Lookup, LookupWithMatchInfo, and LookupDetailed
			if allowedLookup != allowedMatchInfo || allowedLookup != allowedDetailed {
				t.Errorf("Lookup and LookupDetailed allowed mismatch for %s:%d: %v vs %v",
					tt.host, tt.port, allowedLookup, allowedDetailed)
			}
			if matchedLookup != info.Matched || matchedLookup != detailedInfo.Matched {
				t.Errorf("Lookup and LookupDetailed matched mismatch for %s:%d: %v vs %v",
					tt.host, tt.port, matchedLookup, detailedInfo.Matched)
			}
			if detailedInfo.Kind != info.Kind || detailedInfo.Rule != info.Rule {
				t.Errorf("LookupDetailed info mismatch: %+v vs %+v", detailedInfo, info)
			}
			if detailedInfo.Matched && detailedRule.Ports.Ports == nil && !detailedRule.Ports.All {
				t.Errorf("expected parsed rule when matched")
			}

			// Specific expectations for LookupWithMatchInfo
			if allowedMatchInfo != tt.wantAllowed {
				t.Errorf("LookupWithMatchInfo(%s, %d) allowed = %v, want %v", tt.host, tt.port, allowedMatchInfo, tt.wantAllowed)
			}
			if info.Matched != tt.wantMatched {
				t.Errorf("LookupWithMatchInfo(%s, %d) info.Matched = %v, want %v", tt.host, tt.port, info.Matched, tt.wantMatched)
			}
			if info.Kind != tt.wantKind {
				t.Errorf("LookupWithMatchInfo(%s, %d) info.Kind = %q, want %q", tt.host, tt.port, info.Kind, tt.wantKind)
			}
			if info.Rule != tt.wantRule {
				t.Errorf("LookupWithMatchInfo(%s, %d) info.Rule = %q, want %q", tt.host, tt.port, info.Rule, tt.wantRule)
			}
		})
	}
}
