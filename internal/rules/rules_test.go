package rules_test

import (
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/rules"
)

// ---------------------------------------------------------------------------
// DomainRule / RuleStore tests
// ---------------------------------------------------------------------------

func makeStore(rawRules map[string]string, globalPorts []int, policy string) *rules.RuleStore {
	rs := rules.NewRuleStore(globalPorts, policy)
	if err := rs.Swap(rawRules); err != nil {
		panic(err)
	}
	return rs
}

func TestRuleStore_ExactMatch(t *testing.T) {
	rs := makeStore(map[string]string{
		"github.com": `{"ports":[443]}`,
	}, []int{443, 8443}, "reject")

	allowed, matched := rs.Lookup("github.com", 443)
	if !matched || !allowed {
		t.Errorf("github.com:443 should be matched and allowed, got matched=%v allowed=%v", matched, allowed)
	}

	allowed, matched = rs.Lookup("github.com", 80)
	if !matched || allowed {
		t.Errorf("github.com:80 should be matched but denied, got matched=%v allowed=%v", matched, allowed)
	}
}

func TestRuleStore_WildcardMatch(t *testing.T) {
	rs := makeStore(map[string]string{
		"*.google.com": `{"ports":[443]}`,
	}, []int{443}, "reject")

	cases := []struct {
		host    string
		port    int
		matched bool
		allowed bool
	}{
		{"maps.google.com", 443, true, true},
		{"mail.google.com", 443, true, true},
		{"deep.sub.google.com", 443, true, true},
		{"google.com", 443, false, false},     // apex must NOT match wildcard
		{"evilgoogle.com", 443, false, false}, // must not match
		{"maps.google.com", 80, true, false},  // matched but wrong port
	}

	for _, tc := range cases {
		got, gotm := rs.Lookup(tc.host, tc.port)
		if gotm != tc.matched || got != tc.allowed {
			t.Errorf("Lookup(%q, %d): matched=%v allowed=%v, want matched=%v allowed=%v",
				tc.host, tc.port, gotm, got, tc.matched, tc.allowed)
		}
	}
}

func TestRuleStore_ExactOverWildcard(t *testing.T) {
	rs := makeStore(map[string]string{
		"api.example.com": `{"ports":[8443]}`,
		"*.example.com":   `{"ports":[443]}`,
	}, []int{443, 8443}, "reject")

	// Exact entry for api.example.com should win over wildcard.
	allowed, matched := rs.Lookup("api.example.com", 443)
	if !matched || allowed {
		t.Errorf("api.example.com:443 should be matched-but-denied (exact rule is port 8443), got matched=%v allowed=%v", matched, allowed)
	}

	allowed, matched = rs.Lookup("api.example.com", 8443)
	if !matched || !allowed {
		t.Errorf("api.example.com:8443 should be matched and allowed, got matched=%v allowed=%v", matched, allowed)
	}

	// Other subdomains use the wildcard.
	allowed, matched = rs.Lookup("www.example.com", 443)
	if !matched || !allowed {
		t.Errorf("www.example.com:443 should match wildcard and be allowed, got matched=%v allowed=%v", matched, allowed)
	}
}

func TestRuleStore_AllPorts(t *testing.T) {
	globalPorts := []int{443, 8443, 2053}
	rs := makeStore(map[string]string{
		"*.google.com": `{"ports":"all"}`,
	}, globalPorts, "reject")

	// "all" means fall back to global ports.
	for _, port := range globalPorts {
		allowed, matched := rs.Lookup("maps.google.com", port)
		if !matched || !allowed {
			t.Errorf("maps.google.com:%d should be allowed via 'all', got matched=%v allowed=%v", port, matched, allowed)
		}
	}

	// A port NOT in globalPorts should still be denied.
	allowed, matched := rs.Lookup("maps.google.com", 80)
	if !matched || allowed {
		t.Errorf("maps.google.com:80 should be matched-but-denied via 'all', got matched=%v allowed=%v", matched, allowed)
	}
}

func TestRuleStore_DefaultPorts(t *testing.T) {
	// When a rule has no ports field at all, default is [443].
	rs := makeStore(map[string]string{
		"example.com": `{}`,
	}, []int{443, 8443}, "reject")

	allowed, matched := rs.Lookup("example.com", 443)
	if !matched || !allowed {
		t.Errorf("example.com:443 with default rule should be allowed, got matched=%v allowed=%v", matched, allowed)
	}
	allowed, matched = rs.Lookup("example.com", 8443)
	if !matched || allowed {
		t.Errorf("example.com:8443 with default rule should be denied, got matched=%v allowed=%v", matched, allowed)
	}
}

func TestRuleStore_UnknownDomainPolicy_Reject(t *testing.T) {
	rs := makeStore(map[string]string{}, []int{443, 8443}, "reject")

	_, matched := rs.Lookup("unknown.example.com", 443)
	if matched {
		t.Error("unknown domain should not match anything")
	}

	// Policy is "reject" — IsPortAllowedByPolicy should return false.
	if rs.IsPortAllowedByPolicy(443) {
		t.Error("reject policy should not allow any port")
	}
}

func TestRuleStore_UnknownDomainPolicy_AllowDefault(t *testing.T) {
	rs := makeStore(map[string]string{}, []int{443, 8443}, "allow_default_port")

	_, matched := rs.Lookup("unknown.example.com", 443)
	if matched {
		t.Error("unknown domain should not match anything")
	}

	if !rs.IsPortAllowedByPolicy(443) {
		t.Error("allow_default_port policy should allow port 443 (in global list)")
	}
	if rs.IsPortAllowedByPolicy(80) {
		t.Error("allow_default_port policy should deny port 80 (not in global list)")
	}
}

func TestRuleStore_MostSpecificWildcard(t *testing.T) {
	// *.sub.example.com is more specific than *.example.com
	rs := makeStore(map[string]string{
		"*.example.com":     `{"ports":[443]}`,
		"*.sub.example.com": `{"ports":[8443]}`,
	}, []int{443, 8443}, "reject")

	// deep.sub.example.com matches *.sub.example.com (longer suffix → wins).
	allowed, matched := rs.Lookup("deep.sub.example.com", 8443)
	if !matched || !allowed {
		t.Errorf("deep.sub.example.com:8443 should match *.sub.example.com, got matched=%v allowed=%v", matched, allowed)
	}

	// www.example.com only matches *.example.com.
	allowed, matched = rs.Lookup("www.example.com", 443)
	if !matched || !allowed {
		t.Errorf("www.example.com:443 should match *.example.com, got matched=%v allowed=%v", matched, allowed)
	}
}

// ---------------------------------------------------------------------------
// ParsePorts tests
// ---------------------------------------------------------------------------

func TestParsePorts(t *testing.T) {
	cases := []struct {
		input   string
		wantAll bool
		wantLen int
		wantErr bool
	}{
		{"all", true, 0, false},
		{"ALL", true, 0, false},
		{`"all"`, true, 0, false},
		{`\"all\"`, true, 0, false},
		{"443", false, 1, false},
		{"[443]", false, 1, false},
		{`"[443]"`, false, 1, false},
		{"[ 443, 8443 ]", false, 2, false},
		{"443,8443", false, 2, false},
		{"443, 8443 ", false, 2, false},
		{"", false, 0, true},
		{"abc", false, 0, true},
		{"0", false, 0, true},
		{"65536", false, 0, true},
	}
	for _, tc := range cases {
		ps, err := rules.ParsePorts(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParsePorts(%q): expected error, got nil", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePorts(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if ps.All != tc.wantAll {
			t.Errorf("ParsePorts(%q): All=%v, want %v", tc.input, ps.All, tc.wantAll)
		}
		if !tc.wantAll && len(ps.Ports) != tc.wantLen {
			t.Errorf("ParsePorts(%q): len(Ports)=%d, want %d", tc.input, len(ps.Ports), tc.wantLen)
		}
	}
}

func TestDomainRule_GroupNameRoundTrip(t *testing.T) {
	rs := rules.NewRuleStore([]int{443}, "reject")
	rawRules := map[string]string{
		"api.dev.com": `{"group_name":"DevTeam","ports":[443],"use_egress_proxy":"true"}`,
		"main.com":    `{"ports":[443]}`,
	}
	if err := rs.Swap(rawRules); err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	rule, ok := rs.LookupRule("api.dev.com")
	if !ok {
		t.Fatal("expected rule for api.dev.com")
	}
	if rule.GroupName != "DevTeam" {
		t.Errorf("expected GroupName 'DevTeam', got %q", rule.GroupName)
	}

	all := rs.AllRules()
	if all["api.dev.com"].GroupName != "DevTeam" {
		t.Errorf("expected GroupName 'DevTeam' in AllRules, got %q", all["api.dev.com"].GroupName)
	}
	if all["main.com"].GroupName != "" {
		t.Errorf("expected empty GroupName for main.com in AllRules, got %q", all["main.com"].GroupName)
	}
}

func TestDomainRule_ModeRoundTrip(t *testing.T) {
	rs := rules.NewRuleStore([]int{443}, "reject")
	rawRules := map[string]string{
		"block.com":  `{"ports":[443],"mode":"block"}`,
		"direct.com": `{"ports":[443],"mode":"direct"}`,
		"proxy.com":  `{"ports":[443],"mode":"proxy"}`,
		"old.com":    `{"ports":[443]}`, // empty mode should default to proxy
	}
	if err := rs.Swap(rawRules); err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	rule, ok := rs.LookupRule("block.com")
	if !ok || rule.Mode != "block" {
		t.Errorf("expected mode block for block.com, got %q", rule.Mode)
	}

	rule, ok = rs.LookupRule("direct.com")
	if !ok || rule.Mode != "direct" {
		t.Errorf("expected mode direct for direct.com, got %q", rule.Mode)
	}

	rule, ok = rs.LookupRule("old.com")
	if !ok || rule.Mode != "proxy" {
		t.Errorf("expected mode proxy default for old.com, got %q", rule.Mode)
	}
}

func TestRuleStore_ModePrecedence(t *testing.T) {
	rs := rules.NewRuleStore([]int{443}, "reject")
	// Exact block rule wins over wildcard proxy rule
	rawRules := map[string]string{
		"bad.example.com": `{"ports":[443],"mode":"block"}`,
		"*.example.com":   `{"ports":[443],"mode":"proxy"}`,
	}
	if err := rs.Swap(rawRules); err != nil {
		t.Fatalf("Swap failed: %v", err)
	}

	rule, ok := rs.LookupRule("bad.example.com")
	if !ok || rule.Mode != "block" {
		t.Errorf("exact rule bad.example.com should be block, got %q", rule.Mode)
	}

	rule, ok = rs.LookupRule("good.example.com")
	if !ok || rule.Mode != "proxy" {
		t.Errorf("wildcard rule good.example.com should be proxy, got %q", rule.Mode)
	}
}
