package syncer_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
	"github.com/ixabolfazl/tls-relay/internal/syncer"
)

func TestSyncer_Lifecycle(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("failed to init sqlite: %v", err)
	}
	defer store.Close()

	ruleStore := rules.NewRuleStore([]int{443}, "reject")
	accessStore := access.NewAccessStore(access.ModeUser)
	connTracker := relay.NewConnTracker()

	sync := syncer.New(ruleStore, accessStore, store)
	sync.SetConnTracker(connTracker)

	// Seed SQLite
	if err := store.AddDomainRule(ctx, "example.com", "default", "[443]", "default", "proxy"); err != nil {
		t.Fatalf("AddDomainRule: %v", err)
	}
	if err := store.AddBlacklistEntry(ctx, "1.2.3.4"); err != nil {
		t.Fatalf("AddBlacklistEntry: %v", err)
	}
	user, err := store.CreateUser(ctx, "alice", 5)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := store.RegisterIP(ctx, user.ID, "5.6.7.8", 5); err != nil {
		t.Fatalf("RegisterIP: %v", err)
	}

	// 1. Initial Load
	if err := sync.LoadInitial(ctx); err != nil {
		t.Fatalf("LoadInitial failed: %v", err)
	}

	// Verify Domain Loaded
	rule, ok := ruleStore.LookupRule("example.com")
	if !ok || rule.Mode != "proxy" {
		t.Fatalf("expected example.com to be loaded with proxy mode, got ok=%v, rule=%+v", ok, rule)
	}

	// Verify Blacklist Loaded
	if allowed, _ := accessStore.CheckAccess(net.ParseIP("1.2.3.4")); allowed {
		t.Fatalf("expected 1.2.3.4 to be blocked by blacklist")
	}

	// Verify User IP Loaded
	if allowed, _ := accessStore.CheckAccess(net.ParseIP("5.6.7.8")); !allowed {
		t.Fatalf("expected 5.6.7.8 to be allowed for registered user")
	}

	// 2. RefreshDomains
	if err := store.AddDomainRule(ctx, "blocked.com", "default", "[443]", "default", "block"); err != nil {
		t.Fatalf("AddDomainRule: %v", err)
	}
	if err := sync.RefreshDomains(ctx); err != nil {
		t.Fatalf("RefreshDomains failed: %v", err)
	}
	blockRule, ok := ruleStore.LookupRule("blocked.com")
	if !ok || blockRule.Mode != "block" {
		t.Fatalf("expected blocked.com to be loaded with block mode")
	}

	// 3. RefreshBlacklist
	if err := store.AddBlacklistEntry(ctx, "9.9.9.9"); err != nil {
		t.Fatalf("AddBlacklistEntry: %v", err)
	}
	if err := sync.RefreshBlacklist(ctx); err != nil {
		t.Fatalf("RefreshBlacklist failed: %v", err)
	}
	if allowed, _ := accessStore.CheckAccess(net.ParseIP("9.9.9.9")); allowed {
		t.Fatalf("expected 9.9.9.9 to be blocked after RefreshBlacklist")
	}

	// 4. RefreshUserIPs
	if err := store.RegisterIP(ctx, user.ID, "10.20.30.40", 5); err != nil {
		t.Fatalf("RegisterIP: %v", err)
	}
	if err := sync.RefreshUserIPs(ctx); err != nil {
		t.Fatalf("RefreshUserIPs failed: %v", err)
	}
	if allowed, _ := accessStore.CheckAccess(net.ParseIP("10.20.30.40")); !allowed {
		t.Fatalf("expected 10.20.30.40 to be allowed after RefreshUserIPs")
	}

	// Verify ConnTracker user mappings updated via single query
	presence := connTracker.GetPresenceStats()
	if presence.TotalUsers != 1 {
		t.Fatalf("expected 1 total user in presence summary, got %d", presence.TotalUsers)
	}
	if len(presence.Users[0].RegisteredIPs) != 2 {
		t.Fatalf("expected 2 registered IPs for user in presence summary, got %v", presence.Users[0].RegisteredIPs)
	}

	// 5. Test "all" ports rule loading
	if err := store.AddDomainRule(ctx, "allports.org", "allgroup", "all", "default", "proxy"); err != nil {
		t.Fatalf("AddDomainRule with all ports: %v", err)
	}
	if err := sync.RefreshDomains(ctx); err != nil {
		t.Fatalf("RefreshDomains with all ports failed: %v", err)
	}
	allRule, ok := ruleStore.LookupRule("allports.org")
	if !ok || !allRule.Ports.All {
		t.Fatalf("expected allports.org to be loaded with Ports.All=true, got ok=%v, rule=%+v", ok, allRule)
	}
}
