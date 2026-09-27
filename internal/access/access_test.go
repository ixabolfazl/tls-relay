package access_test

import (
	"net"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/access"
)

func TestPublicMode_AllowsUnknownIP(t *testing.T) {
	store := access.NewAccessStore(access.ModePublic)

	ip := net.ParseIP("1.2.3.4")
	allowed, reason := store.CheckAccess(ip)
	if !allowed {
		t.Errorf("public mode should allow unknown IP, got reason=%q", reason)
	}
}

func TestPublicMode_BlocksBlacklist(t *testing.T) {
	store := access.NewAccessStore(access.ModePublic)
	if err := store.SwapBlacklist([]string{"10.0.0.1", "192.168.0.0/16"}); err != nil {
		t.Fatal(err)
	}

	// Exact IP match
	ip := net.ParseIP("10.0.0.1")
	allowed, reason := store.CheckAccess(ip)
	if allowed {
		t.Error("public mode should block blacklisted IP")
	}
	if reason != "blacklisted" {
		t.Errorf("expected reason 'blacklisted', got %q", reason)
	}

	// CIDR match
	ip2 := net.ParseIP("192.168.1.100")
	allowed2, _ := store.CheckAccess(ip2)
	if allowed2 {
		t.Error("public mode should block IP in blacklisted CIDR")
	}

	// Non-blacklisted IP
	ip3 := net.ParseIP("8.8.8.8")
	allowed3, _ := store.CheckAccess(ip3)
	if !allowed3 {
		t.Error("public mode should allow non-blacklisted IP")
	}
}

func TestUserMode_BlocksUnknownIP(t *testing.T) {
	store := access.NewAccessStore(access.ModeUser)

	ip := net.ParseIP("1.2.3.4")
	allowed, reason := store.CheckAccess(ip)
	if allowed {
		t.Error("user mode should block unknown IP")
	}
	if reason != "not_registered" {
		t.Errorf("expected reason 'not_registered', got %q", reason)
	}
}

func TestUserMode_AllowsRegisteredIP(t *testing.T) {
	store := access.NewAccessStore(access.ModeUser)
	store.SwapUserIPs([]string{"1.2.3.4", "10.0.0.1"})

	ip := net.ParseIP("1.2.3.4")
	allowed, reason := store.CheckAccess(ip)
	if !allowed {
		t.Errorf("user mode should allow registered IP, got reason=%q", reason)
	}
}

func TestUserMode_BlocksBlacklistEvenIfRegistered(t *testing.T) {
	store := access.NewAccessStore(access.ModeUser)
	store.SwapUserIPs([]string{"10.0.0.1"})
	if err := store.SwapBlacklist([]string{"10.0.0.1"}); err != nil {
		t.Fatal(err)
	}

	ip := net.ParseIP("10.0.0.1")
	allowed, reason := store.CheckAccess(ip)
	if allowed {
		t.Error("user mode should block blacklisted IP even if registered")
	}
	if reason != "blacklisted" {
		t.Errorf("expected reason 'blacklisted', got %q", reason)
	}
}

func TestUserMode_DisabledUserRejected(t *testing.T) {
	// Disabled users' IPs should not be in the snapshot.
	// This is verified by not including them in SwapUserIPs.
	store := access.NewAccessStore(access.ModeUser)
	// Only enabled user's IP is included
	store.SwapUserIPs([]string{"1.1.1.1"})

	// Disabled user's IP
	ip := net.ParseIP("2.2.2.2")
	allowed, reason := store.CheckAccess(ip)
	if allowed {
		t.Error("disabled user's IP should be rejected")
	}
	if reason != "not_registered" {
		t.Errorf("expected reason 'not_registered', got %q", reason)
	}
}

func TestIsBlacklisted(t *testing.T) {
	store := access.NewAccessStore(access.ModePublic)
	if err := store.SwapBlacklist([]string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}

	if !store.IsBlacklisted(net.ParseIP("10.1.2.3")) {
		t.Error("10.1.2.3 should be blacklisted")
	}
	if store.IsBlacklisted(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 should not be blacklisted")
	}
}

// ---------------------------------------------------------------------------
// EvictionHook tests
// ---------------------------------------------------------------------------

// mockEvictionHook records every EvictNotAllowed call for assertion.
type mockEvictionHook struct {
	calls           []map[string]struct{}
	blacklistCalls  int
	lastBlacklistFn func(net.IP) bool
}

func (h *mockEvictionHook) EvictNotAllowed(allowed map[string]struct{}) {
	// Copy the map so we hold an immutable snapshot.
	cp := make(map[string]struct{}, len(allowed))
	for k := range allowed {
		cp[k] = struct{}{}
	}
	h.calls = append(h.calls, cp)
}

func (h *mockEvictionHook) EvictBlacklisted(isBlacklisted func(net.IP) bool) {
	h.blacklistCalls++
	h.lastBlacklistFn = isBlacklisted
}

func TestEvictionHook_CalledOnSwapUserIPs(t *testing.T) {
	store := access.NewAccessStore(access.ModeUser)
	hook := &mockEvictionHook{}
	store.SetEvictionHook(hook)

	store.SwapUserIPs([]string{"1.1.1.1", "2.2.2.2"})

	if len(hook.calls) != 1 {
		t.Fatalf("expected 1 hook call, got %d", len(hook.calls))
	}
	allowed := hook.calls[0]
	if _, ok := allowed["1.1.1.1"]; !ok {
		t.Error("1.1.1.1 should be in allowed set passed to hook")
	}
	if _, ok := allowed["2.2.2.2"]; !ok {
		t.Error("2.2.2.2 should be in allowed set passed to hook")
	}
}

func TestEvictionHook_ModePublicDoesNotEvict(t *testing.T) {
	store := access.NewAccessStore(access.ModePublic)
	hook := &mockEvictionHook{}
	store.SetEvictionHook(hook)

	// In ModePublic, unregistered users are allowed. SwapUserIPs should not evict.
	store.SwapUserIPs([]string{"1.1.1.1"})

	if len(hook.calls) != 0 {
		t.Errorf("expected 0 hook calls in ModePublic, got %d", len(hook.calls))
	}
}

func TestEvictionHook_BlacklistEviction(t *testing.T) {
	store := access.NewAccessStore(access.ModePublic)
	hook := &mockEvictionHook{}
	store.SetEvictionHook(hook)

	err := store.SwapBlacklist([]string{" 10.0.0.1 ", "192.168.0.0/24", ""})
	if err != nil {
		t.Fatalf("unexpected error swapping blacklist: %v", err)
	}

	if hook.blacklistCalls != 1 {
		t.Fatalf("expected 1 blacklist hook call, got %d", hook.blacklistCalls)
	}
	if hook.lastBlacklistFn == nil {
		t.Fatal("expected non-nil blacklist check function")
	}
	if !hook.lastBlacklistFn(net.ParseIP("10.0.0.1")) {
		t.Error("10.0.0.1 should be matched by blacklist function")
	}
	if !hook.lastBlacklistFn(net.ParseIP("192.168.0.50")) {
		t.Error("192.168.0.50 should be matched by blacklist function")
	}
	if hook.lastBlacklistFn(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 should NOT be matched by blacklist function")
	}
}

func TestEvictionHook_RevokedIPNotInAllowedSet(t *testing.T) {
	store := access.NewAccessStore(access.ModeUser)
	hook := &mockEvictionHook{}
	store.SetEvictionHook(hook)

	store.SwapUserIPs([]string{"1.1.1.1", "2.2.2.2"})
	// Revoke 2.2.2.2.
	store.SwapUserIPs([]string{"1.1.1.1"})

	if len(hook.calls) != 2 {
		t.Fatalf("expected 2 hook calls (one per swap), got %d", len(hook.calls))
	}
	secondCall := hook.calls[1]
	if _, ok := secondCall["2.2.2.2"]; ok {
		t.Error("2.2.2.2 should NOT be in allowed set after revocation")
	}
	if _, ok := secondCall["1.1.1.1"]; !ok {
		t.Error("1.1.1.1 should still be in allowed set")
	}
}

func TestEvictionHook_NoHook_DoesNotPanic(t *testing.T) {
	// Calling SwapUserIPs without a registered hook must not panic.
	store := access.NewAccessStore(access.ModeUser)
	store.SwapUserIPs([]string{"1.2.3.4"})
}

// ---------------------------------------------------------------------------
// Dynamic Mode Switching Tests
// ---------------------------------------------------------------------------

func TestSetMode_RuntimeSwap(t *testing.T) {
	store := access.NewAccessStore(access.ModeUser)
	unregisteredIP := net.ParseIP("9.9.9.9")

	// Initially in ModeUser -> unregistered IP is blocked
	allowed, reason := store.CheckAccess(unregisteredIP)
	if allowed || reason != "not_registered" {
		t.Fatalf("expected blocked in ModeUser, got allowed=%v, reason=%q", allowed, reason)
	}

	// Dynamically switch to ModePublic -> same IP immediately allowed
	store.SetMode(access.ModePublic)
	if store.Mode() != access.ModePublic {
		t.Errorf("expected ModePublic, got %v", store.Mode())
	}

	allowed, reason = store.CheckAccess(unregisteredIP)
	if !allowed {
		t.Errorf("expected allowed in ModePublic after SetMode, got reason=%q", reason)
	}

	// Dynamically switch back to ModeUser -> immediately blocked again
	store.SetMode(access.ModeUser)
	if store.Mode() != access.ModeUser {
		t.Errorf("expected ModeUser, got %v", store.Mode())
	}

	allowed, reason = store.CheckAccess(unregisteredIP)
	if allowed || reason != "not_registered" {
		t.Errorf("expected blocked after switching back to ModeUser, got allowed=%v, reason=%q", allowed, reason)
	}
}

func TestConcurrentSetModeAndCheckAccess(t *testing.T) {
	store := access.NewAccessStore(access.ModeUser)
	store.SwapUserIPs([]string{"1.1.1.1"})

	testIP := net.ParseIP("2.2.2.2")

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			if i%2 == 0 {
				store.SetMode(access.ModePublic)
			} else {
				store.SetMode(access.ModeUser)
			}
		}
	}()

	for i := 0; i < 1000; i++ {
		_ = store.Mode()
		allowed, _ := store.CheckAccess(testIP)
		_ = allowed
	}

	<-done
}
