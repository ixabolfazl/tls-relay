package sqlitestore_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

func newTestStore(t *testing.T) *sqlitestore.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	store, err := sqlitestore.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// ---------------------------------------------------------------------------
// Migration & Grouping Tests
// ---------------------------------------------------------------------------

func TestMigration_GroupNameIdempotency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")

	// Manually create an old-schema database without group_name column
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	oldDDL := `CREATE TABLE domain_rules (
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		domain           TEXT    NOT NULL UNIQUE,
		ports            TEXT    NOT NULL DEFAULT '[443]',
		use_egress_proxy TEXT    NOT NULL DEFAULT 'default',
		enabled          INTEGER NOT NULL DEFAULT 1,
		created_at       DATETIME NOT NULL DEFAULT (datetime('now')),
		updated_at       DATETIME NOT NULL DEFAULT (datetime('now'))
	);`
	if _, err := db.Exec(oldDDL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO domain_rules (domain, ports) VALUES ('legacy.com', '[443]')`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Open with sqlitestore.New — should apply migration automatically
	store, err := sqlitestore.New(path)
	if err != nil {
		t.Fatalf("sqlitestore.New failed on old schema: %v", err)
	}

	ctx := context.Background()
	rules, err := store.ListDomainRules(ctx)
	if err != nil {
		t.Fatalf("ListDomainRules failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule preserved, got %d", len(rules))
	}
	if rules[0].Domain != "legacy.com" {
		t.Errorf("expected legacy.com, got %q", rules[0].Domain)
	}
	if rules[0].GroupName != "" {
		t.Errorf("expected empty group_name for legacy row, got %q", rules[0].GroupName)
	}
	_ = store.Close()

	// Reopen again to confirm idempotency
	store2, err := sqlitestore.New(path)
	if err != nil {
		t.Fatalf("sqlitestore.New failed on second open (idempotency check): %v", err)
	}
	defer store2.Close()
}

func TestDomainRule_EmptyGroupNameRegression(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.AddDomainRule(ctx, "ungrouped.com", "", "[443]", "default", "proxy")
	if err != nil {
		t.Fatal(err)
	}

	rules, err := store.ListDomainRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].GroupName != "" {
		t.Errorf("expected empty GroupName, got %q", rules[0].GroupName)
	}
}

func TestDomainRule_MoveBetweenGroups(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Add in GroupA
	_ = store.AddDomainRule(ctx, "app.com", "GroupA", "[443]", "default", "proxy")

	rules, _ := store.ListDomainRules(ctx)
	if rules[0].GroupName != "GroupA" {
		t.Fatalf("expected GroupA, got %q", rules[0].GroupName)
	}

	// Move to GroupB via UpdateDomainRule
	err := store.UpdateDomainRule(ctx, "app.com", "GroupB", "[443]", "default", "proxy")
	if err != nil {
		t.Fatal(err)
	}

	rules2, _ := store.ListDomainRules(ctx)
	if rules2[0].GroupName != "GroupB" {
		t.Errorf("expected GroupB, got %q", rules2[0].GroupName)
	}

	// Move out of group (empty string)
	_ = store.UpdateDomainRule(ctx, "app.com", " ", "[443]", "default", "proxy")
	rules3, _ := store.ListDomainRules(ctx)
	if rules3[0].GroupName != "" {
		t.Errorf("expected empty GroupName after clearing, got %q", rules3[0].GroupName)
	}
}

// ---------------------------------------------------------------------------
// Bulk Operations & Export/Import Tests
// ---------------------------------------------------------------------------

func TestBulkDeleteDomainRules(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_ = store.AddDomainRule(ctx, "d1.com", "g1", "[443]", "default", "proxy")
	_ = store.AddDomainRule(ctx, "d2.com", "g1", "[443]", "default", "proxy")

	// Delete d1.com and non-existent d3.com
	deleted, skipped, err := store.BulkDeleteDomainRules(ctx, []string{"d1.com", "d3.com", ""})
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Errorf("expected deleted=1, got %d", deleted)
	}
	if skipped != 2 {
		t.Errorf("expected skipped=2, got %d", skipped)
	}

	rules, _ := store.ListDomainRules(ctx)
	if len(rules) != 1 || rules[0].Domain != "d2.com" {
		t.Errorf("expected d2.com remaining, got %v", rules)
	}
}

func TestBulkAssignDomainGroup(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_ = store.AddDomainRule(ctx, "a.com", "", "[443]", "default", "proxy")
	_ = store.AddDomainRule(ctx, "b.com", "old", "[443]", "default", "proxy")

	updated, skipped, err := store.BulkAssignDomainGroup(ctx, []string{"a.com", "b.com", "nonexistent.com"}, "NewGroup")
	if err != nil {
		t.Fatal(err)
	}
	if updated != 2 {
		t.Errorf("expected updated=2, got %d", updated)
	}
	if skipped != 1 {
		t.Errorf("expected skipped=1, got %d", skipped)
	}

	rules, _ := store.ListDomainRules(ctx)
	for _, r := range rules {
		if r.GroupName != "NewGroup" {
			t.Errorf("expected GroupName 'NewGroup' for %s, got %q", r.Domain, r.GroupName)
		}
	}
}

func TestBulkDeleteBlacklist(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_ = store.AddBlacklistEntry(ctx, "1.1.1.1")
	_ = store.AddBlacklistEntry(ctx, "2.2.2.2")
	entries, _ := store.ListBlacklist(ctx)

	deleted, skipped, err := store.BulkDeleteBlacklist(ctx, []int64{entries[0].ID, 99999})
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Errorf("expected deleted=1, got %d", deleted)
	}
	if skipped != 1 {
		t.Errorf("expected skipped=1, got %d", skipped)
	}
}

func TestImport_SuccessTransactionCommit(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_ = store.AddDomainRule(ctx, "existing.com", "", "[80]", "default", "proxy")
	_ = store.AddBlacklistEntry(ctx, "1.1.1.1")

	domainRules := []sqlitestore.DomainRuleRow{
		{Domain: "existing.com", GroupName: "ImportedGroup", Ports: "[443]", UseEgressProxy: "true"},
		{Domain: "new.com", GroupName: "ImportedGroup", Ports: "[8443]", UseEgressProxy: "default"},
	}
	blacklist := []sqlitestore.BlacklistEntry{
		{Entry: "1.1.1.1"},
		{Entry: "2.2.2.2"},
	}

	res, err := store.ImportData(ctx, domainRules, blacklist, nil)
	if err != nil {
		t.Fatal(err)
	}

	if res.DomainsAdded != 1 || res.DomainsUpdated != 1 {
		t.Errorf("expected 1 domain added, 1 updated; got added=%d, updated=%d", res.DomainsAdded, res.DomainsUpdated)
	}
	if res.BlacklistAdded != 1 || res.BlacklistUpdated != 1 {
		t.Errorf("expected 1 blacklist added, 1 updated; got added=%d, updated=%d", res.BlacklistAdded, res.BlacklistUpdated)
	}

	rules, _ := store.ListDomainRules(ctx)
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules after import, got %d", len(rules))
	}

	bl, _ := store.ListBlacklist(ctx)
	if len(bl) != 2 {
		t.Fatalf("expected 2 blacklist entries after import, got %d", len(bl))
	}
}

func TestImport_PartialFailureRollback(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Initial check: database is empty
	initialRules, _ := store.ListDomainRules(ctx)
	if len(initialRules) != 0 {
		t.Fatalf("expected 0 rules initially, got %d", len(initialRules))
	}

	domainRules := []sqlitestore.DomainRuleRow{
		{Domain: "rollback-domain.local", GroupName: "RollbackGroup", Ports: "[443]", UseEgressProxy: "default"},
	}
	blacklist := []sqlitestore.BlacklistEntry{
		{Entry: "192.0.2.99"},
	}
	// Two users with duplicate magic link will trigger UNIQUE constraint violation on users(magic_link)
	users := []sqlitestore.UserWithIPs{
		{
			User: sqlitestore.User{Username: "user1", MagicLink: "duplicatelink", Enabled: true},
		},
		{
			User: sqlitestore.User{Username: "user2", MagicLink: "duplicatelink", Enabled: true},
		},
	}

	// This import must fail due to unique constraint on users(magic_link)
	res, err := store.ImportData(ctx, domainRules, blacklist, users)
	if err == nil {
		t.Fatalf("expected import to fail due to duplicate magic link, but it succeeded: %+v", res)
	}

	// Verify rollback: no domain rules, blacklist entries, or users should be committed
	rules, err := store.ListDomainRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 domain rules after rollback, got %d (rollback failed!)", len(rules))
	}

	bl, err := store.ListBlacklist(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(bl) != 0 {
		t.Errorf("expected 0 blacklist entries after rollback, got %d (rollback failed!)", len(bl))
	}

	userList, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(userList) != 0 {
		t.Errorf("expected 0 users after rollback, got %d (rollback failed!)", len(userList))
	}
}

func TestExportAll(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	u, _ := store.CreateUser(ctx, "alice", 3)
	_ = store.RegisterIP(ctx, u.ID, "1.2.3.4", 3)
	_ = store.AddDomainRule(ctx, "example.com", "grp", "[443]", "default", "proxy")
	_ = store.AddBlacklistEntry(ctx, "10.0.0.0/8")

	exp, err := store.ExportAll(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if len(exp.DomainRules) != 1 || exp.DomainRules[0].Domain != "example.com" {
		t.Errorf("export domain rules mismatch: %v", exp.DomainRules)
	}
	if len(exp.Blacklist) != 1 || exp.Blacklist[0].Entry != "10.0.0.0/8" {
		t.Errorf("export blacklist mismatch: %v", exp.Blacklist)
	}
	if len(exp.Users) != 1 || exp.Users[0].Username != "alice" || len(exp.Users[0].IPs) != 1 {
		t.Errorf("export users mismatch: %v", exp.Users)
	}
}

// ---------------------------------------------------------------------------
// User CRUD tests
// ---------------------------------------------------------------------------

func TestCreateAndGetUser(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user, err := store.CreateUser(ctx, "alice", 3)
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "alice" {
		t.Errorf("expected username 'alice', got %q", user.Username)
	}
	if !user.Enabled {
		t.Error("new user should be enabled by default")
	}
	if user.MagicLink == "" {
		t.Error("magic link should be generated")
	}
	if user.MaxIPs != 3 {
		t.Errorf("expected max_ips 3, got %d", user.MaxIPs)
	}

	// Get by ID
	got, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "alice" {
		t.Errorf("expected 'alice', got %q", got.Username)
	}
}

func TestListUsers(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, _ = store.CreateUser(ctx, "alice", 3)
	_, _ = store.CreateUser(ctx, "bob", 5)

	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
}

func TestUpdateUser(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "alice", 3)

	// Disable and change max IPs
	err := store.UpdateUser(ctx, user.ID, false, 5)
	if err != nil {
		t.Fatal(err)
	}

	got, _ := store.GetUser(ctx, user.ID)
	if got.Enabled {
		t.Error("user should be disabled")
	}
	if got.MaxIPs != 5 {
		t.Errorf("expected max_ips 5, got %d", got.MaxIPs)
	}
}

func TestDeleteUser(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "alice", 3)

	err := store.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.GetUser(ctx, user.ID)
	if err == nil {
		t.Error("expected error getting deleted user")
	}
}

func TestDuplicateUsername(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, _ = store.CreateUser(ctx, "alice", 3)
	_, err := store.CreateUser(ctx, "alice", 3)
	if err == nil {
		t.Error("expected error creating duplicate username")
	}
}

// ---------------------------------------------------------------------------
// Magic Link tests
// ---------------------------------------------------------------------------

func TestGetUserByMagicLink(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "alice", 3)

	got, err := store.GetUserByMagicLink(ctx, user.MagicLink)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != user.ID {
		t.Error("wrong user returned by magic link")
	}
}

func TestResetMagicLink(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "alice", 3)
	oldLink := user.MagicLink

	newLink, err := store.ResetMagicLink(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if newLink == oldLink {
		t.Error("new magic link should differ from old one")
	}

	// Old link should not work
	_, err = store.GetUserByMagicLink(ctx, oldLink)
	if err == nil {
		t.Error("old magic link should be invalidated")
	}

	// New link should work
	got, err := store.GetUserByMagicLink(ctx, newLink)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != user.ID {
		t.Error("new magic link returned wrong user")
	}
}

// ---------------------------------------------------------------------------
// User IP tests
// ---------------------------------------------------------------------------

func TestRegisterIP_Basic(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "alice", 3)

	err := store.RegisterIP(ctx, user.ID, "1.2.3.4", user.MaxIPs)
	if err != nil {
		t.Fatal(err)
	}

	ips, _ := store.ListUserIPs(ctx, user.ID)
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
	if ips[0].IPAddress != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", ips[0].IPAddress)
	}
}

func TestRegisterIP_DuplicateUpdatesLastUsed(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "alice", 3)
	_ = store.RegisterIP(ctx, user.ID, "1.2.3.4", user.MaxIPs)

	// Register same IP again
	err := store.RegisterIP(ctx, user.ID, "1.2.3.4", user.MaxIPs)
	if err != nil {
		t.Fatal(err)
	}

	// Should still be 1 IP
	ips, _ := store.ListUserIPs(ctx, user.ID)
	if len(ips) != 1 {
		t.Errorf("expected 1 IP after duplicate registration, got %d", len(ips))
	}
}

func TestRegisterIP_MaxIPsEviction(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "alice", 2) // max 2 IPs

	_ = store.RegisterIP(ctx, user.ID, "1.1.1.1", user.MaxIPs)
	_ = store.RegisterIP(ctx, user.ID, "2.2.2.2", user.MaxIPs)

	// At max — adding a 3rd should evict the oldest (1.1.1.1)
	err := store.RegisterIP(ctx, user.ID, "3.3.3.3", user.MaxIPs)
	if err != nil {
		t.Fatal(err)
	}

	ips, _ := store.ListUserIPs(ctx, user.ID)
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs after eviction, got %d", len(ips))
	}

	// Check that 1.1.1.1 was evicted
	for _, ip := range ips {
		if ip.IPAddress == "1.1.1.1" {
			t.Error("oldest IP 1.1.1.1 should have been evicted")
		}
	}
}

func TestDeleteUserIP(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "alice", 3)
	_ = store.RegisterIP(ctx, user.ID, "1.2.3.4", user.MaxIPs)

	err := store.DeleteUserIP(ctx, user.ID, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}

	ips, _ := store.ListUserIPs(ctx, user.ID)
	if len(ips) != 0 {
		t.Errorf("expected 0 IPs after deletion, got %d", len(ips))
	}
}

func TestDeleteUserCascadesIPs(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "alice", 3)
	_ = store.RegisterIP(ctx, user.ID, "1.2.3.4", user.MaxIPs)
	_ = store.RegisterIP(ctx, user.ID, "5.6.7.8", user.MaxIPs)

	_ = store.DeleteUser(ctx, user.ID)

	ips, _ := store.ListUserIPs(ctx, user.ID)
	if len(ips) != 0 {
		t.Errorf("expected 0 IPs after user deletion, got %d", len(ips))
	}
}

// ---------------------------------------------------------------------------
// Blacklist tests
// ---------------------------------------------------------------------------

func TestBlacklistCRUD(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Add
	err := store.AddBlacklistEntry(ctx, "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	_ = store.AddBlacklistEntry(ctx, "192.168.1.1")

	// List
	entries, _ := store.ListBlacklist(ctx)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Delete
	err = store.DeleteBlacklistEntry(ctx, entries[0].ID)
	if err != nil {
		t.Fatal(err)
	}

	entries2, _ := store.ListBlacklist(ctx)
	if len(entries2) != 1 {
		t.Errorf("expected 1 entry after deletion, got %d", len(entries2))
	}
}

func TestAllBlacklistEntries(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_ = store.AddBlacklistEntry(ctx, "10.0.0.0/8")
	_ = store.AddBlacklistEntry(ctx, "192.168.1.1")

	entries, err := store.AllBlacklistEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

// ---------------------------------------------------------------------------
// Domain Rules tests
// ---------------------------------------------------------------------------

func TestDomainRuleCRUD(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Add
	err := store.AddDomainRule(ctx, "example.com", "", "[443]", "default", "proxy")
	if err != nil {
		t.Fatal(err)
	}

	// List
	rules, _ := store.ListDomainRules(ctx)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Domain != "example.com" {
		t.Errorf("expected 'example.com', got %q", rules[0].Domain)
	}

	// Update
	err = store.UpdateDomainRule(ctx, "example.com", "", "[443,8443]", "true", "proxy")
	if err != nil {
		t.Fatal(err)
	}

	rules2, _ := store.ListDomainRules(ctx)
	if rules2[0].Ports != "[443,8443]" {
		t.Errorf("expected '[443,8443]', got %q", rules2[0].Ports)
	}

	// Delete
	err = store.DeleteDomainRule(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	rules3, _ := store.ListDomainRules(ctx)
	if len(rules3) != 0 {
		t.Errorf("expected 0 rules after deletion, got %d", len(rules3))
	}
}

func TestAllDomainRulesRaw(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_ = store.AddDomainRule(ctx, "example.com", "", "[443]", "default", "proxy")
	_ = store.AddDomainRule(ctx, "*.google.com", "", `"all"`, "true", "proxy")

	raw, err := store.AllDomainRulesRaw(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 2 {
		t.Errorf("expected 2 rules, got %d", len(raw))
	}
	if _, ok := raw["example.com"]; !ok {
		t.Error("expected entry for example.com")
	}
}

// ---------------------------------------------------------------------------
// AllEnabledUserIPs tests
// ---------------------------------------------------------------------------

func TestAllEnabledUserIPs(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user1, _ := store.CreateUser(ctx, "alice", 3)
	user2, _ := store.CreateUser(ctx, "bob", 3)
	_ = store.RegisterIP(ctx, user1.ID, "1.1.1.1", 3)
	_ = store.RegisterIP(ctx, user2.ID, "2.2.2.2", 3)

	// Disable user2
	_ = store.UpdateUser(ctx, user2.ID, false, 3)

	ips, err := store.AllEnabledUserIPs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP (only enabled user), got %d", len(ips))
	}
	if ips[0] != "1.1.1.1" {
		t.Errorf("expected '1.1.1.1', got %q", ips[0])
	}
}

// ---------------------------------------------------------------------------
// Directory creation test
// ---------------------------------------------------------------------------

func TestNewCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "nested", "test.db")

	store, err := sqlitestore.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := os.Stat(filepath.Dir(path)); os.IsNotExist(err) {
		t.Error("expected directory to be created")
	}
}

// ---------------------------------------------------------------------------
// Settings Table Tests
// ---------------------------------------------------------------------------

func TestAppSettings(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Get non-existent key
	val, found, err := store.GetSetting(ctx, "access_mode")
	if err != nil {
		t.Fatalf("unexpected error getting setting: %v", err)
	}
	if found || val != "" {
		t.Errorf("expected not found for missing key, got found=%v, val=%q", found, val)
	}

	// Set initial setting
	if err := store.SetSetting(ctx, "access_mode", "public"); err != nil {
		t.Fatalf("failed to set setting: %v", err)
	}

	val, found, err = store.GetSetting(ctx, "access_mode")
	if err != nil || !found || val != "public" {
		t.Fatalf("expected 'public', found=%v, val=%q, err=%v", found, val, err)
	}

	// Upsert / Overwrite existing key
	if err := store.SetSetting(ctx, "access_mode", "user"); err != nil {
		t.Fatalf("failed to update setting: %v", err)
	}

	val, found, err = store.GetSetting(ctx, "access_mode")
	if err != nil || !found || val != "user" {
		t.Fatalf("expected 'user', found=%v, val=%q, err=%v", found, val, err)
	}

	// Add more settings and test AllSettings
	_ = store.SetSetting(ctx, "panel_path", "/admin")
	_ = store.SetSetting(ctx, "timezone", "Asia/Tehran")

	all, err := store.AllSettings(ctx)
	if err != nil {
		t.Fatalf("failed to get all settings: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 settings, got %d", len(all))
	}
	if all["access_mode"] != "user" || all["panel_path"] != "/admin" || all["timezone"] != "Asia/Tehran" {
		t.Errorf("unexpected settings map content: %v", all)
	}
}

// ---------------------------------------------------------------------------
// User Last Seen & IP Mappings Tests
// ---------------------------------------------------------------------------

func TestUpdateUserLastSeen_AndRestartPersistence(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_last_seen.db")

	store, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	user, err := store.CreateUser(ctx, "charlie", 3)
	if err != nil {
		t.Fatal(err)
	}

	testTime := time.Date(2026, 8, 5, 17, 30, 21, 0, time.UTC)
	if err := store.UpdateUserLastSeen(ctx, user.ID, testTime); err != nil {
		t.Fatalf("failed to update user last seen: %v", err)
	}

	uFetched, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if uFetched.LastSeenAt == "" {
		t.Fatal("expected LastSeenAt to be set after update")
	}

	// Close store and reopen (simulating service restart)
	_ = store.Close()

	reopenedStore, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen database: %v", err)
	}
	defer reopenedStore.Close()

	uRestarted, err := reopenedStore.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("failed to get user after restart: %v", err)
	}
	if uRestarted.LastSeenAt != "2026-08-05 17:30:21" {
		t.Errorf("expected LastSeenAt '2026-08-05 17:30:21' after restart, got %q", uRestarted.LastSeenAt)
	}
}

func TestGetAllUserIPMappings(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	u1, _ := store.CreateUser(ctx, "dave", 3)
	_ = store.RegisterIP(ctx, u1.ID, "192.0.2.1", 3)
	_ = store.RegisterIP(ctx, u1.ID, "192.0.2.2", 3)

	mappings, err := store.GetAllUserIPMappings(ctx)
	if err != nil {
		t.Fatalf("unexpected error getting mappings: %v", err)
	}

	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(mappings))
	}
}

func TestStore_Backup(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	u1, err := store.CreateUser(ctx, "backupuser", 5)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if err := store.AddDomainRule(ctx, "example.com", "default", "[443]", "default", "proxy"); err != nil {
		t.Fatalf("AddDomainRule failed: %v", err)
	}

	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if err := store.Backup(ctx, backupPath); err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	backupStore, err := sqlitestore.New(backupPath)
	if err != nil {
		t.Fatalf("opening backup store failed: %v", err)
	}
	defer backupStore.Close()

	uFetched, err := backupStore.GetUser(ctx, u1.ID)
	if err != nil {
		t.Fatalf("failed to fetch user from backup: %v", err)
	}
	if uFetched.Username != "backupuser" {
		t.Errorf("expected username 'backupuser', got %q", uFetched.Username)
	}

	rules, err := backupStore.ListDomainRules(ctx)
	if err != nil {
		t.Fatalf("failed to list domain rules from backup: %v", err)
	}
	if len(rules) != 1 || rules[0].Domain != "example.com" {
		t.Errorf("unexpected domain rules in backup: %+v", rules)
	}
}

func TestDomainRuleModePersistence(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if err := store.AddDomainRule(ctx, "block.com", "Group1", "[443]", "default", "block"); err != nil {
		t.Fatalf("AddDomainRule block failed: %v", err)
	}
	if err := store.AddDomainRule(ctx, "direct.com", "Group1", "[443]", "default", "direct"); err != nil {
		t.Fatalf("AddDomainRule direct failed: %v", err)
	}

	rulesMap, err := store.AllDomainRulesRaw(ctx)
	if err != nil {
		t.Fatalf("AllDomainRulesRaw failed: %v", err)
	}
	if !strings.Contains(rulesMap["block.com"], `"mode":"block"`) {
		t.Errorf("expected mode block in raw JSON, got %s", rulesMap["block.com"])
	}
	if !strings.Contains(rulesMap["direct.com"], `"mode":"direct"`) {
		t.Errorf("expected mode direct in raw JSON, got %s", rulesMap["direct.com"])
	}
}

func TestRegisterIP_QuotaReducedMultiEviction(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "bob", 5)
	_ = store.RegisterIP(ctx, user.ID, "1.1.1.1", 5)
	_ = store.RegisterIP(ctx, user.ID, "2.2.2.2", 5)
	_ = store.RegisterIP(ctx, user.ID, "3.3.3.3", 5)
	_ = store.RegisterIP(ctx, user.ID, "4.4.4.4", 5)

	// Now quota is reduced to 2, and new IP 5.5.5.5 is registered
	err := store.RegisterIP(ctx, user.ID, "5.5.5.5", 2)
	if err != nil {
		t.Fatal(err)
	}

	ips, _ := store.ListUserIPs(ctx, user.ID)
	if len(ips) != 2 {
		t.Fatalf("expected strictly 2 IPs after reduced quota eviction, got %d", len(ips))
	}
	if ips[0].IPAddress != "4.4.4.4" || ips[1].IPAddress != "5.5.5.5" {
		t.Fatalf("expected [4.4.4.4, 5.5.5.5], got %+v", ips)
	}
}

func TestListAllUserWithIPs(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	u1, _ := store.CreateUser(ctx, "user1", 3)
	u2, _ := store.CreateUser(ctx, "user2", 3)
	_ = store.RegisterIP(ctx, u1.ID, "10.0.0.1", 3)
	_ = store.RegisterIP(ctx, u1.ID, "10.0.0.2", 3)
	_ = u2 // u2 has 0 IPs

	users, err := store.ListAllUserWithIPs(ctx)
	if err != nil {
		t.Fatalf("ListAllUserWithIPs failed: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if len(users[0].IPs) != 2 || len(users[1].IPs) != 0 {
		t.Fatalf("expected user1 with 2 IPs and user2 with 0 IPs, got %+v", users)
	}
}

func TestAllDomainRulesRaw_AllPortsAndFallback(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_ = store.AddDomainRule(ctx, "allports.com", "grp", "all", "default", "proxy")
	_ = store.AddDomainRule(ctx, "singleport.com", "grp", "80", "default", "proxy")
	_ = store.AddDomainRule(ctx, "arrayports.com", "grp", "[443, 8443]", "default", "proxy")

	raw, err := store.AllDomainRulesRaw(ctx)
	if err != nil {
		t.Fatalf("AllDomainRulesRaw: %v", err)
	}
	for domain, val := range raw {
		var js map[string]interface{}
		if err := json.Unmarshal([]byte(val), &js); err != nil {
			t.Fatalf("domain %s generated invalid JSON %s: %v", domain, val, err)
		}
	}
}

func TestSanitizeGroupName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "control characters stripped",
			input:    "grp\x01\a\x7fname",
			expected: "grpname",
		},
		{
			name:     "unicode preserved and trimmed",
			input:    "   گروه ۱   ",
			expected: "گروه ۱",
		},
		{
			name:     "max 64 runes enforced on long unicode string",
			input:    strings.Repeat("گ", 100),
			expected: strings.Repeat("گ", 64),
		},
		{
			name:     "empty string",
			input:    "   \x01\x7f   ",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sqlitestore.SanitizeGroupName(tt.input)
			if got != tt.expected {
				t.Errorf("SanitizeGroupName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestSanitizeGroupName_WritePaths(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// 1. AddDomainRule
	if err := store.AddDomainRule(ctx, "d1.com", "grp\x01\a\x7f", "[443]", "default", "proxy"); err != nil {
		t.Fatal(err)
	}
	r, err := store.GetDomainRule(ctx, "d1.com")
	if err != nil {
		t.Fatal(err)
	}
	if r.GroupName != "grp" {
		t.Errorf("AddDomainRule: expected group_name 'grp', got %q", r.GroupName)
	}

	// 2. UpdateDomainRule
	if err := store.UpdateDomainRule(ctx, "d1.com", "updated\x02grp", "[443]", "default", "proxy"); err != nil {
		t.Fatal(err)
	}
	r, err = store.GetDomainRule(ctx, "d1.com")
	if err != nil {
		t.Fatal(err)
	}
	if r.GroupName != "updatedgrp" {
		t.Errorf("UpdateDomainRule: expected group_name 'updatedgrp', got %q", r.GroupName)
	}

	// 3. BulkAssignDomainGroup
	if _, _, err := store.BulkAssignDomainGroup(ctx, []string{"d1.com"}, "bulk\a\x7fgrp"); err != nil {
		t.Fatal(err)
	}
	r, err = store.GetDomainRule(ctx, "d1.com")
	if err != nil {
		t.Fatal(err)
	}
	if r.GroupName != "bulkgrp" {
		t.Errorf("BulkAssignDomainGroup: expected group_name 'bulkgrp', got %q", r.GroupName)
	}

	// 4. ImportData
	importRules := []sqlitestore.DomainRuleRow{
		{Domain: "imported.com", GroupName: "imp\x01\a\x7fgrp", Ports: "[443]", UseEgressProxy: "default", Mode: "proxy"},
	}
	if _, err := store.ImportData(ctx, importRules, nil, nil); err != nil {
		t.Fatal(err)
	}
	r, err = store.GetDomainRule(ctx, "imported.com")
	if err != nil {
		t.Fatal(err)
	}
	if r.GroupName != "impgrp" {
		t.Errorf("ImportData: expected group_name 'impgrp', got %q", r.GroupName)
	}
}
