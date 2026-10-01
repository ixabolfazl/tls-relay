package sqlitestore_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/catalog"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

func TestCatalog_MigrationIdempotency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old_catalog.db")

	// Create legacy DB without catalog_nodes and catalog_node column
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacyDDL := `CREATE TABLE domain_rules (
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		domain           TEXT    NOT NULL UNIQUE,
		group_name       TEXT    NOT NULL DEFAULT '',
		ports            TEXT    NOT NULL DEFAULT '[443]',
		use_egress_proxy TEXT    NOT NULL DEFAULT 'default',
		mode             TEXT    NOT NULL DEFAULT 'proxy',
		enabled          INTEGER NOT NULL DEFAULT 1,
		total_bytes_sent INTEGER NOT NULL DEFAULT 0,
		total_bytes_received INTEGER NOT NULL DEFAULT 0,
		created_at       DATETIME NOT NULL DEFAULT (datetime('now')),
		updated_at       DATETIME NOT NULL DEFAULT (datetime('now'))
	);`
	if _, err := db.Exec(legacyDDL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO domain_rules (domain) VALUES ('legacy.com')`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Open with sqlitestore.New — should apply migration automatically
	store, err := sqlitestore.New(path)
	if err != nil {
		t.Fatalf("sqlitestore.New failed: %v", err)
	}

	ctx := context.Background()
	rules, err := store.ListDomainRules(ctx)
	if err != nil {
		t.Fatalf("ListDomainRules failed: %v", err)
	}
	if len(rules) != 1 || rules[0].CatalogNode != "" {
		t.Errorf("expected 1 legacy rule with empty catalog_node, got %+v", rules)
	}
	_ = store.Close()

	// Reopen to confirm idempotency
	store2, err := sqlitestore.New(path)
	if err != nil {
		t.Fatalf("reopening store failed: %v", err)
	}
	_ = store2.Close()
}

func TestCatalog_ApplyCatalog(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// 1. Pre-insert a manual domain that will also be in the catalog (adoption test)
	// and a manual domain NOT in catalog (never delete test)
	if err := store.AddDomainRule(ctx, "manual.com", "Manual Group", "[80]", "default", "direct"); err != nil {
		t.Fatalf("pre-insert manual.com: %v", err)
	}
	if err := store.AddDomainRule(ctx, "unrelated.org", "Unrelated Group", "[443]", "default", "proxy"); err != nil {
		t.Fatalf("pre-insert unrelated.org: %v", err)
	}

	catJSON := `{
		"version": 1,
		"categories": [
			{
				"id": "social",
				"name": "Social Media",
				"default_enabled": true,
				"subcategories": [
					{
						"id": "social.telegram",
						"name": "Telegram",
						"default_enabled": true,
						"domains": [
							{"domain": "telegram.org", "wildcard": true},
							{"domain": "manual.com", "mode": "proxy", "ports": [443]}
						]
					},
					{
						"id": "social.other",
						"name": "Other Social",
						"default_enabled": false,
						"domains": [
							{"domain": "dis.com"}
						]
					}
				]
			}
		]
	}`

	cat, err := catalog.Parse([]byte(catJSON))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 2. Dry run test: writes nothing
	dryRes, err := store.ApplyCatalog(ctx, cat, true)
	if err != nil {
		t.Fatalf("ApplyCatalog dry-run error: %v", err)
	}
	if dryRes.DomainsAdded != 3 { // telegram.org, *.telegram.org, dis.com
		t.Errorf("dry-run expected 3 added, got %d", dryRes.DomainsAdded)
	}
	if dryRes.DomainsUpdated != 1 { // manual.com
		t.Errorf("dry-run expected 1 updated, got %d", dryRes.DomainsUpdated)
	}
	if dryRes.DisabledNewDomains != 1 { // dis.com is under disabled subcategory
		t.Errorf("dry-run expected 1 disabled new domain, got %d", dryRes.DisabledNewDomains)
	}

	// Verify DB state unchanged after dry run
	nodesAfterDry, _ := store.ListCatalogNodes(ctx)
	if len(nodesAfterDry) != 0 {
		t.Fatalf("expected 0 catalog nodes after dry run, got %d", len(nodesAfterDry))
	}

	// 3. Real Apply
	res, err := store.ApplyCatalog(ctx, cat, false)
	if err != nil {
		t.Fatalf("ApplyCatalog real apply error: %v", err)
	}
	if res.CategoriesAdded != 1 || res.SubcategoriesAdded != 2 {
		t.Errorf("expected 1 cat and 2 subs added, got %d and %d", res.CategoriesAdded, res.SubcategoriesAdded)
	}
	if res.DomainsAdded != 3 || res.DomainsUpdated != 1 {
		t.Errorf("expected 3 added, 1 updated, got added=%d updated=%d", res.DomainsAdded, res.DomainsUpdated)
	}

	// Verify catalog_version setting recorded
	val, ok, _ := store.GetSetting(ctx, "catalog_version")
	if !ok || val != "1" {
		t.Errorf("expected catalog_version=1, got %q (found=%v)", val, ok)
	}

	// Verify adopted domain was updated
	adopted, err := store.GetDomainRule(ctx, "manual.com")
	if err != nil {
		t.Fatalf("GetDomainRule manual.com: %v", err)
	}
	if adopted.Mode != "proxy" || adopted.Ports != "[443]" || adopted.CatalogNode != "social.telegram" || adopted.GroupName != "Telegram" {
		t.Errorf("unexpected adopted domain rule: %+v", adopted)
	}

	// Verify unrelated domain was NOT deleted
	unrelated, err := store.GetDomainRule(ctx, "unrelated.org")
	if err != nil || unrelated == nil {
		t.Fatalf("unrelated.org should still exist: %v", err)
	}

	// Verify disabled subcategory new domain arrived disabled
	disRule, err := store.GetDomainRule(ctx, "dis.com")
	if err != nil {
		t.Fatalf("GetDomainRule dis.com: %v", err)
	}
	if disRule.Enabled {
		t.Errorf("expected dis.com to arrive disabled, got enabled=true")
	}

	// 4. Re-apply unchanged catalog: all should be unchanged
	res2, err := store.ApplyCatalog(ctx, cat, false)
	if err != nil {
		t.Fatalf("second apply error: %v", err)
	}
	if res2.DomainsAdded != 0 || res2.DomainsUpdated != 0 || res2.DomainsUnchanged != 4 {
		t.Errorf("expected 0 added, 0 updated, 4 unchanged; got added=%d updated=%d unchanged=%d",
			res2.DomainsAdded, res2.DomainsUpdated, res2.DomainsUnchanged)
	}

	// 5. Admin disables subcategory: re-apply must respect admin's choice
	_, err = store.SetCatalogNodeEnabled(ctx, "social.telegram", false)
	if err != nil {
		t.Fatalf("SetCatalogNodeEnabled failed: %v", err)
	}

	// Re-apply catalog: social.telegram should remain disabled in catalog_nodes
	_, err = store.ApplyCatalog(ctx, cat, false)
	if err != nil {
		t.Fatalf("re-apply after admin disable failed: %v", err)
	}
	nodes, _ := store.ListCatalogNodes(ctx)
	for _, n := range nodes {
		if n.ID == "social.telegram" && n.Enabled {
			t.Errorf("expected social.telegram to stay disabled after catalog re-apply")
		}
	}
}

func TestCatalog_SetCatalogNodeEnabled(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	catJSON := `{
		"version": 1,
		"categories": [
			{
				"id": "cat1",
				"name": "Cat 1",
				"default_enabled": true,
				"subcategories": [
					{
						"id": "cat1.sub1",
						"name": "Sub 1",
						"default_enabled": true,
						"domains": [{"domain": "d1.com"}]
					},
					{
						"id": "cat1.sub2",
						"name": "Sub 2",
						"default_enabled": true,
						"domains": [{"domain": "d2.com"}]
					}
				]
			}
		]
	}`
	cat, err := catalog.Parse([]byte(catJSON))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyCatalog(ctx, cat, false); err != nil {
		t.Fatal(err)
	}

	// Disable category -> cascades to sub1, sub2, d1, d2
	affected, err := store.SetCatalogNodeEnabled(ctx, "cat1", false)
	if err != nil {
		t.Fatalf("SetCatalogNodeEnabled(cat1, false): %v", err)
	}
	if affected != 2 {
		t.Errorf("expected 2 affected domains, got %d", affected)
	}

	nodes, _ := store.ListCatalogNodes(ctx)
	for _, n := range nodes {
		if n.Enabled {
			t.Errorf("expected node %s to be disabled", n.ID)
		}
	}
	r1, _ := store.GetDomainRule(ctx, "d1.com")
	r2, _ := store.GetDomainRule(ctx, "d2.com")
	if r1.Enabled || r2.Enabled {
		t.Errorf("expected both domains to be disabled")
	}

	// Subcategory enable when parent is disabled:
	// Enabling sub1 should enable parent cat1, but leave sub2 disabled!
	affectedSub, err := store.SetCatalogNodeEnabled(ctx, "cat1.sub1", true)
	if err != nil {
		t.Fatalf("SetCatalogNodeEnabled(cat1.sub1, true): %v", err)
	}
	if affectedSub != 1 {
		t.Errorf("expected 1 affected domain, got %d", affectedSub)
	}

	nodesMap := make(map[string]sqlitestore.CatalogNodeRow)
	nodes, _ = store.ListCatalogNodes(ctx)
	for _, n := range nodes {
		nodesMap[n.ID] = n
	}

	if !nodesMap["cat1"].Enabled {
		t.Errorf("expected parent cat1 to be auto-enabled")
	}
	if !nodesMap["cat1.sub1"].Enabled {
		t.Errorf("expected cat1.sub1 to be enabled")
	}
	if nodesMap["cat1.sub2"].Enabled {
		t.Errorf("expected cat1.sub2 to remain disabled")
	}

	r1, _ = store.GetDomainRule(ctx, "d1.com")
	r2, _ = store.GetDomainRule(ctx, "d2.com")
	if !r1.Enabled {
		t.Errorf("expected d1.com to be enabled")
	}
	if r2.Enabled {
		t.Errorf("expected d2.com to stay disabled")
	}
}

func TestCatalog_ImportData_HonoursEnabledAndCatalogNode(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Initial import with disabled rule and catalog_node
	rules := []sqlitestore.DomainRuleRow{
		{
			Domain:      "example.org",
			GroupName:   "Grp",
			Ports:       "[443]",
			Mode:        "proxy",
			Enabled:     false,
			CatalogNode: "cat1.sub1",
		},
	}

	res, err := store.ImportData(ctx, rules, nil, nil)
	if err != nil {
		t.Fatalf("ImportData failed: %v", err)
	}
	if res.DomainsAdded != 1 {
		t.Errorf("expected 1 domain added, got %d", res.DomainsAdded)
	}

	r, err := store.GetDomainRule(ctx, "example.org")
	if err != nil {
		t.Fatalf("GetDomainRule: %v", err)
	}
	if r.Enabled {
		t.Errorf("expected enabled=false, got true")
	}
	if r.CatalogNode != "cat1.sub1" {
		t.Errorf("expected catalog_node='cat1.sub1', got %q", r.CatalogNode)
	}

	// Update via import with enabled=true and changed catalog_node
	rules[0].Enabled = true
	rules[0].CatalogNode = "cat2.sub2"

	res2, err := store.ImportData(ctx, rules, nil, nil)
	if err != nil {
		t.Fatalf("second ImportData failed: %v", err)
	}
	if res2.DomainsUpdated != 1 {
		t.Errorf("expected 1 domain updated, got %d", res2.DomainsUpdated)
	}

	rUpdated, err := store.GetDomainRule(ctx, "example.org")
	if err != nil {
		t.Fatalf("GetDomainRule after update: %v", err)
	}
	if !rUpdated.Enabled {
		t.Errorf("expected enabled=true after update")
	}
	if rUpdated.CatalogNode != "cat2.sub2" {
		t.Errorf("expected catalog_node='cat2.sub2', got %q", rUpdated.CatalogNode)
	}
}

func TestCatalog_ExportImportRoundTrip(t *testing.T) {
	store1 := newTestStore(t)
	ctx := context.Background()

	// Populate store1 with catalog nodes and domain rules
	if err := store1.CreateCatalogNode(ctx, "social", "", "Social Media"); err != nil {
		t.Fatal(err)
	}
	if err := store1.CreateCatalogNode(ctx, "social.telegram", "social", "Telegram"); err != nil {
		t.Fatal(err)
	}
	if err := store1.AddDomainRuleWithNode(ctx, "t.me", "Telegram", "[443]", "default", "proxy", "social.telegram"); err != nil {
		t.Fatal(err)
	}

	exp, err := store1.ExportAll(ctx)
	if err != nil {
		t.Fatalf("ExportAll: %v", err)
	}
	if len(exp.CatalogNodes) != 2 {
		t.Errorf("expected 2 catalog nodes exported, got %d", len(exp.CatalogNodes))
	}
	if len(exp.DomainRules) != 1 {
		t.Errorf("expected 1 domain rule exported, got %d", len(exp.DomainRules))
	}

	// Import into clean store2
	store2 := newTestStore(t)

	_, err = store2.ImportData(ctx, exp.DomainRules, exp.Blacklist, exp.Users, exp.CatalogNodes)
	if err != nil {
		t.Fatalf("ImportData into store2 failed: %v", err)
	}

	nodes2, err := store2.ListCatalogNodes(ctx)
	if err != nil {
		t.Fatalf("ListCatalogNodes store2: %v", err)
	}
	if len(nodes2) != 2 {
		t.Errorf("expected 2 catalog nodes in store2, got %d", len(nodes2))
	}
	r2, err := store2.GetDomainRule(ctx, "t.me")
	if err != nil {
		t.Fatalf("GetDomainRule store2: %v", err)
	}
	if r2.CatalogNode != "social.telegram" {
		t.Errorf("expected catalog_node='social.telegram', got %q", r2.CatalogNode)
	}
}

func TestCatalog_NodeCRUD(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if err := store.CreateCatalogNode(ctx, "tools", "", "Tools"); err != nil {
		t.Fatalf("CreateCatalogNode category: %v", err)
	}
	if err := store.CreateCatalogNode(ctx, "tools.dns", "tools", "DNS Tools"); err != nil {
		t.Fatalf("CreateCatalogNode subcategory: %v", err)
	}

	// Update subcategory name
	if err := store.UpdateCatalogNode(ctx, "tools.dns", "DNS & Network Tools"); err != nil {
		t.Fatalf("UpdateCatalogNode: %v", err)
	}

	// Assign a domain rule to tools.dns
	if err := store.AddDomainRuleWithNode(ctx, "dns.google", "DNS & Network Tools", "[443]", "default", "proxy", "tools.dns"); err != nil {
		t.Fatal(err)
	}

	// Delete subcategory: should detach domain rule
	if err := store.DeleteCatalogNode(ctx, "tools.dns"); err != nil {
		t.Fatalf("DeleteCatalogNode: %v", err)
	}

	r, err := store.GetDomainRule(ctx, "dns.google")
	if err != nil {
		t.Fatalf("GetDomainRule after node delete: %v", err)
	}
	if r.CatalogNode != "" {
		t.Errorf("expected catalog_node to be cleared (''), got %q", r.CatalogNode)
	}
}

func TestCatalog_StartupAutoLoadLogic(t *testing.T) {
	ctx := context.Background()

	// Helper matching cmd/relay/main.go startup auto-load logic
	shouldAutoLoad := func(s *sqlitestore.Store) bool {
		catVer, hasCatVer, err := s.GetSetting(ctx, sqlitestore.SettingCatalogVersion)
		if err != nil || (hasCatVer && strings.TrimSpace(catVer) != "") {
			return false
		}
		rules, err := s.ListDomainRules(ctx)
		return err == nil && len(rules) == 0
	}

	// 1. Fresh empty DB -> should auto load
	freshStore := newTestStore(t)
	if !shouldAutoLoad(freshStore) {
		t.Errorf("expected fresh empty store to trigger auto-load")
	}

	// 2. Existing store with rules but no catalog_version (upgrade scenario) -> should NOT auto load
	existingStore := newTestStore(t)
	if err := existingStore.AddDomainRule(ctx, "custom.org", "custom", "[443]", "default", "proxy"); err != nil {
		t.Fatal(err)
	}
	if shouldAutoLoad(existingStore) {
		t.Errorf("expected existing store with rules to NOT trigger auto-load")
	}

	// 3. Store with catalog_version already set -> should NOT auto load
	installedStore := newTestStore(t)
	if err := installedStore.SetSetting(ctx, sqlitestore.SettingCatalogVersion, "1"); err != nil {
		t.Fatal(err)
	}
	if shouldAutoLoad(installedStore) {
		t.Errorf("expected store with catalog_version set to NOT trigger auto-load")
	}
}
