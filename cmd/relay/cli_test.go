package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/panel"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/requestlog"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

func writeTestConfig(t *testing.T, dbPath string) string {
	t.Helper()
	cfgContent := `listen:
  addr: "127.0.0.1"
  ports: [443]
sqlite:
  path: "` + dbPath + `"
access_mode: "user"
panel:
  addr: "127.0.0.1:8080"
  path: "/admin"
logging:
  request_logs:
    enabled: true
    retention: 24h
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatalf("writing test config: %v", err)
	}
	return cfgPath
}

func TestCLI_SettingsGetAndSet(t *testing.T) {
	dbDir := t.TempDir()
	dbPath := filepath.Join(dbDir, "test.db")
	cfgPath := writeTestConfig(t, dbPath)

	// 1. Set access_mode to public
	if err := handleSettingsCmd(cfgPath, []string{"set", "access_mode", "public"}); err != nil {
		t.Fatalf("settings set access_mode failed: %v", err)
	}

	// 2. Get access_mode
	store, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	defer store.Close()

	val, found, err := store.GetSetting(context.Background(), "access_mode")
	if err != nil || !found || val != "public" {
		t.Errorf("expected access_mode=public, got found=%v, val=%q, err=%v", found, val, err)
	}

	// 3. Test invalid setting key or value
	if err := handleSettingsCmd(cfgPath, []string{"set", "access_mode", "invalid_mode"}); err == nil {
		t.Error("expected error setting invalid access_mode, got nil")
	}

	if err := handleSettingsCmd(cfgPath, []string{"set", "unknown_key", "val"}); err == nil {
		t.Error("expected error setting unknown key, got nil")
	}

	// 4. Test get command
	if err := handleSettingsCmd(cfgPath, []string{"get", "access_mode"}); err != nil {
		t.Errorf("settings get access_mode failed: %v", err)
	}

	if err := handleSettingsCmd(cfgPath, []string{"get"}); err != nil {
		t.Errorf("settings get (all) failed: %v", err)
	}
}

func TestCLI_Backup(t *testing.T) {
	dbDir := t.TempDir()
	dbPath := filepath.Join(dbDir, "source.db")
	cfgPath := writeTestConfig(t, dbPath)

	// Initialize source database
	store, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	_ = store.SetSetting(context.Background(), "test_key", "test_val")
	store.Close()

	backupDir := filepath.Join(t.TempDir(), "backups")
	backupPath := filepath.Join(backupDir, "backup.db")

	if err := handleBackupCmd(cfgPath, backupPath); err != nil {
		t.Fatalf("backup cmd failed: %v", err)
	}

	// Verify backup file exists and permissions
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("backup stat failed: %v", err)
	}
	if info.Size() == 0 {
		t.Errorf("backup file is empty")
	}

	// Verify parent dir permissions (0700) and file permissions (0600)
	dirInfo, err := os.Stat(backupDir)
	if err == nil {
		perm := dirInfo.Mode().Perm()
		if perm != 0o700 {
			t.Errorf("backup dir permission expected 0700, got %o", perm)
		}
	}
	filePerm := info.Mode().Perm()
	if filePerm != 0o600 {
		t.Errorf("backup file permission expected 0600, got %o", filePerm)
	}

	// Verify content of backup
	backupStore, err := sqlitestore.New(backupPath)
	if err != nil {
		t.Fatalf("opening backup store: %v", err)
	}
	defer backupStore.Close()

	val, found, err := backupStore.GetSetting(context.Background(), "test_key")
	if err != nil || !found || val != "test_val" {
		t.Errorf("expected test_key=test_val in backup, got found=%v, val=%q, err=%v", found, val, err)
	}
}

func TestCLI_InitAdmin(t *testing.T) {
	dbDir := t.TempDir()
	dbPath := filepath.Join(dbDir, "admin.db")
	cfgPath := writeTestConfig(t, dbPath)

	if err := handleInitAdmin(cfgPath, "custom_admin", "SuperSecure123!"); err != nil {
		t.Fatalf("handleInitAdmin failed: %v", err)
	}

	store, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	defer store.Close()

	user, found, err := store.GetSetting(context.Background(), "panel_admin_user")
	if err != nil || !found || user != "custom_admin" {
		t.Errorf("expected user=custom_admin, got %q (found: %v, err: %v)", user, found, err)
	}

	hash, found, err := store.GetSetting(context.Background(), "panel_admin_password_hash")
	if err != nil || !found || len(hash) == 0 {
		t.Errorf("expected password hash, got %q (found: %v, err: %v)", hash, found, err)
	}

	// Short password should fail
	if err := handleInitAdmin(cfgPath, "admin", "123"); err == nil {
		t.Error("expected error for password < 6 chars, got nil")
	}
}

func TestCLI_ReloadSettings(t *testing.T) {
	dbDir := t.TempDir()
	dbPath := filepath.Join(dbDir, "reload.db")
	store, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	_ = store.SetSetting(ctx, "panel_admin_user", "admin")
	_ = store.SetSetting(ctx, "panel_admin_password_hash", "$2a$10$dummyhashxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

	cfg := &config.Config{
		AccessMode: "user",
		Panel: config.PanelConfig{
			Path: "/admin",
		},
		UnknownDomainPolicy: "reject",
		AllowedDestPorts:    []int{443},
		Limits: config.LimitConfig{
			MaxConnectionsPerIP: 100,
		},
		Timezone: "UTC",
	}

	accessStore := access.NewAccessStore(access.ModeUser)
	ruleStore := rules.NewRuleStore([]int{443}, "reject")
	allowList := relay.NewPortAllowList([]int{443})
	limits := relay.NewLimitTracker(1000, 100)
	reqLogger := requestlog.New(store, 24*time.Hour, true)
	panelSrv, err := panel.New("127.0.0.1:8080", "/admin", ruleStore, accessStore, store, nil)
	if err != nil {
		t.Fatalf("panel.New failed: %v", err)
	}

	comp := &RuntimeComponents{
		Cfg:         cfg,
		SqlStore:    store,
		RuleStore:   ruleStore,
		AccessStore: accessStore,
		AllowList:   allowList,
		Limits:      limits,
		ReqLogger:   reqLogger,
		PanelSrv:    panelSrv,
	}

	if accessStore.Mode() != access.ModeUser {
		t.Fatalf("expected initial mode to be user")
	}

	// Modify settings in SQLite: switch access mode to public, change panel path to /secret
	_ = store.SetSetting(ctx, "access_mode", "public")
	_ = store.SetSetting(ctx, "panel_path", "/secret")
	_ = store.SetSetting(ctx, "unknown_domain_policy", "allow_default_port")
	_ = store.SetSetting(ctx, "max_connections_per_ip", "250")
	_ = store.SetSetting(ctx, "panel_admin_user", "reloaded_admin")

	// Trigger ReloadSettings
	if err := ReloadSettings(ctx, comp); err != nil {
		t.Fatalf("ReloadSettings failed: %v", err)
	}

	// Verify runtime state updated without restarting listeners
	if accessStore.Mode() != access.ModePublic {
		t.Errorf("expected accessStore mode to be public after reload, got %v", accessStore.Mode())
	}
	if ruleStore.UnknownDomainPolicy() != "allow_default_port" {
		t.Errorf("expected unknown domain policy allow_default_port, got %q", ruleStore.UnknownDomainPolicy())
	}
	if cfg.Panel.Path != "/secret" {
		t.Errorf("expected panel path /secret, got %q", cfg.Panel.Path)
	}
	if cfg.Limits.MaxConnectionsPerIP != 250 {
		t.Errorf("expected max connections per IP 250, got %d", cfg.Limits.MaxConnectionsPerIP)
	}
}
