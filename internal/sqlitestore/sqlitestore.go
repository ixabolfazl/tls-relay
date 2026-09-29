// Package sqlitestore provides a SQLite-backed persistent store for users,
// user IPs, global blacklist, and domain rules. It uses modernc.org/sqlite
// which is a pure-Go SQLite implementation (CGO_ENABLED=0 compatible).
package sqlitestore

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// Store wraps a writer *sql.DB and a reader *sql.DB connected to a SQLite database.
type Store struct {
	writer *sql.DB
	reader *sql.DB

	reqLogsCountCache    atomic.Int64
	reqLogsCountCachedAt atomic.Int64 // unix nano
}

// New opens (or creates) a SQLite database at the given path. It creates
// the parent directory if it doesn't exist, applies PRAGMAs, and runs
// schema migration.
func New(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating sqlite directory %q: %w", dir, err)
	}

	dsn := path
	if !strings.Contains(path, "?") {
		dsn = path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	}

	writer, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database %q: %w", path, err)
	}

	// modernc pure-Go SQLite works best with serialized writes to prevent SQLITE_BUSY.
	writer.SetMaxOpenConns(1)
	writer.SetMaxIdleConns(1)
	writer.SetConnMaxLifetime(0)

	// Apply PRAGMAs explicitly as well.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
		"PRAGMA synchronous=NORMAL",
	}
	for _, p := range pragmas {
		if _, err := writer.Exec(p); err != nil {
			_ = writer.Close()
			return nil, fmt.Errorf("executing %q: %w", p, err)
		}
	}

	s := &Store{writer: writer}
	if err := s.migrate(); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("migrating schema: %w", err)
	}

	// 0600 on the DB file after opening
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		_ = os.Chmod(path, 0o600)
	}

	// Open reader connection pool (MaxOpenConns(4), mode=ro, same pragmas, WAL)
	var reader *sql.DB
	if path == ":memory:" || strings.HasPrefix(path, "file::memory:") {
		reader = writer
	} else {
		readerDSN := path
		if !strings.Contains(path, "?") {
			readerDSN = path + "?mode=ro&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
		} else {
			readerDSN = path + "&mode=ro"
		}

		rdb, err := sql.Open("sqlite", readerDSN)
		if err != nil {
			_ = writer.Close()
			return nil, fmt.Errorf("opening sqlite reader database %q: %w", path, err)
		}
		rdb.SetMaxOpenConns(4)
		rdb.SetMaxIdleConns(4)
		rdb.SetConnMaxLifetime(0)

		for _, p := range pragmas {
			if _, err := rdb.Exec(p); err != nil {
				_ = rdb.Close()
				_ = writer.Close()
				return nil, fmt.Errorf("executing reader %q: %w", p, err)
			}
		}
		reader = rdb
	}

	s.reader = reader

	slog.Info("sqlite store initialized", "path", path)
	return s, nil
}

// Close closes the database connections.
func (s *Store) Close() error {
	var errs []string
	if s.reader != nil && s.reader != s.writer {
		if err := s.reader.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if s.writer != nil {
		if err := s.writer.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("closing sqlite connections: %s", strings.Join(errs, "; "))
	}
	return nil
}

// DB returns the underlying writer *sql.DB for advanced usage (e.g. transactions in tests).
func (s *Store) DB() *sql.DB {
	return s.writer
}

// ReaderDB returns the underlying reader *sql.DB.
func (s *Store) ReaderDB() *sql.DB {
	return s.reader
}

func (s *Store) migrate() error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id                   INTEGER PRIMARY KEY AUTOINCREMENT,
			username             TEXT    NOT NULL UNIQUE,
			enabled              INTEGER NOT NULL DEFAULT 1,
			magic_link           TEXT    NOT NULL UNIQUE,
			max_ips              INTEGER NOT NULL DEFAULT 3,
			created_at           DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at           DATETIME NOT NULL DEFAULT (datetime('now')),
			last_seen_at         DATETIME,
			total_bytes_sent     INTEGER NOT NULL DEFAULT 0,
			total_bytes_received INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS user_ips (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			ip_address   TEXT    NOT NULL,
			created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
			last_used_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(user_id, ip_address)
		)`,
		`CREATE TABLE IF NOT EXISTS global_blacklist (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			entry      TEXT    NOT NULL UNIQUE,
			created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS domain_rules (
			id                   INTEGER PRIMARY KEY AUTOINCREMENT,
			domain               TEXT    NOT NULL UNIQUE,
			group_name           TEXT    NOT NULL DEFAULT '',
			ports                TEXT    NOT NULL DEFAULT '[443]',
			use_egress_proxy     TEXT    NOT NULL DEFAULT 'default',
			mode                 TEXT    NOT NULL DEFAULT 'proxy',
			enabled              INTEGER NOT NULL DEFAULT 1,
			total_bytes_sent     INTEGER NOT NULL DEFAULT 0,
			total_bytes_received INTEGER NOT NULL DEFAULT 0,
			created_at           DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at           DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS app_settings (
			key        TEXT PRIMARY KEY,
			value      TEXT NOT NULL,
			updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS request_logs (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id      INTEGER,
			username     TEXT NOT NULL DEFAULT '',
			client_ip    TEXT NOT NULL,
			request_type TEXT NOT NULL,
			protocol     TEXT NOT NULL DEFAULT 'TLS',
			domain       TEXT NOT NULL,
			port         INTEGER NOT NULL DEFAULT 0,
			status       TEXT NOT NULL DEFAULT '',
			created_at   DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_request_logs_created_at ON request_logs(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_request_logs_domain ON request_logs(domain)`,
		`CREATE INDEX IF NOT EXISTS idx_request_logs_client_ip ON request_logs(client_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_request_logs_type_id ON request_logs(request_type, id)`,
		`CREATE INDEX IF NOT EXISTS idx_request_logs_user_id ON request_logs(user_id, id)`,
		`CREATE TABLE IF NOT EXISTS user_usage_daily (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			usage_date     TEXT    NOT NULL,
			bytes_sent     INTEGER NOT NULL DEFAULT 0,
			bytes_received INTEGER NOT NULL DEFAULT 0,
			UNIQUE(user_id, usage_date)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_user_usage_daily_user_date ON user_usage_daily(user_id, usage_date)`,
		`CREATE TABLE IF NOT EXISTS domain_usage_daily (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			domain         TEXT    NOT NULL,
			usage_date     TEXT    NOT NULL,
			bytes_sent     INTEGER NOT NULL DEFAULT 0,
			bytes_received INTEGER NOT NULL DEFAULT 0,
			UNIQUE(domain, usage_date)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_domain_usage_daily_domain_date ON domain_usage_daily(domain, usage_date)`,
		`CREATE TABLE IF NOT EXISTS user_domain_usage_daily (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			domain         TEXT    NOT NULL,
			usage_date     TEXT    NOT NULL,
			bytes_sent     INTEGER NOT NULL DEFAULT 0,
			bytes_received INTEGER NOT NULL DEFAULT 0,
			UNIQUE(user_id, domain, usage_date)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_user_domain_usage_daily_user_domain ON user_domain_usage_daily(user_id, domain)`,
		`CREATE INDEX IF NOT EXISTS idx_user_domain_usage_daily_domain_date ON user_domain_usage_daily(domain, usage_date)`,
		`CREATE TABLE IF NOT EXISTS request_stats_daily (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			stat_date    TEXT    NOT NULL,
			request_type TEXT    NOT NULL,
			category     TEXT    NOT NULL,
			count        INTEGER NOT NULL DEFAULT 0,
			UNIQUE(stat_date, request_type, category)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_request_stats_daily_date ON request_stats_daily(stat_date)`,
		`CREATE TABLE IF NOT EXISTS protocol_usage_daily (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			protocol       TEXT    NOT NULL,
			usage_date     TEXT    NOT NULL,
			bytes_sent     INTEGER NOT NULL DEFAULT 0,
			bytes_received INTEGER NOT NULL DEFAULT 0,
			UNIQUE(protocol, usage_date)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_protocol_usage_daily_proto_date ON protocol_usage_daily(protocol, usage_date)`,
		`CREATE TABLE IF NOT EXISTS user_dns_usage_daily (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			usage_date  TEXT    NOT NULL,
			query_count INTEGER NOT NULL DEFAULT 0,
			UNIQUE(user_id, usage_date)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_user_dns_usage_daily_user_date ON user_dns_usage_daily(user_id, usage_date)`,
		`CREATE TABLE IF NOT EXISTS domain_dns_usage_daily (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			domain      TEXT    NOT NULL,
			usage_date  TEXT    NOT NULL,
			query_count INTEGER NOT NULL DEFAULT 0,
			UNIQUE(domain, usage_date)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_domain_dns_usage_daily_domain_date ON domain_dns_usage_daily(domain, usage_date)`,
	}
	for _, ddl := range tables {
		if _, err := s.writer.Exec(ddl); err != nil {
			return fmt.Errorf("executing DDL: %w\n%s", err, ddl)
		}
	}

	// Migration: Add group_name, total_bytes_sent, total_bytes_received columns to domain_rules if missing.
	rows, err := s.writer.Query(`PRAGMA table_info(domain_rules)`)
	if err != nil {
		return fmt.Errorf("inspecting domain_rules table info: %w", err)
	}
	defer rows.Close()

	hasGroupName := false
	hasDomainBytesSent := false
	hasDomainBytesReceived := false
	hasMode := false
	for rows.Next() {
		var cid int
		var name, typeStr string
		var notNull int
		var dfltValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typeStr, &notNull, &dfltValue, &pk); err != nil {
			return fmt.Errorf("scanning domain_rules table_info row: %w", err)
		}
		switch name {
		case "group_name":
			hasGroupName = true
		case "total_bytes_sent":
			hasDomainBytesSent = true
		case "total_bytes_received":
			hasDomainBytesReceived = true
		case "mode":
			hasMode = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("domain_rules table_info iteration error: %w", err)
	}

	if !hasGroupName {
		if _, err := s.writer.Exec(`ALTER TABLE domain_rules ADD COLUMN group_name TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("adding group_name column to domain_rules: %w", err)
		}
	}
	if !hasDomainBytesSent {
		if _, err := s.writer.Exec(`ALTER TABLE domain_rules ADD COLUMN total_bytes_sent INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("adding total_bytes_sent column to domain_rules: %w", err)
		}
	}
	if !hasDomainBytesReceived {
		if _, err := s.writer.Exec(`ALTER TABLE domain_rules ADD COLUMN total_bytes_received INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("adding total_bytes_received column to domain_rules: %w", err)
		}
	}
	if !hasMode {
		if _, err := s.writer.Exec(`ALTER TABLE domain_rules ADD COLUMN mode TEXT NOT NULL DEFAULT 'proxy'`); err != nil {
			return fmt.Errorf("adding mode column to domain_rules: %w", err)
		}
	}

	// Migration: Add last_seen_at, total_bytes_sent, total_bytes_received columns to users if missing.
	userRows, err := s.writer.Query(`PRAGMA table_info(users)`)
	if err == nil {
		hasLastSeen := false
		hasBytesSent := false
		hasBytesReceived := false
		for userRows.Next() {
			var cid int
			var name, typeStr string
			var notNull int
			var dfltValue sql.NullString
			var pk int
			if err := userRows.Scan(&cid, &name, &typeStr, &notNull, &dfltValue, &pk); err == nil {
				switch name {
				case "last_seen_at":
					hasLastSeen = true
				case "total_bytes_sent":
					hasBytesSent = true
				case "total_bytes_received":
					hasBytesReceived = true
				}
			}
		}
		_ = userRows.Close()
		if !hasLastSeen {
			if _, err := s.writer.Exec(`ALTER TABLE users ADD COLUMN last_seen_at DATETIME`); err != nil {
				return fmt.Errorf("adding last_seen_at column to users: %w", err)
			}
		}
		if !hasBytesSent {
			if _, err := s.writer.Exec(`ALTER TABLE users ADD COLUMN total_bytes_sent INTEGER NOT NULL DEFAULT 0`); err != nil {
				return fmt.Errorf("adding total_bytes_sent column to users: %w", err)
			}
		}
		if !hasBytesReceived {
			if _, err := s.writer.Exec(`ALTER TABLE users ADD COLUMN total_bytes_received INTEGER NOT NULL DEFAULT 0`); err != nil {
				return fmt.Errorf("adding total_bytes_received column to users: %w", err)
			}
		}
	}

	// Migration: Add protocol column to request_logs if missing.
	reqLogRows, err := s.writer.Query(`PRAGMA table_info(request_logs)`)
	if err == nil {
		hasProtocol := false
		for reqLogRows.Next() {
			var cid int
			var name, typeStr string
			var notNull int
			var dfltValue sql.NullString
			var pk int
			if err := reqLogRows.Scan(&cid, &name, &typeStr, &notNull, &dfltValue, &pk); err == nil {
				if name == "protocol" {
					hasProtocol = true
				}
			}
		}
		_ = reqLogRows.Close()
		if !hasProtocol {
			_, _ = s.writer.Exec(`ALTER TABLE request_logs ADD COLUMN protocol TEXT NOT NULL DEFAULT 'TLS'`)
		}
	}

	return nil
}

func quoteSQLiteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func generateMagicLink() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// FormatTime formats a time.Time to SQLite-compatible datetime string.
func FormatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}

func parseTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02 15:04:05", raw)
}
