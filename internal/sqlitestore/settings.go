package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
)

// GetSetting retrieves a setting value by key. Returns value, found bool, error.
func (s *Store) GetSetting(ctx context.Context, key string) (string, bool, error) {
	var val string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM app_settings WHERE key = ?`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("getting setting %q: %w", key, err)
	}
	return val, true, nil
}

// SetSetting sets or updates a setting value by key (upsert).
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("setting %q: %w", key, err)
	}
	return nil
}

// SetSettings sets or updates multiple settings in a single transaction.
func (s *Store) SetSettings(ctx context.Context, settings map[string]string) error {
	if len(settings) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning settings transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
	if err != nil {
		return fmt.Errorf("preparing settings statement: %w", err)
	}
	defer stmt.Close()

	for k, v := range settings {
		if _, err := stmt.ExecContext(ctx, k, v); err != nil {
			return fmt.Errorf("setting %q: %w", k, err)
		}
	}
	return tx.Commit()
}

// AllSettings retrieves all stored key-value settings.
func (s *Store) AllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM app_settings`)
	if err != nil {
		return nil, fmt.Errorf("querying settings: %w", err)
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("scanning setting row: %w", err)
		}
		settings[k] = v
	}
	return settings, rows.Err()
}
