package sqlitestore

import (
	"context"
)

// BlacklistEntry represents a row in the global_blacklist table.
type BlacklistEntry struct {
	ID        int64  `json:"id"`
	Entry     string `json:"entry"`
	CreatedAt string `json:"created_at"`
}

// ListBlacklist returns all blacklist entries.
func (s *Store) ListBlacklist(ctx context.Context) ([]BlacklistEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, entry, created_at FROM global_blacklist ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []BlacklistEntry
	for rows.Next() {
		var e BlacklistEntry
		if err := rows.Scan(&e.ID, &e.Entry, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// AddBlacklistEntry adds an IP or CIDR to the global blacklist.
func (s *Store) AddBlacklistEntry(ctx context.Context, entry string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO global_blacklist (entry) VALUES (?)`, entry)
	return err
}

// DeleteBlacklistEntry removes a blacklist entry by ID.
func (s *Store) DeleteBlacklistEntry(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM global_blacklist WHERE id = ?`, id)
	return err
}

// AllBlacklistEntries returns all blacklist entries as strings (for in-memory snapshot).
func (s *Store) AllBlacklistEntries(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT entry FROM global_blacklist`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// BulkDeleteBlacklist deletes multiple blacklist entries by ID.
func (s *Store) BulkDeleteBlacklist(ctx context.Context, ids []int64) (int, int, error) {
	deleted := 0
	skipped := 0
	for _, id := range ids {
		res, err := s.db.ExecContext(ctx, `DELETE FROM global_blacklist WHERE id = ?`, id)
		if err != nil {
			return deleted, skipped, err
		}
		rows, _ := res.RowsAffected()
		if rows > 0 {
			deleted++
		} else {
			skipped++
		}
	}
	return deleted, skipped, nil
}
