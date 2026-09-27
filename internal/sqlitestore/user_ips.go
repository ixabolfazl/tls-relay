package sqlitestore

import (
	"context"
	"database/sql"
)

// UserIP represents a row in the user_ips table.
type UserIP struct {
	ID         int64  `json:"id"`
	UserID     int64  `json:"user_id"`
	IPAddress  string `json:"ip_address"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at"`
}

// ListUserIPs returns all IPs for a given user.
func (s *Store) ListUserIPs(ctx context.Context, userID int64) ([]UserIP, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, ip_address, created_at, last_used_at FROM user_ips WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []UserIP
	for rows.Next() {
		var ip UserIP
		if err := rows.Scan(&ip.ID, &ip.UserID, &ip.IPAddress, &ip.CreatedAt, &ip.LastUsedAt); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

// RegisterIP registers a client IP for the user, enforcing max_ips.
//
// If the IP already exists: update last_used_at.
// If IP count < maxIPs: add the IP.
// If IP count == maxIPs: remove the oldest IP by created_at, then add the new IP.
func (s *Store) RegisterIP(ctx context.Context, userID int64, ip string, maxIPs int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Check if IP already exists for this user.
	var existingID int64
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM user_ips WHERE user_id = ? AND ip_address = ?`, userID, ip,
	).Scan(&existingID)
	if err == nil {
		// IP already exists — update last_used_at.
		_, err = tx.ExecContext(ctx,
			`UPDATE user_ips SET last_used_at = datetime('now') WHERE id = ?`, existingID)
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	if err != sql.ErrNoRows {
		return err
	}

	// Count current IPs for the user.
	var count int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_ips WHERE user_id = ?`, userID,
	).Scan(&count); err != nil {
		return err
	}

	// If at or above max, evict the oldest IPs so count + 1 <= maxIPs.
	if count >= maxIPs {
		toEvict := count - maxIPs + 1
		_, err = tx.ExecContext(ctx,
			`DELETE FROM user_ips WHERE id IN (
				SELECT id FROM user_ips WHERE user_id = ? ORDER BY created_at ASC LIMIT ?
			)`, userID, toEvict)
		if err != nil {
			return err
		}
	}

	// Add the new IP.
	_, err = tx.ExecContext(ctx,
		`INSERT INTO user_ips (user_id, ip_address) VALUES (?, ?)`, userID, ip)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// DeleteUserIP removes a specific IP from a user.
func (s *Store) DeleteUserIP(ctx context.Context, userID int64, ip string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_ips WHERE user_id = ? AND ip_address = ?`, userID, ip)
	return err
}

// CountUserIPs returns the number of IPs registered for a user.
func (s *Store) CountUserIPs(ctx context.Context, userID int64) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_ips WHERE user_id = ?`, userID).Scan(&count)
	return count, err
}

// AllEnabledUserIPs returns all IPs belonging to enabled users (for in-memory snapshot).
func (s *Store) AllEnabledUserIPs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ui.ip_address FROM user_ips ui
		 JOIN users u ON u.id = ui.user_id
		 WHERE u.enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}
