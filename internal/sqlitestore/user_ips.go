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
	rows, err := s.reader.QueryContext(ctx,
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

// RegisterIPResult registers a client IP for the user, enforcing max_ips (<= 0 means unlimited).
// Returns isNew=true if the IP was newly inserted, isNew=false if it already existed for this user.
func (s *Store) RegisterIPResult(ctx context.Context, userID int64, ip string, maxIPs int) (bool, error) {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return false, err
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
			return false, err
		}
		return false, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return false, err
	}

	// Count current IPs for the user if maxIPs > 0 (maxIPs <= 0 means unlimited).
	if maxIPs > 0 {
		var count int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM user_ips WHERE user_id = ?`, userID,
		).Scan(&count); err != nil {
			return false, err
		}

		// If at or above max, evict the oldest IPs so count + 1 <= maxIPs.
		if count >= maxIPs {
			toEvict := count - maxIPs + 1
			_, err = tx.ExecContext(ctx,
				`DELETE FROM user_ips WHERE id IN (
					SELECT id FROM user_ips WHERE user_id = ? ORDER BY created_at ASC LIMIT ?
				)`, userID, toEvict)
			if err != nil {
				return false, err
			}
		}
	}

	// Add the new IP.
	_, err = tx.ExecContext(ctx,
		`INSERT INTO user_ips (user_id, ip_address) VALUES (?, ?)`, userID, ip)
	if err != nil {
		return false, err
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// RegisterIP registers a client IP for the user, enforcing max_ips.
func (s *Store) RegisterIP(ctx context.Context, userID int64, ip string, maxIPs int) error {
	_, err := s.RegisterIPResult(ctx, userID, ip, maxIPs)
	return err
}

// DeleteUserIP removes a specific IP from a user.
func (s *Store) DeleteUserIP(ctx context.Context, userID int64, ip string) error {
	_, err := s.writer.ExecContext(ctx,
		`DELETE FROM user_ips WHERE user_id = ? AND ip_address = ?`, userID, ip)
	return err
}

// DeleteAllUserIPs removes all registered IPs for a user and returns the count removed.
func (s *Store) DeleteAllUserIPs(ctx context.Context, userID int64) (int, error) {
	res, err := s.writer.ExecContext(ctx,
		`DELETE FROM user_ips WHERE user_id = ?`, userID)
	if err != nil {
		return 0, err
	}
	ra, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return int(ra), nil
}

// CountUserIPs returns the number of IPs registered for a user.
func (s *Store) CountUserIPs(ctx context.Context, userID int64) (int, error) {
	var count int
	err := s.reader.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_ips WHERE user_id = ?`, userID).Scan(&count)
	return count, err
}

// AllEnabledUserIPs returns all IPs belonging to enabled users (for in-memory snapshot).
func (s *Store) AllEnabledUserIPs(ctx context.Context) ([]string, error) {
	rows, err := s.reader.QueryContext(ctx,
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

// GetUsersIPCounts returns a map of user_id -> count of registered IPs for that user.
func (s *Store) GetUsersIPCounts(ctx context.Context) (map[int64]int, error) {
	rows, err := s.reader.QueryContext(ctx,
		`SELECT user_id, COUNT(*) FROM user_ips GROUP BY user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[int64]int)
	for rows.Next() {
		var (
			userID int64
			count  int
		)
		if err := rows.Scan(&userID, &count); err != nil {
			return nil, err
		}
		counts[userID] = count
	}
	return counts, rows.Err()
}
