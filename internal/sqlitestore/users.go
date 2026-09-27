package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// User represents a row in the users table with aggregated last_seen_at timestamp.
type User struct {
	ID         int64  `json:"id"`
	Username   string `json:"username"`
	Enabled    bool   `json:"enabled"`
	MagicLink  string `json:"magic_link"`
	MaxIPs     int    `json:"max_ips"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	LastSeenAt string `json:"last_seen_at"`
}

// CreateUser creates a new user with an auto-generated magic link.
func (s *Store) CreateUser(ctx context.Context, username string, maxIPs int) (*User, error) {
	return s.CreateUserWithLink(ctx, username, maxIPs, "")
}

// CreateUserWithLink creates a new user with a custom or auto-generated magic link token.
func (s *Store) CreateUserWithLink(ctx context.Context, username string, maxIPs int, customLink string) (*User, error) {
	link := strings.TrimSpace(customLink)
	if link == "" {
		var err error
		link, err = generateMagicLink()
		if err != nil {
			return nil, fmt.Errorf("generating magic link: %w", err)
		}
	}

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, max_ips, magic_link) VALUES (?, ?, ?)`,
		username, maxIPs, link,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting user: %w", err)
	}

	id, _ := res.LastInsertId()
	return s.GetUser(ctx, id)
}

// GetUser retrieves a user by ID.
func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	u := &User{}
	var enabled int
	var lastSeen sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT u.id, u.username, u.enabled, u.magic_link, u.max_ips, u.created_at, u.updated_at,
		        COALESCE(u.last_seen_at, (SELECT MAX(last_used_at) FROM user_ips WHERE user_id = u.id)) AS last_seen_at
		 FROM users u WHERE u.id = ?`, id,
	).Scan(&u.ID, &u.Username, &enabled, &u.MagicLink, &u.MaxIPs, &u.CreatedAt, &u.UpdatedAt, &lastSeen)
	if err != nil {
		return nil, err
	}
	u.Enabled = enabled != 0
	if lastSeen.Valid {
		u.LastSeenAt = lastSeen.String
	}
	return u, nil
}

// ListUsers returns all users with their last_seen_at timestamp.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT u.id, u.username, u.enabled, u.magic_link, u.max_ips, u.created_at, u.updated_at,
		        COALESCE(u.last_seen_at, MAX(i.last_used_at)) AS last_seen_at
		 FROM users u
		 LEFT JOIN user_ips i ON u.id = i.user_id
		 GROUP BY u.id
		 ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var enabled int
		var lastSeen sql.NullString
		if err := rows.Scan(&u.ID, &u.Username, &enabled, &u.MagicLink, &u.MaxIPs, &u.CreatedAt, &u.UpdatedAt, &lastSeen); err != nil {
			return nil, err
		}
		u.Enabled = enabled != 0
		if lastSeen.Valid {
			u.LastSeenAt = lastSeen.String
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// UpdateUserLastSeen updates a user's last_seen_at timestamp.
func (s *Store) UpdateUserLastSeen(ctx context.Context, userID int64, lastSeen time.Time) error {
	ts := FormatTime(lastSeen)
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET last_seen_at = ? WHERE id = ?`,
		ts, userID,
	)
	return err
}

// IsIPRegistered checks if an IP address is registered to any active user.
func (s *Store) IsIPRegistered(ctx context.Context, ip string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM user_ips WHERE ip_address = ?)`, ip).Scan(&exists)
	return exists, err
}

// UserIPMapping represents an IP address mapping to a registered user.
type UserIPMapping struct {
	UserID    int64
	Username  string
	IPAddress string
}

// UserWithAllIPs represents a user along with their associated IPs and last seen timestamp.
type UserWithAllIPs struct {
	UserID     int64
	Username   string
	LastSeenAt string
	IPs        []string
}

// ListAllUserWithIPs returns all users and their registered IPs in a single query.
func (s *Store) ListAllUserWithIPs(ctx context.Context) ([]UserWithAllIPs, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.username,
		       COALESCE(u.last_seen_at, (SELECT MAX(last_used_at) FROM user_ips WHERE user_id = u.id), ''),
		       COALESCE(ui.ip_address, '')
		FROM users u
		LEFT JOIN user_ips ui ON u.id = ui.user_id
		ORDER BY u.id, ui.created_at
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []UserWithAllIPs
	var cur *UserWithAllIPs

	for rows.Next() {
		var (
			uid      int64
			username string
			lastSeen string
			ip       string
		)
		if err := rows.Scan(&uid, &username, &lastSeen, &ip); err != nil {
			return nil, err
		}
		if cur == nil || cur.UserID != uid {
			result = append(result, UserWithAllIPs{
				UserID:     uid,
				Username:   username,
				LastSeenAt: lastSeen,
			})
			cur = &result[len(result)-1]
		}
		if ip != "" {
			cur.IPs = append(cur.IPs, ip)
		}
	}
	return result, rows.Err()
}

// GetAllUserIPMappings returns all registered IP mappings for users.
func (s *Store) GetAllUserIPMappings(ctx context.Context) ([]UserIPMapping, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ui.user_id, u.username, ui.ip_address
		 FROM user_ips ui
		 JOIN users u ON u.id = ui.user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mappings []UserIPMapping
	for rows.Next() {
		var m UserIPMapping
		if err := rows.Scan(&m.UserID, &m.Username, &m.IPAddress); err != nil {
			return nil, err
		}
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

// UpdateUser updates a user's enabled status and max_ips.
func (s *Store) UpdateUser(ctx context.Context, id int64, enabled bool, maxIPs int) error {
	return s.UpdateUserFull(ctx, id, "", enabled, maxIPs, "")
}

// UpdateUserFull updates a user's username, enabled status, max_ips, and magic link token.
func (s *Store) UpdateUserFull(ctx context.Context, id int64, username string, enabled bool, maxIPs int, magicLink string) error {
	e := 0
	if enabled {
		e = 1
	}
	current, err := s.GetUser(ctx, id)
	if err != nil {
		return err
	}
	uName := strings.TrimSpace(username)
	if uName == "" {
		uName = current.Username
	}
	mLink := strings.TrimSpace(magicLink)
	if mLink == "" {
		mLink = current.MagicLink
	}

	_, err = s.db.ExecContext(ctx,
		`UPDATE users SET username = ?, enabled = ?, max_ips = ?, magic_link = ?, updated_at = datetime('now') WHERE id = ?`,
		uName, e, maxIPs, mLink, id,
	)
	return err
}

// DeleteUser deletes a user by ID. Cascade deletes user_ips.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// GetUserByMagicLink retrieves a user by their magic link.
func (s *Store) GetUserByMagicLink(ctx context.Context, link string) (*User, error) {
	u := &User{}
	var enabled int
	var lastSeen sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT u.id, u.username, u.enabled, u.magic_link, u.max_ips, u.created_at, u.updated_at,
		        COALESCE(u.last_seen_at, (SELECT MAX(last_used_at) FROM user_ips WHERE user_id = u.id)) AS last_seen_at
		 FROM users u WHERE u.magic_link = ?`, link,
	).Scan(&u.ID, &u.Username, &enabled, &u.MagicLink, &u.MaxIPs, &u.CreatedAt, &u.UpdatedAt, &lastSeen)
	if err != nil {
		return nil, err
	}
	u.Enabled = enabled != 0
	if lastSeen.Valid {
		u.LastSeenAt = lastSeen.String
	}
	return u, nil
}

// ResetMagicLink generates a new magic link for the user, invalidating the old one.
func (s *Store) ResetMagicLink(ctx context.Context, userID int64) (string, error) {
	link, err := generateMagicLink()
	if err != nil {
		return "", fmt.Errorf("generating magic link: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE users SET magic_link = ?, updated_at = datetime('now') WHERE id = ?`,
		link, userID,
	)
	if err != nil {
		return "", err
	}
	return link, nil
}

// NewMagicLink is an alias for ResetMagicLink.
func (s *Store) NewMagicLink(ctx context.Context, userID int64) (string, error) {
	return s.ResetMagicLink(ctx, userID)
}
