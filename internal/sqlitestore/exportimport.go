package sqlitestore

import (
	"context"
	"fmt"
	"strings"
)

// UserWithIPs represents a user along with their registered IP addresses for export/import.
type UserWithIPs struct {
	User
	IPs []UserIP `json:"ips"`
}

// ExportData represents the complete export payload format.
type ExportData struct {
	DomainRules []DomainRuleRow  `json:"domain_rules"`
	Blacklist   []BlacklistEntry `json:"blacklist"`
	Users       []UserWithIPs    `json:"users"`
}

// ImportResult contains statistics returned after applying an import payload.
type ImportResult struct {
	DomainsAdded     int `json:"domains_added"`
	DomainsUpdated   int `json:"domains_updated"`
	BlacklistAdded   int `json:"blacklist_added"`
	BlacklistUpdated int `json:"blacklist_updated"`
	UsersAdded       int `json:"users_added"`
	UsersUpdated     int `json:"users_updated"`
}

// ExportAll retrieves all domain rules, global blacklist entries, and users with their IPs.
func (s *Store) ExportAll(ctx context.Context) (*ExportData, error) {
	rules, err := s.ListDomainRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("export domain rules: %w", err)
	}
	if rules == nil {
		rules = []DomainRuleRow{}
	}

	bl, err := s.ListBlacklist(ctx)
	if err != nil {
		return nil, fmt.Errorf("export blacklist: %w", err)
	}
	if bl == nil {
		bl = []BlacklistEntry{}
	}

	users, err := s.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("export users: %w", err)
	}

	usersWithIPs := make([]UserWithIPs, 0, len(users))
	for _, u := range users {
		ips, err := s.ListUserIPs(ctx, u.ID)
		if err != nil {
			return nil, fmt.Errorf("export user ips for user %d: %w", u.ID, err)
		}
		if ips == nil {
			ips = []UserIP{}
		}
		usersWithIPs = append(usersWithIPs, UserWithIPs{
			User: u,
			IPs:  ips,
		})
	}

	return &ExportData{
		DomainRules: rules,
		Blacklist:   bl,
		Users:       usersWithIPs,
	}, nil
}

// ImportData applies domain rules, blacklist entries, and users inside a SINGLE transaction.
func (s *Store) ImportData(ctx context.Context, domainRules []DomainRuleRow, blacklist []BlacklistEntry, users []UserWithIPs) (*ImportResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning import transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res := &ImportResult{}

	// 1. Process Domain Rules
	for _, r := range domainRules {
		domain := strings.TrimSpace(r.Domain)
		groupName := strings.TrimSpace(r.GroupName)
		ports := strings.TrimSpace(r.Ports)
		if ports == "" {
			ports = "[443]"
		}
		useProxy := strings.ToLower(strings.TrimSpace(r.UseEgressProxy))
		if useProxy == "" {
			useProxy = "default"
		}
		mode := strings.ToLower(strings.TrimSpace(r.Mode))
		if mode == "" {
			mode = "proxy"
		}

		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM domain_rules WHERE domain = ?`, domain).Scan(&count); err != nil {
			return nil, fmt.Errorf("checking domain rule %q: %w", domain, err)
		}

		if count > 0 {
			_, err = tx.ExecContext(ctx,
				`UPDATE domain_rules SET group_name = ?, ports = ?, use_egress_proxy = ?, mode = ?, updated_at = datetime('now') WHERE domain = ?`,
				groupName, ports, useProxy, mode, domain)
			if err != nil {
				return nil, fmt.Errorf("updating domain rule %q: %w", domain, err)
			}
			res.DomainsUpdated++
		} else {
			_, err = tx.ExecContext(ctx,
				`INSERT INTO domain_rules (domain, group_name, ports, use_egress_proxy, mode) VALUES (?, ?, ?, ?, ?)`,
				domain, groupName, ports, useProxy, mode)
			if err != nil {
				return nil, fmt.Errorf("inserting domain rule %q: %w", domain, err)
			}
			res.DomainsAdded++
		}
	}

	// 2. Process Blacklist Entries
	for _, b := range blacklist {
		entry := strings.TrimSpace(b.Entry)

		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM global_blacklist WHERE entry = ?`, entry).Scan(&count); err != nil {
			return nil, fmt.Errorf("checking blacklist entry %q: %w", entry, err)
		}

		if count > 0 {
			res.BlacklistUpdated++
		} else {
			_, err = tx.ExecContext(ctx, `INSERT INTO global_blacklist (entry) VALUES (?)`, entry)
			if err != nil {
				return nil, fmt.Errorf("inserting blacklist entry %q: %w", entry, err)
			}
			res.BlacklistAdded++
		}
	}

	// 3. Process Users and their Registered IPs
	for _, u := range users {
		username := strings.TrimSpace(u.Username)
		if username == "" {
			continue
		}
		maxIPs := u.MaxIPs
		if maxIPs <= 0 {
			maxIPs = 3
		}

		var userID int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE username = ?`, username).Scan(&userID)
		if err == nil && userID > 0 {
			// User exists -> update properties
			enabledVal := 1
			if !u.Enabled {
				enabledVal = 0
			}
			_, err = tx.ExecContext(ctx,
				`UPDATE users SET max_ips = ?, enabled = ?, updated_at = datetime('now') WHERE id = ?`,
				maxIPs, enabledVal, userID,
			)
			if err != nil {
				return nil, fmt.Errorf("updating user %q: %w", username, err)
			}
			res.UsersUpdated++
		} else {
			// User does not exist -> insert new user
			link := strings.TrimSpace(u.MagicLink)
			if link == "" {
				link, err = generateMagicLink()
				if err != nil {
					return nil, fmt.Errorf("generating magic link for user %q: %w", username, err)
				}
			}
			enabledVal := 1
			if !u.Enabled {
				enabledVal = 0
			}
			r, err := tx.ExecContext(ctx,
				`INSERT INTO users (username, max_ips, magic_link, enabled) VALUES (?, ?, ?, ?)`,
				username, maxIPs, link, enabledVal,
			)
			if err != nil {
				return nil, fmt.Errorf("inserting user %q: %w", username, err)
			}
			userID, _ = r.LastInsertId()
			res.UsersAdded++
		}

		// Insert user IPs if any
		for _, ip := range u.IPs {
			ipStr := strings.TrimSpace(ip.IPAddress)
			if ipStr == "" {
				continue
			}
			_, _ = tx.ExecContext(ctx,
				`INSERT INTO user_ips (user_id, ip_address) VALUES (?, ?) ON CONFLICT DO NOTHING`,
				userID, ipStr,
			)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing import transaction: %w", err)
	}

	return res, nil
}
