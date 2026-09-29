package sqlitestore

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
)

// SanitizeGroupName strips control characters (<0x20, 0x7f), trims whitespace,
// and limits the group name to at most 64 runes.
func SanitizeGroupName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	cleaned := strings.TrimSpace(b.String())
	runes := []rune(cleaned)
	if len(runes) > 64 {
		runes = runes[:64]
	}
	return string(runes)
}

// DomainRuleRow represents a row in the domain_rules table.
type DomainRuleRow struct {
	ID             int64  `json:"id"`
	Domain         string `json:"domain"`
	GroupName      string `json:"group_name"`
	Ports          string `json:"ports"`            // JSON: [443] or "all"
	UseEgressProxy string `json:"use_egress_proxy"` // "default", "true", "false"
	Mode           string `json:"mode"`             // "proxy", "direct", "block"
	Enabled        bool   `json:"enabled"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

// ListDomainRules returns all domain rule rows.
func (s *Store) ListDomainRules(ctx context.Context) ([]DomainRuleRow, error) {
	rows, err := s.reader.QueryContext(ctx,
		`SELECT id, domain, group_name, ports, use_egress_proxy, mode, enabled, created_at, updated_at FROM domain_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []DomainRuleRow
	for rows.Next() {
		var r DomainRuleRow
		var enabled int
		if err := rows.Scan(&r.ID, &r.Domain, &r.GroupName, &r.Ports, &r.UseEgressProxy, &r.Mode, &enabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// GetDomainRule retrieves a single domain rule row by domain name.
func (s *Store) GetDomainRule(ctx context.Context, domain string) (*DomainRuleRow, error) {
	r := &DomainRuleRow{}
	var enabled int
	err := s.reader.QueryRowContext(ctx,
		`SELECT id, domain, group_name, ports, use_egress_proxy, mode, enabled, created_at, updated_at FROM domain_rules WHERE domain = ?`, domain,
	).Scan(&r.ID, &r.Domain, &r.GroupName, &r.Ports, &r.UseEgressProxy, &r.Mode, &enabled, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	r.Enabled = enabled != 0
	return r, nil
}

// AddDomainRule inserts or replaces a domain rule.
func (s *Store) AddDomainRule(ctx context.Context, domain, groupName, ports, useEgressProxy, mode string) error {
	groupName = SanitizeGroupName(groupName)
	if mode == "" {
		mode = "proxy"
	}
	_, err := s.writer.ExecContext(ctx,
		`INSERT INTO domain_rules (domain, group_name, ports, use_egress_proxy, mode)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(domain) DO UPDATE SET group_name = excluded.group_name, ports = excluded.ports, use_egress_proxy = excluded.use_egress_proxy, mode = excluded.mode, updated_at = datetime('now')`,
		domain, groupName, ports, useEgressProxy, mode,
	)
	return err
}

// UpdateDomainRule updates an existing domain rule.
func (s *Store) UpdateDomainRule(ctx context.Context, domain, groupName, ports, useEgressProxy, mode string) error {
	groupName = SanitizeGroupName(groupName)
	if mode == "" {
		mode = "proxy"
	}
	_, err := s.writer.ExecContext(ctx,
		`UPDATE domain_rules SET group_name = ?, ports = ?, use_egress_proxy = ?, mode = ?, updated_at = datetime('now') WHERE domain = ?`,
		groupName, ports, useEgressProxy, mode, domain,
	)
	return err
}

// DeleteDomainRule deletes a domain rule by domain name.
func (s *Store) DeleteDomainRule(ctx context.Context, domain string) error {
	_, err := s.writer.ExecContext(ctx, `DELETE FROM domain_rules WHERE domain = ?`, domain)
	return err
}

type domainRuleRawPayload struct {
	GroupName      string          `json:"group_name,omitempty"`
	Ports          json.RawMessage `json:"ports"`
	UseEgressProxy string          `json:"use_egress_proxy,omitempty"`
	Mode           string          `json:"mode,omitempty"`
}

// AllDomainRulesRaw returns all enabled domain rules in the same
// map[domain]json format used by RuleStore.Swap().
func (s *Store) AllDomainRulesRaw(ctx context.Context) (map[string]string, error) {
	rows, err := s.reader.QueryContext(ctx,
		`SELECT domain, group_name, ports, use_egress_proxy, mode FROM domain_rules WHERE enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var domain, groupName, ports, useProxy, mode string
		if err := rows.Scan(&domain, &groupName, &ports, &useProxy, &mode); err != nil {
			return nil, err
		}
		if mode == "" {
			mode = "proxy"
		}
		ports = strings.TrimSpace(ports)
		if ports == "" {
			ports = "[443]"
		} else if !strings.HasPrefix(ports, "[") {
			if ports == "all" || ports == `"all"` {
				ports = `"all"`
			} else {
				ports = "[" + ports + "]"
			}
		}
		if !json.Valid([]byte(ports)) {
			slog.Error("skipping domain rule with invalid ports JSON", "domain", domain, "ports", ports)
			continue
		}

		payload := domainRuleRawPayload{
			GroupName:      groupName,
			Ports:          json.RawMessage(ports),
			UseEgressProxy: useProxy,
			Mode:           mode,
		}

		data, err := json.Marshal(payload)
		if err != nil {
			slog.Error("failed to marshal domain rule, skipping", "domain", domain, "error", err)
			continue
		}
		result[domain] = string(data)
	}
	return result, rows.Err()
}

// BulkDeleteDomainRules deletes multiple domain rules by name, returning deleted and skipped counts.
func (s *Store) BulkDeleteDomainRules(ctx context.Context, domains []string) (int, int, error) {
	deleted := 0
	skipped := 0
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			skipped++
			continue
		}
		res, err := s.writer.ExecContext(ctx, `DELETE FROM domain_rules WHERE domain = ?`, d)
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

// BulkAssignDomainGroup updates the group_name for multiple existing domain rules.
func (s *Store) BulkAssignDomainGroup(ctx context.Context, domains []string, groupName string) (int, int, error) {
	groupName = SanitizeGroupName(groupName)
	updated := 0
	skipped := 0
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			skipped++
			continue
		}
		res, err := s.writer.ExecContext(ctx, `UPDATE domain_rules SET group_name = ?, updated_at = datetime('now') WHERE domain = ?`, groupName, d)
		if err != nil {
			return updated, skipped, err
		}
		rows, _ := res.RowsAffected()
		if rows > 0 {
			updated++
		} else {
			skipped++
		}
	}
	return updated, skipped, nil
}

// BulkAssignDomainEgress updates the use_egress_proxy for multiple existing domain rules.
func (s *Store) BulkAssignDomainEgress(ctx context.Context, domains []string, useEgress string) (int, int, error) {
	if len(domains) == 0 {
		return 0, 0, nil
	}
	useEgress = strings.ToLower(strings.TrimSpace(useEgress))
	if useEgress != "true" && useEgress != "false" && useEgress != "default" {
		useEgress = "default"
	}

	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `UPDATE domain_rules SET use_egress_proxy = ?, updated_at = datetime('now') WHERE domain = ?`)
	if err != nil {
		return 0, 0, err
	}
	defer stmt.Close()

	updated := 0
	failed := 0
	for _, domain := range domains {
		res, err := stmt.ExecContext(ctx, useEgress, domain)
		if err != nil {
			failed++
			continue
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			updated++
		} else {
			failed++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, len(domains), err
	}
	return updated, failed, nil
}

// BulkAssignDomainMode updates the mode field for multiple domain rules.
func (s *Store) BulkAssignDomainMode(ctx context.Context, domains []string, mode string) (int, int, error) {
	if len(domains) == 0 {
		return 0, 0, nil
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "proxy" && mode != "direct" && mode != "block" {
		mode = "proxy"
	}

	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `UPDATE domain_rules SET mode = ?, updated_at = datetime('now') WHERE domain = ?`)
	if err != nil {
		return 0, 0, err
	}
	defer stmt.Close()

	updated := 0
	failed := 0
	for _, domain := range domains {
		res, err := stmt.ExecContext(ctx, mode, domain)
		if err != nil {
			failed++
			continue
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			updated++
		} else {
			failed++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, len(domains), err
	}
	return updated, failed, nil
}
