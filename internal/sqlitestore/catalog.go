package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/ixabolfazl/tls-relay/internal/catalog"
)

// CatalogNodeRow represents a row in catalog_nodes along with domain count aggregations.
type CatalogNodeRow struct {
	ID                 string `json:"id"`
	ParentID           string `json:"parent_id"` // "" for categories
	Name               string `json:"name"`
	Enabled            bool   `json:"enabled"`
	SortOrder          int    `json:"sort_order"`
	DomainCount        int    `json:"domain_count"`
	EnabledDomainCount int    `json:"enabled_domain_count"`
}

// CatalogApplySamples holds sample domain names added or updated during catalog apply.
type CatalogApplySamples struct {
	Added   []string `json:"added"`
	Updated []string `json:"updated"`
}

// CatalogApplyResult contains statistics of an ApplyCatalog operation.
type CatalogApplyResult struct {
	Version            int                 `json:"version"`
	CategoriesAdded    int                 `json:"categories_added"`
	SubcategoriesAdded int                 `json:"subcategories_added"`
	DomainsAdded       int                 `json:"domains_added"`
	DomainsUpdated     int                 `json:"domains_updated"`
	DomainsUnchanged   int                 `json:"domains_unchanged"`
	DomainsTotal       int                 `json:"domains_total"`
	DisabledNewDomains int                 `json:"disabled_new_domains"`
	Samples            CatalogApplySamples `json:"samples"`
}

// ListCatalogNodes returns all catalog nodes with domain counts and enabled-domain counts.
func (s *Store) ListCatalogNodes(ctx context.Context) ([]CatalogNodeRow, error) {
	rows, err := s.reader.QueryContext(ctx,
		`SELECT id, parent_id, name, enabled, sort_order FROM catalog_nodes ORDER BY sort_order ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("listing catalog nodes: %w", err)
	}
	defer rows.Close()

	var nodes []CatalogNodeRow
	for rows.Next() {
		var n CatalogNodeRow
		var enabled int
		if err := rows.Scan(&n.ID, &n.ParentID, &n.Name, &enabled, &n.SortOrder); err != nil {
			return nil, fmt.Errorf("scanning catalog node: %w", err)
		}
		n.Enabled = enabled != 0
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Single GROUP BY query to fetch total and enabled domain counts per catalog_node
	countRows, err := s.reader.QueryContext(ctx,
		`SELECT catalog_node, COUNT(*), SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END)
		 FROM domain_rules
		 WHERE catalog_node != ''
		 GROUP BY catalog_node`)
	if err != nil {
		return nil, fmt.Errorf("counting catalog node domains: %w", err)
	}
	defer countRows.Close()

	type counts struct {
		total   int
		enabled int
	}
	subCounts := make(map[string]counts)
	for countRows.Next() {
		var nodeID string
		var c counts
		if err := countRows.Scan(&nodeID, &c.total, &c.enabled); err != nil {
			return nil, fmt.Errorf("scanning domain counts: %w", err)
		}
		subCounts[nodeID] = c
	}

	// Assign subcategory counts and aggregate category counts
	catTotal := make(map[string]int)
	catEnabled := make(map[string]int)

	for i := range nodes {
		if nodes[i].ParentID != "" {
			c := subCounts[nodes[i].ID]
			nodes[i].DomainCount = c.total
			nodes[i].EnabledDomainCount = c.enabled
			catTotal[nodes[i].ParentID] += c.total
			catEnabled[nodes[i].ParentID] += c.enabled
		}
	}

	for i := range nodes {
		if nodes[i].ParentID == "" {
			nodes[i].DomainCount = catTotal[nodes[i].ID]
			nodes[i].EnabledDomainCount = catEnabled[nodes[i].ID]
		}
	}

	return nodes, nil
}

// SetCatalogNodeEnabled toggles the enabled state of a catalog category or subcategory
// and updates the enabled state of all associated domain rules.
func (s *Store) SetCatalogNodeEnabled(ctx context.Context, id string, enabled bool) (int, error) {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var parentID string
	var currentEnabled int
	err = tx.QueryRowContext(ctx, `SELECT parent_id, enabled FROM catalog_nodes WHERE id = ?`, id).Scan(&parentID, &currentEnabled)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("catalog node %q not found", id)
	}
	if err != nil {
		return 0, fmt.Errorf("querying catalog node: %w", err)
	}

	enabledInt := 0
	if enabled {
		enabledInt = 1
	}

	var affectedDomains int64

	if parentID == "" {
		// Category node: cascade to all subcategories and their domains
		if _, err := tx.ExecContext(ctx, `UPDATE catalog_nodes SET enabled = ? WHERE id = ?`, enabledInt, id); err != nil {
			return 0, fmt.Errorf("updating category node: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE catalog_nodes SET enabled = ? WHERE parent_id = ?`, enabledInt, id); err != nil {
			return 0, fmt.Errorf("updating child subcategories: %w", err)
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE domain_rules SET enabled = ?, updated_at = datetime('now')
			 WHERE catalog_node IN (SELECT id FROM catalog_nodes WHERE parent_id = ?)`,
			enabledInt, id)
		if err != nil {
			return 0, fmt.Errorf("updating category domains: %w", err)
		}
		affectedDomains, _ = res.RowsAffected()
	} else {
		// Subcategory node: update this subcategory and its domains.
		// If enabling a subcategory whose parent is disabled, also enable the parent (do not cascade parent's other children).
		if _, err := tx.ExecContext(ctx, `UPDATE catalog_nodes SET enabled = ? WHERE id = ?`, enabledInt, id); err != nil {
			return 0, fmt.Errorf("updating subcategory node: %w", err)
		}
		if enabled {
			if _, err := tx.ExecContext(ctx, `UPDATE catalog_nodes SET enabled = 1 WHERE id = ? AND enabled = 0`, parentID); err != nil {
				return 0, fmt.Errorf("enabling parent category: %w", err)
			}
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE domain_rules SET enabled = ?, updated_at = datetime('now') WHERE catalog_node = ?`,
			enabledInt, id)
		if err != nil {
			return 0, fmt.Errorf("updating subcategory domains: %w", err)
		}
		affectedDomains, _ = res.RowsAffected()
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("committing transaction: %w", err)
	}

	return int(affectedDomains), nil
}

// CreateCatalogNode creates a new category or subcategory node.
func (s *Store) CreateCatalogNode(ctx context.Context, id, parentID, name string) error {
	id = strings.ToLower(strings.TrimSpace(id))
	parentID = strings.ToLower(strings.TrimSpace(parentID))
	name = catalog.SanitizeName(name)
	if id == "" {
		return fmt.Errorf("node id cannot be empty")
	}
	if name == "" {
		return fmt.Errorf("node name cannot be empty")
	}

	_, err := s.writer.ExecContext(ctx,
		`INSERT INTO catalog_nodes (id, parent_id, name, enabled, sort_order) VALUES (?, ?, ?, 1, 0)`,
		id, parentID, name)
	if err != nil {
		return fmt.Errorf("inserting catalog node: %w", err)
	}
	return nil
}

// UpdateCatalogNode updates the name of an existing catalog node.
func (s *Store) UpdateCatalogNode(ctx context.Context, id, name string) error {
	id = strings.TrimSpace(id)
	name = catalog.SanitizeName(name)
	if name == "" {
		return fmt.Errorf("node name cannot be empty")
	}
	res, err := s.writer.ExecContext(ctx, `UPDATE catalog_nodes SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		return fmt.Errorf("updating catalog node: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("catalog node %q not found", id)
	}
	return nil
}

// DeleteCatalogNode removes a category or subcategory node and detaches any referencing domain rules.
func (s *Store) DeleteCatalogNode(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning delete transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var parentID string
	err = tx.QueryRowContext(ctx, `SELECT parent_id FROM catalog_nodes WHERE id = ?`, id).Scan(&parentID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("catalog node %q not found", id)
	}
	if err != nil {
		return err
	}

	if parentID == "" {
		// Category: detach domains in all child subcategories, then delete children and category
		_, err = tx.ExecContext(ctx,
			`UPDATE domain_rules SET catalog_node = '', updated_at = datetime('now')
			 WHERE catalog_node IN (SELECT id FROM catalog_nodes WHERE parent_id = ?)`, id)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM catalog_nodes WHERE parent_id = ?`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM catalog_nodes WHERE id = ?`, id); err != nil {
			return err
		}
	} else {
		// Subcategory: detach domains, then delete subcategory
		_, err = tx.ExecContext(ctx,
			`UPDATE domain_rules SET catalog_node = '', updated_at = datetime('now') WHERE catalog_node = ?`, id)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM catalog_nodes WHERE id = ?`, id); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ApplyCatalog merges a catalog into SQLite using exact merge semantics (§4).
// If dryRun is true, computes the result without writing anything to the database.
func (s *Store) ApplyCatalog(ctx context.Context, cat *catalog.Catalog, dryRun bool) (*CatalogApplyResult, error) {
	if cat == nil {
		return nil, fmt.Errorf("catalog cannot be nil")
	}

	result := &CatalogApplyResult{
		Version: cat.Version,
		Samples: CatalogApplySamples{
			Added:   []string{},
			Updated: []string{},
		},
	}

	// 1. Read existing catalog_nodes to know current enabled state and existence
	existingNodes := make(map[string]bool) // id -> enabled
	nodeRows, err := s.reader.QueryContext(ctx, `SELECT id, enabled FROM catalog_nodes`)
	if err != nil {
		return nil, fmt.Errorf("reading existing catalog nodes: %w", err)
	}
	defer nodeRows.Close()

	for nodeRows.Next() {
		var nid string
		var en int
		if err := nodeRows.Scan(&nid, &en); err != nil {
			return nil, err
		}
		existingNodes[nid] = (en == 1)
	}

	// 2. Read existing domain_rules
	type existingRule struct {
		Mode           string
		Ports          string
		GroupName      string
		CatalogNode    string
		Enabled        bool
		UseEgressProxy string
	}
	existingRules := make(map[string]existingRule)

	drRows, err := s.reader.QueryContext(ctx,
		`SELECT domain, mode, ports, group_name, catalog_node, enabled, use_egress_proxy FROM domain_rules`)
	if err != nil {
		return nil, fmt.Errorf("reading existing domain rules: %w", err)
	}
	defer drRows.Close()

	for drRows.Next() {
		var dom string
		var r existingRule
		var en int
		if err := drRows.Scan(&dom, &r.Mode, &r.Ports, &r.GroupName, &r.CatalogNode, &en, &r.UseEgressProxy); err != nil {
			return nil, err
		}
		r.Enabled = (en == 1)
		existingRules[dom] = r
	}

	// Begin write transaction if not dryRun
	var tx *sql.Tx
	var insertNodeStmt, updateNodeStmt *sql.Stmt
	var insertRuleStmt, updateRuleStmt *sql.Stmt

	if !dryRun {
		tx, err = s.writer.BeginTx(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("beginning catalog apply transaction: %w", err)
		}
		defer func() { _ = tx.Rollback() }()

		insertNodeStmt, err = tx.PrepareContext(ctx,
			`INSERT INTO catalog_nodes (id, parent_id, name, enabled, sort_order) VALUES (?, ?, ?, ?, ?)`)
		if err != nil {
			return nil, err
		}
		defer insertNodeStmt.Close()

		updateNodeStmt, err = tx.PrepareContext(ctx,
			`UPDATE catalog_nodes SET name = ?, sort_order = ? WHERE id = ?`)
		if err != nil {
			return nil, err
		}
		defer updateNodeStmt.Close()

		insertRuleStmt, err = tx.PrepareContext(ctx,
			`INSERT INTO domain_rules (domain, group_name, ports, use_egress_proxy, mode, enabled, catalog_node)
			 VALUES (?, ?, ?, 'false', ?, ?, ?)`)
		if err != nil {
			return nil, err
		}
		defer insertRuleStmt.Close()

		updateRuleStmt, err = tx.PrepareContext(ctx,
			`UPDATE domain_rules SET mode = ?, ports = ?, group_name = ?, catalog_node = ?, enabled = ?, updated_at = datetime('now')
			 WHERE domain = ?`)
		if err != nil {
			return nil, err
		}
		defer updateRuleStmt.Close()
	}

	// 3. Process categories and subcategories
	effectiveEnabled := make(map[string]bool) // subcategoryID -> effective enabled bool

	for catIdx, c := range cat.Categories {
		cDefEnabled := catalog.IsDefaultEnabled(c.DefaultEnabled)
		cEnabled := cDefEnabled
		if en, exists := existingNodes[c.ID]; exists {
			cEnabled = en
			if !dryRun {
				if _, err := updateNodeStmt.ExecContext(ctx, c.Name, catIdx, c.ID); err != nil {
					return nil, fmt.Errorf("updating category node %q: %w", c.ID, err)
				}
			}
		} else {
			result.CategoriesAdded++
			enInt := 0
			if cDefEnabled {
				enInt = 1
			}
			if !dryRun {
				if _, err := insertNodeStmt.ExecContext(ctx, c.ID, "", c.Name, enInt, catIdx); err != nil {
					return nil, fmt.Errorf("inserting category node %q: %w", c.ID, err)
				}
			}
			existingNodes[c.ID] = cDefEnabled
		}

		for subIdx, sNode := range c.Subcategories {
			sDefEnabled := catalog.IsDefaultEnabled(sNode.DefaultEnabled)
			sEnabled := sDefEnabled
			if en, exists := existingNodes[sNode.ID]; exists {
				sEnabled = en
				if !dryRun {
					if _, err := updateNodeStmt.ExecContext(ctx, sNode.Name, subIdx, sNode.ID); err != nil {
						return nil, fmt.Errorf("updating subcategory node %q: %w", sNode.ID, err)
					}
				}
			} else {
				result.SubcategoriesAdded++
				enInt := 0
				if sDefEnabled {
					enInt = 1
				}
				if !dryRun {
					if _, err := insertNodeStmt.ExecContext(ctx, sNode.ID, c.ID, sNode.Name, enInt, subIdx); err != nil {
						return nil, fmt.Errorf("inserting subcategory node %q: %w", sNode.ID, err)
					}
				}
				existingNodes[sNode.ID] = sDefEnabled
			}

			effectiveEnabled[sNode.ID] = (cEnabled && sEnabled)
		}
	}

	// 4. Process expanded domains
	expanded := catalog.Expand(cat)
	result.DomainsTotal = len(expanded)

	for _, d := range expanded {
		targetEnabled := effectiveEnabled[d.SubcategoryID]
		targetEnabledInt := 0
		if targetEnabled {
			targetEnabledInt = 1
		}

		existing, found := existingRules[d.Domain]
		if !found {
			result.DomainsAdded++
			if !targetEnabled {
				result.DisabledNewDomains++
			}
			if len(result.Samples.Added) < 20 {
				result.Samples.Added = append(result.Samples.Added, d.Domain)
			}
			if !dryRun {
				if _, err := insertRuleStmt.ExecContext(ctx,
					d.Domain, d.SubcategoryName, d.Ports, d.Mode, targetEnabledInt, d.SubcategoryID); err != nil {
					return nil, fmt.Errorf("inserting domain %q: %w", d.Domain, err)
				}
			}
		} else {
			// Check if row already matches catalog target values
			isUnchanged := existing.Mode == d.Mode &&
				existing.Ports == d.Ports &&
				existing.GroupName == d.SubcategoryName &&
				existing.CatalogNode == d.SubcategoryID &&
				existing.Enabled == targetEnabled

			if isUnchanged {
				result.DomainsUnchanged++
			} else {
				result.DomainsUpdated++
				if len(result.Samples.Updated) < 20 {
					result.Samples.Updated = append(result.Samples.Updated, d.Domain)
				}
				if !dryRun {
					if _, err := updateRuleStmt.ExecContext(ctx,
						d.Mode, d.Ports, d.SubcategoryName, d.SubcategoryID, targetEnabledInt, d.Domain); err != nil {
						return nil, fmt.Errorf("updating domain %q: %w", d.Domain, err)
					}
				}
			}
		}
	}

	if !dryRun {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("committing catalog apply: %w", err)
		}

		// Update catalog_version setting
		if err := s.SetSetting(ctx, "catalog_version", strconv.Itoa(cat.Version)); err != nil {
			return nil, fmt.Errorf("recording catalog version: %w", err)
		}
	}

	return result, nil
}
