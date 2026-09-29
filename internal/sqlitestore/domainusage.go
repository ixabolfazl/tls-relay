package sqlitestore

import (
	"context"
	"time"
)

// DomainUsageTotal represents cumulative byte totals for a domain rule.
type DomainUsageTotal struct {
	BytesSent     int64 `json:"bytes_sent"`
	BytesReceived int64 `json:"bytes_received"`
}

// DomainUsageDayRow represents a single day's usage for a domain.
type DomainUsageDayRow struct {
	Date          string `json:"date"` // "YYYY-MM-DD" UTC
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
	DNSQueries    int64  `json:"dns_queries"`
}

// DomainUsageMonthRow represents a single month's usage for a domain.
type DomainUsageMonthRow struct {
	Month         string `json:"month"` // "YYYY-MM" UTC
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
}

// UserDomainUsageDayRow represents a single day's usage for a user on a domain.
type UserDomainUsageDayRow struct {
	Date          string `json:"date"` // "YYYY-MM-DD" UTC
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
}

// UserDomainTotalRow represents total usage for a user on a domain.
type UserDomainTotalRow struct {
	Domain        string `json:"domain"`
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
}

// DomainUserTotalRow represents total usage for a domain by a user.
type DomainUserTotalRow struct {
	UserID        int64  `json:"user_id"`
	Username      string `json:"username"`
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
}

// IncrementDomainUsage updates the cumulative totals on domain_rules (best-effort)
// and upserts the daily usage row in domain_usage_daily in one transaction.
func (s *Store) IncrementDomainUsage(ctx context.Context, domain string, bytesSent, bytesReceived int64, date time.Time) error {
	if bytesSent == 0 && bytesReceived == 0 {
		return nil
	}

	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Best effort UPDATE domain_rules — rule may have been deleted, ignore if 0 rows affected.
	_, err = tx.ExecContext(ctx,
		`UPDATE domain_rules
		    SET total_bytes_sent     = total_bytes_sent     + ?,
		        total_bytes_received = total_bytes_received + ?
		  WHERE domain = ?`,
		bytesSent, bytesReceived, domain,
	)
	if err != nil {
		return err
	}

	dayStr := utcDayString(date)
	_, err = tx.ExecContext(ctx,
		`INSERT INTO domain_usage_daily (domain, usage_date, bytes_sent, bytes_received)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(domain, usage_date) DO UPDATE
		    SET bytes_sent     = bytes_sent     + excluded.bytes_sent,
		        bytes_received = bytes_received + excluded.bytes_received`,
		domain, dayStr, bytesSent, bytesReceived,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// IncrementUserDomainUsage upserts the daily usage row in user_domain_usage_daily.
func (s *Store) IncrementUserDomainUsage(ctx context.Context, userID int64, domain string, bytesSent, bytesReceived int64, date time.Time) error {
	if bytesSent == 0 && bytesReceived == 0 {
		return nil
	}

	dayStr := utcDayString(date)
	_, err := s.writer.ExecContext(ctx,
		`INSERT INTO user_domain_usage_daily (user_id, domain, usage_date, bytes_sent, bytes_received)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(user_id, domain, usage_date) DO UPDATE
		    SET bytes_sent     = bytes_sent     + excluded.bytes_sent,
		        bytes_received = bytes_received + excluded.bytes_received`,
		userID, domain, dayStr, bytesSent, bytesReceived,
	)
	return err
}

// GetDomainUsageDaily returns daily usage rows for a domain starting from sinceDate (UTC day).
func (s *Store) GetDomainUsageDaily(ctx context.Context, domain string, sinceDate time.Time) ([]DomainUsageDayRow, error) {
	dayStr := utcDayString(sinceDate)
	rows, err := s.reader.QueryContext(ctx,
		`SELECT usage_date, bytes_sent, bytes_received
		   FROM domain_usage_daily
		  WHERE domain = ? AND usage_date >= ?
		  ORDER BY usage_date ASC`,
		domain, dayStr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DomainUsageDayRow
	for rows.Next() {
		var r DomainUsageDayRow
		if err := rows.Scan(&r.Date, &r.BytesSent, &r.BytesReceived); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetDomainUsageMonthly returns monthly usage rows for a domain starting from sinceDate (UTC day).
func (s *Store) GetDomainUsageMonthly(ctx context.Context, domain string, sinceDate time.Time) ([]DomainUsageMonthRow, error) {
	dayStr := utcDayString(sinceDate)
	rows, err := s.reader.QueryContext(ctx,
		`SELECT substr(usage_date, 1, 7) AS month, SUM(bytes_sent), SUM(bytes_received)
		   FROM domain_usage_daily
		  WHERE domain = ? AND usage_date >= ?
		  GROUP BY substr(usage_date, 1, 7)
		  ORDER BY month ASC`,
		domain, dayStr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DomainUsageMonthRow
	for rows.Next() {
		var r DomainUsageMonthRow
		if err := rows.Scan(&r.Month, &r.BytesSent, &r.BytesReceived); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListDomainsTotalUsage returns a map of domain -> DomainUsageTotal for domain rules.
// If sinceDate is not zero, usage is aggregated from domain_usage_daily for dates >= sinceDate.
func (s *Store) ListDomainsTotalUsage(ctx context.Context, sinceDate time.Time) (map[string]DomainUsageTotal, error) {
	if sinceDate.IsZero() {
		rows, err := s.reader.QueryContext(ctx,
			`SELECT domain, total_bytes_sent, total_bytes_received FROM domain_rules`,
		)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		out := make(map[string]DomainUsageTotal)
		for rows.Next() {
			var domain string
			var sent, received int64
			if err := rows.Scan(&domain, &sent, &received); err != nil {
				return nil, err
			}
			out[domain] = DomainUsageTotal{
				BytesSent:     sent,
				BytesReceived: received,
			}
		}
		return out, rows.Err()
	}

	dayStr := utcDayString(sinceDate)
	rows, err := s.reader.QueryContext(ctx,
		`SELECT domain, COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0)
		   FROM domain_usage_daily
		  WHERE usage_date >= ?
		  GROUP BY domain`,
		dayStr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]DomainUsageTotal)
	for rows.Next() {
		var domain string
		var sent, received int64
		if err := rows.Scan(&domain, &sent, &received); err != nil {
			return nil, err
		}
		out[domain] = DomainUsageTotal{
			BytesSent:     sent,
			BytesReceived: received,
		}
	}
	return out, rows.Err()
}

// GetUserDomainUsageDaily returns daily usage rows for a (user_id, domain) pair starting from sinceDate.
func (s *Store) GetUserDomainUsageDaily(ctx context.Context, userID int64, domain string, sinceDate time.Time) ([]UserDomainUsageDayRow, error) {
	dayStr := utcDayString(sinceDate)
	rows, err := s.reader.QueryContext(ctx,
		`SELECT usage_date, bytes_sent, bytes_received
		   FROM user_domain_usage_daily
		  WHERE user_id = ? AND domain = ? AND usage_date >= ?
		  ORDER BY usage_date ASC`,
		userID, domain, dayStr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UserDomainUsageDayRow
	for rows.Next() {
		var r UserDomainUsageDayRow
		if err := rows.Scan(&r.Date, &r.BytesSent, &r.BytesReceived); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetUserDomainUsageTotal returns total bytes sent and received for a (user_id, domain) pair.
func (s *Store) GetUserDomainUsageTotal(ctx context.Context, userID int64, domain string) (bytesSent, bytesReceived int64, err error) {
	err = s.reader.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0)
		   FROM user_domain_usage_daily
		  WHERE user_id = ? AND domain = ?`,
		userID, domain,
	).Scan(&bytesSent, &bytesReceived)
	return bytesSent, bytesReceived, err
}

// ListUserUsageByDomain returns usage totals per domain for a given user, ordered by total bytes DESC.
// If sinceDate is provided, aggregates only usage on or after sinceDate.
func (s *Store) ListUserUsageByDomain(ctx context.Context, userID int64, sinceDate ...time.Time) ([]UserDomainTotalRow, error) {
	var query string
	var args []interface{}
	if len(sinceDate) > 0 && !sinceDate[0].IsZero() {
		dayStr := utcDayString(sinceDate[0])
		query = `SELECT domain, SUM(bytes_sent), SUM(bytes_received)
		   FROM user_domain_usage_daily
		  WHERE user_id = ? AND usage_date >= ?
		  GROUP BY domain
		  ORDER BY (SUM(bytes_sent) + SUM(bytes_received)) DESC`
		args = []interface{}{userID, dayStr}
	} else {
		query = `SELECT domain, SUM(bytes_sent), SUM(bytes_received)
		   FROM user_domain_usage_daily
		  WHERE user_id = ?
		  GROUP BY domain
		  ORDER BY (SUM(bytes_sent) + SUM(bytes_received)) DESC`
		args = []interface{}{userID}
	}

	rows, err := s.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UserDomainTotalRow
	for rows.Next() {
		var r UserDomainTotalRow
		if err := rows.Scan(&r.Domain, &r.BytesSent, &r.BytesReceived); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListDomainUsageByUser returns usage totals per user for a given domain, ordered by total bytes DESC.
// If sinceDate is provided, aggregates only usage on or after sinceDate.
func (s *Store) ListDomainUsageByUser(ctx context.Context, domain string, sinceDate ...time.Time) ([]DomainUserTotalRow, error) {
	var query string
	var args []interface{}
	if len(sinceDate) > 0 && !sinceDate[0].IsZero() {
		dayStr := utcDayString(sinceDate[0])
		query = `SELECT d.user_id, COALESCE(u.username, ''), SUM(d.bytes_sent), SUM(d.bytes_received)
		   FROM user_domain_usage_daily d
		   LEFT JOIN users u ON u.id = d.user_id
		  WHERE d.domain = ? AND d.usage_date >= ?
		  GROUP BY d.user_id
		  ORDER BY (SUM(d.bytes_sent) + SUM(d.bytes_received)) DESC`
		args = []interface{}{domain, dayStr}
	} else {
		query = `SELECT d.user_id, COALESCE(u.username, ''), SUM(d.bytes_sent), SUM(d.bytes_received)
		   FROM user_domain_usage_daily d
		   LEFT JOIN users u ON u.id = d.user_id
		  WHERE d.domain = ?
		  GROUP BY d.user_id
		  ORDER BY (SUM(d.bytes_sent) + SUM(d.bytes_received)) DESC`
		args = []interface{}{domain}
	}

	rows, err := s.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DomainUserTotalRow
	for rows.Next() {
		var r DomainUserTotalRow
		if err := rows.Scan(&r.UserID, &r.Username, &r.BytesSent, &r.BytesReceived); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
