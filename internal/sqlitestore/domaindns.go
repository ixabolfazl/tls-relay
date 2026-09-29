package sqlitestore

import (
	"context"
	"time"
)

// DomainDNSUsageDayRow represents daily aggregated DNS query count for a domain.
type DomainDNSUsageDayRow struct {
	Date       string `json:"date"` // "YYYY-MM-DD" UTC
	QueryCount int64  `json:"query_count"`
}

// IncrementDomainDNSUsage upserts DNS query count for (domain, usage_date).
func (s *Store) IncrementDomainDNSUsage(ctx context.Context, domain string, date time.Time, count int64) error {
	if domain == "" || count <= 0 {
		return nil
	}
	dayStr := utcDayString(date)
	_, err := s.writer.ExecContext(ctx,
		`INSERT INTO domain_dns_usage_daily (domain, usage_date, query_count)
		 VALUES (?, ?, ?)
		 ON CONFLICT(domain, usage_date) DO UPDATE
		    SET query_count = query_count + excluded.query_count`,
		domain, dayStr, count,
	)
	return err
}

// GetDomainDNSUsageDaily returns daily DNS query rows for a domain starting from sinceDate.
func (s *Store) GetDomainDNSUsageDaily(ctx context.Context, domain string, sinceDate time.Time) ([]DomainDNSUsageDayRow, error) {
	var query string
	var args []interface{}
	if !sinceDate.IsZero() {
		dayStr := utcDayString(sinceDate)
		query = `SELECT usage_date, query_count
		   FROM domain_dns_usage_daily
		  WHERE domain = ? AND usage_date >= ?
		  ORDER BY usage_date ASC`
		args = []interface{}{domain, dayStr}
	} else {
		query = `SELECT usage_date, query_count
		   FROM domain_dns_usage_daily
		  WHERE domain = ?
		  ORDER BY usage_date ASC`
		args = []interface{}{domain}
	}

	rows, err := s.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DomainDNSUsageDayRow
	for rows.Next() {
		var r DomainDNSUsageDayRow
		if err := rows.Scan(&r.Date, &r.QueryCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetDomainDNSUsageTotal returns total DNS query count for a domain starting from sinceDate.
func (s *Store) GetDomainDNSUsageTotal(ctx context.Context, domain string, sinceDate time.Time) (int64, error) {
	var query string
	var args []interface{}
	if !sinceDate.IsZero() {
		dayStr := utcDayString(sinceDate)
		query = `SELECT COALESCE(SUM(query_count), 0)
		   FROM domain_dns_usage_daily
		  WHERE domain = ? AND usage_date >= ?`
		args = []interface{}{domain, dayStr}
	} else {
		query = `SELECT COALESCE(SUM(query_count), 0)
		   FROM domain_dns_usage_daily
		  WHERE domain = ?`
		args = []interface{}{domain}
	}

	var total int64
	err := s.reader.QueryRowContext(ctx, query, args...).Scan(&total)
	return total, err
}

// ListDomainsDNSTotals returns map[domain]queryCount starting from sinceDate.
func (s *Store) ListDomainsDNSTotals(ctx context.Context, sinceDate time.Time) (map[string]int64, error) {
	var query string
	var args []interface{}
	if !sinceDate.IsZero() {
		dayStr := utcDayString(sinceDate)
		query = `SELECT domain, COALESCE(SUM(query_count), 0)
		   FROM domain_dns_usage_daily
		  WHERE usage_date >= ?
		  GROUP BY domain`
		args = []interface{}{dayStr}
	} else {
		query = `SELECT domain, COALESCE(SUM(query_count), 0)
		   FROM domain_dns_usage_daily
		  GROUP BY domain`
	}

	rows, err := s.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]int64)
	for rows.Next() {
		var domain string
		var cnt int64
		if err := rows.Scan(&domain, &cnt); err != nil {
			return nil, err
		}
		out[domain] = cnt
	}
	return out, rows.Err()
}
