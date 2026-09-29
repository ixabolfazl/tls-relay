package sqlitestore

import (
	"context"
	"time"
)

// RequestStatDayRow represents daily aggregated request counts by category.
type RequestStatDayRow struct {
	Date     string `json:"date"`     // "YYYY-MM-DD" UTC
	Category string `json:"category"` // e.g. "authorized", "unauthorized_passthrough", "registered"
	Count    int64  `json:"count"`
}

// IncrementRequestStat upserts count for (stat_date, request_type, category) in request_stats_daily.
func (s *Store) IncrementRequestStat(ctx context.Context, date time.Time, requestType, category string, count int64) error {
	if count <= 0 || requestType == "" || category == "" {
		return nil
	}
	dayStr := utcDayString(date)
	_, err := s.writer.ExecContext(ctx,
		`INSERT INTO request_stats_daily (stat_date, request_type, category, count)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(stat_date, request_type, category) DO UPDATE
		    SET count = count + excluded.count`,
		dayStr, requestType, category, count,
	)
	return err
}

// GetRequestStatsDaily returns daily rows for a requestType ("DNS" or "TLS") starting from sinceDate.
func (s *Store) GetRequestStatsDaily(ctx context.Context, requestType string, sinceDate time.Time) ([]RequestStatDayRow, error) {
	dayStr := utcDayString(sinceDate)
	rows, err := s.reader.QueryContext(ctx,
		`SELECT stat_date, category, count
		   FROM request_stats_daily
		  WHERE request_type = ? AND stat_date >= ? AND category != 'total'
		  ORDER BY stat_date ASC, category ASC`,
		requestType, dayStr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RequestStatDayRow
	for rows.Next() {
		var r RequestStatDayRow
		if err := rows.Scan(&r.Date, &r.Category, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRequestStatsTotals returns cumulative totals grouped by category for a requestType ("DNS", "TLS", or "HTTP").
// If sinceDate is provided, only aggregates stats on or after sinceDate.
func (s *Store) GetRequestStatsTotals(ctx context.Context, requestType string, sinceDate ...time.Time) (map[string]int64, error) {
	var query string
	var args []interface{}
	if len(sinceDate) > 0 && !sinceDate[0].IsZero() {
		dayStr := utcDayString(sinceDate[0])
		query = `SELECT category, SUM(count)
		   FROM request_stats_daily
		  WHERE request_type = ? AND stat_date >= ? AND category != 'total'
		  GROUP BY category`
		args = []interface{}{requestType, dayStr}
	} else {
		query = `SELECT category, SUM(count)
		   FROM request_stats_daily
		  WHERE request_type = ? AND category != 'total'
		  GROUP BY category`
		args = []interface{}{requestType}
	}

	rows, err := s.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]int64)
	var grandTotal int64
	for rows.Next() {
		var cat string
		var cnt int64
		if err := rows.Scan(&cat, &cnt); err != nil {
			return nil, err
		}
		out[cat] = cnt
		grandTotal += cnt
	}
	out["total"] = grandTotal
	return out, rows.Err()
}
