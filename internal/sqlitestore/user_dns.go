package sqlitestore

import (
	"context"
	"time"
)

// UserDNSUsageDayRow represents daily aggregated DNS query count for a user.
type UserDNSUsageDayRow struct {
	Date       string `json:"date"` // "YYYY-MM-DD" UTC
	QueryCount int64  `json:"query_count"`
}

// IncrementUserDNSUsage upserts DNS query count for (user_id, usage_date).
func (s *Store) IncrementUserDNSUsage(ctx context.Context, userID int64, date time.Time, count int64) error {
	if userID <= 0 || count <= 0 {
		return nil
	}
	dayStr := utcDayString(date)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_dns_usage_daily (user_id, usage_date, query_count)
		 VALUES (?, ?, ?)
		 ON CONFLICT(user_id, usage_date) DO UPDATE
		    SET query_count = query_count + excluded.query_count`,
		userID, dayStr, count,
	)
	return err
}

// GetUserDNSUsageDaily returns daily DNS query rows for a user starting from sinceDate.
func (s *Store) GetUserDNSUsageDaily(ctx context.Context, userID int64, sinceDate time.Time) ([]UserDNSUsageDayRow, error) {
	var query string
	var args []interface{}
	if !sinceDate.IsZero() {
		dayStr := utcDayString(sinceDate)
		query = `SELECT usage_date, query_count
		   FROM user_dns_usage_daily
		  WHERE user_id = ? AND usage_date >= ?
		  ORDER BY usage_date ASC`
		args = []interface{}{userID, dayStr}
	} else {
		query = `SELECT usage_date, query_count
		   FROM user_dns_usage_daily
		  WHERE user_id = ?
		  ORDER BY usage_date ASC`
		args = []interface{}{userID}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UserDNSUsageDayRow
	for rows.Next() {
		var r UserDNSUsageDayRow
		if err := rows.Scan(&r.Date, &r.QueryCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetUserDNSUsageTotal returns total DNS query count for a user starting from sinceDate.
func (s *Store) GetUserDNSUsageTotal(ctx context.Context, userID int64, sinceDate time.Time) (int64, error) {
	var query string
	var args []interface{}
	if !sinceDate.IsZero() {
		dayStr := utcDayString(sinceDate)
		query = `SELECT COALESCE(SUM(query_count), 0)
		   FROM user_dns_usage_daily
		  WHERE user_id = ? AND usage_date >= ?`
		args = []interface{}{userID, dayStr}
	} else {
		query = `SELECT COALESCE(SUM(query_count), 0)
		   FROM user_dns_usage_daily
		  WHERE user_id = ?`
		args = []interface{}{userID}
	}

	var total int64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&total)
	return total, err
}

// GetAllUsersDNSTotals returns map[userID]queryCount starting from sinceDate.
func (s *Store) GetAllUsersDNSTotals(ctx context.Context, sinceDate time.Time) (map[int64]int64, error) {
	var query string
	var args []interface{}
	if !sinceDate.IsZero() {
		dayStr := utcDayString(sinceDate)
		query = `SELECT user_id, SUM(query_count)
		   FROM user_dns_usage_daily
		  WHERE usage_date >= ?
		  GROUP BY user_id`
		args = []interface{}{dayStr}
	} else {
		query = `SELECT user_id, SUM(query_count)
		   FROM user_dns_usage_daily
		  GROUP BY user_id`
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[int64]int64)
	for rows.Next() {
		var uid, cnt int64
		if err := rows.Scan(&uid, &cnt); err != nil {
			return nil, err
		}
		out[uid] = cnt
	}
	return out, rows.Err()
}

// GetGlobalDNSQueriesTotal returns sum of all user DNS queries starting from sinceDate.
func (s *Store) GetGlobalDNSQueriesTotal(ctx context.Context, sinceDate time.Time) (int64, error) {
	var query string
	var args []interface{}
	if !sinceDate.IsZero() {
		dayStr := utcDayString(sinceDate)
		query = `SELECT COALESCE(SUM(query_count), 0)
		   FROM user_dns_usage_daily
		  WHERE usage_date >= ?`
		args = []interface{}{dayStr}
	} else {
		query = `SELECT COALESCE(SUM(query_count), 0)
		   FROM user_dns_usage_daily`
	}

	var total int64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&total)
	return total, err
}
