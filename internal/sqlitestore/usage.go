package sqlitestore

import (
	"context"
	"time"
)

// UserUsageDayRow represents a single day's usage for a user.
type UserUsageDayRow struct {
	Date          string `json:"date"` // "YYYY-MM-DD" UTC
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
}

// GlobalUsageDayRow represents a single day's aggregated usage across all users.
type GlobalUsageDayRow struct {
	Date          string `json:"date"` // "YYYY-MM-DD" UTC
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
}

// utcDayString returns the UTC calendar day string ("YYYY-MM-DD") for t.
func utcDayString(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// GetGlobalUsageTotals returns sum of (bytes_sent, bytes_received) from protocol_usage_daily starting from sinceDate,
// falling back to user_usage_daily only when the protocol table has no rows.
func (s *Store) GetGlobalUsageTotals(ctx context.Context, sinceDate time.Time) (int64, int64, error) {
	dayStr := utcDayString(sinceDate)
	var protoCount int
	err := s.reader.QueryRowContext(ctx, `SELECT COUNT(*) FROM protocol_usage_daily`).Scan(&protoCount)
	if err == nil && protoCount > 0 {
		var sent, recv int64
		err := s.reader.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0)
			   FROM protocol_usage_daily
			  WHERE usage_date >= ?`,
			dayStr,
		).Scan(&sent, &recv)
		return sent, recv, err
	}

	var sent, recv int64
	err = s.reader.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0)
		   FROM user_usage_daily
		  WHERE usage_date >= ?`,
		dayStr,
	).Scan(&sent, &recv)
	return sent, recv, err
}

// IncrementUserUsage atomically increments the cumulative usage totals for a
// registered user AND upserts the per-day breakdown row, all in a single
// transaction.  If both bytesSent and bytesReceived are zero, the call is a
// no-op (avoids useless writes for zero-byte connections).
func (s *Store) IncrementUserUsage(ctx context.Context, userID int64, bytesSent, bytesReceived int64, date time.Time) error {
	if bytesSent == 0 && bytesReceived == 0 {
		return nil
	}

	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// (a) Increment totals on the users row.
	_, err = tx.ExecContext(ctx,
		`UPDATE users
		    SET total_bytes_sent     = total_bytes_sent     + ?,
		        total_bytes_received = total_bytes_received + ?
		  WHERE id = ?`,
		bytesSent, bytesReceived, userID,
	)
	if err != nil {
		return err
	}

	// (b) Upsert the daily breakdown row.
	dayStr := utcDayString(date)
	_, err = tx.ExecContext(ctx,
		`INSERT INTO user_usage_daily (user_id, usage_date, bytes_sent, bytes_received)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(user_id, usage_date) DO UPDATE
		    SET bytes_sent     = bytes_sent     + excluded.bytes_sent,
		        bytes_received = bytes_received + excluded.bytes_received`,
		userID, dayStr, bytesSent, bytesReceived,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// ResetUserUsage zeros the cumulative usage totals for a user and deletes all
// daily breakdown rows — a full history wipe.
func (s *Store) ResetUserUsage(ctx context.Context, userID int64) error {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx,
		`UPDATE users SET total_bytes_sent = 0, total_bytes_received = 0 WHERE id = ?`,
		userID,
	)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		`DELETE FROM user_usage_daily WHERE user_id = ?`,
		userID,
	)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		`DELETE FROM user_dns_usage_daily WHERE user_id = ?`,
		userID,
	)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		`DELETE FROM user_domain_usage_daily WHERE user_id = ?`,
		userID,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// GetUserUsageDaily returns daily usage rows for the given user, ordered by
// usage_date ASC, starting from the UTC calendar day of sinceDate.
func (s *Store) GetUserUsageDaily(ctx context.Context, userID int64, sinceDate time.Time) ([]UserUsageDayRow, error) {
	dayStr := utcDayString(sinceDate)
	rows, err := s.reader.QueryContext(ctx,
		`SELECT usage_date, bytes_sent, bytes_received
		   FROM user_usage_daily
		  WHERE user_id = ? AND usage_date >= ?
		  ORDER BY usage_date ASC`,
		userID, dayStr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UserUsageDayRow
	for rows.Next() {
		var r UserUsageDayRow
		if err := rows.Scan(&r.Date, &r.BytesSent, &r.BytesReceived); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetGlobalUsageDaily returns daily usage rows aggregated across ALL users,
// ordered by usage_date ASC, starting from the UTC calendar day of sinceDate.
func (s *Store) GetGlobalUsageDaily(ctx context.Context, sinceDate time.Time) ([]GlobalUsageDayRow, error) {
	dayStr := utcDayString(sinceDate)
	rows, err := s.reader.QueryContext(ctx,
		`SELECT usage_date, SUM(bytes_sent), SUM(bytes_received)
		   FROM user_usage_daily
		  WHERE usage_date >= ?
		  GROUP BY usage_date
		  ORDER BY usage_date ASC`,
		dayStr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []GlobalUsageDayRow
	for rows.Next() {
		var r GlobalUsageDayRow
		if err := rows.Scan(&r.Date, &r.BytesSent, &r.BytesReceived); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetUsersTotalUsage returns a map of userID → {Sent, Received} for all users.
// If sinceDate is not zero, usage is aggregated from user_usage_daily for dates >= sinceDate.
func (s *Store) GetUsersTotalUsage(ctx context.Context, sinceDate time.Time) (map[int64]struct {
	Sent     int64
	Received int64
}, error) {
	if sinceDate.IsZero() {
		rows, err := s.reader.QueryContext(ctx,
			`SELECT id, total_bytes_sent, total_bytes_received FROM users`,
		)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		out := make(map[int64]struct {
			Sent     int64
			Received int64
		})
		for rows.Next() {
			var id, sent, received int64
			if err := rows.Scan(&id, &sent, &received); err != nil {
				return nil, err
			}
			out[id] = struct {
				Sent     int64
				Received int64
			}{Sent: sent, Received: received}
		}
		return out, rows.Err()
	}

	dayStr := utcDayString(sinceDate)
	rows, err := s.reader.QueryContext(ctx,
		`SELECT user_id, COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0)
		   FROM user_usage_daily
		  WHERE usage_date >= ?
		  GROUP BY user_id`,
		dayStr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[int64]struct {
		Sent     int64
		Received int64
	})
	for rows.Next() {
		var id, sent, received int64
		if err := rows.Scan(&id, &sent, &received); err != nil {
			return nil, err
		}
		out[id] = struct {
			Sent     int64
			Received int64
		}{Sent: sent, Received: received}
	}
	return out, rows.Err()
}

// IncrementProtocolUsage atomically increments daily usage totals for a protocol ("TLS" or "HTTP").
func (s *Store) IncrementProtocolUsage(ctx context.Context, protocol string, bytesSent, bytesReceived int64, date time.Time) error {
	if (bytesSent == 0 && bytesReceived == 0) || protocol == "" {
		return nil
	}
	dayStr := utcDayString(date)
	_, err := s.writer.ExecContext(ctx,
		`INSERT INTO protocol_usage_daily (protocol, usage_date, bytes_sent, bytes_received)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(protocol, usage_date) DO UPDATE
		    SET bytes_sent     = bytes_sent     + excluded.bytes_sent,
		        bytes_received = bytes_received + excluded.bytes_received`,
		protocol, dayStr, bytesSent, bytesReceived,
	)
	return err
}

// GetProtocolUsageTotals returns sum of (bytes_sent, bytes_received) for protocol starting from sinceDate.
func (s *Store) GetProtocolUsageTotals(ctx context.Context, protocol string, sinceDate ...time.Time) (int64, int64, error) {
	var query string
	var args []interface{}
	if len(sinceDate) > 0 && !sinceDate[0].IsZero() {
		dayStr := utcDayString(sinceDate[0])
		query = `SELECT COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0)
		   FROM protocol_usage_daily
		  WHERE protocol = ? AND usage_date >= ?`
		args = []interface{}{protocol, dayStr}
	} else {
		query = `SELECT COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0)
		   FROM protocol_usage_daily
		  WHERE protocol = ?`
		args = []interface{}{protocol}
	}
	var sent, recv int64
	err := s.reader.QueryRowContext(ctx, query, args...).Scan(&sent, &recv)
	return sent, recv, err
}

// GetProtocolUsageDaily returns daily usage rows for a protocol starting from sinceDate.
func (s *Store) GetProtocolUsageDaily(ctx context.Context, protocol string, sinceDate time.Time) ([]GlobalUsageDayRow, error) {
	dayStr := utcDayString(sinceDate)
	rows, err := s.reader.QueryContext(ctx,
		`SELECT usage_date, bytes_sent, bytes_received
		   FROM protocol_usage_daily
		  WHERE protocol = ? AND usage_date >= ?
		  ORDER BY usage_date ASC`,
		protocol, dayStr,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []GlobalUsageDayRow
	for rows.Next() {
		var r GlobalUsageDayRow
		if err := rows.Scan(&r.Date, &r.BytesSent, &r.BytesReceived); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
