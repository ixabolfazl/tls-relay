package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/requestlog"
)

// RequestLogFilter specifies filtering criteria for querying request logs.
type RequestLogFilter struct {
	Domain      string
	ClientIP    string
	Username    string
	UserID      *int64
	RequestType string
	Since       *time.Time
	Until       *time.Time
	Limit       int
	Offset      int
}

// InsertRequestLogs writes a slice of request log events in a single transaction.
func (s *Store) InsertRequestLogs(ctx context.Context, logs []requestlog.Event) error {
	if len(logs) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction for request logs insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO request_logs (user_id, username, client_ip, request_type, protocol, domain, port, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert request_logs statement: %w", err)
	}
	defer stmt.Close()

	for _, l := range logs {
		var userIDVal interface{}
		if l.UserID > 0 {
			userIDVal = l.UserID
		}
		proto := l.Protocol
		if proto == "" {
			if l.RequestType == requestlog.TypeHTTP {
				proto = "HTTP"
			} else if l.RequestType == requestlog.TypeDNS {
				proto = "DNS"
			} else {
				proto = "TLS"
			}
		}
		ts := FormatTime(l.Timestamp)

		_, err := stmt.ExecContext(ctx,
			userIDVal,
			l.Username,
			l.ClientIP,
			string(l.RequestType),
			proto,
			l.Domain,
			l.Port,
			l.Status,
			ts,
		)
		if err != nil {
			return fmt.Errorf("exec insert request_log: %w", err)
		}
	}

	return tx.Commit()
}

// ListRequestLogs queries request logs matching the filter, along with total matching count.
func (s *Store) ListRequestLogs(ctx context.Context, filter RequestLogFilter) ([]requestlog.Event, int, error) {
	var conditions []string
	var args []interface{}

	if filter.Domain != "" {
		conditions = append(conditions, "domain LIKE ?")
		args = append(args, "%"+filter.Domain+"%")
	}
	if filter.ClientIP != "" {
		conditions = append(conditions, "client_ip LIKE ?")
		args = append(args, "%"+filter.ClientIP+"%")
	}
	if filter.Username != "" {
		conditions = append(conditions, "username LIKE ?")
		args = append(args, "%"+filter.Username+"%")
	}
	if filter.UserID != nil {
		conditions = append(conditions, "user_id = ?")
		args = append(args, *filter.UserID)
	}
	if filter.RequestType != "" {
		conditions = append(conditions, "request_type = ?")
		args = append(args, strings.ToUpper(filter.RequestType))
	}
	if filter.Since != nil {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, FormatTime(*filter.Since))
	}
	if filter.Until != nil {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, FormatTime(*filter.Until))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	countQuery := "SELECT COUNT(*) FROM request_logs" + whereClause
	var total int
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count request_logs: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := "SELECT user_id, username, client_ip, request_type, protocol, domain, port, status, created_at FROM request_logs" +
		whereClause + " ORDER BY id DESC LIMIT ? OFFSET ?"
	queryArgs := append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query request_logs: %w", err)
	}
	defer rows.Close()

	var logs []requestlog.Event
	for rows.Next() {
		var l requestlog.Event
		var reqTypeStr string
		var rawCreatedAt string
		var nullUserID sql.NullInt64

		if err := rows.Scan(&nullUserID, &l.Username, &l.ClientIP, &reqTypeStr, &l.Protocol, &l.Domain, &l.Port, &l.Status, &rawCreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan request_log row: %w", err)
		}

		if nullUserID.Valid {
			l.UserID = nullUserID.Int64
		}
		l.RequestType = requestlog.RequestType(reqTypeStr)
		if parsed, err := parseTime(rawCreatedAt); err == nil {
			l.Timestamp = parsed
		}

		logs = append(logs, l)
	}

	return logs, total, rows.Err()
}

// DeleteExpiredRequestLogs deletes request logs created before the specified timestamp.
func (s *Store) DeleteExpiredRequestLogs(ctx context.Context, before time.Time) (int64, error) {
	ts := FormatTime(before)
	res, err := s.db.ExecContext(ctx, `DELETE FROM request_logs WHERE created_at < ?`, ts)
	if err != nil {
		return 0, fmt.Errorf("delete expired request_logs: %w", err)
	}
	return res.RowsAffected()
}

// ClearAllRequestLogs truncates/deletes all request logs.
func (s *Store) ClearAllRequestLogs(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM request_logs`)
	if err != nil {
		return fmt.Errorf("clear request_logs: %w", err)
	}
	return nil
}

// CountRequestLogs returns the total number of logs in request_logs table.
func (s *Store) CountRequestLogs(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM request_logs`).Scan(&count)
	return count, err
}
