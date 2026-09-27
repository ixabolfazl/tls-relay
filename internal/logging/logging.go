// Package logging sets up the structured logger used throughout the relay.
package logging

import (
	"io"
	"log/slog"
	"os"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/ixabolfazl/tls-relay/internal/config"
)

// ConnFields carries all per-connection log fields.
type ConnFields struct {
	ClientIP      string
	SNI           string
	DestIP        string
	DestPort      int
	Protocol      string
	Status        string
	Duration      time.Duration
	BytesSent     int64
	BytesReceived int64
	Egress        string
	MatchedRule   string
}

// Setup initialises the global slog logger according to cfg and returns a
// closer that should be called on shutdown (flushes/closes the log file).
func Setup(cfg *config.LogConfig) (closer func(), err error) {
	var w io.Writer
	var closeFunc func()

	if cfg.Path == "" {
		w = os.Stdout
		closeFunc = func() {}
	} else {
		lj := &lumberjack.Logger{
			Filename:   cfg.Path,
			MaxSize:    cfg.Rotation.MaxSizeMB, // megabytes
			MaxBackups: cfg.Rotation.MaxBackups,
			MaxAge:     cfg.Rotation.MaxAgeDays,
			Compress:   cfg.Rotation.Compress,
		}
		w = lj
		closeFunc = func() { _ = lj.Close() }
	}

	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	slog.SetDefault(slog.New(handler))
	return closeFunc, nil
}

// LogConnection emits a structured log line for a completed (or rejected)
// connection attempt.
func LogConnection(f ConnFields) {
	proto := f.Protocol
	if proto == "" {
		proto = "TLS"
	}
	slog.Info("connection",
		slog.String("client_ip", f.ClientIP),
		slog.String("sni", f.SNI),
		slog.String("dest_ip", f.DestIP),
		slog.Int("dest_port", f.DestPort),
		slog.String("protocol", proto),
		slog.String("status", f.Status),
		slog.String("duration", f.Duration.Round(time.Millisecond).String()),
		slog.Int64("bytes_sent", f.BytesSent),
		slog.Int64("bytes_received", f.BytesReceived),
		slog.String("egress", f.Egress),
		slog.String("matched_rule", f.MatchedRule),
	)
}
