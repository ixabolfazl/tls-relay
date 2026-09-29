package requestlog

import (
	"context"
	"sync/atomic"
	"time"
)

// RequestType indicates the type of request logged (DNS, TLS, or HTTP).
type RequestType string

const (
	TypeDNS  RequestType = "DNS"
	TypeTLS  RequestType = "TLS"
	TypeHTTP RequestType = "HTTP"
)

// Event represents a single logged DNS, TLS, or HTTP request metadata.
type Event struct {
	ID          int64       `json:"id"`
	UserID      int64       `json:"user_id"`
	Username    string      `json:"username"`
	ClientIP    string      `json:"client_ip"`
	RequestType RequestType `json:"request_type"`
	Protocol    string      `json:"protocol,omitempty"`
	Domain      string      `json:"domain"`
	Port        int         `json:"port"`
	Status      string      `json:"status"`
	Timestamp   time.Time   `json:"timestamp"`
}

// LogStore interface isolates the database persistence operations needed by the logger.
type LogStore interface {
	InsertRequestLogs(ctx context.Context, logs []Event) error
	DeleteExpiredRequestLogs(ctx context.Context, before time.Time) (int64, error)
	ClearAllRequestLogs(ctx context.Context) error
}

// Logger provides high-performance, non-blocking event collection and batch persistence.
type Logger struct {
	enabled       atomic.Bool
	queue         chan Event
	droppedEvents atomic.Int64
	store         LogStore
	retention     atomic.Int64 // stored as time.Duration in nanoseconds
	batchSize     int
	flushInterval time.Duration
}

// New creates a new Logger instance.
func New(store LogStore, retention time.Duration, enabled bool) *Logger {
	l := &Logger{
		queue:         make(chan Event, 4096),
		store:         store,
		batchSize:     100,
		flushInterval: 1 * time.Second,
	}
	l.enabled.Store(enabled)
	l.retention.Store(int64(retention))
	return l
}

// SetEnabled enables or disables event logging.
func (l *Logger) SetEnabled(enabled bool) {
	l.enabled.Store(enabled)
}

// IsEnabled returns whether logging is currently enabled.
func (l *Logger) IsEnabled() bool {
	return l.enabled.Load()
}

// SetRetention updates the log retention duration.
func (l *Logger) SetRetention(d time.Duration) {
	l.retention.Store(int64(d))
}

// Retention returns the current retention duration.
func (l *Logger) Retention() time.Duration {
	return time.Duration(l.retention.Load())
}

// DroppedCount returns the total number of events dropped due to a full queue.
func (l *Logger) DroppedCount() int64 {
	return l.droppedEvents.Load()
}

// Emit enqueues an event for background processing.
// If logging is disabled or the queue is full, it drops the event without blocking.
func (l *Logger) Emit(event Event) {
	if !l.enabled.Load() {
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	select {
	case l.queue <- event:
	default:
		l.droppedEvents.Add(1)
	}
}

// Start launches the background worker goroutines (batch writer and retention cleanup).
func (l *Logger) Start(ctx context.Context) {
	go l.runWorker(ctx)
	go l.runRetentionCleaner(ctx)
}

func (l *Logger) runWorker(ctx context.Context) {
	ticker := time.NewTicker(l.flushInterval)
	defer ticker.Stop()

	batch := make([]Event, 0, l.batchSize)

	flushWithCtx := func(fCtx context.Context) {
		if len(batch) == 0 {
			return
		}
		if l.store != nil {
			_ = l.store.InsertRequestLogs(fCtx, batch)
		}
		batch = batch[:0]
	}

	flush := func() {
		flushWithCtx(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			// Flush remaining items on exit
			for {
				select {
				case ev := <-l.queue:
					batch = append(batch, ev)
					if len(batch) >= l.batchSize {
						flushWithCtx(shutdownCtx)
					}
				default:
					flushWithCtx(shutdownCtx)
					return
				}
			}
		case ev := <-l.queue:
			batch = append(batch, ev)
			if len(batch) >= l.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (l *Logger) runRetentionCleaner(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	clean := func() {
		ret := l.Retention()
		if ret <= 0 || l.store == nil {
			return
		}
		cutoff := time.Now().Add(-ret)
		_, _ = l.store.DeleteExpiredRequestLogs(ctx, cutoff)
	}

	// Run clean once on start
	clean()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			clean()
		}
	}
}
