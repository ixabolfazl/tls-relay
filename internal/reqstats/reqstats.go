package reqstats

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// StatsStore is the interface required to persist aggregated request stats.
type StatsStore interface {
	IncrementRequestStat(ctx context.Context, date time.Time, requestType, category string, count int64) error
}

type statEvent struct {
	requestType string
	category    string
	at          time.Time
}

type statKey struct {
	requestType string
	category    string
	dateStr     string
}

const (
	statsChanSize    = 2048
	statsFlushKeys   = 1000
	statsFlushPeriod = 5 * time.Second
	warnCooldownNs   = int64(10 * time.Second)
)

// Collector receives DNS/TLS request events asynchronously and flushes aggregated counts to storage.
type Collector struct {
	ch           chan statEvent
	droppedCount atomic.Int64
	lastWarnNs   atomic.Int64
}

// New creates a new Collector instance.
func New() *Collector {
	return &Collector{
		ch: make(chan statEvent, statsChanSize),
	}
}

// Emit enqueues a request stat event. It is O(1) and non-blocking.
func (c *Collector) Emit(requestType, category string) {
	if requestType == "" || category == "" {
		return
	}
	ev := statEvent{
		requestType: requestType,
		category:    category,
		at:          time.Now(),
	}
	select {
	case c.ch <- ev:
	default:
		c.droppedCount.Add(1)
		now := time.Now().UnixNano()
		last := c.lastWarnNs.Load()
		if now-last >= warnCooldownNs {
			if c.lastWarnNs.CompareAndSwap(last, now) {
				slog.Warn("request stats collector channel full; dropping event",
					"request_type", requestType,
					"category", category,
					"total_dropped", c.droppedCount.Load(),
				)
			}
		}
	}
}

// DroppedCount returns total dropped events due to a full channel.
func (c *Collector) DroppedCount() int64 {
	return c.droppedCount.Load()
}

// StartWriter launches the background batch writer goroutine.
func (c *Collector) StartWriter(ctx context.Context, store StatsStore) {
	if store == nil {
		return
	}
	go c.runWriter(ctx, store)
}

func (c *Collector) runWriter(ctx context.Context, store StatsStore) {
	ticker := time.NewTicker(statsFlushPeriod)
	defer ticker.Stop()

	batch := make(map[statKey]int64)
	timestamps := make(map[statKey]time.Time)

	flushWithCtx := func(fCtx context.Context) {
		if len(batch) == 0 {
			return
		}
		for key, count := range batch {
			if count <= 0 {
				continue
			}
			ts := timestamps[key]
			if err := store.IncrementRequestStat(fCtx, ts, key.requestType, key.category, count); err != nil {
				slog.Error("reqstats writer: failed to increment stat in store",
					"type", key.requestType, "category", key.category, "error", err)
			}
		}
		batch = make(map[statKey]int64)
		timestamps = make(map[statKey]time.Time)
	}

	flush := func() {
		flushWithCtx(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			for {
				select {
				case ev := <-c.ch:
					accumulate(batch, timestamps, ev)
					if len(batch) >= statsFlushKeys {
						flushWithCtx(shutdownCtx)
					}
				default:
					flushWithCtx(shutdownCtx)
					return
				}
			}

		case ev := <-c.ch:
			accumulate(batch, timestamps, ev)
			if len(batch) >= statsFlushKeys {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

func accumulate(batch map[statKey]int64, timestamps map[statKey]time.Time, ev statEvent) {
	dateStr := ev.at.UTC().Format("2006-01-02")
	key := statKey{
		requestType: ev.requestType,
		category:    ev.category,
		dateStr:     dateStr,
	}
	batch[key] += 1
	timestamps[key] = ev.at
}
