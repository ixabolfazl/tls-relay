package relay

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// UsageStore is the minimal interface required by UsageTracker to persist
// usage events.  It is defined here so that internal/relay does not need to
// import internal/sqlitestore directly (matches the DBUserStore pattern in
// conntrack.go).
type UsageStore interface {
	IncrementUserUsage(ctx context.Context, userID, bytesSent, bytesReceived int64, date time.Time) error
	IncrementDomainUsage(ctx context.Context, domain string, bytesSent, bytesReceived int64, date time.Time) error
	IncrementUserDomainUsage(ctx context.Context, userID int64, domain string, bytesSent, bytesReceived int64, date time.Time) error
	IncrementUserDNSUsage(ctx context.Context, userID int64, date time.Time, count int64) error
	IncrementProtocolUsage(ctx context.Context, protocol string, bytesSent, bytesReceived int64, date time.Time) error
}

// usageEvent is the in-channel payload emitted once per closed connection.
type usageEvent struct {
	protocol      string
	userID        int64
	domain        string
	bytesSent     int64
	bytesReceived int64
	isDNS         bool
	at            time.Time
}

// usageKey identifies an aggregation bucket in memory.
type usageKey struct {
	protocol string
	userID   int64
	domain   string
}

// usageBatch accumulates bytes for a single user/domain key before a flush.
type usageBatch struct {
	sent     int64
	received int64
	dnsCount int64
	at       time.Time // timestamp of the most recent event in the batch
}

const (
	usageChanSize    = 2048
	usageFlushUsers  = 500 // flush when this many distinct keys are batched
	usageFlushPeriod = 5 * time.Second
	// Warn at most once per 10 s to avoid log spam when the channel is full.
	usageWarnCooldownNs = int64(10 * time.Second)
)

// UsageTracker collects per-connection byte counts and writes them
// asynchronously in batches to the UsageStore.
//
// All public methods are safe for concurrent use.  Emit() never blocks.
type UsageTracker struct {
	ch           chan usageEvent
	droppedCount atomic.Int64
	lastWarnNs   atomic.Int64 // Unix nanoseconds of the last warn emission
}

// NewUsageTracker creates a UsageTracker ready for use.  Call StartWriter to
// activate the background flush goroutine.
func NewUsageTracker() *UsageTracker {
	return &UsageTracker{
		ch: make(chan usageEvent, usageChanSize),
	}
}

// Emit enqueues a usage event with default "TLS" protocol.
func (ut *UsageTracker) Emit(userID int64, domain string, bytesSent, bytesReceived int64) {
	ut.EmitProtocol("TLS", userID, domain, bytesSent, bytesReceived)
}

// EmitProtocol enqueues a usage event for the connection identified by protocol, userID and domain.
func (ut *UsageTracker) EmitProtocol(protocol string, userID int64, domain string, bytesSent, bytesReceived int64) {
	if userID <= 0 && domain == "" && (bytesSent <= 0 && bytesReceived <= 0) {
		return
	}
	if protocol == "" {
		protocol = "TLS"
	}
	ev := usageEvent{
		protocol:      protocol,
		userID:        userID,
		domain:        domain,
		bytesSent:     bytesSent,
		bytesReceived: bytesReceived,
		at:            time.Now(),
	}
	select {
	case ut.ch <- ev:
	default:
		ut.droppedCount.Add(1)
		// Rate-limit the warning to at most once per 10 s.
		now := time.Now().UnixNano()
		last := ut.lastWarnNs.Load()
		if now-last >= usageWarnCooldownNs {
			if ut.lastWarnNs.CompareAndSwap(last, now) {
				slog.Warn("usage tracker channel full; dropping usage event",
					"protocol", protocol,
					"user_id", userID,
					"domain", domain,
					"total_dropped", ut.droppedCount.Load(),
				)
			}
		}
	}
}

// EmitDNSQuery enqueues a DNS query event for the user identified by userID.
func (ut *UsageTracker) EmitDNSQuery(userID int64) {
	if userID <= 0 {
		return
	}
	ev := usageEvent{
		protocol: "DNS",
		userID:   userID,
		isDNS:    true,
		at:       time.Now(),
	}
	select {
	case ut.ch <- ev:
	default:
		ut.droppedCount.Add(1)
	}
}

// DroppedCount returns the total number of events dropped due to a full channel.
func (ut *UsageTracker) DroppedCount() int64 {
	return ut.droppedCount.Load()
}

// StartWriter launches the background batch-flush goroutine. It returns a done channel
// that closes when the writer finishes draining upon context cancellation.
func (ut *UsageTracker) StartWriter(ctx context.Context, store UsageStore) <-chan struct{} {
	done := make(chan struct{})
	if store == nil {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		ut.runWriter(ctx, store)
	}()
	return done
}

func (ut *UsageTracker) runWriter(ctx context.Context, store UsageStore) {
	ticker := time.NewTicker(usageFlushPeriod)
	defer ticker.Stop()

	batch := make(map[usageKey]*usageBatch)

	flushWithCtx := func(fCtx context.Context) {
		if len(batch) == 0 {
			return
		}
		for key, b := range batch {
			if b.sent == 0 && b.received == 0 && b.dnsCount == 0 {
				continue
			}
			if key.userID > 0 && (b.sent > 0 || b.received > 0) {
				if err := store.IncrementUserUsage(fCtx, key.userID, b.sent, b.received, b.at); err != nil {
					slog.Error("usage tracker: failed to flush user usage to store",
						"user_id", key.userID, "error", err)
				}
			}
			if key.domain != "" && (b.sent > 0 || b.received > 0) {
				if err := store.IncrementDomainUsage(fCtx, key.domain, b.sent, b.received, b.at); err != nil {
					slog.Error("usage tracker: failed to flush domain usage to store",
						"domain", key.domain, "error", err)
				}
			}
			if key.userID > 0 && key.domain != "" && (b.sent > 0 || b.received > 0) {
				if err := store.IncrementUserDomainUsage(fCtx, key.userID, key.domain, b.sent, b.received, b.at); err != nil {
					slog.Error("usage tracker: failed to flush user domain usage to store",
						"user_id", key.userID, "domain", key.domain, "error", err)
				}
			}
			if key.protocol != "" && (b.sent > 0 || b.received > 0) {
				if err := store.IncrementProtocolUsage(fCtx, key.protocol, b.sent, b.received, b.at); err != nil {
					slog.Error("usage tracker: failed to flush protocol usage to store",
						"protocol", key.protocol, "error", err)
				}
			}
			if b.dnsCount > 0 && key.userID > 0 {
				if err := store.IncrementUserDNSUsage(fCtx, key.userID, b.at, b.dnsCount); err != nil {
					slog.Error("usage tracker: failed to flush user dns usage to store",
						"user_id", key.userID, "error", err)
				}
			}
		}
		// Reset the batch map.
		batch = make(map[usageKey]*usageBatch)
	}

	flush := func() {
		flushWithCtx(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			// Drain remaining events before exiting.
			for {
				select {
				case ev := <-ut.ch:
					accumulate(batch, ev)
					if len(batch) >= usageFlushUsers {
						flushWithCtx(shutdownCtx)
					}
				default:
					flushWithCtx(shutdownCtx)
					return
				}
			}

		case ev := <-ut.ch:
			accumulate(batch, ev)
			if len(batch) >= usageFlushUsers {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

// accumulate merges an event into the batch map.
func accumulate(batch map[usageKey]*usageBatch, ev usageEvent) {
	key := usageKey{protocol: ev.protocol, userID: ev.userID, domain: ev.domain}
	b, ok := batch[key]
	if !ok {
		b = &usageBatch{at: ev.at}
		batch[key] = b
	}
	if ev.isDNS {
		b.dnsCount += 1
	} else {
		b.sent += ev.bytesSent
		b.received += ev.bytesReceived
	}
	if ev.at.After(b.at) {
		b.at = ev.at
	}
}
