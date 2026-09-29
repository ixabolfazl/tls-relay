package relay

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// UserMappingInfo represents a user and their registered IP addresses.
type UserMappingInfo struct {
	UserID     int64
	Username   string
	IPs        []string
	LastSeenAt string // ISO8601 or SQLite datetime string if available
}

// UserPresenceDTO represents user presence status returned to the admin dashboard.
type UserPresenceDTO struct {
	UserID            int64    `json:"user_id"`
	Username          string   `json:"username"`
	RegisteredIPs     []string `json:"registered_ips"`
	ActiveIPs         []string `json:"active_ips"`
	Status            string   `json:"status"` // "Online" or "Offline"
	ActiveConnections int      `json:"active_connections"`
	FirstActiveAt     string   `json:"first_active_at"` // ISO8601 formatted timestamp or empty
	LastSeenAt        string   `json:"last_seen_at"`    // ISO8601 formatted timestamp or empty
}

// UserPresenceSummary contains aggregate metrics and user list for presence tracking.
type UserPresenceSummary struct {
	TotalOnline       int               `json:"total_online"`
	TotalOffline      int               `json:"total_offline"`
	TotalUsers        int               `json:"total_users"`
	ActiveConnections int               `json:"active_connections"`
	Users             []UserPresenceDTO `json:"users"`
}

type userPresenceState struct {
	userID           int64
	username         string
	registeredIPs    map[string]struct{}
	activeConns      atomic.Int64
	firstActiveNanos atomic.Int64 // unix nano, 0 when inactive
	lastSeenNanos    atomic.Int64 // unix nano, 0 when never
	dirty            atomic.Bool  // marks last-seen as pending DB flush
}

// DBUserStore is an interface for updating user last seen timestamps asynchronously.
type DBUserStore interface {
	UpdateUserLastSeen(ctx context.Context, userID int64, lastSeen time.Time) error
}

// BatchLastSeenUpdater is an optional interface for updating user last seen timestamps in batch.
type BatchLastSeenUpdater interface {
	UpdateUsersLastSeen(ctx context.Context, updates map[int64]time.Time) error
}

type userMappingSnapshot struct {
	ipToUser   map[string]int64
	userStates map[int64]*userPresenceState
}

const numShards = 16

type connShard struct {
	mu    sync.Mutex
	conns map[string]map[net.Conn]int64 // ip -> (conn -> resolvedUserID)
}

func shardIndex(ip string) int {
	var h uint32 = 2166136261
	for i := 0; i < len(ip); i++ {
		h ^= uint32(ip[i])
		h *= 16777619
	}
	return int(h % numShards)
}

// ConnTracker maintains a registry of all active TCP connections keyed by
// client IP. It is used to forcibly close connections belonging to IPs that
// are no longer permitted, and to track per-user live online presence.
//
// Lookups are lock-free; connection registration is sharded into 16 mutex-protected shards.
// All methods are safe for concurrent use.
type ConnTracker struct {
	snapshot      atomic.Pointer[userMappingSnapshot]
	shards        [numShards]connShard
	masterMu      sync.Mutex
	masterStates  map[int64]*userPresenceState
	flushInterval atomic.Int64 // nanoseconds
}

// NewConnTracker creates a new ConnTracker.
func NewConnTracker() *ConnTracker {
	ct := &ConnTracker{
		masterStates: make(map[int64]*userPresenceState),
	}
	for i := 0; i < numShards; i++ {
		ct.shards[i].conns = make(map[string]map[net.Conn]int64)
	}
	ct.flushInterval.Store(int64(10 * time.Second))
	initSnap := &userMappingSnapshot{
		ipToUser:   make(map[string]int64),
		userStates: make(map[int64]*userPresenceState),
	}
	ct.snapshot.Store(initSnap)
	return ct
}

// SetLastSeenFlushInterval configures the period between batch DB flushes.
func (ct *ConnTracker) SetLastSeenFlushInterval(d time.Duration) {
	ct.flushInterval.Store(int64(d))
}

// StartLastSeenWriter starts a background worker that processes last seen updates in batches.
// Returns a done channel that closes when the worker finishes draining on shutdown.
func (ct *ConnTracker) StartLastSeenWriter(ctx context.Context, store DBUserStore) <-chan struct{} {
	done := make(chan struct{})
	if store == nil {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		interval := time.Duration(ct.flushInterval.Load())
		if interval <= 0 {
			interval = 10 * time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		flush := func(fCtx context.Context) {
			dirtyUpdates := make(map[int64]time.Time)

			snap := ct.snapshot.Load()
			if snap != nil {
				for uid, state := range snap.userStates {
					if state.dirty.Swap(false) {
						ls := state.lastSeenNanos.Load()
						if ls > 0 {
							dirtyUpdates[uid] = time.Unix(0, ls)
						}
					}
				}
			}

			ct.masterMu.Lock()
			for uid, state := range ct.masterStates {
				if snap == nil || snap.userStates[uid] == nil {
					if state.dirty.Swap(false) {
						ls := state.lastSeenNanos.Load()
						if ls > 0 {
							dirtyUpdates[uid] = time.Unix(0, ls)
						}
					}
				}
			}
			ct.masterMu.Unlock()

			if len(dirtyUpdates) == 0 {
				return
			}

			if batchStore, ok := store.(BatchLastSeenUpdater); ok {
				if err := batchStore.UpdateUsersLastSeen(fCtx, dirtyUpdates); err != nil {
					slog.Error("failed to batch update user last_seen_at in DB", "error", err)
				}
			} else {
				for uid, ls := range dirtyUpdates {
					if err := store.UpdateUserLastSeen(fCtx, uid, ls); err != nil {
						slog.Error("failed to update user last_seen_at in DB", "user_id", uid, "error", err)
					}
				}
			}
		}

		for {
			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
				flush(shutdownCtx)
				cancel()
				return
			case <-ticker.C:
				flush(ctx)
			}
		}
	}()
	return done
}

func canonicalIP(raw string) string {
	ipStr := strings.TrimSpace(raw)
	if ipStr == "" {
		return ""
	}
	if parsed := net.ParseIP(ipStr); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return v4.String()
		}
		return parsed.String()
	}
	return ipStr
}

// SetUserMappings updates the in-memory mapping of IPs to Users.
// User state objects are reused across swaps by user ID.
func (ct *ConnTracker) SetUserMappings(users []UserMappingInfo) {
	ct.masterMu.Lock()
	defer ct.masterMu.Unlock()

	newIPToUser := make(map[string]int64)
	newUserState := make(map[int64]*userPresenceState)

	for _, u := range users {
		state, exists := ct.masterStates[u.UserID]
		if !exists {
			state = &userPresenceState{
				userID:        u.UserID,
				username:      u.Username,
				registeredIPs: make(map[string]struct{}),
			}
			if u.LastSeenAt != "" {
				if parsed, err := parseTime(u.LastSeenAt); err == nil && !parsed.IsZero() {
					state.lastSeenNanos.Store(parsed.UnixNano())
				}
			}
			ct.masterStates[u.UserID] = state
		} else {
			state.username = u.Username
			state.registeredIPs = make(map[string]struct{})
		}

		for _, rawIP := range u.IPs {
			ip := canonicalIP(rawIP)
			if ip != "" {
				newIPToUser[ip] = u.UserID
				state.registeredIPs[ip] = struct{}{}
			}
		}
		newUserState[u.UserID] = state
	}

	newSnap := &userMappingSnapshot{
		ipToUser:   newIPToUser,
		userStates: newUserState,
	}
	ct.snapshot.Store(newSnap)
}

func (ct *ConnTracker) getUserState(userID int64) *userPresenceState {
	snap := ct.snapshot.Load()
	if snap != nil {
		if st, ok := snap.userStates[userID]; ok {
			return st
		}
	}
	ct.masterMu.Lock()
	defer ct.masterMu.Unlock()
	return ct.masterStates[userID]
}

// LookupUser checks if the given client IP belongs to a registered user.
// Returns (userID, username, true) if found, otherwise (0, "", false).
// This is completely lock-free via atomic snapshot read.
func (ct *ConnTracker) LookupUser(ip string) (int64, string, bool) {
	normIP := canonicalIP(ip)
	snap := ct.snapshot.Load()
	if snap == nil {
		return 0, "", false
	}
	userID, ok := snap.ipToUser[normIP]
	if !ok {
		return 0, "", false
	}
	state, ok := snap.userStates[userID]
	if !ok {
		return userID, "", true
	}
	return userID, state.username, true
}

// Register records conn as an active connection for the given client IP
// and updates user presence state if the IP belongs to a registered user.
// The resolved user ID is bound to the connection record.
func (ct *ConnTracker) Register(ip string, conn net.Conn) {
	normIP := canonicalIP(ip)
	snap := ct.snapshot.Load()
	var userID int64
	if snap != nil {
		userID = snap.ipToUser[normIP]
	}

	idx := shardIndex(normIP)
	shard := &ct.shards[idx]
	shard.mu.Lock()
	if shard.conns[normIP] == nil {
		shard.conns[normIP] = make(map[net.Conn]int64)
	}
	shard.conns[normIP][conn] = userID
	shard.mu.Unlock()

	if userID > 0 {
		if state := ct.getUserState(userID); state != nil {
			now := time.Now()
			newConns := state.activeConns.Add(1)
			if newConns == 1 {
				state.firstActiveNanos.Store(now.UnixNano())
			}
			state.lastSeenNanos.Store(now.UnixNano())
			state.dirty.Store(true)
		}
	}
}

// Unregister removes conn from the tracker and decrements the user counter
// for the user resolved at Register time (preventing ghost "Online" users).
func (ct *ConnTracker) Unregister(ip string, conn net.Conn) {
	normIP := canonicalIP(ip)
	idx := shardIndex(normIP)
	shard := &ct.shards[idx]

	shard.mu.Lock()
	var resolvedUserID int64
	var found bool
	if set := shard.conns[normIP]; set != nil {
		if uid, ok := set[conn]; ok {
			resolvedUserID = uid
			found = true
			delete(set, conn)
			if len(set) == 0 {
				delete(shard.conns, normIP)
			}
		}
	}
	shard.mu.Unlock()

	if found && resolvedUserID > 0 {
		if state := ct.getUserState(resolvedUserID); state != nil {
			newConns := state.activeConns.Add(-1)
			if newConns < 0 {
				state.activeConns.Store(0)
				newConns = 0
			}
			now := time.Now()
			state.lastSeenNanos.Store(now.UnixNano())
			state.dirty.Store(true)
			if newConns == 0 {
				state.firstActiveNanos.Store(0)
			}
		}
	}
}

// EvictNotAllowed closes every active connection whose client IP is NOT present
// in the allowedIPs set.
func (ct *ConnTracker) EvictNotAllowed(allowedIPs map[string]struct{}) {
	var toClose []net.Conn
	for i := 0; i < numShards; i++ {
		shard := &ct.shards[i]
		shard.mu.Lock()
		for ip, set := range shard.conns {
			if allowedIPs == nil {
				for conn := range set {
					toClose = append(toClose, conn)
				}
			} else if _, ok := allowedIPs[ip]; !ok {
				for conn := range set {
					toClose = append(toClose, conn)
				}
			}
		}
		shard.mu.Unlock()
	}

	for _, conn := range toClose {
		_ = conn.Close()
	}
}

// EvictBlacklisted closes every active connection whose client IP matches the blacklist predicate.
func (ct *ConnTracker) EvictBlacklisted(isBlacklisted func(net.IP) bool) {
	if isBlacklisted == nil {
		return
	}
	var toClose []net.Conn
	for i := 0; i < numShards; i++ {
		shard := &ct.shards[i]
		shard.mu.Lock()
		for ipStr, set := range shard.conns {
			ip := net.ParseIP(ipStr)
			if ip != nil && isBlacklisted(ip) {
				for conn := range set {
					toClose = append(toClose, conn)
				}
			}
		}
		shard.mu.Unlock()
	}

	for _, conn := range toClose {
		_ = conn.Close()
	}
}

// ActiveCount returns the total number of currently tracked TCP connections.
func (ct *ConnTracker) ActiveCount() int {
	total := 0
	for i := 0; i < numShards; i++ {
		shard := &ct.shards[i]
		shard.mu.Lock()
		for _, set := range shard.conns {
			total += len(set)
		}
		shard.mu.Unlock()
	}
	return total
}

// GetPresenceStats returns current aggregate metrics and user list for presence tracking.
func (ct *ConnTracker) GetPresenceStats() UserPresenceSummary {
	snap := ct.snapshot.Load()
	userCount := 0
	if snap != nil {
		userCount = len(snap.userStates)
	}

	summary := UserPresenceSummary{
		Users: make([]UserPresenceDTO, 0, userCount),
	}

	userActiveIPs := make(map[int64]map[string]struct{})
	summary.ActiveConnections = 0

	for i := 0; i < numShards; i++ {
		shard := &ct.shards[i]
		shard.mu.Lock()
		for ip, set := range shard.conns {
			if len(set) > 0 {
				summary.ActiveConnections += len(set)
				for _, uid := range set {
					if uid > 0 {
						if userActiveIPs[uid] == nil {
							userActiveIPs[uid] = make(map[string]struct{})
						}
						userActiveIPs[uid][ip] = struct{}{}
					}
				}
			}
		}
		shard.mu.Unlock()
	}

	if snap == nil {
		return summary
	}

	for _, state := range snap.userStates {
		summary.TotalUsers++
		active := int(state.activeConns.Load())
		status := "Offline"
		if active > 0 {
			status = "Online"
			summary.TotalOnline++
		} else {
			summary.TotalOffline++
		}

		var ips []string
		for ip := range state.registeredIPs {
			ips = append(ips, ip)
		}
		sort.Strings(ips)

		var activeIPs []string
		if activeSet, ok := userActiveIPs[state.userID]; ok {
			for ip := range activeSet {
				activeIPs = append(activeIPs, ip)
			}
			sort.Strings(activeIPs)
		}

		firstActiveStr := ""
		if fa := state.firstActiveNanos.Load(); fa > 0 {
			firstActiveStr = time.Unix(0, fa).UTC().Format(time.RFC3339)
		}

		lastSeenStr := ""
		if ls := state.lastSeenNanos.Load(); ls > 0 {
			lastSeenStr = time.Unix(0, ls).UTC().Format(time.RFC3339)
		}

		summary.Users = append(summary.Users, UserPresenceDTO{
			UserID:            state.userID,
			Username:          state.username,
			RegisteredIPs:     ips,
			ActiveIPs:         activeIPs,
			Status:            status,
			ActiveConnections: active,
			FirstActiveAt:     firstActiveStr,
			LastSeenAt:        lastSeenStr,
		})
	}

	sort.Slice(summary.Users, func(i, j int) bool {
		return summary.Users[i].Username < summary.Users[j].Username
	})

	return summary
}

func parseTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02 15:04:05", raw)
}
