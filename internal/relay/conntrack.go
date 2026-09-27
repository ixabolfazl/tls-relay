package relay

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
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
	userID          int64
	username        string
	registeredIPs   map[string]struct{}
	activeConns     int
	firstActiveTime time.Time
	lastSeenTime    time.Time
}

type lastSeenEvent struct {
	userID   int64
	lastSeen time.Time
}

// DBUserStore is an interface for updating user last seen timestamps asynchronously.
type DBUserStore interface {
	UpdateUserLastSeen(ctx context.Context, userID int64, lastSeen time.Time) error
}

// ConnTracker maintains a registry of all active TCP connections keyed by
// client IP. It is used to forcibly close connections belonging to IPs that
// are no longer permitted, and to track per-user live online presence.
//
// All methods are safe for concurrent use.
type ConnTracker struct {
	mu         sync.Mutex
	conns      map[string]map[net.Conn]struct{} // ip → set of open conns
	ipToUser   map[string]int64                 // ip → user_id
	userState  map[int64]*userPresenceState     // user_id → user presence state
	lastSeenCh chan lastSeenEvent
}

// NewConnTracker creates a new ConnTracker.
func NewConnTracker() *ConnTracker {
	return &ConnTracker{
		conns:      make(map[string]map[net.Conn]struct{}),
		ipToUser:   make(map[string]int64),
		userState:  make(map[int64]*userPresenceState),
		lastSeenCh: make(chan lastSeenEvent, 256),
	}
}

// StartLastSeenWriter starts a background worker that processes last seen updates asynchronously.
func (ct *ConnTracker) StartLastSeenWriter(ctx context.Context, store DBUserStore) {
	if store == nil {
		return
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
				defer cancel()
				for {
					select {
					case ev, ok := <-ct.lastSeenCh:
						if ok {
							_ = store.UpdateUserLastSeen(shutdownCtx, ev.userID, ev.lastSeen)
						}
					default:
						return
					}
				}
			case ev, ok := <-ct.lastSeenCh:
				if !ok {
					return
				}
				if err := store.UpdateUserLastSeen(ctx, ev.userID, ev.lastSeen); err != nil {
					slog.Error("failed to update user last_seen_at in DB", "user_id", ev.userID, "error", err)
				}
			}
		}
	}()
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
func (ct *ConnTracker) SetUserMappings(users []UserMappingInfo) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	newIPToUser := make(map[string]int64)
	newUserState := make(map[int64]*userPresenceState)

	for _, u := range users {
		existingState, exists := ct.userState[u.UserID]
		state := &userPresenceState{
			userID:        u.UserID,
			username:      u.Username,
			registeredIPs: make(map[string]struct{}),
		}

		if exists {
			state.activeConns = existingState.activeConns
			state.firstActiveTime = existingState.firstActiveTime
			state.lastSeenTime = existingState.lastSeenTime
		} else if u.LastSeenAt != "" {
			if parsed, err := parseTime(u.LastSeenAt); err == nil {
				state.lastSeenTime = parsed
			}
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

	ct.ipToUser = newIPToUser
	ct.userState = newUserState
}

// LookupUser checks if the given client IP belongs to a registered user.
// Returns (userID, username, true) if found, otherwise (0, "", false).
func (ct *ConnTracker) LookupUser(ip string) (int64, string, bool) {
	normIP := canonicalIP(ip)
	ct.mu.Lock()
	defer ct.mu.Unlock()

	userID, ok := ct.ipToUser[normIP]
	if !ok {
		return 0, "", false
	}
	state, ok := ct.userState[userID]
	if !ok {
		return userID, "", true
	}
	return userID, state.username, true
}

// Register records conn as an active connection for the given client IP
// and updates user presence state if the IP belongs to a registered user.
func (ct *ConnTracker) Register(ip string, conn net.Conn) {
	normIP := canonicalIP(ip)
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.conns[normIP] == nil {
		ct.conns[normIP] = make(map[net.Conn]struct{})
	}
	ct.conns[normIP][conn] = struct{}{}

	if userID, ok := ct.ipToUser[normIP]; ok {
		if state, ok := ct.userState[userID]; ok {
			now := time.Now()
			state.activeConns++
			if state.activeConns == 1 {
				state.firstActiveTime = now
			}
			state.lastSeenTime = now

			select {
			case ct.lastSeenCh <- lastSeenEvent{userID: userID, lastSeen: now}:
			default:
			}
		}
	}
}

// Unregister removes conn from the tracker and updates user presence state.
func (ct *ConnTracker) Unregister(ip string, conn net.Conn) {
	normIP := canonicalIP(ip)
	ct.mu.Lock()
	defer ct.mu.Unlock()

	set := ct.conns[normIP]
	if set != nil {
		delete(set, conn)
		if len(set) == 0 {
			delete(ct.conns, normIP)
		}
	}

	if userID, ok := ct.ipToUser[normIP]; ok {
		if state, ok := ct.userState[userID]; ok {
			now := time.Now()
			if state.activeConns > 0 {
				state.activeConns--
			}
			state.lastSeenTime = now
			if state.activeConns == 0 {
				state.firstActiveTime = time.Time{}
			}

			// Queue async DB write without blocking TCP connection thread.
			select {
			case ct.lastSeenCh <- lastSeenEvent{userID: userID, lastSeen: now}:
			default:
				slog.Warn("lastSeenCh worker queue is full; skipping DB write queue", "user_id", userID)
			}
		}
	}
}

// EvictNotAllowed closes every active connection whose client IP is NOT present
// in the allowedIPs set.
func (ct *ConnTracker) EvictNotAllowed(allowedIPs map[string]struct{}) {
	ct.mu.Lock()
	var toClose []net.Conn
	for ip, set := range ct.conns {
		if _, ok := allowedIPs[ip]; !ok {
			for conn := range set {
				toClose = append(toClose, conn)
			}
		}
	}
	ct.mu.Unlock()

	for _, conn := range toClose {
		_ = conn.Close()
	}
}

// EvictBlacklisted closes every active connection whose client IP matches the blacklist predicate.
func (ct *ConnTracker) EvictBlacklisted(isBlacklisted func(net.IP) bool) {
	if isBlacklisted == nil {
		return
	}
	ct.mu.Lock()
	var toClose []net.Conn
	for ipStr, set := range ct.conns {
		ip := net.ParseIP(ipStr)
		if ip != nil && isBlacklisted(ip) {
			for conn := range set {
				toClose = append(toClose, conn)
			}
		}
	}
	ct.mu.Unlock()

	for _, conn := range toClose {
		_ = conn.Close()
	}
}

// ActiveCount returns the total number of currently tracked TCP connections.
func (ct *ConnTracker) ActiveCount() int {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	total := 0
	for _, set := range ct.conns {
		total += len(set)
	}
	return total
}

// GetPresenceStats returns current aggregate metrics and user list for presence tracking.
func (ct *ConnTracker) GetPresenceStats() UserPresenceSummary {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	summary := UserPresenceSummary{
		Users: make([]UserPresenceDTO, 0, len(ct.userState)),
	}

	userActiveIPs := make(map[int64]map[string]struct{})
	summary.ActiveConnections = 0
	for ip, set := range ct.conns {
		if len(set) > 0 {
			summary.ActiveConnections += len(set)
			if userID, ok := ct.ipToUser[ip]; ok {
				if userActiveIPs[userID] == nil {
					userActiveIPs[userID] = make(map[string]struct{})
				}
				userActiveIPs[userID][ip] = struct{}{}
			}
		}
	}

	for _, state := range ct.userState {
		summary.TotalUsers++

		status := "Offline"
		if state.activeConns > 0 {
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
		if !state.firstActiveTime.IsZero() {
			firstActiveStr = state.firstActiveTime.UTC().Format(time.RFC3339)
		}

		lastSeenStr := ""
		if !state.lastSeenTime.IsZero() {
			lastSeenStr = state.lastSeenTime.UTC().Format(time.RFC3339)
		}

		summary.Users = append(summary.Users, UserPresenceDTO{
			UserID:            state.userID,
			Username:          state.username,
			RegisteredIPs:     ips,
			ActiveIPs:         activeIPs,
			Status:            status,
			ActiveConnections: state.activeConns,
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
