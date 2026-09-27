// Package syncer coordinates the in-memory state of domain rules and access controls
// with the backing SQLite database. It loads rules on startup and refreshes in-memory
// atomic snapshots whenever changes are committed via the admin panel or portal.
package syncer

import (
	"context"
	"log/slog"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

// Syncer loads initial state from SQLite into in-memory atomic snapshots
// and provides direct refresh hooks called after administrative writes.
type Syncer struct {
	ruleStore   *rules.RuleStore
	accessStore *access.AccessStore
	sqlStore    *sqlitestore.Store
	connTracker *relay.ConnTracker
}

// New creates a Syncer bound to the given in-memory stores and SQLite store.
func New(rs *rules.RuleStore, as *access.AccessStore, sq *sqlitestore.Store) *Syncer {
	return &Syncer{
		ruleStore:   rs,
		accessStore: as,
		sqlStore:    sq,
	}
}

// SetConnTracker registers a ConnTracker with the Syncer.
func (s *Syncer) SetConnTracker(ct *relay.ConnTracker) {
	s.connTracker = ct
}

// LoadInitial performs a one-shot load of all domain rules, blacklist entries,
// and user IP mappings from SQLite directly into in-memory caches.
// This must be called before starting listeners.
func (s *Syncer) LoadInitial(ctx context.Context) error {
	if err := s.RefreshDomains(ctx); err != nil {
		return err
	}
	if err := s.RefreshBlacklist(ctx); err != nil {
		return err
	}
	return s.RefreshUserIPs(ctx)
}

// RefreshDomains reloads domain rules from SQLite and atomically swaps RuleStore in memory.
func (s *Syncer) RefreshDomains(ctx context.Context) error {
	rawRules, err := s.sqlStore.AllDomainRulesRaw(ctx)
	if err != nil {
		return err
	}
	if err := s.ruleStore.Swap(rawRules); err != nil {
		return err
	}
	slog.Info("domain rules loaded from SQLite", "count", len(rawRules))
	return nil
}

// RefreshBlacklist reloads the blacklist from SQLite and atomically swaps AccessStore in memory.
func (s *Syncer) RefreshBlacklist(ctx context.Context) error {
	entries, err := s.sqlStore.AllBlacklistEntries(ctx)
	if err != nil {
		return err
	}
	if err := s.accessStore.SwapBlacklist(entries); err != nil {
		return err
	}
	slog.Info("global blacklist loaded from SQLite", "count", len(entries))
	return nil
}

// RefreshUserIPs reloads user IPs from SQLite into AccessStore and updates ConnTracker user mappings.
func (s *Syncer) RefreshUserIPs(ctx context.Context) error {
	ips, err := s.sqlStore.AllEnabledUserIPs(ctx)
	if err != nil {
		return err
	}
	s.accessStore.SwapUserIPs(ips)

	if s.connTracker != nil {
		usersWithIPs, err := s.sqlStore.ListAllUserWithIPs(ctx)
		if err != nil {
			slog.Error("failed to list users for connTracker mapping", "error", err)
			return err
		}
		userInfos := make([]relay.UserMappingInfo, 0, len(usersWithIPs))
		for _, u := range usersWithIPs {
			userInfos = append(userInfos, relay.UserMappingInfo{
				UserID:     u.UserID,
				Username:   u.Username,
				IPs:        u.IPs,
				LastSeenAt: u.LastSeenAt,
			})
		}
		s.connTracker.SetUserMappings(userInfos)
	}

	slog.Info("user IPs loaded from SQLite", "count", len(ips))
	return nil
}
