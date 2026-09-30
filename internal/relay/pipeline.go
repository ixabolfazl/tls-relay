package relay

import (
	"context"
	"net"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

// CheckClientAccess validates client IP against the access store.
// Returns (allowed bool, status string). If not allowed, status is "rejected_ip_invalid" or "rejected_" + reason.
func CheckClientAccess(store *access.AccessStore, clientIP string) (bool, string) {
	if store == nil {
		return true, ""
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false, "rejected_ip_invalid"
	}
	allowed, reason := store.CheckAccess(ip)
	if !allowed {
		return false, "rejected_" + reason
	}
	return true, ""
}

// RouteDecision contains the outcome of evaluating a domain rule and port permissions for a relay connection.
type RouteDecision struct {
	Allowed      bool
	Status       string // Rejection status if !Allowed: "rejected_domain_blocked", "rejected_direct_mode", "rejected_port", "rejected_domain"
	MatchedRule  string // "exact", wildcard rule pattern, or "none"
	RuleUseProxy string // "default", "true", "false"
	RuleMode     string // "proxy", "block", "direct" (empty string defaults to "proxy")
}

// EvaluateRoute evaluates whether a connection to the specified host and port should be allowed,
// considering the ruleStore, global port allowList, and an optional pre-validated domain rule.
func EvaluateRoute(
	ruleStore *rules.RuleStore,
	allowList *PortAllowList,
	host string,
	port int,
	prevalidatedRule *rules.DomainRule,
	prevalidatedMatchInfo *rules.MatchInfo,
) RouteDecision {
	ruleUseProxy := "default"

	if prevalidatedRule != nil && prevalidatedMatchInfo != nil {
		ruleUseProxy = prevalidatedRule.UseEgressProxy
		matched := "none"
		if prevalidatedMatchInfo.Kind == "exact" {
			matched = "exact"
		} else if prevalidatedMatchInfo.Kind == "wildcard" {
			matched = prevalidatedMatchInfo.Rule
		}
		return RouteDecision{
			Allowed:      true,
			MatchedRule:  matched,
			RuleUseProxy: ruleUseProxy,
			RuleMode:     prevalidatedRule.Mode,
		}
	}

	if ruleStore != nil {
		allowed, rule, matchInfo := ruleStore.LookupDetailed(host, port)
		matched := "none"
		if matchInfo.Kind == "exact" {
			matched = "exact"
		} else if matchInfo.Kind == "wildcard" {
			matched = matchInfo.Rule
		}

		if matchInfo.Matched {
			ruleUseProxy = rule.UseEgressProxy
			switch rule.Mode {
			case "block":
				return RouteDecision{
					Allowed:      false,
					Status:       "rejected_domain_blocked",
					MatchedRule:  matched,
					RuleUseProxy: ruleUseProxy,
					RuleMode:     rule.Mode,
				}
			case "direct":
				return RouteDecision{
					Allowed:      false,
					Status:       "rejected_direct_mode",
					MatchedRule:  matched,
					RuleUseProxy: ruleUseProxy,
					RuleMode:     rule.Mode,
				}
			}

			if !allowed {
				return RouteDecision{
					Allowed:      false,
					Status:       "rejected_port",
					MatchedRule:  matched,
					RuleUseProxy: ruleUseProxy,
					RuleMode:     rule.Mode,
				}
			}

			return RouteDecision{
				Allowed:      true,
				MatchedRule:  matched,
				RuleUseProxy: ruleUseProxy,
				RuleMode:     rule.Mode,
			}
		}

		// No rule matches: apply unknown_domain_policy
		if !ruleStore.IsPortAllowedByPolicy(port) {
			return RouteDecision{
				Allowed:      false,
				Status:       "rejected_domain",
				MatchedRule:  "none",
				RuleUseProxy: ruleUseProxy,
			}
		}
		if allowList != nil && !allowList.Allowed(port) {
			return RouteDecision{
				Allowed:      false,
				Status:       "rejected_port",
				MatchedRule:  "none",
				RuleUseProxy: ruleUseProxy,
			}
		}
		return RouteDecision{
			Allowed:      true,
			MatchedRule:  "none",
			RuleUseProxy: ruleUseProxy,
		}
	}

	// No rule store configured: use global port allow-list
	if allowList != nil && !allowList.Allowed(port) {
		return RouteDecision{
			Allowed:      false,
			Status:       "rejected_port",
			MatchedRule:  "none",
			RuleUseProxy: ruleUseProxy,
		}
	}
	return RouteDecision{
		Allowed:      true,
		MatchedRule:  "none",
		RuleUseProxy: ruleUseProxy,
	}
}

// BuildDialer constructs a dial function honoring customDialer, egressDialer with rule override, or default net.Dialer.
func BuildDialer(
	customDialer func(context.Context, string, string) (net.Conn, error),
	egressDialer *EgressDialer,
	ruleUseProxy string,
) func(context.Context, string, string) (net.Conn, error) {
	return func(dCtx context.Context, network, addr string) (net.Conn, error) {
		if customDialer != nil {
			return customDialer(dCtx, network, addr)
		}
		if egressDialer != nil {
			return egressDialer.DialContextWithOverride(dCtx, network, addr, ruleUseProxy)
		}
		var dialer net.Dialer
		return dialer.DialContext(dCtx, network, addr)
	}
}
