package relay_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

func TestCheckClientAccess(t *testing.T) {
	// Nil store -> always allowed
	allowed, status := relay.CheckClientAccess(nil, "1.2.3.4")
	if !allowed || status != "" {
		t.Fatalf("expected allowed with nil store, got %v, %s", allowed, status)
	}

	store := access.NewAccessStore(access.ModeUser)

	// Invalid IP
	allowed, status = relay.CheckClientAccess(store, "not-an-ip")
	if allowed || status != "rejected_ip_invalid" {
		t.Fatalf("expected rejected_ip_invalid, got %v, %s", allowed, status)
	}

	// Unregistered IP in ModeUser
	allowed, status = relay.CheckClientAccess(store, "1.2.3.4")
	if allowed || status != "rejected_not_registered" {
		t.Fatalf("expected rejected_not_registered, got %v, %s", allowed, status)
	}
}

func TestEvaluateRoute(t *testing.T) {
	allowList := relay.NewPortAllowList([]int{443, 80})

	// Prevalidated rule takes precedence
	preRule := &rules.DomainRule{Mode: "proxy", UseEgressProxy: "true"}
	preMatch := &rules.MatchInfo{Matched: true, Kind: "exact"}
	dec := relay.EvaluateRoute(nil, allowList, "example.com", 443, preRule, preMatch)
	if !dec.Allowed || dec.MatchedRule != "exact" || dec.RuleUseProxy != "true" {
		t.Fatalf("unexpected prevalidated decision: %+v", dec)
	}

	// Rule store nil: uses allowList
	dec = relay.EvaluateRoute(nil, allowList, "example.com", 443, nil, nil)
	if !dec.Allowed || dec.MatchedRule != "none" {
		t.Fatalf("unexpected allowList decision: %+v", dec)
	}
	dec = relay.EvaluateRoute(nil, allowList, "example.com", 8080, nil, nil)
	if dec.Allowed || dec.Status != "rejected_port" {
		t.Fatalf("expected rejected_port, got %+v", dec)
	}
}

func TestBuildDialer(t *testing.T) {
	customCalled := false
	customDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		customCalled = true
		return nil, errors.New("custom called")
	}

	dialer := relay.BuildDialer(customDialer, nil, "default")
	_, _ = dialer(context.Background(), "tcp", "1.1.1.1:443")
	if !customCalled {
		t.Fatal("expected customDialer to be invoked")
	}
}
