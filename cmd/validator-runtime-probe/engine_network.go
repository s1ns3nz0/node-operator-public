package main

import (
	"context"
	"errors"
	"net"
	"time"
)

func runEngineNetworkDeny(ctx context.Context) (map[string]any, error) {
	select {
	case <-ctx.Done():
		return nil, errors.New("network control cancelled")
	case <-time.After(20 * time.Second):
	}
	lookupContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	ips, err := net.DefaultResolver.LookupIP(lookupContext, "ip4", "nethermind-engine.node-operator.svc")
	cancel()
	if err != nil || len(ips) != 1 || ips[0].To4() == nil {
		return nil, errors.New("INCONCLUSIVE network control DNS")
	}
	_, approved, _ := net.ParseCIDR("10.80.0.0/16")
	if !approved.Contains(ips[0]) {
		return nil, errors.New("network control outside approved VPC")
	}
	started := time.Now()
	dial := &net.Dialer{Timeout: 5 * time.Second}
	connection, err := dial.DialContext(ctx, "tcp4", net.JoinHostPort(ips[0].String(), "8551"))
	if connection != nil {
		_ = connection.Close()
	}
	return classifyEngineNetworkDeny(ctx, ips[0].String(), err, time.Since(started))
}

func classifyEngineNetworkDeny(ctx context.Context, ip string, err error, elapsed time.Duration) (map[string]any, error) {
	var timeout net.Error
	if ctx.Err() != nil || err == nil || !errors.As(err, &timeout) || !timeout.Timeout() || elapsed < 4*time.Second {
		return nil, errors.New("INCONCLUSIVE network denial control")
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return nil, errors.New("INCONCLUSIVE network control DNS")
	}
	return map[string]any{"result": "NETWORK_DENIAL_OBSERVED", "layer": "tcp", "destination_ip": ip,
		"destination_port": 8551, "scope": "resolved fixed Engine endpoint TCP timeout; interpret only with same-node positive controls and policy evidence"}, nil
}
