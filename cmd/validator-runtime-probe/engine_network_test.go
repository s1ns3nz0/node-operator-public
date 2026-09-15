package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestNetworkDenialRequiresResolvedTCPTimeout(t *testing.T) {
	timeout := &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	result, err := classifyEngineNetworkDeny(context.Background(), "10.80.6.135", timeout, 5*time.Second)
	if err != nil || result["result"] != "NETWORK_DENIAL_OBSERVED" {
		t.Fatalf("expected observed timeout: %v", err)
	}
	for _, bad := range []error{nil, errors.New("connection refused"), &net.DNSError{IsTimeout: true}} {
		if _, err := classifyEngineNetworkDeny(context.Background(), "10.80.6.135", bad, 5*time.Second); err == nil {
			t.Fatal("non-TCP-timeout accepted")
		}
	}
	if _, err := classifyEngineNetworkDeny(context.Background(), "10.80.6.135", timeout, time.Second); err == nil {
		t.Fatal("premature timeout accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := classifyEngineNetworkDeny(ctx, "10.80.6.135", timeout, 5*time.Second); err == nil {
		t.Fatal("cancelled observation accepted")
	}
}
