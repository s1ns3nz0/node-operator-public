package jmxreceiver

import (
	"testing"

	"go.opentelemetry.io/collector/config/confignet"
	"go.opentelemetry.io/collector/receiver/otlpreceiver"
)

func TestConfigOptionalGRPCPreservesJMXEndpointAndDisablesHTTP(t *testing.T) {
	factory := otlpreceiver.NewFactory()
	config := factory.CreateDefaultConfig().(*otlpreceiver.Config)

	if config.HTTP.HasValue() {
		t.Fatal("HTTP must be absent before JMX configures its gRPC listener")
	}
	if err := insertDefault(&config.GRPC); err != nil {
		t.Fatalf("initialize optional gRPC config: %v", err)
	}
	if !config.GRPC.HasValue() {
		t.Fatal("gRPC must be present after initialization")
	}

	const endpoint = "127.0.0.1:4317"
	config.GRPC.Get().NetAddr = confignet.AddrConfig{
		Endpoint:  endpoint,
		Transport: confignet.TransportTypeTCP,
	}
	if got := config.GRPC.Get().NetAddr.Endpoint; got != endpoint {
		t.Fatalf("gRPC endpoint = %q, want %q", got, endpoint)
	}
	if config.HTTP.HasValue() {
		t.Fatal("JMX must leave HTTP absent/disabled")
	}
}
