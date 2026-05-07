package main

import "testing"

func TestGRPCPortFromEnv(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv("GRPC_PORT", "")
		if got := grpcPortFromEnv(); got != "3001" {
			t.Fatalf("grpcPortFromEnv() = %q, want 3001", got)
		}
	})

	t.Run("configured", func(t *testing.T) {
		t.Setenv("GRPC_PORT", "4001")
		if got := grpcPortFromEnv(); got != "4001" {
			t.Fatalf("grpcPortFromEnv() = %q, want 4001", got)
		}
	})
}
