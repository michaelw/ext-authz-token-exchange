package main

import "testing"

func TestNewCommandFlags(t *testing.T) {
	cmd := newCommand()

	for _, name := range []string{"config", "base-url", "namespace-prefix", "system-namespace", "insecure-skip-verify"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Fatalf("expected flag %q to be registered", name)
		}
	}
}
