package config_test

import (
	"testing"

	"github.com/michaelw/ext-authz-token-exchange/internal/config"
)

func TestLoggingFormatAndReleasedDefaults(t *testing.T) {
	t.Setenv("TOKEN_EXCHANGE_LOG_FORMAT", "")
	t.Setenv("TOKEN_EXCHANGE_INSECURE_LOG_TOKENS", "")
	t.Setenv("GRPC_LOG_HEALTH_CHECKS", "")
	cfg, _ := config.LoadFromEnv()
	if cfg.LogFormat != "json" || cfg.InsecureLogTokens || !cfg.LogHealthChecks {
		t.Fatal("changed released logging defaults")
	}
	t.Setenv("TOKEN_EXCHANGE_LOG_FORMAT", "text")
	cfg, _ = config.LoadFromEnv()
	if cfg.LogFormat != "text" {
		t.Fatal("explicit text option ignored")
	}
	t.Setenv("TOKEN_EXCHANGE_LOG_FORMAT", "invalid")
	cfg, err := config.LoadFromEnv()
	if err == nil || cfg.LogFormat != "invalid" {
		t.Fatal("invalid logging format accepted")
	}
}
