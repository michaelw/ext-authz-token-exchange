package config

import "testing"

func TestApigeeConfiguration(t *testing.T) {
	for _, name := range []string{"APIGEE_GRPC_PORT", "APIGEE_TLS_CERT_FILE", "APIGEE_TLS_KEY_FILE", "APIGEE_AUTH_AUDIENCE", "APIGEE_AUTH_ALLOWED_SUBJECTS"} {
		t.Setenv(name, "")
	}
	c, err := LoadApigeeFromEnv()
	if err != nil || c.Port != "" {
		t.Fatalf("disabled: %v", err)
	}
	t.Setenv("APIGEE_GRPC_PORT", "3003")
	if _, err := LoadApigeeFromEnv(); err == nil {
		t.Fatal("enabled listener must require TLS and identity")
	}
	t.Setenv("APIGEE_TLS_CERT_FILE", "cert.pem")
	t.Setenv("APIGEE_TLS_KEY_FILE", "key.pem")
	t.Setenv("APIGEE_AUTH_AUDIENCE", "callout")
	t.Setenv("APIGEE_AUTH_ALLOWED_SUBJECTS", "123, 456")
	c, err = LoadApigeeFromEnv()
	if err != nil || len(c.AllowedSubjects) != 2 {
		t.Fatalf("valid: %v", err)
	}
	t.Setenv("APIGEE_GRPC_PORT", "0")
	if _, err := LoadApigeeFromEnv(); err == nil {
		t.Fatal("invalid port accepted")
	}
}
