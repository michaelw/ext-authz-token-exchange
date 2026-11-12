package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ApigeeConfig controls the isolated, authenticated ExternalCallout listener.
type ApigeeConfig struct {
	Port            string
	CertFile        string
	KeyFile         string
	Audience        string
	AllowedSubjects []string
	InspectMessages bool
}

func LoadApigeeFromEnv() (ApigeeConfig, error) {
	c := ApigeeConfig{Port: strings.TrimSpace(os.Getenv("APIGEE_GRPC_PORT")), CertFile: strings.TrimSpace(os.Getenv("APIGEE_TLS_CERT_FILE")), KeyFile: strings.TrimSpace(os.Getenv("APIGEE_TLS_KEY_FILE")), Audience: strings.TrimSpace(os.Getenv("APIGEE_AUTH_AUDIENCE")), InspectMessages: envBool("APIGEE_INSPECT_MESSAGES", false)}
	for _, subject := range strings.Split(os.Getenv("APIGEE_AUTH_ALLOWED_SUBJECTS"), ",") {
		if subject = strings.TrimSpace(subject); subject != "" {
			c.AllowedSubjects = append(c.AllowedSubjects, subject)
		}
	}
	if c.Port == "" {
		return c, nil
	}
	port, err := strconv.Atoi(c.Port)
	if err != nil || port < 1 || port > 65535 {
		return c, fmt.Errorf("APIGEE_GRPC_PORT must be a valid TCP port")
	}
	if c.CertFile == "" || c.KeyFile == "" || c.Audience == "" || len(c.AllowedSubjects) == 0 {
		return c, fmt.Errorf("Apigee listener requires APIGEE_TLS_CERT_FILE, APIGEE_TLS_KEY_FILE, APIGEE_AUTH_AUDIENCE and APIGEE_AUTH_ALLOWED_SUBJECTS")
	}
	return c, nil
}
