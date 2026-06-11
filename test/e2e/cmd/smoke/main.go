package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultMode                = "ext-authz"
	defaultClusterNamePrefix   = "ext-authz-token-exchange-smoke"
	defaultBaseURL             = "https://httpbin.int.kube"
	defaultTimeout             = 90 * time.Minute
	defaultClusterCreateWait   = 5 * time.Minute
	defaultReadyTimeout        = 10 * time.Minute
	defaultReadyReportInterval = 10 * time.Second
	defaultCleanupTimeout      = 5 * time.Minute
	defaultDiagnosticTimeout   = 45 * time.Second
	defaultTokenReadyTimeout   = 10 * time.Minute
	defaultTokenReadyInterval  = 10 * time.Second
)

type config struct {
	mode                string
	clusterName         string
	baseURL             string
	timeout             time.Duration
	clusterCreateWait   time.Duration
	readyTimeout        time.Duration
	readyReportInterval time.Duration
	cleanupTimeout      time.Duration
	diagnosticTimeout   time.Duration
	tokenReadyTimeout   time.Duration
	tokenReadyInterval  time.Duration
}

type tokenProbeResult struct {
	allowCode int
	denyCode  int
	allowAuth string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "smoke failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	tempDir, err := os.MkdirTemp("", "ext-authz-token-exchange-smoke-*")
	if err != nil {
		return fmt.Errorf("create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	kubeconfig := filepath.Join(tempDir, "kubeconfig")
	env := append(os.Environ(), "KUBECONFIG="+kubeconfig)

	fmt.Printf("smoke: mode=%s cluster=%s kubeconfig=%s\n", cfg.mode, cfg.clusterName, kubeconfig)
	if err := runStep(ctx, env, "kind", "create", "cluster", "--name", cfg.clusterName, "--kubeconfig", kubeconfig, "--wait", cfg.clusterCreateWait.String()); err != nil {
		return err
	}

	clusterCreated := true
	defer func() {
		if !clusterCreated {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cfg.cleanupTimeout)
		defer cancel()
		if err := runStep(cleanupCtx, env, "kind", "delete", "cluster", "--name", cfg.clusterName, "--kubeconfig", kubeconfig); err != nil {
			fmt.Fprintf(os.Stderr, "smoke: failed to delete cluster %q: %v\n", cfg.clusterName, err)
		}
	}()

	if err := runStep(ctx, env, "kubectl", "cluster-info"); err != nil {
		return err
	}

	if err := runStep(ctx, env, "devspace", deployArgs(cfg.mode)...); err != nil {
		collectDiagnostics(env, cfg.diagnosticTimeout)
		return err
	}
	if err := waitForPodsReady(ctx, env, cfg); err != nil {
		collectDiagnostics(env, cfg.diagnosticTimeout)
		return err
	}
	if err := waitForTokenExchange(ctx, cfg); err != nil {
		collectDiagnostics(env, cfg.diagnosticTimeout)
		return err
	}

	testEnv := append(env, "E2E_BASE_URL="+strings.TrimRight(cfg.baseURL, "/"))
	if err := runStep(ctx, testEnv, "devspace", "run", "test-e2e"); err != nil {
		collectDiagnostics(env, cfg.diagnosticTimeout)
		return err
	}

	fmt.Println("smoke: completed successfully")
	return nil
}

func loadConfig() (config, error) {
	mode := getenvDefault("SMOKE_MODE", defaultMode)
	if _, err := deployProfiles(mode); err != nil {
		return config{}, err
	}
	clusterName := os.Getenv("SMOKE_CLUSTER_NAME")
	if clusterName == "" {
		clusterName = defaultClusterNamePrefix + "-" + mode
	}

	return config{
		mode:                mode,
		clusterName:         clusterName,
		baseURL:             getenvDefault("E2E_BASE_URL", defaultBaseURL),
		timeout:             durationFromEnv("SMOKE_TIMEOUT", defaultTimeout),
		clusterCreateWait:   durationFromEnv("SMOKE_CLUSTER_CREATE_WAIT", defaultClusterCreateWait),
		readyTimeout:        durationFromEnv("SMOKE_READY_TIMEOUT", defaultReadyTimeout),
		readyReportInterval: durationFromEnv("SMOKE_READY_REPORT_INTERVAL", defaultReadyReportInterval),
		cleanupTimeout:      durationFromEnv("SMOKE_CLEANUP_TIMEOUT", defaultCleanupTimeout),
		diagnosticTimeout:   durationFromEnv("SMOKE_DIAGNOSTIC_TIMEOUT", defaultDiagnosticTimeout),
		tokenReadyTimeout:   durationFromEnv("SMOKE_TOKEN_READY_TIMEOUT", defaultTokenReadyTimeout),
		tokenReadyInterval:  durationFromEnv("SMOKE_TOKEN_READY_INTERVAL", defaultTokenReadyInterval),
	}, nil
}

func deployArgs(mode string) []string {
	args := []string{"deploy"}
	for _, profile := range mustDeployProfiles(mode) {
		args = append(args, "-p", profile)
	}
	return args
}

func mustDeployProfiles(mode string) []string {
	profiles, err := deployProfiles(mode)
	if err != nil {
		panic(err)
	}
	return profiles
}

func deployProfiles(mode string) ([]string, error) {
	switch mode {
	case "ext-authz":
		return []string{"with-infra", "with-keycloak"}, nil
	case "ext-proc":
		return []string{"with-infra", "with-keycloak", "ext-proc"}, nil
	default:
		return nil, fmt.Errorf("unknown SMOKE_MODE %q; expected ext-authz or ext-proc", mode)
	}
}

func waitForPodsReady(ctx context.Context, env []string, cfg config) error {
	waitCtx, cancel := context.WithTimeout(ctx, cfg.readyTimeout)
	defer cancel()

	ticker := time.NewTicker(cfg.readyReportInterval)
	defer ticker.Stop()

	for {
		notReady, ready, err := podReadiness(waitCtx, env)
		if err != nil {
			return err
		}
		if ready {
			fmt.Println("smoke: all pods are Ready")
			return nil
		}
		printPodReadiness(notReady)

		select {
		case <-waitCtx.Done():
			return fmt.Errorf("timed out waiting for pods to become Ready: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func podReadiness(ctx context.Context, env []string) ([]string, bool, error) {
	output, err := commandOutput(ctx, env, "kubectl", "get", "pods", "--all-namespaces", "--no-headers")
	if err != nil {
		return nil, false, err
	}
	return parsePodReadiness(output), strings.TrimSpace(output) != "" && len(parsePodReadiness(output)) == 0, nil
}

func parsePodReadiness(output string) []string {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}
	var notReady []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[3] == "Completed" || fields[3] == "Succeeded" {
			continue
		}
		readyParts := strings.SplitN(fields[2], "/", 2)
		if len(readyParts) != 2 || readyParts[0] != readyParts[1] || fields[3] != "Running" {
			notReady = append(notReady, line)
		}
	}
	return notReady
}

func printPodReadiness(notReady []string) {
	if len(notReady) == 0 {
		fmt.Println("smoke: waiting for pods to be created")
		return
	}
	fmt.Printf("smoke: waiting for %d non-ready pod(s)\n", len(notReady))
	for _, line := range notReady {
		fmt.Printf("smoke: non-ready pod: %s\n", line)
	}
}

func waitForTokenExchange(ctx context.Context, cfg config) error {
	waitCtx, cancel := context.WithTimeout(ctx, cfg.tokenReadyTimeout)
	defer cancel()

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // CI uses the starter-pack local test CA.
		}},
	}
	url := strings.TrimRight(cfg.baseURL, "/") + "/anything/yellow"
	ticker := time.NewTicker(cfg.tokenReadyInterval)
	defer ticker.Stop()

	for {
		result, err := probeTokenExchange(waitCtx, client, url)
		if err == nil && tokenProbeReady(result) {
			fmt.Printf("smoke: token exchange is enforcing at %s\n", url)
			return nil
		}
		status := tokenProbeStatus(result, err)
		fmt.Printf("smoke: waiting for token exchange enforcement at %s (%s)\n", url, status)

		select {
		case <-waitCtx.Done():
			return fmt.Errorf("timed out waiting for token exchange enforcement at %s (%s): %w", url, status, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func probeTokenExchange(ctx context.Context, client *http.Client, url string) (tokenProbeResult, error) {
	allowCode, allowBody, allowErr := request(ctx, client, url, "readiness-yellow")
	denyCode, _, denyErr := request(ctx, client, url, "")
	result := tokenProbeResult{
		allowCode: allowCode,
		denyCode:  denyCode,
		allowAuth: exchangedAuthorization(allowBody),
	}
	return result, errors.Join(allowErr, denyErr)
}

func request(ctx context.Context, client *http.Client, url, bearer string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

func tokenProbeReady(result tokenProbeResult) bool {
	return result.allowCode == http.StatusOK &&
		strings.HasPrefix(result.allowAuth, "Bearer ") &&
		result.allowAuth != "Bearer readiness-yellow" &&
		result.denyCode == http.StatusUnauthorized
}

func tokenProbeStatus(result tokenProbeResult, err error) string {
	exchanged := "missing"
	if result.allowAuth != "" {
		exchanged = "present"
	}
	if err != nil {
		return fmt.Sprintf("allow=%d deny=%d exchanged_auth=%s err=%v", result.allowCode, result.denyCode, exchanged, err)
	}
	return fmt.Sprintf("allow=%d deny=%d exchanged_auth=%s", result.allowCode, result.denyCode, exchanged)
}

func exchangedAuthorization(body []byte) string {
	var parsed struct {
		Headers map[string]any `json:"headers"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ""
	}
	for key, value := range parsed.Headers {
		if strings.EqualFold(key, "authorization") {
			return headerValue(value)
		}
	}
	return ""
}

func headerValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		if len(typed) == 0 {
			return ""
		}
		first, _ := typed[0].(string)
		return first
	default:
		return ""
	}
}

func collectDiagnostics(env []string, timeout time.Duration) {
	fmt.Fprintln(os.Stderr, "smoke: collecting Kubernetes diagnostics")
	steps := [][]string{
		{"kubectl", "get", "pods", "--all-namespaces", "-o", "wide"},
		{"kubectl", "get", "events", "--all-namespaces", "--sort-by=.lastTimestamp"},
		{"kubectl", "describe", "pods", "--all-namespaces"},
		{"kubectl", "get", "authorizationpolicy,envoyfilter,serviceentry", "--all-namespaces", "-o", "yaml"},
		{"kubectl", "get", "service", "--all-namespaces", "-o", "yaml"},
		{"kubectl", "get", "configmap", "istio", "-n", "istio-system", "-o", "yaml"},
		{"kubectl", "logs", "-n", "ext-authz-token-exchange", "-l", "app.kubernetes.io/name=ext-authz-token-exchange", "--all-containers", "--tail=200"},
		{"kubectl", "logs", "-n", "ext-authz-token-exchange-e2e", "-l", "app.kubernetes.io/name=fake-token-endpoint", "--all-containers", "--tail=200"},
		{"helm", "list", "--all-namespaces"},
	}
	for _, step := range steps {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_ = runStep(ctx, env, step[0], step[1:]...)
		cancel()
	}
}

func runStep(ctx context.Context, env []string, name string, args ...string) error {
	fmt.Printf("smoke: running %s %s\n", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func commandOutput(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w\n%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func getenvDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func durationFromEnv(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "smoke: ignoring invalid %s=%q: %v\n", name, value, err)
		return fallback
	}
	return parsed
}
