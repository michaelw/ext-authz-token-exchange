package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/michaelw/ext-authz-token-exchange/internal/directhttp"
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
	host                string
	directAddress       string
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
	allowBody string
	denyBody  string
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
	keepCluster := os.Getenv("SMOKE_KEEP_CLUSTER") == "true"
	if !keepCluster {
		defer removeSmokeTempDir(tempDir)
	}
	restoreDevspaceCache, err := isolateDevspaceCache(filepath.Join(".devspace", "cache.yaml"), tempDir)
	if err != nil {
		return err
	}
	defer restoreDevspaceCache()

	kubeconfig := filepath.Join(tempDir, "kubeconfig")
	env := append(os.Environ(), "KUBECONFIG="+kubeconfig)
	if err := prepareDockerConfig(tempDir); err != nil {
		return err
	}
	env = append(env,
		"DEVSPACE_TMPDIR="+filepath.Join(tempDir, "devspace"),
		"GOCACHE="+filepath.Join(tempDir, "go-cache"),
		"GOMODCACHE="+filepath.Join(tempDir, "go-mod-cache"),
		"DOCKER_CONFIG="+filepath.Join(tempDir, "docker"),
		"BUILDX_BUILDER=default",
		"HELM_CACHE_HOME="+filepath.Join(tempDir, "helm", "cache"),
		"HELM_CONFIG_HOME="+filepath.Join(tempDir, "helm", "config"),
		"HELM_DATA_HOME="+filepath.Join(tempDir, "helm", "data"),
	)
	env = append(env, "HOST_INTEGRATION=false")

	fmt.Printf("smoke: mode=%s cluster=%s kubeconfig=%s\n", cfg.mode, cfg.clusterName, kubeconfig)
	kindArgs := []string{"create", "cluster", "--name", cfg.clusterName, "--kubeconfig", kubeconfig, "--wait", cfg.clusterCreateWait.String()}
	if cfg.mode == "ext-proc-inferencepool" {
		kindArgs = append(kindArgs, "--image", "kindest/node:v1.34.3")
	}
	if err := runStep(ctx, env, "kind", kindArgs...); err != nil {
		return err
	}

	clusterCreated := true
	defer func() {
		if !clusterCreated || keepCluster {
			if keepCluster {
				fmt.Printf("smoke: retained cluster %s and task files %s\n", cfg.clusterName, tempDir)
			}
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
	infraPath, err := prepareSmokeInfrastructure(ctx, env, tempDir)
	if err != nil {
		return err
	}
	env = append(env, "SMOKE_INFRA_PATH="+infraPath)
	var inferenceChart string
	poolBaseURL := ""
	poolHost := ""
	keycloakBaseURL := ""
	if cfg.mode == "ext-proc-inferencepool" {
		inferenceChart, err = prepareInferencePool(ctx, env, tempDir)
		if err != nil {
			return err
		}
		if err := runStep(ctx, env, "docker", "build", "--target", "inference-test-backend", "-t", "inference-test-backend:smoke", "."); err != nil {
			return err
		}
		if err := runStep(ctx, env, "kind", "load", "docker-image", "inference-test-backend:smoke", "--name", cfg.clusterName); err != nil {
			return err
		}
	}

	if err := runStep(ctx, env, "devspace", deployArgs(cfg.mode)...); err != nil {
		collectDiagnostics(env, cfg.diagnosticTimeout)
		return err
	}
	if inferenceChart != "" {
		for _, name := range []string{"e2e-inferencepool", "e2e-inferencepool-second"} {
			if err := installInferencePool(ctx, env, inferenceChart, name); err != nil {
				collectDiagnostics(env, cfg.diagnosticTimeout)
				return err
			}
		}
	}
	if err := waitForPodsReady(ctx, env, cfg); err != nil {
		collectDiagnostics(env, cfg.diagnosticTimeout)
		return err
	}
	if inferenceChart != "" {
		if err := waitForInferenceRoute(ctx, env); err != nil {
			return err
		}
		if err := waitForInferenceOverride(ctx, env); err != nil {
			return err
		}
	}
	address, stopForward, err := startGatewayPortForward(ctx, env)
	if err != nil {
		return err
	}
	defer stopForward()
	originalBaseURL := cfg.baseURL
	parsed, err := url.Parse(originalBaseURL)
	if err != nil {
		return err
	}
	cfg.host = parsed.Hostname()
	port := strings.TrimPrefix(address, "127.0.0.1:")
	cfg.baseURL = "https://" + net.JoinHostPort(cfg.host, port)
	cfg.directAddress = "127.0.0.1"
	env = append(env, "E2E_RESOURCE_BASE_URL="+originalBaseURL)
	if inferenceChart != "" {
		poolHost = "inference." + strings.TrimPrefix(cfg.host, "httpbin.")
		poolBaseURL = "https://" + net.JoinHostPort(poolHost, port)
	} else {
		keycloakAddress, stopKeycloak, err := startServicePortForward(ctx, env, "ext-authz-token-exchange-e2e", "keycloak", "8080")
		if err != nil {
			return err
		}
		defer stopKeycloak()
		keycloakBaseURL = "http://" + keycloakAddress
	}
	if err := waitForTokenExchange(ctx, cfg); err != nil {
		collectDiagnostics(env, cfg.diagnosticTimeout)
		return err
	}

	testBaseURL := cfg.baseURL
	if poolBaseURL != "" {
		testBaseURL = poolBaseURL
	}
	testEnv := append(env, "E2E_BASE_URL="+strings.TrimRight(testBaseURL, "/"))
	if inferenceChart != "" {
		testEnv = append(testEnv,
			"E2E_INFERENCEPOOL_ENABLED=true",
			"E2E_HOST="+poolHost,
		)
	} else {
		testEnv = append(testEnv,
			"E2E_HOST="+cfg.host,
			"E2E_KEYCLOAK_BASE_URL="+keycloakBaseURL,
			"E2E_KEYCLOAK_ISSUER="+keycloakIssuerURL(originalBaseURL),
		)
	}
	testEnv = append(testEnv, "E2E_SKIP_INSTALL=true", "E2E_DIRECT_ADDRESS="+cfg.directAddress)
	testArgs := []string{"run", "test-e2e"}
	if inferenceChart != "" {
		testArgs = append(testArgs, "--label-filter=inferencepool")
	}
	if err := runStep(ctx, testEnv, "devspace", testArgs...); err != nil {
		collectDiagnostics(env, cfg.diagnosticTimeout)
		return err
	}

	fmt.Println("smoke: completed successfully")
	return nil
}

func removeSmokeTempDir(path string) {
	modCache := filepath.Join(path, "go-mod-cache")
	if err := filepath.WalkDir(modCache, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return os.Chmod(current, info.Mode().Perm()|0o700)
	}); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "smoke: make temporary Go module cache removable: %v\n", err)
	}
	if err := os.RemoveAll(path); err != nil {
		fmt.Fprintf(os.Stderr, "smoke: remove temporary task files: %v\n", err)
	}
}

func prepareDockerConfig(tempDir string) error {
	plugins := filepath.Join(tempDir, "docker", "cli-plugins")
	if err := os.MkdirAll(plugins, 0o700); err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	buildx := filepath.Join(home, ".docker", "cli-plugins", "docker-buildx")
	if _, err := os.Stat(buildx); err == nil {
		return os.Symlink(buildx, filepath.Join(plugins, "docker-buildx"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func isolateDevspaceCache(cachePath, tempDir string) (func(), error) {
	backup := filepath.Join(tempDir, "devspace-cache.yaml")
	hadCache := false
	if err := os.Rename(cachePath, backup); err == nil {
		hadCache = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("isolate DevSpace cache: %w", err)
	}
	return func() {
		if err := os.Remove(cachePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "smoke: remove temporary DevSpace cache: %v\n", err)
		}
		if hadCache {
			if err := os.Rename(backup, cachePath); err != nil {
				fmt.Fprintf(os.Stderr, "smoke: restore DevSpace cache: %v\n", err)
			}
		}
	}, nil
}

func loadConfig() (config, error) {
	mode := getenvDefault("SMOKE_MODE", defaultMode)
	if _, err := deployProfiles(mode); err != nil {
		return config{}, err
	}
	clusterName := os.Getenv("SMOKE_CLUSTER_NAME")
	if clusterName == "" {
		clusterName = defaultClusterNamePrefix + "-" + mode
		if mode == "ext-proc-inferencepool" {
			clusterName = "txe-inferencepool"
		}
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
	args := []string{"deploy", "--var", "HOST_INTEGRATION=false"}
	if mode == "ext-proc-inferencepool" {
		args = append(args, "--var", "ISTIO_CHART_VERSION="+getenvDefault("SMOKE_ISTIO_VERSION", "1.28.0"))
	}
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
		return []string{"with-infra-smoke", "with-keycloak"}, nil
	case "ext-proc":
		return []string{"with-infra-smoke", "with-keycloak", "ext-proc"}, nil
	case "ext-proc-inferencepool":
		return []string{"with-infra-smoke", "ext-proc", "inferencepool-test"}, nil
	default:
		return nil, fmt.Errorf("unknown SMOKE_MODE %q; expected ext-authz, ext-proc, or ext-proc-inferencepool", mode)
	}
}

func prepareSmokeInfrastructure(ctx context.Context, env []string, tempDir string) (string, error) {
	source := filepath.Join(tempDir, "devspace-starter-pack")
	gatewayAPI := filepath.Join(tempDir, "gateway-api")
	if err := runStep(ctx, env, "git", "clone", "--depth", "1", "--branch", "v1.3.0", "https://github.com/kubernetes-sigs/gateway-api.git", gatewayAPI); err != nil {
		return "", err
	}
	if err := checkSourceRevision(ctx, env, gatewayAPI, "40be951cebe5cb3f0365fe6951403de4ff8b9f33"); err != nil {
		return "", err
	}
	if err := runStep(ctx, env, "git", "clone", "--depth", "1", "https://github.com/michaelw/devspace-starter-pack.git", source); err != nil {
		return "", err
	}
	if err := runStep(ctx, env, "git", "-C", source, "fetch", "--depth", "1", "origin", "7f8174a46185be7faa7fe88f4440e4f84ecfa6e0"); err != nil {
		return "", err
	}
	if err := runStep(ctx, env, "git", "-C", source, "checkout", "--detach", "FETCH_HEAD"); err != nil {
		return "", err
	}
	if getenvDefault("SMOKE_ISTIO_VERSION", "1.28.0") == "1.31.3" {
		if err := useCurrentIstioChartRepository(source); err != nil {
			return "", err
		}
	}
	if err := runStep(ctx, env, "yq", "-i", `(.hooks[] | select(.name == "docker-mac-net-connect-hook")).disabled = true`, filepath.Join(source, "devspace.yaml")); err != nil {
		return "", err
	}
	if err := runStep(ctx, env, "yq", "-i", `(.profiles[] | select(.name == "local-network") | .merge.deployments.istiod.helm.values.pilot.env.ENABLE_GATEWAY_API_INFERENCE_EXTENSION) = true`, filepath.Join(source, "devspace.yaml")); err != nil {
		return "", err
	}
	if err := runStep(ctx, append(env, "GATEWAY_API_CRD_PATH="+filepath.Join(gatewayAPI, "config", "crd")), "yq", "-i", `(.profiles[] | select(.name == "local-network") | .merge.deployments.gateway-api-crds.kubectl.manifests[0]) = strenv(GATEWAY_API_CRD_PATH)`, filepath.Join(source, "devspace.yaml")); err != nil {
		return "", err
	}
	return source, nil
}

func useCurrentIstioChartRepository(source string) error {
	path := filepath.Join(source, "devspace.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	old := "https://istio-release.storage.googleapis.com/charts"
	if !strings.Contains(string(data), old) {
		return fmt.Errorf("Istio chart repository was not found in %s", path)
	}
	updated := strings.ReplaceAll(string(data), old, "https://blob.istio.io/istio-release/charts")
	return os.WriteFile(path, []byte(updated), 0o600)
}

func startGatewayPortForward(ctx context.Context, env []string) (string, func(), error) {
	name, err := commandOutput(ctx, env, "kubectl", "-n", "istio-ingress", "get", "service", "-l", "gateway.networking.k8s.io/gateway-name=gateway", "-o", "jsonpath={.items[0].metadata.name}")
	if err != nil {
		return "", nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, errors.New("gateway Service was not found")
	}
	return startServicePortForward(ctx, env, "istio-ingress", name, "443")
}

func startServicePortForward(ctx context.Context, env []string, namespace, service, remotePort string) (string, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	address := listener.Addr().String()
	listener.Close()

	forwardCtx, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(forwardCtx, "kubectl", "-n", namespace, "port-forward", "service/"+service, strings.TrimPrefix(address, "127.0.0.1:")+":"+remotePort)
	command.Env = env
	command.Stdout = io.Discard
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		cancel()
		return "", nil, err
	}
	stop := func() {
		cancel()
		_ = command.Wait()
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			connection.Close()
			return address, stop, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	return "", nil, fmt.Errorf("gateway port-forward did not become ready at %s", address)
}

func prepareInferencePool(ctx context.Context, env []string, tempDir string) (string, error) {
	source := filepath.Join(tempDir, "gateway-api-inference-extension")
	if err := runStep(ctx, env, "git", "clone", "--depth", "1", "--branch", "v1.5.0", "https://github.com/kubernetes-sigs/gateway-api-inference-extension.git", source); err != nil {
		return "", err
	}
	if err := checkSourceRevision(ctx, env, source, "df9f8909fe06fe2dfd4a6fc0bd0c01a0acabf849"); err != nil {
		return "", err
	}
	if err := pinInferencePickerImage(source); err != nil {
		return "", err
	}
	crd := filepath.Join(source, "config", "crd", "bases", "inference.networking.k8s.io_inferencepools.yaml")
	if err := runStep(ctx, env, "kubectl", "apply", "-f", crd); err != nil {
		return "", err
	}
	chart := filepath.Join(source, "config", "charts", "inferencepool")
	if err := runStep(ctx, env, "helm", "dependency", "build", "--skip-refresh", chart); err != nil {
		return "", err
	}
	return chart, nil
}

func pinInferencePickerImage(source string) error {
	path := filepath.Join(source, "config", "charts", "epplib", "templates", "_deployment.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	old := `{{ .Values.inferenceExtension.image.registry }}/{{ .Values.inferenceExtension.image.repository }}:{{ .Values.inferenceExtension.image.tag }}`
	newImage := `registry.k8s.io/gateway-api-inference-extension/epp@sha256:86c679b057298e68c6e65ff5603e92066d432e77b11f1f81f0a06399694810bc`
	if !strings.Contains(string(data), old) {
		return fmt.Errorf("endpoint picker chart image template changed at %s", path)
	}
	return os.WriteFile(path, []byte(strings.Replace(string(data), old, newImage, 1)), 0o600)
}

func checkSourceRevision(ctx context.Context, env []string, source, expected string) error {
	actual, err := commandOutput(ctx, env, "git", "-C", source, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	if strings.TrimSpace(actual) != expected {
		return fmt.Errorf("source revision at %s changed: got %s, want %s", source, strings.TrimSpace(actual), expected)
	}
	return nil
}

func installInferencePool(ctx context.Context, env []string, chart, name string) error {
	return runStep(ctx, env, "helm", "upgrade", "--install", name, chart,
		"--namespace", "ext-authz-token-exchange-e2e", "--wait", "--timeout", "5m",
		"--set", "provider.name=istio",
		"--set", "inferencePool.modelServers.matchLabels.app=inference-test-backend",
		"--set", "inferenceExtension.resources.requests.cpu=50m",
		"--set", "inferenceExtension.resources.requests.memory=128Mi",
		"--set", "inferenceExtension.resources.limits.memory=512Mi")
}

func waitForInferenceRoute(ctx context.Context, env []string) error {
	routes := []string{"inference-pool", "weighted-ordinary", "weighted-pool", "weighted-mixed", "two-pools-a", "two-pools-b", "two-pools-mixed"}
	var pending string
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); {
		pending = ""
		for _, route := range routes {
			conditions, err := commandOutput(ctx, env, "kubectl", "-n", "ext-authz-token-exchange-e2e", "get", "httproute", route, "-o", `jsonpath={range .status.parents[*].conditions[*]}{.type}={.status} {.message}{"\n"}{end}`)
			if err != nil || !strings.Contains(conditions, "Accepted=True") || !strings.Contains(conditions, "ResolvedRefs=True") {
				pending = fmt.Sprintf("%s: %s %v", route, strings.TrimSpace(conditions), err)
				break
			}
		}
		if pending == "" {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("InferencePool route did not resolve: %s", pending)
}

func waitForInferenceOverride(ctx context.Context, env []string) error {
	pod, err := commandOutput(ctx, env, "kubectl", "-n", "istio-ingress", "get", "pod", "-l", "gateway.networking.k8s.io/gateway-name=gateway", "-o", "jsonpath={.items[0].metadata.name}")
	if err != nil {
		return err
	}
	pod = strings.TrimSpace(pod)
	if pod == "" {
		return errors.New("Gateway API gateway pod was not found")
	}
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); {
		dump, dumpErr := commandOutput(ctx, env, "kubectl", "-n", "istio-ingress", "exec", "pod/"+pod, "--", "pilot-agent", "request", "GET", "config_dump")
		if dumpErr == nil && hasInferenceOverride([]byte(dump)) && hasIsolatedFilters([]byte(dump)) {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("gateway xDS did not receive separate token-exchange and InferencePool ext_proc filters with the pool override")
}

func hasIsolatedFilters(data []byte) bool {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return false
	}
	return containsIsolatedFilters(value)
}

func containsIsolatedFilters(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		if filters, ok := typed["http_filters"].([]any); ok {
			generic, service := 0, 0
			for _, raw := range filters {
				filter, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				switch filter["name"] {
				case "envoy.filters.http.ext_proc":
					generic++
				case "ext-authz-token-exchange.ext_proc":
					config, _ := filter["typed_config"].(map[string]any)
					grpc, _ := config["grpc_service"].(map[string]any)
					envoy, _ := grpc["envoy_grpc"].(map[string]any)
					cluster, _ := envoy["cluster_name"].(string)
					if strings.HasPrefix(cluster, "outbound|3001||ext-authz-token-exchange.") {
						service++
					}
				}
			}
			if generic == 1 && service == 1 {
				return true
			}
		}
		for _, child := range typed {
			if containsIsolatedFilters(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsIsolatedFilters(child) {
				return true
			}
		}
	}
	return false
}

func hasInferenceOverride(data []byte) bool {
	var value any
	if json.Unmarshal(data, &value) != nil {
		return false
	}
	return containsInferenceOverride(value)
}

func containsInferenceOverride(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		if typeURL, _ := typed["@type"].(string); strings.HasSuffix(typeURL, ".ExtProcPerRoute") {
			encoded, _ := json.Marshal(typed)
			return strings.Contains(string(encoded), "outbound|9002||e2e-inferencepool-epp.")
		}
		for _, child := range typed {
			if containsInferenceOverride(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsInferenceOverride(child) {
				return true
			}
		}
	}
	return false
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

	transport, err := directhttp.NewTransport(cfg.directAddress, true)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: transport}
	url := strings.TrimRight(cfg.baseURL, "/") + "/anything/yellow"
	ticker := time.NewTicker(cfg.tokenReadyInterval)
	defer ticker.Stop()

	for {
		result, err := probeTokenExchange(waitCtx, client, url, cfg.host)
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

func probeTokenExchange(ctx context.Context, client *http.Client, url, host string) (tokenProbeResult, error) {
	allowCode, allowBody, allowErr := request(ctx, client, url, "readiness-yellow", host)
	denyCode, denyBody, denyErr := request(ctx, client, url, "", host)
	result := tokenProbeResult{
		allowCode: allowCode,
		denyCode:  denyCode,
		allowAuth: exchangedAuthorization(allowBody),
		allowBody: bodySnippet(allowBody),
		denyBody:  bodySnippet(denyBody),
	}
	return result, errors.Join(allowErr, denyErr)
}

func request(ctx context.Context, client *http.Client, url, bearer, host string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if host != "" {
		req.Host = host
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
	body := ""
	if result.allowBody != "" || result.denyBody != "" {
		body = fmt.Sprintf(" allow_body=%q deny_body=%q", result.allowBody, result.denyBody)
	}
	if err != nil {
		return fmt.Sprintf("allow=%d deny=%d exchanged_auth=%s%s err=%v", result.allowCode, result.denyCode, exchanged, body, err)
	}
	return fmt.Sprintf("allow=%d deny=%d exchanged_auth=%s%s", result.allowCode, result.denyCode, exchanged, body)
}

func bodySnippet(body []byte) string {
	const limit = 240
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) <= limit {
		return trimmed
	}
	return trimmed[:limit] + "..."
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

func keycloakBaseURL(baseURL string) string {
	if value := os.Getenv("E2E_KEYCLOAK_BASE_URL"); value != "" {
		return value
	}
	return keycloakExternalURL(baseURL)
}

func keycloakIssuerURL(baseURL string) string {
	if value := os.Getenv("E2E_KEYCLOAK_ISSUER"); value != "" {
		return value
	}
	return keycloakExternalURL(baseURL) + "/realms/token-exchange-e2e"
}

func keycloakExternalURL(baseURL string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" {
		return "https://keycloak.int.kube"
	}
	host := parsed.Host
	if strings.HasPrefix(host, "httpbin.") {
		host = "keycloak." + strings.TrimPrefix(host, "httpbin.")
	} else {
		host = "keycloak." + host
	}
	return "https://" + host
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
	var stderr strings.Builder
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w\n%s%s", name, strings.Join(args, " "), err, string(output), stderr.String())
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
