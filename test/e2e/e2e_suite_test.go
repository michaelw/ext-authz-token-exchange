package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const (
	e2eLabelKey                = "app.kubernetes.io/part-of"
	e2eLabelValue              = "ext-authz-token-exchange-e2e"
	oauthSecretName            = "ext-authz-token-exchange-oauth"
	policyLabelKey             = "ext-authz-token-exchange.magneticflux.net/enabled"
	policyLabelValue           = "true"
	policyNamespaceLabelKey    = "ext-authz-token-exchange.magneticflux.net/policy"
	policyNamespaceLabelValue  = "enabled"
	policyNamespaceSelector    = "ext-authz-token-exchange.magneticflux.net/policy=enabled"
	tokenEndpointName          = "fake-token-endpoint"
	tokenEndpointPort          = int32(8080)
	defaultReleaseName         = "ext-authz-token-exchange-e2e"
	defaultPluginImage         = "ghcr.io/michaelw/ext-authz-token-exchange:latest"
	defaultFakeTokenImage      = "ghcr.io/michaelw/ext-authz-token-exchange-fake-token-endpoint:latest"
	defaultOAuthClientID       = "e2e-client"
	defaultOAuthClientSecret   = "e2e-secret"
	defaultBearerRealm         = "ext-authz-token-exchange-e2e"
	defaultHTTPBinResourceBase = "https://httpbin.int.kube"
)

var env e2eEnv

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Kubernetes E2E Suite")
}

var _ = BeforeSuite(func(ctx SpecContext) {
	env = loadE2EEnv()
	if env.baseURL == "" {
		Skip("set E2E_BASE_URL, for example https://httpbin.int.kube, to run Kubernetes e2e tests")
	}

	var err error
	env.kube, err = newKubeClient()
	Expect(err).NotTo(HaveOccurred())

	if !env.skipInstall {
		installDemo(ctx)
	}
	waitForDeployment(ctx, env.systemNamespace, env.releaseName)
	waitForDeployment(ctx, env.systemNamespace, tokenEndpointName)
})

var _ = AfterSuite(func(ctx SpecContext) {
	if env.baseURL == "" || env.skipCleanup || env.skipInstall {
		return
	}
	uninstallDemo(ctx)
	for _, namespace := range env.allNamespaces() {
		deleteOwnedNamespace(ctx, namespace)
	}
})

type e2eEnv struct {
	baseURL             string
	host                string
	namespacePrefix     string
	systemNamespace     string
	releaseName         string
	pluginImage         string
	fakeTokenImage      string
	oauthClientID       string
	oauthClientSecret   string
	httpbinResourceBase string
	skipInstall         bool
	skipCleanup         bool
	insecureTLS         bool
	kube                *kubernetes.Clientset
}

func loadE2EEnv() e2eEnv {
	base := strings.TrimRight(os.Getenv("E2E_BASE_URL"), "/")
	host := strings.TrimSpace(os.Getenv("E2E_HOST"))
	if host == "" && base != "" {
		if parsed, err := url.Parse(base); err == nil {
			host = parsed.Hostname()
		}
	}
	return e2eEnv{
		baseURL:             base,
		host:                host,
		namespacePrefix:     envDefault("E2E_NAMESPACE_PREFIX", "service"),
		systemNamespace:     envDefault("E2E_SYSTEM_NAMESPACE", defaultReleaseName),
		releaseName:         envDefault("E2E_RELEASE", defaultReleaseName),
		pluginImage:         envDefault("E2E_PLUGIN_IMAGE", defaultPluginImage),
		fakeTokenImage:      envDefault("E2E_FAKE_TOKEN_ENDPOINT_IMAGE", defaultFakeTokenImage),
		oauthClientID:       envDefault("E2E_OAUTH_CLIENT_ID", defaultOAuthClientID),
		oauthClientSecret:   envDefault("E2E_OAUTH_CLIENT_SECRET", defaultOAuthClientSecret),
		httpbinResourceBase: envDefault("E2E_HTTPBIN_RESOURCE_BASE", defaultHTTPBinResourceBase),
		skipInstall:         envBool("E2E_SKIP_INSTALL", false),
		skipCleanup:         envBool("E2E_SKIP_CLEANUP", false),
		insecureTLS:         envBool("E2E_INSECURE_SKIP_VERIFY", true),
	}
}

func (e e2eEnv) teamNamespace(color string) string {
	return e.namespacePrefix + "-" + color
}

func (e e2eEnv) allNamespaces() []string {
	return []string{e.systemNamespace, e.teamNamespace("yellow"), e.teamNamespace("red"), e.teamNamespace("blue"), e.teamNamespace("black")}
}

func newKubeClient() (*kubernetes.Clientset, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = filepath.Join(homedir.HomeDir(), ".kube", "config")
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
	}
	return kubernetes.NewForConfig(cfg)
}

func installDemo(ctx context.Context) {
	valuesPath := filepath.Join(os.TempDir(), env.releaseName+"-e2e-values.yaml")
	Expect(os.WriteFile(valuesPath, []byte(demoValues()), 0o600)).To(Succeed())

	chartPath := repoPath("charts", "ext-authz-token-exchange-e2e")
	args := []string{
		"upgrade", "--install", env.releaseName, chartPath,
		"--namespace", env.systemNamespace,
		"--create-namespace",
		"--dependency-update",
		"--values", valuesPath,
		"--wait",
		"--timeout", "2m",
	}
	cmd := exec.CommandContext(ctx, "helm", args...)
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), string(out))
}

func uninstallDemo(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "helm", "uninstall", env.releaseName, "--namespace", env.systemNamespace, "--wait", "--timeout", "2m")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "release: not found") {
		Expect(err).NotTo(HaveOccurred(), string(out))
	}
}

func demoValues() string {
	defaultEndpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d/token/success", tokenEndpointName, env.systemNamespace, tokenEndpointPort)
	return fmt.Sprintf(`host: %q
namespacePrefix: %q
systemNamespace: %q
policy:
  labelKey: %q
  labelValue: %q
  namespaceLabelKey: %q
  namespaceLabelValue: %q
  namespaceSelector: %q
  httpbinResourceBase: %q
oauth:
  secretName: %q
  clientID: %q
  clientSecret: %q
fakeTokenEndpoint:
  name: %q
  image: %q
  port: %d
plugin:
  service:
    serviceAccountName: ext-authz-token-exchange
    containers:
      - name: ext-authz-token-exchange-service
        image: %q
        imagePullPolicy: IfNotPresent
        env:
          - name: GRPC_PORT
            value: "3001"
          - name: OAUTH_CLIENT_ID
            valueFrom:
              secretKeyRef:
                name: %q
                key: client_id
          - name: OAUTH_CLIENT_SECRET
            valueFrom:
              secretKeyRef:
                name: %q
                key: client_secret
          - name: TOKEN_ENDPOINT_AUTH_METHOD
            value: "client_secret_basic"
          - name: TOKEN_EXCHANGE_GRANT_TYPE
            value: "urn:ietf:params:oauth:grant-type:token-exchange"
          - name: TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE
            value: "urn:ietf:params:oauth:token-type:access_token"
          - name: CONFIGMAP_LABEL_SELECTOR
            value: "%s=%s"
          - name: CONFIGMAP_NAMESPACE_SELECTOR
            value: %q
          - name: TOKEN_EXCHANGE_ERROR_PASSTHROUGH
            value: "false"
          - name: TOKEN_EXCHANGE_ALLOW_HTTP_TOKEN_ENDPOINT
            value: "true"
          - name: TOKEN_EXCHANGE_DEFAULT_TOKEN_ENDPOINT
            value: %q
          - name: TOKEN_ENDPOINT_ALLOWLIST
            value: ""
          - name: TOKEN_EXCHANGE_BEARER_REALM
            value: %q
          - name: TOKEN_EXCHANGE_ALLOW_UNAUTHENTICATED_OPTIONS
            value: "false"
          - name: TOKEN_ENDPOINT_REQUEST_TIMEOUT
            value: "2s"
          - name: TOKEN_ENDPOINT_DIAL_TIMEOUT
            value: "1s"
          - name: TOKEN_ENDPOINT_TLS_HANDSHAKE_TIMEOUT
            value: "1s"
          - name: TOKEN_ENDPOINT_RESPONSE_HEADER_TIMEOUT
            value: "2s"
          - name: TOKEN_ENDPOINT_IDLE_CONN_TIMEOUT
            value: "30s"
          - name: TOKEN_ENDPOINT_MAX_IDLE_CONNS
            value: "10"
          - name: TOKEN_ENDPOINT_MAX_IDLE_CONNS_PER_HOST
            value: "5"
        ports:
          - name: grpc-authz
            containerPort: 3001
        resources:
          requests:
            cpu: 50m
            memory: 64Mi
          limits:
            cpu: 500m
            memory: 256Mi
    service:
      type: ClusterIP
      ports:
        - name: grpc-api
          port: 3001
          containerPort: grpc-authz
          appProtocol: grpc
  oauth:
    existingSecret:
      name: %q
      clientIDKey: client_id
      clientSecretKey: client_secret
`, env.host, env.namespacePrefix, env.systemNamespace,
		policyLabelKey, policyLabelValue, policyNamespaceLabelKey, policyNamespaceLabelValue, policyNamespaceSelector, env.httpbinResourceBase,
		oauthSecretName, env.oauthClientID, env.oauthClientSecret,
		tokenEndpointName, env.fakeTokenImage, tokenEndpointPort,
		env.pluginImage, oauthSecretName, oauthSecretName, policyLabelKey, policyLabelValue,
		policyNamespaceSelector, defaultEndpoint, defaultBearerRealm, oauthSecretName)
}

func createUnlabeledTeamNamespace(ctx context.Context, color string) string {
	namespace := env.teamNamespace(color)
	existing, err := env.kube.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		_, err = env.kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
				Labels: map[string]string{
					e2eLabelKey: e2eLabelValue,
				},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		return namespace
	}
	Expect(err).NotTo(HaveOccurred())
	if existing.Labels == nil {
		existing.Labels = map[string]string{}
	}
	existing.Labels[e2eLabelKey] = e2eLabelValue
	delete(existing.Labels, policyNamespaceLabelKey)
	_, err = env.kube.CoreV1().Namespaces().Update(ctx, existing, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())
	return namespace
}

func createPolicy(ctx context.Context, namespace, name, scope, pathPrefix, tokenPath string) {
	tokenEndpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d%s", tokenEndpointName, env.systemNamespace, tokenEndpointPort, tokenPath)
	config := fmt.Sprintf(`version: v1
entries:
  - host: %s
    pathPrefix: %s
    methods: ["GET", "POST", "OPTIONS"]
    scope: %s
    resource: %s%s
    tokenEndpoint: %s
`, env.host, pathPrefix, scope, env.httpbinResourceBase, pathPrefix, tokenEndpoint)
	upsertConfigMap(ctx, namespace, name, config)
}

type ephemeralPolicy struct {
	Name string
	Path string
}

func createEphemeralPolicy(ctx context.Context, namespace, scenario, scope, tokenPath string) ephemeralPolicy {
	policy := newEphemeralPolicy(scenario)
	createPolicy(ctx, namespace, policy.Name, scope, policy.Path, tokenPath)
	DeferCleanup(func() {
		deleteConfigMapIgnoreNotFound(context.Background(), namespace, policy.Name)
	})
	return policy
}

func newEphemeralPolicy(scenario string) ephemeralPolicy {
	safeScenario := dnsSafe(scenario)
	suffix := randomHexSuffix()
	return ephemeralPolicy{
		Name: safeScenario + "-" + suffix,
		Path: "/anything/e2e/" + safeScenario + "/" + suffix,
	}
}

func dnsSafe(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if valid {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "policy"
	}
	return out
}

func randomHexSuffix() string {
	var data [6]byte
	_, err := rand.Read(data[:])
	Expect(err).NotTo(HaveOccurred())
	return hex.EncodeToString(data[:])
}

func upsertConfigMap(ctx context.Context, namespace, name, configYAML string) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				e2eLabelKey:    e2eLabelValue,
				policyLabelKey: policyLabelValue,
			},
		},
		Data: map[string]string{"config.yaml": configYAML},
	}
	_, err := env.kube.CoreV1().ConfigMaps(namespace).Create(ctx, cm, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		current, getErr := env.kube.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
		Expect(getErr).NotTo(HaveOccurred())
		cm.ResourceVersion = current.ResourceVersion
		cm.Annotations = current.Annotations
		cm.Labels = mergeStringMaps(current.Labels, cm.Labels)
		_, err = env.kube.CoreV1().ConfigMaps(namespace).Update(ctx, cm, metav1.UpdateOptions{})
	}
	Expect(err).NotTo(HaveOccurred())
}

func deleteConfigMapIgnoreNotFound(ctx context.Context, namespace, name string) {
	err := env.kube.CoreV1().ConfigMaps(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if errors.IsNotFound(err) {
		return
	}
	Expect(err).NotTo(HaveOccurred())
}

func waitForDeployment(ctx context.Context, namespace, name string) {
	Eventually(func(g Gomega) {
		deployment, err := env.kube.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(deployment.Status.AvailableReplicas).To(BeNumerically(">=", 1))
		g.Expect(deployment.Status.UpdatedReplicas).To(Equal(*deployment.Spec.Replicas))
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func deleteOwnedNamespace(ctx context.Context, namespace string) {
	existing, err := env.kube.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return
	}
	Expect(err).NotTo(HaveOccurred())
	if existing.Labels[e2eLabelKey] != e2eLabelValue {
		return
	}
	Expect(env.kube.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})).To(Succeed())
}

func repoPath(parts ...string) string {
	_, file, _, ok := runtime.Caller(0)
	Expect(ok).To(BeTrue())
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return filepath.Join(append([]string{root}, parts...)...)
}

func mergeStringMaps(base, overlay map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range base {
		out[key] = value
	}
	for key, value := range overlay {
		out[key] = value
	}
	return out
}

func httpClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: env.insecureTLS},
	}}
}

func request(ctx context.Context, method, path, bearer string, headers map[string]string) (*http.Response, []byte) {
	req, err := http.NewRequestWithContext(ctx, method, env.baseURL+path, nil)
	Expect(err).NotTo(HaveOccurred())
	if env.host != "" {
		req.Host = env.host
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := httpClient().Do(req)
	Expect(err).NotTo(HaveOccurred())
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())
	return resp, body
}

func headerFromHTTPBin(body []byte, name string) string {
	var parsed struct {
		Headers map[string][]string `json:"headers"`
	}
	Expect(json.Unmarshal(body, &parsed)).To(Succeed(), string(body))
	for key, values := range parsed.Headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func tokenEndpointLogs(ctx context.Context) string {
	pods, err := env.kube.CoreV1().Pods(env.systemNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=" + tokenEndpointName,
	})
	Expect(err).NotTo(HaveOccurred())
	var logs bytes.Buffer
	for _, pod := range pods.Items {
		req := env.kube.CoreV1().Pods(env.systemNamespace).GetLogs(pod.Name, &corev1.PodLogOptions{})
		stream, err := req.Stream(ctx)
		if err != nil {
			continue
		}
		_, _ = io.Copy(&logs, stream)
		_ = stream.Close()
	}
	return logs.String()
}

func envDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func envBool(name string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if value == "" {
		return fallback
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}
