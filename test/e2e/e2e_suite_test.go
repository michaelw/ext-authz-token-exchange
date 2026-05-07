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
	"k8s.io/client-go/util/retry"
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
	defaultReleaseName         = "ext-authz-token-exchange"
	defaultNamespace           = "ext-authz-token-exchange"
	defaultDemoReleaseName     = "ext-authz-token-exchange-e2e"
	defaultDemoNamespace       = "ext-authz-token-exchange-e2e"
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
	waitForDeployment(ctx, env.namespace, env.releaseName)
	waitForDeployment(ctx, env.demoNamespace, tokenEndpointName)
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
	namespace           string
	releaseName         string
	demoNamespace       string
	demoReleaseName     string
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
		releaseName:         envDefault("E2E_RELEASE", defaultReleaseName),
		namespace:           envDefault("E2E_NAMESPACE", defaultNamespace),
		demoReleaseName:     envDefault("E2E_DEMO_RELEASE", defaultDemoReleaseName),
		demoNamespace:       envDefault("E2E_DEMO_NAMESPACE", defaultDemoNamespace),
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
	return []string{e.namespace, e.demoNamespace, e.teamNamespace("yellow"), e.teamNamespace("red"), e.teamNamespace("blue"), e.teamNamespace("black")}
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
	pluginValuesPath := filepath.Join(os.TempDir(), env.releaseName+"-plugin-values.yaml")
	Expect(os.WriteFile(pluginValuesPath, []byte(pluginValues()), 0o600)).To(Succeed())
	installHelmRelease(ctx, env.releaseName, env.namespace, repoPath("charts", "ext-authz-token-exchange"), pluginValuesPath, true)

	demoValuesPath := filepath.Join(os.TempDir(), env.demoReleaseName+"-values.yaml")
	Expect(os.WriteFile(demoValuesPath, []byte(demoValues()), 0o600)).To(Succeed())
	installHelmRelease(ctx, env.demoReleaseName, env.demoNamespace, repoPath("charts", "ext-authz-token-exchange-e2e"), demoValuesPath, false)
}

func installHelmRelease(ctx context.Context, releaseName, namespace, chartPath, valuesPath string, dependencyUpdate bool) {
	args := []string{
		"upgrade", "--install", releaseName, chartPath,
		"--namespace", namespace,
		"--create-namespace",
		"--values", valuesPath,
		"--wait",
		"--timeout", "2m",
	}
	if dependencyUpdate {
		args = append(args, "--dependency-update")
	}
	cmd := exec.CommandContext(ctx, "helm", args...)
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), string(out))
}

func uninstallDemo(ctx context.Context) {
	uninstallHelmRelease(ctx, env.demoReleaseName, env.demoNamespace)
	uninstallHelmRelease(ctx, env.releaseName, env.namespace)
}

func uninstallHelmRelease(ctx context.Context, releaseName, namespace string) {
	cmd := exec.CommandContext(ctx, "helm", "uninstall", releaseName, "--namespace", namespace, "--wait", "--timeout", "2m")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "release: not found") {
		Expect(err).NotTo(HaveOccurred(), string(out))
	}
}

func imageValues(image string) string {
	if repo, digest, ok := strings.Cut(image, "@"); ok {
		return fmt.Sprintf("  repository: %q\n  digest: %q", repo, digest)
	}
	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")
	if lastColon > lastSlash {
		return fmt.Sprintf("  repository: %q\n  tag: %q", image[:lastColon], image[lastColon+1:])
	}
	return fmt.Sprintf("  repository: %q\n  tag: %q", image, "latest")
}

func pluginValues() string {
	defaultEndpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d/token/success", tokenEndpointName, env.demoNamespace, tokenEndpointPort)
	return fmt.Sprintf(`image:
%s
env:
  TOKEN_EXCHANGE_ALLOW_HTTP_TOKEN_ENDPOINT: "true"
  TOKEN_EXCHANGE_DEFAULT_TOKEN_ENDPOINT: %q
  TOKEN_EXCHANGE_BEARER_REALM: %q
  # INSECURE DEMO-ONLY TOKEN LOGGING: DO NOT COPY THIS VALUE INTO PRODUCTION.
  TOKEN_EXCHANGE_INSECURE_LOG_TOKENS: "true"
resources:
  requests:
    cpu: 50m
    memory: 64Mi
  limits:
    cpu: 500m
    memory: 256Mi
oauth:
  createSecret: true
  secretName: %q
  clientID: %q
  clientSecret: %q
  existingSecret:
    name: %q
    clientIDKey: client_id
    clientSecretKey: client_secret
`, imageValues(env.pluginImage), defaultEndpoint, defaultBearerRealm,
		oauthSecretName, env.oauthClientID, env.oauthClientSecret, oauthSecretName)
}

func demoValues() string {
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
fakeTokenEndpoint:
  name: %q
  image: %q
  port: %d
`, env.host, env.namespacePrefix, env.demoNamespace,
		policyLabelKey, policyLabelValue, policyNamespaceLabelKey, policyNamespaceLabelValue, policyNamespaceSelector, env.httpbinResourceBase,
		tokenEndpointName, env.fakeTokenImage, tokenEndpointPort)
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
	tokenEndpoint := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d%s", tokenEndpointName, env.demoNamespace, tokenEndpointPort, tokenPath)
	config := fmt.Sprintf(`version: v1
entries:
  - match:
      host: %s
      pathPrefix: %s
      methods: ["GET", "POST", "OPTIONS"]
    action: exchange
    exchange:
      scope: %s
      resources:
        - %s%s
      audiences:
        - %s
      tokenEndpoint: %s
`, env.host, pathPrefix, scope, env.httpbinResourceBase, pathPrefix, audienceForNamespace(namespace), tokenEndpoint)
	upsertConfigMap(ctx, namespace, name, config)
}

func audienceForNamespace(namespace string) string {
	prefix := env.namespacePrefix + "-"
	if color := strings.TrimPrefix(namespace, prefix); color != namespace && color != "" {
		return "httpbin-" + color
	}
	return "httpbin-" + namespace
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

func setPluginEnv(ctx context.Context, name, value string) {
	Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
		deployment, err := env.kube.AppsV1().Deployments(env.namespace).Get(ctx, env.releaseName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		for i := range deployment.Spec.Template.Spec.Containers {
			container := &deployment.Spec.Template.Spec.Containers[i]
			if container.Name != "ext-authz-token-exchange" {
				continue
			}
			for j := range container.Env {
				if container.Env[j].Name == name {
					container.Env[j].Value = value
					_, err = env.kube.AppsV1().Deployments(env.namespace).Update(ctx, deployment, metav1.UpdateOptions{})
					return err
				}
			}
			container.Env = append(container.Env, corev1.EnvVar{Name: name, Value: value})
			_, err = env.kube.AppsV1().Deployments(env.namespace).Update(ctx, deployment, metav1.UpdateOptions{})
			return err
		}
		return fmt.Errorf("deployment %s/%s does not contain ext-authz-token-exchange", env.namespace, env.releaseName)
	})).To(Succeed())
	waitForDeployment(ctx, env.namespace, env.releaseName)
}

func waitForDeployment(ctx context.Context, namespace, name string) {
	Eventually(func(g Gomega) {
		deployment, err := env.kube.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		g.Expect(err).NotTo(HaveOccurred())
		replicas := int32(1)
		if deployment.Spec.Replicas != nil {
			replicas = *deployment.Spec.Replicas
		}
		g.Expect(deployment.Status.ObservedGeneration).To(BeNumerically(">=", deployment.Generation))
		g.Expect(deployment.Status.UpdatedReplicas).To(Equal(replicas))
		g.Expect(deployment.Status.ReadyReplicas).To(Equal(replicas))
		g.Expect(deployment.Status.AvailableReplicas).To(Equal(replicas))

		selector := metav1.FormatLabelSelector(deployment.Spec.Selector)
		pods, err := env.kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(pods.Items).To(HaveLen(int(replicas)))
		for i := range pods.Items {
			pod := pods.Items[i]
			g.Expect(pod.DeletionTimestamp).To(BeNil())
			g.Expect(pod.Status.Phase).To(Equal(corev1.PodRunning))
			g.Expect(pod.Status.ContainerStatuses).NotTo(BeEmpty())
			for _, status := range pod.Status.ContainerStatuses {
				g.Expect(status.Ready).To(BeTrue())
			}
		}
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
	pods, err := env.kube.CoreV1().Pods(env.demoNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=" + tokenEndpointName,
	})
	Expect(err).NotTo(HaveOccurred())
	return podLogs(ctx, pods.Items)
}

func pluginLogs(ctx context.Context) string {
	pods, err := env.kube.CoreV1().Pods(env.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/instance=" + env.releaseName + ",app.kubernetes.io/name=ext-authz-token-exchange",
	})
	Expect(err).NotTo(HaveOccurred())
	return podLogs(ctx, pods.Items)
}

func podLogs(ctx context.Context, pods []corev1.Pod) string {
	var logs bytes.Buffer
	for _, pod := range pods {
		req := env.kube.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name, &corev1.PodLogOptions{})
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
