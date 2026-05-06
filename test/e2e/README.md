# Kubernetes E2E Tests

These tests assume the local test cluster infrastructure is already installed,
including Istio/Gateway and the shared `mccutchen/go-httpbin` backend reachable
as `https://httpbin.int.kube/` through the Gateway API gateway.

Run the suite only when the cluster and plugin image are available:

```sh
E2E_BASE_URL=https://httpbin.int.kube \
E2E_PLUGIN_IMAGE=ghcr.io/michaelw/ext-authz-token-exchange:latest \
E2E_FAKE_TOKEN_ENDPOINT_IMAGE=ghcr.io/michaelw/ext-authz-token-exchange-fake-token-endpoint:latest \
go run github.com/onsi/ginkgo/v2/ginkgo -r -v ./test/e2e
```

When `E2E_SKIP_INSTALL=false`, the Ginkgo suite installs the plugin chart and
the demo/e2e chart as separate Helm releases. The plugin chart owns the OAuth
client credentials it consumes. The demo/e2e chart owns demo-only resources:
the fake token endpoint, color team namespaces, and app-owned policy ConfigMaps.
The test code intentionally does not construct baseline Kubernetes manifests;
use chart values to change namespaces, credentials, images, policy entries, or
the fake token endpoint.

You can also let DevSpace deploy the full local demo stack:

```sh
devspace deploy -p local-test
devspace run test-e2e
```

`devspace run test-e2e` uses the Ginkgo runner, so repeated runs are not served
from the Go test cache. Pass Ginkgo flags directly, for example
`devspace run test-e2e -v`.

The `local-test` profile builds the plugin and fake token endpoint images, then
deploys the plugin chart as release `ext-authz-token-exchange` and the demo/e2e
chart as release `ext-authz-token-exchange-e2e`. DevSpace updates the image
tags in Helm values in memory, so the local-test flow does not require pushing
images to `ghcr.io/michaelw` when your cluster can use DevSpace-built images.

The production plugin image intentionally contains only
`ext-authz-token-exchange-service`. The fake token endpoint is packaged through
the separate Dockerfile `fake-token-endpoint` target and should be pushed as its
own image.

## Recorded Demo

Use the Go demo runner for a terminal-friendly walkthrough once
`devspace deploy -p local-test` has installed the demo stack. It uses typed HTTP
and JSON handling, and renders `test/e2e/demo-scenarios.yaml` as a Go template:

```sh
go run ./cmd/demo-scenario list
go run ./cmd/demo-scenario yellow-success
go run ./cmd/demo-scenario all
```

To try alternate scenarios or namespace names, pass a different config file or
override the template values:

```sh
go run ./cmd/demo-scenario --config test/e2e/demo-scenarios.yaml --namespace-prefix service all
```

For a browser-recorded walkthrough, start the local dashboard:

```sh
devspace run demo-dashboard -- -open
```

Omit `-open` to keep the current manual-open behavior and then open
`http://127.0.0.1:8088/` yourself. The dashboard is a demo-only binary with
embedded static assets. It is not copied into the production `prod` image; that
image intentionally copies only `ext-authz-token-exchange-service`.

The dashboard reads plugin logs from `DEMO_PLUGIN_NAMESPACE` and
`DEMO_PLUGIN_DEPLOYMENT`, which default to `ext-authz-token-exchange`. It reads
fake issuer logs from `DEMO_SYSTEM_NAMESPACE`, which defaults to
`ext-authz-token-exchange-e2e`.

For a recorded demo, a useful four-terminal layout is:

```sh
# 1. Scenario runner.
go run ./cmd/demo-scenario all

# 2. Central plugin logs.
kubectl logs -f -n ext-authz-token-exchange deploy/ext-authz-token-exchange

# 3. Fake token endpoint logs.
kubectl logs -f -n ext-authz-token-exchange-e2e deploy/fake-token-endpoint

# 4. App-owned policy watch across namespaces.
kubectl get cm -A -w -l ext-authz-token-exchange.magneticflux.net/enabled=true
```

The runner covers the non-mutating scenarios: yellow/red/blue success, missing
bearer, CORS preflight, plain `OPTIONS` without bearer, `OPTIONS` with bearer,
unmatched pass-through, explicit deny, opt-in default-deny for unmatched traffic,
and token endpoint error responses. The
`expired-subject-token` scenario demonstrates the compatibility-friendly path
where the authorization server returns RFC6749 `invalid_grant` for an expired
but validly shaped subject token, even though RFC8693 points invalid
`subject_token` cases toward `invalid_request`. `go-httpbin` does not echo
request headers in its `OPTIONS` response body, so use the fake token endpoint
log pane to show the `OPTIONS` with bearer exchange. Ginkgo remains the
authoritative runner for mutating fail-closed scenarios such as temporary
cross-namespace conflicts and invalid policy ConfigMaps.

### Successful Token Exchange

```mermaid
sequenceDiagram
    participant Client
    participant Gateway as "Gateway API pod"
    participant Plugin as "ext-authz plugin"
    participant Issuer as "fake token endpoint"
    participant Httpbin as "go-httpbin"

    Client->>Gateway: "GET /anything/yellow<br/>Authorization: Bearer incoming-yellow"
    Gateway->>Plugin: "Envoy ext_authz Check"
    Plugin->>Plugin: "Match service-yellow/yellow-policy"
    Plugin->>Issuer: "POST /token/yellow<br/>subject_token=incoming-yellow"
    Issuer-->>Plugin: "200 access_token=JWT scenario=yellow sub=incoming-yellow aud=httpbin-yellow"
    Plugin-->>Gateway: "OK, replace Authorization"
    Gateway->>Httpbin: "GET /anything/yellow<br/>Authorization: Bearer JWT scenario=yellow sub=incoming-yellow aud=httpbin-yellow"
    Httpbin-->>Client: "200 JSON echoed headers"
```

### Missing Bearer Challenge

```mermaid
sequenceDiagram
    participant Client
    participant Gateway as "Gateway API pod"
    participant Plugin as "ext-authz plugin"

    Client->>Gateway: "GET /anything/yellow"
    Gateway->>Plugin: "Envoy ext_authz Check"
    Plugin->>Plugin: "Match service-yellow/yellow-policy"
    Plugin-->>Client: "401 WWW-Authenticate: Bearer<br/>{"error":"bearer_token_required"}"
```

### CORS Preflight Pass-Through

```mermaid
sequenceDiagram
    participant Browser
    participant Gateway as "Gateway API pod"
    participant Plugin as "ext-authz plugin"
    participant Httpbin as "go-httpbin"

    Browser->>Gateway: "OPTIONS /anything/yellow<br/>Origin + Access-Control-Request-Method"
    Gateway->>Plugin: "Envoy ext_authz Check"
    Plugin-->>Gateway: "OK without token exchange"
    Gateway->>Httpbin: "OPTIONS /anything/yellow"
    Httpbin-->>Browser: "200 CORS response headers"
```

When `TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED=true`, this pass-through applies
only after the preflight matches a healthy policy region. Unmatched preflights
receive `403 Forbidden` with `policy_denied`, like other unmatched traffic.
Routes matched by `action: deny` also return `policy_denied`, and the plugin
logs whether the denial was explicit or caused by default deny.

### Token Endpoint Error Mapping

```mermaid
sequenceDiagram
    participant Client
    participant Gateway as "Gateway API pod"
    participant Plugin as "ext-authz plugin"
    participant Issuer as "fake token endpoint"

    Client->>Gateway: "GET /anything/error-invalid-target<br/>Authorization: Bearer incoming-error"
    Gateway->>Plugin: "Envoy ext_authz Check"
    Plugin->>Plugin: "Match service-red/error-invalid-target-policy"
    Plugin->>Issuer: "POST /token/invalid-target"
    Issuer-->>Plugin: "400 {"error":"invalid_target"}"
    Plugin-->>Client: "400 sanitized OAuth error"
```

### Multi-Namespace Policy Discovery

```mermaid
sequenceDiagram
    participant Yellow as "service-yellow ConfigMap"
    participant Red as "service-red ConfigMaps"
    participant Blue as "service-blue ConfigMap"
    participant Plugin as "ext-authz plugin"
    participant Gateway as "Gateway API pod"

    Yellow-->>Plugin: "yellow-policy"
    Red-->>Plugin: "red-policy + error policies"
    Blue-->>Plugin: "blue-policy"
    Plugin->>Plugin: "Build atomic host/path/method index"
    Gateway->>Plugin: "Check /anything/red"
    Plugin-->>Gateway: "Use service-red/red-policy"
```

### Fail-Closed Policy Regions

```mermaid
sequenceDiagram
    participant TeamA as "team ConfigMap A"
    participant TeamB as "team ConfigMap B"
    participant Plugin as "ext-authz plugin"
    participant Client

    TeamA-->>Plugin: "host/path/method entry"
    TeamB-->>Plugin: "same most-specific host/path/method or invalid policy"
    Plugin->>Plugin: "Mark affected region unhealthy or ambiguous"
    Client->>Plugin: "Request matching affected region"
    Plugin-->>Client: "500 generic fail-closed response"
```

By default the suite creates:

- `ext-authz-token-exchange` for the central ext-authz plugin.
- `ext-authz-token-exchange-e2e` for the fake token endpoint and demo support resources.
- `service-yellow`, `service-red`, and `service-blue` for app-owned policy ConfigMaps.
  These namespaces are labeled
  `ext-authz-token-exchange.magneticflux.net/policy=enabled`, which is the
  plugin's default namespace selector.

The e2e suite also creates an unlabeled `service-black` namespace during one
test and places a valid policy ConfigMap in it. Requests for that policy must
pass through unchanged, proving that ConfigMap labels alone are not enough:
the namespace must match `CONFIGMAP_NAMESPACE_SELECTOR`.

When using `devspace deploy -p local-test`, DevSpace creates or updates the
color namespaces before Helm deploys the demo chart and labels them with the
policy namespace selector. A direct `helm upgrade --install` of the demo chart
also labels namespaces that the chart creates or already owns.

The namespace selector is plugin-side discovery policy. Kubernetes RBAC cannot
grant ConfigMap access by namespace label, so production deployments should
still treat RBAC as the hard access boundary.

Policy ConfigMaps use the nested `v1` policy shape with `match`, `action`, and
`exchange` sections. The e2e chart values are checked by Helm's
`values.schema.json` before rendering, and the rendered ConfigMaps are still
strictly validated by the plugin at runtime. Arbitrary app-owned ConfigMaps can
also be checked in CI or editors with `docs/policy.schema.json`.

Useful overrides:

- `E2E_HOST`: Host header and ConfigMap host. Defaults to the host from `E2E_BASE_URL`.
- `E2E_NAMESPACE_PREFIX`: Prefix for team namespaces. Defaults to `service`.
- `E2E_RELEASE`: Helm release name for the plugin. Defaults to `ext-authz-token-exchange`.
- `E2E_NAMESPACE`: Namespace for the plugin. Defaults to `ext-authz-token-exchange`.
- `E2E_DEMO_RELEASE`: Helm release name for demo/e2e resources. Defaults to `ext-authz-token-exchange-e2e`.
- `E2E_DEMO_NAMESPACE`: Namespace for demo/e2e resources. Defaults to `ext-authz-token-exchange-e2e`.
- `E2E_FAKE_TOKEN_ENDPOINT_IMAGE`: Image for the demo token endpoint.
- `E2E_HTTPBIN_RESOURCE_BASE`: Resource URI base used in demo ConfigMaps.
- `E2E_SKIP_CLEANUP=true`: Keep test namespaces for inspection.
- `E2E_SKIP_INSTALL=true`: Test an already deployed local-test chart release.
- `E2E_INSECURE_SKIP_VERIFY=false`: Enforce TLS verification for the gateway URL.

The suite skips automatically when `E2E_BASE_URL` is not set, so `go test ./...`
remains safe for ordinary unit-test runs.
