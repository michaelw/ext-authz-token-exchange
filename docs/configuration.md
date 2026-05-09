# Configuration Reference

This document is the human-readable reference for app-owned token exchange
policy, plugin runtime settings, and Kubernetes deployment wiring. The
machine-readable policy schema is `docs/policy.schema.json`.

## Team Policy Configuration

Teams configure protected routes with Kubernetes ConfigMaps. The plugin watches
only ConfigMaps in namespaces selected by `CONFIGMAP_NAMESPACE_SELECTOR` and
only ConfigMaps selected by `CONFIGMAP_LABEL_SELECTOR`.

With the default selectors, a namespace must have:

```yaml
metadata:
  labels:
    ext-authz-token-exchange.magneticflux.net/policy: enabled
```

and a policy ConfigMap must have:

```yaml
metadata:
  labels:
    ext-authz-token-exchange.magneticflux.net/enabled: "true"
data:
  config.yaml: |
    version: v1
    entries:
      - match:
          host: api.example.com
          pathPrefix: /orders
          methods: ["GET", "POST"]
        action: exchange
        exchange:
          scope: read:orders
          resources:
            - https://api.example.com/orders
          audiences:
            - orders-api
          tokenEndpoint: https://issuer.example.com/oauth/token
```

### Policy File

`config.yaml` uses this top-level shape:

| Field | Required | Description |
| --- | --- | --- |
| `version` | Yes | Must be `v1`. |
| `entries` | Yes | Ordered list of policy entries. |

Unknown fields are rejected. A ConfigMap missing `data["config.yaml"]` is
treated as invalid policy.

### Policy Entries

Each entry has a required `match`, a required `action`, and action-specific
configuration.

| Field | Required | Description |
| --- | --- | --- |
| `match.host` | Yes | Hostname to match. It is trimmed, lowercased, has any port stripped, and is matched case-insensitively. |
| `match.pathPrefix` | Yes | Path prefix to match. If the value does not start with `/`, the plugin adds it. The longest matching prefix wins. |
| `match.methods` | No | HTTP methods to match. Values are trimmed, uppercased, and sorted. Empty or omitted methods default to `["*"]`; `*` matches every method. |
| `action` | Yes | `exchange` performs token exchange. `deny` rejects matching requests without calling the token endpoint. |
| `exchange` | For `action: exchange` | Token exchange request configuration. Ignored for `action: deny`. |

When more than one healthy policy entry matches the same host, path, and method
with the same longest `pathPrefix`, the affected region fails closed because
the match is ambiguous.

### Exchange Fields

`action: exchange` requires an `exchange` object and at least one of `scope`,
`resources`, or `audiences`.

| Field | Required | Description |
| --- | --- | --- |
| `exchange.scope` | Conditional | Space-delimited OAuth scope string sent as one `scope` form parameter. |
| `exchange.resources` | Conditional | Resource indicator URIs sent as repeated `resource` form parameters. |
| `exchange.audiences` | Conditional | Logical audience values sent as repeated `audience` form parameters. |
| `exchange.tokenEndpoint` | Conditional | Absolute token endpoint URL. May be omitted only when `TOKEN_EXCHANGE_DEFAULT_TOKEN_ENDPOINT` is configured. |

The plugin sends all configured target fields to the authorization server. It
does not choose precedence between `scope`, `resources`, and `audiences`, and it
does not interpret their combined meaning locally. Per RFC 8693 Section 2.1.1,
combining scope with resource or audience asks for the requested scope at the
requested target services. Broad combinations may be rejected by the
authorization server with `invalid_target`.

### Request Behavior

- Unmatched requests pass through unchanged by default.
- If `TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED=true`, unmatched requests receive
  `403 Forbidden` with `policy_denied`.
- `action: deny` returns `403 Forbidden` with `policy_denied` for matching
  requests.
- Matched `action: exchange` requests require `Authorization: Bearer ...`,
  except true CORS preflight requests.
- A true CORS preflight is an `OPTIONS` request with both `Origin` and
  `Access-Control-Request-Method` headers. It bypasses token exchange unless it
  also carries a bearer token.
- Other unauthenticated `OPTIONS` requests bypass token exchange only when
  `TOKEN_EXCHANGE_ALLOW_UNAUTHENTICATED_OPTIONS=true`.
- Missing bearer tokens on protected requests receive `401 Unauthorized` with a
  `WWW-Authenticate: Bearer` challenge. If the matched policy has `scope`, the
  challenge includes that scope.
- Successful exchanges allow the request and replace the upstream
  `Authorization` header with `Bearer <exchanged access token>`.
- Invalid policy fails closed for the affected host/path/method region. Other
  valid policy regions continue to work.

## Plugin Configuration

The service reads runtime configuration from environment variables. In the
production Helm chart, set runtime environment variables with the chart's `env`
map. Runtime defaults live in the binary; omit values from `env` when the binary
default is appropriate.

The chart owns OAuth client credential Secret wiring through `oauth.*`, because
those settings are Kubernetes Secret references rather than plain runtime
defaults.

For example:

```yaml
env:
  TOKEN_EXCHANGE_DEFAULT_TOKEN_ENDPOINT: https://issuer.example.com/oauth/token
  TOKEN_ENDPOINT_ALLOWLIST: issuer.example.com
  TOKEN_EXCHANGE_BEARER_REALM: ext-authz-token-exchange
oauth:
  existingSecret:
    name: ext-authz-token-exchange-oauth
    clientIDKey: client_id
    clientSecretKey: client_secret
```

### Core Service

| Environment variable | Default | Required | Description |
| --- | --- | --- | --- |
| `GRPC_LOG_HEALTH_CHECKS` | `true` | No | Logs successful gRPC health probe requests. Disable in noisy local/demo environments when probe chatter is not useful. |
| `GRPC_PORT` | `3001` | No | Port for the ext-authz gRPC service. |
| `OAUTH_CLIENT_ID` | none | Yes | OAuth client ID used when calling token endpoints. |
| `OAUTH_CLIENT_SECRET` | none | Yes | OAuth client secret. Do not log or commit this value. |
| `TOKEN_ENDPOINT_AUTH_METHOD` | `client_secret_basic` | No | OAuth client authentication method. Supported values are `client_secret_basic` and `client_secret_post`. |
| `TOKEN_EXCHANGE_GRANT_TYPE` | `urn:ietf:params:oauth:grant-type:token-exchange` | No | Grant type form parameter for token exchange requests. |
| `TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE` | `urn:ietf:params:oauth:token-type:access_token` | No | Subject token type form parameter. |

### Policy Discovery

| Environment variable | Default | Required | Description |
| --- | --- | --- | --- |
| `CONFIGMAP_LABEL_SELECTOR` | `ext-authz-token-exchange.magneticflux.net/enabled=true` | Yes | Label selector for app-owned policy ConfigMaps. |
| `CONFIGMAP_NAMESPACE_SELECTOR` | `ext-authz-token-exchange.magneticflux.net/policy=enabled` | Yes | Label selector for namespaces that may contain policy ConfigMaps. Must be a valid Kubernetes label selector. |

Namespace selection is a discovery control, not an RBAC replacement. Kubernetes
RBAC still controls which namespaces and ConfigMaps the plugin can read.

### Token Endpoint Controls

| Environment variable | Default | Required | Description |
| --- | --- | --- | --- |
| `TOKEN_EXCHANGE_DEFAULT_TOKEN_ENDPOINT` | empty | No | Fallback token endpoint used when policy omits `exchange.tokenEndpoint`. |
| `TOKEN_ENDPOINT_ALLOWLIST` | empty | No | Comma-separated hostname allowlist for token endpoints. Empty means no hostname restriction. |
| `TOKEN_EXCHANGE_ALLOW_HTTP_TOKEN_ENDPOINT` | `false` | No | Allows `http://` token endpoints. Keep `false` for production unless there is a deliberate local/demo exception. |

Token endpoints must be absolute URLs. They must use HTTPS unless
`TOKEN_EXCHANGE_ALLOW_HTTP_TOKEN_ENDPOINT=true`.

`TOKEN_ENDPOINT_ALLOWLIST` is evaluated against the parsed endpoint hostname:

- `auth.example.com` matches `auth.example.com`, case-insensitively.
- `.example.com` matches subdomains such as `auth.example.com`.
- `.example.com` does not match the bare hostname `example.com`.
- Ports are not part of the allowlist comparison.

### Error Handling And Validation

| Environment variable | Default | Required | Description |
| --- | --- | --- | --- |
| `TOKEN_EXCHANGE_ERROR_PASSTHROUGH` | `false` | No | When `false`, token endpoint error details are sanitized before being returned to the original caller. |
| `TOKEN_EXCHANGE_REQUIRE_ISSUED_TOKEN_TYPE` | `true` | No | Requires successful token responses to include the expected `issued_token_type`. |
| `TOKEN_EXCHANGE_EXPECTED_ISSUED_TOKEN_TYPE` | `urn:ietf:params:oauth:token-type:access_token` | Conditional | Expected issued token type when issued token type validation is enabled. |
| `TOKEN_EXCHANGE_BEARER_REALM` | `ext-authz-token-exchange` | No | Realm used in `WWW-Authenticate: Bearer` challenges. |
| `TOKEN_EXCHANGE_INSECURE_LOG_TOKENS` | `false` | No | Logs subject and exchanged tokens. Demo/debug only; do not enable in production. |

Successful token endpoint responses must include `access_token`, must have
`token_type` equal to `Bearer` case-insensitively, and must have the expected
`issued_token_type` when validation is enabled.

### Request Policy Switches

| Environment variable | Default | Required | Description |
| --- | --- | --- | --- |
| `TOKEN_EXCHANGE_ALLOW_UNAUTHENTICATED_OPTIONS` | `false` | No | Allows non-preflight `OPTIONS` requests without bearer tokens. True CORS preflights already bypass by default. |
| `TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED` | `false` | No | Denies requests that do not match any healthy or unhealthy policy region. |

### HTTP Client Settings

Durations use Go duration strings such as `500ms`, `2s`, or `1m`.
Because token exchange runs in the Envoy ext-authz hot path,
`TOKEN_ENDPOINT_REQUEST_TIMEOUT` must be lower than `envoyFilter.timeout`.
The default chart values keep the token endpoint request budget below the
default `1s` Envoy ext-authz deadline.

| Environment variable | Default | Required | Description |
| --- | --- | --- | --- |
| `TOKEN_ENDPOINT_REQUEST_TIMEOUT` | `750ms` | No | Overall token endpoint request timeout. Must be positive and lower than `envoyFilter.timeout`. |
| `TOKEN_ENDPOINT_DIAL_TIMEOUT` | `3s` | No | TCP dial timeout. Must be positive. |
| `TOKEN_ENDPOINT_TLS_HANDSHAKE_TIMEOUT` | `3s` | No | TLS handshake timeout. Must be positive. |
| `TOKEN_ENDPOINT_RESPONSE_HEADER_TIMEOUT` | `500ms` | No | Timeout waiting for response headers. Must be positive. |
| `TOKEN_ENDPOINT_IDLE_CONN_TIMEOUT` | `90s` | No | Idle connection timeout. Must be positive. |
| `TOKEN_ENDPOINT_MAX_IDLE_CONNS` | `100` | No | Maximum idle connections. Must not be negative. |
| `TOKEN_ENDPOINT_MAX_IDLE_CONNS_PER_HOST` | `10` | No | Maximum idle connections per host. Must not be negative. |

### Metrics

Metrics are recorded with OpenTelemetry instruments. The preferred Kubernetes
path is OTLP metrics export to an OpenTelemetry Collector, using the same
collector endpoint pattern as traces. A Prometheus `/metrics` listener is
available as an opt-in fallback for clusters that scrape workloads directly.

The main service-level RED metrics are:

| Metric | Type | Description |
| --- | --- | --- |
| `ext_authz_check_requests_total` | Counter | Envoy ext-authz `Check` requests by `decision` and `result`. |
| `ext_authz_check_duration_seconds` | Histogram | Envoy ext-authz `Check` duration by `decision` and `result`. |
| `ext_authz_check_in_flight` | Gauge | Envoy ext-authz `Check` requests currently in flight. |

The token endpoint dependency metrics are:

| Metric | Type | Description |
| --- | --- | --- |
| `ext_authz_token_exchange_requests_total` | Counter | Token endpoint exchange attempts by endpoint host, result, error kind, and HTTP status class. |
| `ext_authz_token_exchange_latency_seconds` | Histogram | Token endpoint exchange latency by endpoint host, result, error kind, and HTTP status class. |
| `ext_authz_token_exchange_timeouts_total` | Counter | Token endpoint request timeouts by endpoint host. |
| `ext_authz_token_exchange_context_cancellations_total` | Counter | Token endpoint requests canceled by the incoming ext-authz context by endpoint host. |
| `ext_authz_token_exchange_in_flight` | Gauge | Token endpoint exchange requests currently in flight by endpoint host. |

`result="auth_denied"` is for expected authorization denials, such as missing
bearer tokens or issuer OAuth denials that map below HTTP 500. `result="system_error"`
is for reliability failures such as unhealthy policy state or exchange errors
that map to HTTP 500. Alert on system errors, timeout/cancellation behavior,
and latency against the ext-authz deadline before alerting on all denials.

When metrics are exported into a Prometheus-compatible backend, useful example
PromQL includes:

```promql
sum(rate(ext_authz_check_requests_total{result="system_error"}[5m]))
histogram_quantile(0.99, sum by (le) (rate(ext_authz_check_duration_seconds_bucket[5m])))
sum(rate(ext_authz_token_exchange_requests_total{result="failure",http_status_class="5xx"}[5m])) by (endpoint_host)
histogram_quantile(0.99, sum by (le, endpoint_host) (rate(ext_authz_token_exchange_latency_seconds_bucket[5m])))
```

Metric labels are limited to bounded decisions, result categories, endpoint
host, error kind, and HTTP status class. They never include bearer tokens,
exchanged tokens, client secrets, request paths, OAuth bodies, or full token
endpoint URLs.

### Grafana Dashboard

The chart can render an opt-in Grafana RED dashboard ConfigMap for clusters
that use the with-infra Grafana sidecar loader. It is disabled by default and,
when enabled, renders in the Helm release namespace.

```yaml
grafanaDashboard:
  enabled: true
```

The default ConfigMap labels and annotations match the with-infra sidecar
convention:

```yaml
labels:
  grafana_dashboard: "1"
annotations:
  grafana_folder: Ext AuthZ
```

The dashboard includes plugin RED metrics, token endpoint dependency metrics,
Istio gateway traffic, Envoy ext-authz decision metrics, and optional provider
backend transport panels. Provider backend panels require the environment's
generated Envoy cluster name, supplied by deployment values:

```yaml
grafanaDashboard:
  providerCluster: <envoy-provider-cluster-name>
```

Provider cluster names are infrastructure-specific, so the chart default is
empty and the backend transport panels show no data until
`grafanaDashboard.providerCluster` is configured.

Relevant values:

| Value | Default | Description |
| --- | --- | --- |
| `grafanaDashboard.enabled` | `false` | Render the Grafana dashboard ConfigMap. |
| `grafanaDashboard.name` | `ext-authz-token-exchange-red-dashboard` | Dashboard ConfigMap name. |
| `grafanaDashboard.labels.grafana_dashboard` | `"1"` | Label consumed by the with-infra Grafana sidecar. |
| `grafanaDashboard.annotations.grafana_folder` | `Ext AuthZ` | Grafana folder annotation consumed by the sidecar. |
| `grafanaDashboard.datasourceUid` | `prometheus` | Default Prometheus datasource UID. |
| `grafanaDashboard.pluginJob` | `ext-authz-token-exchange` | Prometheus job label for plugin metrics. |
| `grafanaDashboard.gatewayJob` | `observability/istio-gateway-api-gateway` | Prometheus job label for gateway Envoy metrics. |
| `grafanaDashboard.gatewayWorkload` | `gateway-istio` | Istio source workload used for gateway traffic panels. |
| `grafanaDashboard.providerCluster` | empty | Envoy provider-backend cluster name for optional transport panels. |
| `grafanaDashboard.envoyTimeoutMs` | `1000` | Ext-authz timeout threshold marker for Check latency panels. |
| `grafanaDashboard.tokenEndpointTimeoutSeconds` | `0.75` | Token endpoint timeout threshold marker for dependency latency panels. |

Optional Prometheus scrape fallback:

| Environment variable | Default | Required | Description |
| --- | --- | --- | --- |
| `METRICS_ENABLED` | `false` | No | Enables the fallback Prometheus metrics HTTP listener. |
| `METRICS_PORT` | `3002` | Conditional | Metrics listener port when fallback scraping is enabled. |
| `METRICS_PATH` | `/metrics` | Conditional | Metrics scrape path when fallback scraping is enabled. Must start with `/`. |

### OpenTelemetry Tracing

The service extracts W3C Trace Context (`traceparent`, `tracestate`) and
baggage from Envoy `CheckRequest` HTTP headers, then propagates that context to
token endpoint subrequests. The gRPC ext-authz server and outbound token
endpoint HTTP client are instrumented; gRPC health checks are intentionally not
traced to avoid probe noise. Without an OTLP exporter configured,
instrumentation is inert but propagation still works inside the request path.
The local fake token endpoint can use the same `OTEL_*` settings when the e2e
demo needs a token issuer application span.
For a local walkthrough with Jaeger screenshots, see the
[Tracing Tutorial](tracing.md).

| Environment variable | Default | Required | Description |
| --- | --- | --- | --- |
| `OTEL_TRACES_EXPORTER` | empty | No | Set to `otlp` to enable trace export. Empty or `none` leaves tracing inert. |
| `OTEL_METRICS_EXPORTER` | empty | No | Set to `otlp` to enable OTLP metrics export. Empty or `none` leaves metric export inert. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry SDK default | No | Base OTLP endpoint used by the exporter, for example `http://otel-collector:4317`. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | empty | No | Trace-specific OTLP endpoint. Takes precedence over `OTEL_EXPORTER_OTLP_ENDPOINT`. |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | empty | No | Metrics-specific OTLP endpoint. Takes precedence over `OTEL_EXPORTER_OTLP_ENDPOINT`. |
| `OTEL_SERVICE_NAME` | `ext-authz-token-exchange` | No | Service name attached to exported spans. |
| `OTEL_RESOURCE_ATTRIBUTES` | empty | No | Additional resource attributes, such as `deployment.environment=dev`. |
| `OTEL_SDK_DISABLED` | `false` | No | Set to `true` to disable SDK initialization. |

Minimal values example for a cluster-local collector:

```yaml
env:
  OTEL_TRACES_EXPORTER: otlp
  OTEL_METRICS_EXPORTER: otlp
  OTEL_EXPORTER_OTLP_ENDPOINT: http://otel-collector.observability.svc.cluster.local:4317
  OTEL_SERVICE_NAME: ext-authz-token-exchange
  OTEL_RESOURCE_ATTRIBUTES: deployment.environment=local
```

The collector must also have a `metrics` pipeline that receives OTLP metrics
and exports them to the chosen metrics backend. A traces-only collector route
accepts spans but does not make service metrics queryable.

B3 propagation is not enabled by default in this release. If a deployment needs
B3 for Envoy or Istio compatibility, track that as an explicit compatibility
decision so the supported propagation surface stays documented.

## Kubernetes Deployment Configuration

The production chart lives in `charts/ext-authz-token-exchange`. The local demo
and e2e chart lives in `charts/ext-authz-token-exchange-e2e`.

### OAuth Secret

The plugin chart expects an existing Secret by default:

```yaml
oauth:
  existingSecret:
    name: ext-authz-token-exchange-oauth
    clientIDKey: client_id
    clientSecretKey: client_secret
```

The chart renders `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` from the
configured Secret name and keys. These OAuth variables are chart-owned and
cannot be replaced through `env`.

For local or demo installs, the plugin chart can create the OAuth client
credential Secret itself:

```yaml
oauth:
  createSecret: true
  secretName: ext-authz-token-exchange-oauth
  clientID: e2e-client
  clientSecret: e2e-secret
  existingSecret:
    name: ext-authz-token-exchange-oauth
    clientIDKey: client_id
    clientSecretKey: client_secret
```

The demo/e2e chart does not create OAuth credentials; they are owned by the
plugin chart that consumes them.

### RBAC

When `rbac.create=true`, the production chart creates:

- A ServiceAccount named by `rbac.serviceAccountName`.
- A ClusterRole with `get`, `list`, and `watch` on core `configmaps`.
- A ClusterRole with `get`, `list`, and `watch` on core `namespaces`.
- A ClusterRoleBinding from that ClusterRole to the ServiceAccount.

The plugin needs namespace watch access because namespace labels determine
which namespaces may contain policy. It needs ConfigMap watch access because
policy is owned by app teams in selected namespaces.

If `rbac.create=false`, provide equivalent permissions out of band. Namespace
label selection does not grant or restrict Kubernetes API permissions by
itself.

### Gateway Authorization

Gateway authorization wiring is disabled by default. Enable exactly one gateway
integration mode when installing the chart:

- `authorizationPolicy.enabled=true` uses Istio's native `CUSTOM`
  `AuthorizationPolicy` and a mesh-level `extensionProvider`.
- `envoyFilter.enabled=true` uses the legacy chart-owned `EnvoyFilter` that
  inserts `envoy.filters.http.ext_authz` before the router.

The `AuthorizationPolicy` mode expects infrastructure to provide an Istio
provider, defaulting to `gateway-ext-authz-grpc`. The optional
`gatewayExtAuthzService` resource creates a configurable provider host in the
gateway namespace so the infra provider can stay generic. Its name does not
have to be `gateway-ext-authz`; it only needs to match the service FQDN
configured in `extensionProviders[].envoyExtAuthzGrpc.service`.

The default local infra provider points at
`gateway-ext-authz.istio-ingress.svc.cluster.local:3001`. By default, the chart
renders an Istio `ServiceEntry` for that host and points it at this chart's
plugin Service. That is the recommended shape for Istio `envoyExtAuthzGrpc`
because the gateway needs the generic provider host as an Envoy cluster. If
`gatewayExtAuthzService.serviceEntry.enabled=false`, the chart instead renders
a Kubernetes Service alias.

Relevant values:

| Value | Default | Description |
| --- | --- | --- |
| `authorizationPolicy.enabled` | `false` | Render an Istio `AuthorizationPolicy` using `action: CUSTOM`. |
| `authorizationPolicy.namespace` | `istio-ingress` | Namespace where the `AuthorizationPolicy` is created. |
| `authorizationPolicy.providerName` | `gateway-ext-authz-grpc` | Istio extension provider name to reference. |
| `authorizationPolicy.workloadSelectorLabels` | Gateway label selector | Default labels for selecting gateway workloads. |
| `authorizationPolicy.workloadSelectorLabelsOverride` | `{}` | Complete replacement for the default authorization policy selector labels. |
| `authorizationPolicy.rules` | `[{}]` | Authorization policy rules. The default applies to all selected gateway traffic. |
| `gatewayExtAuthzService.enabled` | `false` | Render provider-host wiring for the generic Istio provider backend. |
| `gatewayExtAuthzService.namespace` | `istio-ingress` | Namespace for the provider host resources. |
| `gatewayExtAuthzService.name` | `gateway-ext-authz` | Provider host name. Must match the infra provider service name. |
| `gatewayExtAuthzService.type` | `ExternalName` | Kubernetes Service type when `serviceEntry.enabled=false`. |
| `gatewayExtAuthzService.externalName` | Plugin Service FQDN | Backend target. Empty uses this chart's plugin Service FQDN. |
| `gatewayExtAuthzService.port` | `3001` | Provider host port. |
| `gatewayExtAuthzService.targetPort` | `3001` | Backend target port. |
| `gatewayExtAuthzService.appProtocol` | `grpc` | Kubernetes Service port app protocol when `serviceEntry.enabled=false`. |
| `gatewayExtAuthzService.serviceEntry.enabled` | `true` | Render an Istio `ServiceEntry` for the generic provider host. When true, no Kubernetes Service alias is rendered. |
| `gatewayExtAuthzService.serviceEntry.location` | `MESH_INTERNAL` | ServiceEntry location. |
| `gatewayExtAuthzService.serviceEntry.resolution` | `DNS` | ServiceEntry endpoint resolution. |
| `gatewayExtAuthzService.serviceEntry.protocol` | `GRPC` | ServiceEntry port protocol. |
| `envoyFilter.enabled` | `false` | Render the legacy Istio `EnvoyFilter`. Mutually exclusive with `authorizationPolicy.enabled`. |
| `envoyFilter.namespace` | `istio-ingress` | Namespace where the EnvoyFilter is created. |
| `envoyFilter.workloadSelectorLabels` | Gateway label selector | Default labels for selecting gateway workloads. |
| `envoyFilter.workloadSelectorLabelsOverride` | `{}` | Complete replacement for the default selector labels. |
| `envoyFilter.timeout` | `1s` | Envoy ext-authz gRPC timeout. |
| `service.ports.http-metrics.port` | `3002` | Optional Prometheus metrics Service port. |
| `serviceMonitor.enabled` | `false` | Render a Prometheus Operator `ServiceMonitor` for the fallback `/metrics` endpoint. Enable only when direct Prometheus scraping is desired and the Prometheus Operator CRDs are installed. |
| `serviceMonitor.interval` | `30s` | Metrics scrape interval. |
| `serviceMonitor.scrapeTimeout` | `10s` | Metrics scrape timeout. |

The legacy filter is configured with `failure_mode_allow: false`, so Envoy
fails closed if the external authorization service is unavailable or times out.

### Demo And E2E Deployment

The e2e chart configures a local fake token endpoint, demo namespaces, namespace
labels, policy ConfigMaps, and demo-only runtime overrides. In particular, it
sets `GRPC_LOG_HEALTH_CHECKS=false`,
`TOKEN_EXCHANGE_ALLOW_HTTP_TOKEN_ENDPOINT=true`, and
`TOKEN_EXCHANGE_INSECURE_LOG_TOKENS=true` for local testing. Do not copy those
settings into production.

## References

- [RFC 8693 Section 2.1](https://www.rfc-editor.org/rfc/rfc8693#section-2.1):
  token exchange request parameters.
- [RFC 8693 Section 2.1.1](https://www.rfc-editor.org/rfc/rfc8693#section-2.1.1):
  relationship between resource, audience, and scope.
- [RFC 8693 Section 2.2.1](https://www.rfc-editor.org/rfc/rfc8693#section-2.2.1):
  successful token exchange responses.
- [RFC 8693 Section 2.2.2](https://www.rfc-editor.org/rfc/rfc8693#section-2.2.2):
  token exchange error responses.
- [RFC 8707 Section 2](https://www.rfc-editor.org/rfc/rfc8707#section-2):
  OAuth `resource` parameter.
- [RFC 6749 Section 2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1):
  OAuth client password authentication.
- [RFC 6749 Section 3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3):
  OAuth scope.
- [RFC 6750 Section 3](https://www.rfc-editor.org/rfc/rfc6750#section-3):
  bearer authentication challenges.
