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
production Helm chart, the current source of truth is the container env map at
`env`. The `tokenExchange.*` values block exists in `values.yaml` and
`values.schema.json`, but those friendly values do not drive the service
environment on their own unless the chart rendering is changed to consume them.
For example, `tokenExchange.tokenEndpointAllowlist` exists in values, while the
service currently reads `TOKEN_ENDPOINT_ALLOWLIST`.

### Core Service

| Environment variable | Default | Required | Description |
| --- | --- | --- | --- |
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

| Environment variable | Default | Required | Description |
| --- | --- | --- | --- |
| `TOKEN_ENDPOINT_REQUEST_TIMEOUT` | `5s` | No | Overall token endpoint request timeout. Must be positive. |
| `TOKEN_ENDPOINT_DIAL_TIMEOUT` | `3s` | No | TCP dial timeout. Must be positive. |
| `TOKEN_ENDPOINT_TLS_HANDSHAKE_TIMEOUT` | `3s` | No | TLS handshake timeout. Must be positive. |
| `TOKEN_ENDPOINT_RESPONSE_HEADER_TIMEOUT` | `5s` | No | Timeout waiting for response headers. Must be positive. |
| `TOKEN_ENDPOINT_IDLE_CONN_TIMEOUT` | `90s` | No | Idle connection timeout. Must be positive. |
| `TOKEN_ENDPOINT_MAX_IDLE_CONNS` | `100` | No | Maximum idle connections. Must not be negative. |
| `TOKEN_ENDPOINT_MAX_IDLE_CONNS_PER_HOST` | `10` | No | Maximum idle connections per host. Must not be negative. |

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

The chart validation requires the `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET`
env entries in `env` to point at the same Secret name and keys.

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

### EnvoyFilter

The chart renders an Istio `EnvoyFilter` that inserts
`envoy.filters.http.ext_authz` before the router on gateway listeners selected
by `envoyFilter.workloadSelectorLabels` or
`envoyFilter.workloadSelectorLabelsOverride`.

Relevant values:

| Value | Default | Description |
| --- | --- | --- |
| `envoyFilter.namespace` | `istio-ingress` | Namespace where the EnvoyFilter is created. |
| `envoyFilter.workloadSelectorLabels` | Gateway label selector | Default labels for selecting gateway workloads. |
| `envoyFilter.workloadSelectorLabelsOverride` | `{}` | Complete replacement for the default selector labels. |
| `envoyFilter.timeout` | `1s` | Envoy ext-authz gRPC timeout. |

The filter is configured with `failure_mode_allow: false`, so Envoy fails
closed if the external authorization service is unavailable or times out.

### Demo And E2E Deployment

The e2e chart configures a local fake token endpoint, demo namespaces, namespace
labels, policy ConfigMaps, and demo-only runtime overrides. In particular, it
sets `TOKEN_EXCHANGE_ALLOW_HTTP_TOKEN_ENDPOINT=true` and
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
