# Compatibility Notes

This project intentionally tightened several protocol and configuration details
while moving from the original token-exchange plan to the RFC-aligned design.

## Configuration Changes

For the current operator-facing configuration and behavior reference, see
`docs/configuration.md`.

- `target_upstream` was the previous planning name for what is now the
  RFC8707/RFC8693 `resources` field. Use `exchange.resources` for target API or
  upstream URIs where the exchanged token will be used.
- `exchange.audiences` remains available for authorization-server-specific
  logical audience names.
- App-owned ConfigMaps now use `exchange.issuerRef`; token endpoints are owned
  by operator-defined issuer profiles so app-owned policy cannot introduce
  arbitrary token endpoint URLs.

## OAuth Client Authentication

`client_secret_basic` is now the default token endpoint authentication method.
This follows RFC6749 Section 2.3.1, where HTTP Basic is the required-to-support
method for clients with a password. The older body-credential behavior is still
available by setting:

```text
TOKEN_ENDPOINT_AUTH_METHOD=client_secret_post
```

Use `client_secret_post` only for authorization servers that cannot support
Basic authentication.

## Token Response Validation

Successful token exchange responses are now validated more strictly:

- `access_token` is required.
- `token_type` must be `Bearer`, case-insensitively.
- `issued_token_type` must default to
  `urn:ietf:params:oauth:token-type:access_token`.

This prevents forwarding a token that the authorization server did not describe
as a bearer access token.

## Error Handling

Token endpoint error bodies are sanitized by default before returning anything
to the original request originator. Body passthrough is available only as an
explicit compatibility setting:

```text
TOKEN_EXCHANGE_ERROR_PASSTHROUGH=true
```

Recognized OAuth error codes, including RFC8693 `invalid_target` and RFC6749
`invalid_grant`, are preserved when safe. Default sanitized responses replace
authorization-server `error_description` values with a diagnostic message, so a
client will see `invalid_grant` but not a detail like `subject_token_expired`.
Set `TOKEN_EXCHANGE_ERROR_PASSTHROUGH=true` only when clients must receive a
documented, machine-readable authorization-server detail.

There is a deliberate compatibility choice for expired incoming subject tokens:
RFC8693 Section 2.2.2 says invalid or unacceptable `subject_token` cases use
`invalid_request`, while RFC6749 Section 5.2 defines `invalid_grant` for grants
that are invalid, expired, or revoked. The plugin preserves an authorization
server's `invalid_grant` response so deployments can use it for refreshable
expired-token UX.

## Diagnostic Codes

Sanitized plugin-generated errors include stable diagnostic codes such as
`TXE-2001`. These are operational markers intended to map a client-visible
error back to a source branch by grep. They are not random per-request
correlation IDs.

Diagnostic codes deliberately do not encode source file paths, line numbers,
hostnames, token endpoint URLs, token contents, or authorization-server response
details. Treat them as compatibility surface: change or retire an existing code
only when the corresponding error branch is deliberately retired.

## Policy Safety

Misconfigured app-owned policy now fails closed for the affected host, path, and
method area instead of being silently ignored. Unrelated teams' valid policy
continues to work.

Policy ConfigMaps are discovered only from namespaces selected by
`CONFIGMAP_NAMESPACE_SELECTOR`, which defaults to:

```text
ext-authz-token-exchange.magneticflux.net/policy=enabled
```

This namespace selector is a scalable Kubernetes-style discovery control, not a
replacement for RBAC. Kubernetes RBAC does not grant ConfigMap access by
namespace label, so platform owners should still use appropriate Roles,
RoleBindings, ClusterRoles, or externally managed RBAC as the hard access
boundary.

Only CORS preflight `OPTIONS` requests bypass token exchange by default. A
request is treated as preflight when it has both `Origin` and
`Access-Control-Request-Method` headers. Non-preflight `OPTIONS` requests can
bypass without credentials only when explicitly enabled with:

```text
TOKEN_EXCHANGE_ALLOW_UNAUTHENTICATED_OPTIONS=true
```

If an `OPTIONS` request includes an `Authorization: Bearer ...` header, the
plugin treats it like a protected request and performs token exchange.

Requests that do not match any healthy or unhealthy policy region pass through
unchanged by default. Deployments that need policy coverage to be an explicit
allow-list can enable catch-all denial for unmatched requests:

```text
TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED=true
```

With default deny enabled, unmatched requests receive `403 Forbidden` with
`policy_denied`. This also applies to unmatched true CORS preflights. Matched
healthy CORS preflights still bypass token exchange and continue to the resource
server. The plugin logs whether a `policy_denied` response came from unmatched
default-deny behavior or from an explicit deny policy.

Policy entries use explicit `match`, `action`, and action-specific sections.
Use `action: exchange` for normal token exchange behavior:

```yaml
version: v1
entries:
  - match:
      host: api.example.com
      pathPrefix: /orders
      methods: ["GET"]
    action: exchange
    exchange:
      resources:
        - https://api.example.com/orders
```

Use `action: deny` to intentionally reject a matched route even when
`TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED=false`:

```yaml
version: v1
entries:
  - match:
      host: api.example.com
      pathPrefix: /admin
      methods: ["*"]
    action: deny
```

`action` is required. Unknown action values, unknown policy fields, and invalid
exchange config make the affected host/path/method region fail closed.

Policy YAML is decoded with known-field validation. The Helm charts include
values schemas for deployment-time feedback, and `docs/policy.schema.json` can
be used by editors or CI for app-owned ConfigMaps. Kubernetes cannot deeply
validate the YAML string stored in `ConfigMap.data["config.yaml"]`; the running
service remains the authoritative runtime validator for arbitrary ConfigMaps.
