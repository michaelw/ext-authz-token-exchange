# Compatibility Notes

This project intentionally tightened several protocol and configuration details
while moving from the original token-exchange plan to the RFC-aligned design.

## Configuration Changes

- `target_upstream` was the previous planning name for what is now the
  RFC8707/RFC8693 `resource` field. Use `resource` for the target API or
  upstream URI where the exchanged token will be used.
- `audience` remains available for authorization-server-specific logical
  audience names.
- App-owned ConfigMaps may omit `tokenEndpoint` only when the plugin deployment
  configures `TOKEN_EXCHANGE_DEFAULT_TOKEN_ENDPOINT`.

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

## Policy Safety

Misconfigured app-owned policy now fails closed for the affected host, path, and
method area instead of being silently ignored. Unrelated teams' valid policy
continues to work.

Only CORS preflight `OPTIONS` requests bypass token exchange by default. A
request is treated as preflight when it has both `Origin` and
`Access-Control-Request-Method` headers. Non-preflight `OPTIONS` requests can
bypass without credentials only when explicitly enabled with:

```text
TOKEN_EXCHANGE_ALLOW_UNAUTHENTICATED_OPTIONS=true
```

If an `OPTIONS` request includes an `Authorization: Bearer ...` header, the
plugin treats it like a protected request and performs token exchange.
