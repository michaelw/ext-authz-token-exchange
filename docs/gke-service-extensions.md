# GKE Service Extensions

This runbook tests the plugin on a GKE Gateway target that uses
`*.gcp.kube`. It intentionally does not deploy the shared infra profile; missing
Gateway, DNS, certificate, forwarding rule, or callout backend prerequisites
belong in `devspace-starter-pack`.

For a cluster-admin-only deployment into an existing wildcard-capable Gateway,
use the separate `gke-platform` and `gke-app` model documented in
[DevSpace Configuration](devspace.md#existing-gateway-gke-deployment). That
model uses public release images, creates no external infrastructure, keeps the
callout on plaintext HTTP/2 port `3001`, and disables Keycloak IAP. The legacy
GKE model described below remains unchanged.

## Deploy

Use the provider-aware smoke command on the selected GKE context:

```sh
devspace run smoke -v
```

When the current DevSpace context is a standard `gke_*` context, the GKE
profile activates from `DEVSPACE_CONTEXT`. Shared starter-pack values such as
the deployment domain, project, region, gateway namespace, and Artifact Registry
prefix are read from the `devspace-system/devspace-starter-pack-env`
ConfigMap.

The GKE image registry defaults to:

```text
${GKE_REGION}-docker.pkg.dev/${GKE_PROJECT_ID}/devspace-dev
```

Set `DEV_REGISTRY_IMAGE_PREFIX` to override it. Do not push local developer
artifacts to `ghcr.io/michaelw`; GHCR is for CI/release artifacts.

## Traffic Extension

The primary GKE path uses the Gateway-native `GCPTrafficExtension` CRD with the
Envoy `ext_proc` protocol. The plugin still serves `ext_authz` for local Istio
and GKE diagnostics, but GKE `ext_proc` is preferred because
`GCPTrafficExtension` can reference the private Kubernetes Service directly with
`backendRef`.

The chart creates the GKE callout backend plumbing:

- TLS gRPC listener on plugin port `3000`.
- cert-manager generated certificate and Secret.
- Service `gateway-ext-authz` in the Gateway namespace on TLS callout port
  `3000`, plus plaintext gRPC health port `3001`.
- GKE `HealthCheckPolicy` on plaintext gRPC health port `3001`.
- GKE `GCPBackendPolicy` with connection draining for rollout safety.
- `BackendTLSPolicy`.
- `GCPTrafficExtension` attached to `Gateway/gateway`.

The chart does not publish an external `HTTPRoute` for
`gateway-ext-authz`. The callout backend is a private GKE Service Extensions
target, not a browser- or client-reachable route.

The GKE profile runs the plugin with two replicas, `maxUnavailable: 0`,
`minReadySeconds: 10`, and a short `preStop` drain delay. This keeps an old
healthy callout endpoint alive while GKE removes it from the load balancer
backend during config-changing rollouts. The callout itself remains TLS gRPC on
port `3000`; the GKE health check uses the plaintext gRPC health service on
port `3001` because the Google health checker does not participate in the
BackendTLSPolicy TLS callout path.

For `ext_proc`, omit both `forwardHeaders` and `forwardAttributes` on the
current GKE Gateway CRD. Live validation on GKE `1.35.3-gke.2190000` showed
that omitting `forwardHeaders` forwards all headers, including pseudo headers
such as `:method`, `:scheme`, `:authority`, and `:path`; the plugin uses those
pseudo headers for policy matching.

The intended least-privilege configuration is explicit `forwardHeaders` for
bearer/CORS/trace and Cloudflare/CDN provenance headers, paired with
`forwardAttributes` for `request.method`, `request.scheme`, `request.host`,
`request.path`, and `request.query`. Uncomment that values block only after
`kubectl explain gcptrafficextension.spec.extensionChains.extensions --recursive`
shows `forwardAttributes`.

The current live GKE cluster's `GCPTrafficExtension` CRD does not yet include
`forwardAttributes`; server-side dry-run rejects it as an unknown field. Update
the starter-pack GKE Service Extensions CRDs/controller channel before applying
this chart shape to the live cluster.

## Authorization Extension Fallback

Google Cloud authorization extensions are configured as Cloud Service
Extensions resources, not as a Kubernetes `AuthorizationExtension` CRD. The
fallback script configures an authorization extension with `wireFormat:
EXT_AUTHZ_GRPC`, but live validation on 2026-05-29 showed that a private
NEG-backed Service alone does not cause the GKE Gateway controller to publish a
regional Compute backend service for authorization-extension discovery.

If you intentionally test the fallback authz path, the authz import script
discovers these values from the Gateway annotations:

- `GKE_PROJECT_ID`, for example `devspace-gke-example`.
- `GKE_REGION`, for example `us-central1`.
- the generated callout backend service for `gateway-ext-authz`.
- the regional forwarding rules owned by the GKE Gateway.

Manual authz attach, for diagnostics only:

```sh
./scripts/gke-authz.sh apply
```

The script configures explicit forwarded headers by default:
`authorization`, `cookie`, `origin`, `access-control-request-method`,
`access-control-request-headers`, `x-request-id`, `traceparent`, and
`tracestate`. The CORS headers are required so the plugin can distinguish true
preflight requests from unauthenticated `OPTIONS` requests. Set
`GKE_AUTHZ_FORWARD_HEADERS=all` only as a diagnostic variant; it omits the
`forwardHeaders` field, which Google Cloud documents as forwarding all client
headers.

## Header Representation

GKE Service Extensions currently delivers `ext_proc` request headers as Envoy
`HeaderValue` entries with `rawValue` bytes, and selected `forwardAttributes` in
`ProcessingRequest.attributes`. Header mutations must also use `rawValue`;
Google Cloud documents that the load balancer ignores the `value` field for
`HeaderMutation`.

For the `ext_authz` fallback, GKE delivers forwarded request headers in the
Envoy `CheckRequest` `attributes.request.http.headerMap.headers`
representation with `rawValue` bytes. The plugin also supports the legacy
`attributes.request.http.headers` map representation used by other ext-authz
callers.

A temporary diagnostic policy condition,
`request.headers["authorization"] != ""`, proved that the GKE load balancer
matcher could see `Authorization`; that condition is not part of the working
configuration because no-token requests must still invoke the plugin and receive
the plugin's `401 bearer_token_required` challenge.

## Test

```sh
devspace run test-e2e -v --label-filter=
```

If the callout backend service does not exist or the forwarding rule cannot be
used with a custom authorization policy, stop and fix the missing prerequisite
in `devspace-starter-pack`.
