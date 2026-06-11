# DevSpace Configuration

This project includes DevSpace configuration for Kubernetes development and deployment.

## Prerequisites

1. Install DevSpace CLI:
   ```bash
   # macOS
   brew install devspace

   # Or download from https://github.com/devspace-sh/devspace/releases
   ```

2. Ensure you have access to a Kubernetes cluster and `kubectl` is configured

## Quick Start

### Development Mode

Start development mode with hot reloading:

```bash
devspace dev
```

This will:
- Build the dev container image
- Deploy to Kubernetes
- Set up file synchronization
- Enable hot reloading with Air
- Forward ports (3001 for gRPC)
- Open a terminal in the container

This will take some time, you can follow progress in another terminal:

```bash
devspace logs -f
```

### Default Test Deployment

Deploy the provider-selected demo/e2e stack:

```bash
devspace deploy
```

The auto-activated `with-test` profile assumes starter-pack already provides
httpbin and provider-appropriate routes through the active Gateway. It deploys
the plugin chart as release `ext-authz-token-exchange`, and the demo/e2e chart
as release `ext-authz-token-exchange-e2e`.
The demo/e2e chart owns the fake token endpoint, color team namespaces, and
app-owned policy ConfigMaps. The fake token endpoint response behavior is
configured by the required `fakeTokenEndpoint.routes` e2e chart value. The
chart renders those routes into a ConfigMap and sets
`FAKE_TOKEN_ENDPOINT_CONFIG`; the binary does not carry fallback routes. The
plugin still uses the single `fake-issuer` issuer profile endpoint.

Profiles are composable:

```bash
# plugin and demo/e2e resources, assumes starter-pack httpbin/routes exist
devspace deploy

# same, plus required starter-pack infrastructure and httpbin/routes
devspace deploy -p with-infra

# plugin plus demo/e2e resources and a real Keycloak issuer
devspace deploy -p with-keycloak

# same Keycloak stack, plus starter-pack infrastructure and httpbin/routes
devspace deploy -p with-infra -p with-keycloak

# same e2e stack through the local Envoy ext_proc filter path
devspace deploy -p with-infra -p with-keycloak -p ext-proc
```

After deployment, run the e2e assertions against the already deployed releases:

```bash
devspace run test-e2e
```

`devspace run test-e2e` runs the fake baseline for the default `with-test`
stack. Keycloak-gated specs skip when Keycloak is unavailable and execute when
the `with-keycloak` profile is deployed. The default local `ext_authz` profile
uses the starter-pack `gateway-ext-authz` Service alias contract; add `-p
ext-proc` when testing the Envoy external processor path instead.

For manual Keycloak testing, start the dashboard. Each scenario declares its
input token shape in the scenario YAML, and the token tab's `Fetch` button
generates the selected scenario's token when needed:

```bash
devspace run demo-dashboard
```

Use the dashboard for Keycloak scenarios that declare generated token prefill
types. The command-line demo client can still list the configured scenarios:

```bash
go run ./cmd/demo-scenario --config test/e2e/demo-scenarios.yaml list
```

The dashboard shows every configured scenario from the unified catalog.
Scenarios that require `local-keycloak` are marked `Skipped` until the
`with-keycloak` profile is deployed. The token tab decodes JWT-shaped input
tokens and uses the scenario's `request.token.prefill` plus local Keycloak
profile defaults for its `Fetch` action. Those defaults can be adjusted with
`DEMO_KEYCLOAK_BASE_URL`, `DEMO_KEYCLOAK_REALM`,
`DEMO_KEYCLOAK_SUBJECT_CLIENT_ID`, `DEMO_KEYCLOAK_SUBJECT_CLIENT_SECRET`,
`DEMO_KEYCLOAK_USER`, and `DEMO_KEYCLOAK_PASSWORD`.

On GKE, `keycloak.${DEPLOYMENT_DOMAIN}` is IAP-protected by design. If
`DEMO_KEYCLOAK_BASE_URL` is not set, `devspace run demo-dashboard` opens a
temporary local port-forward to `svc/keycloak` and uses that URL for dashboard
subject-token fetches. This does not change the plugin issuer profile, which
continues to use the in-cluster Keycloak Service.

The `keycloak-audience` scenario should reach httpbin with an upstream
Keycloak-issued bearer token. The `keycloak-resource` scenario keeps resource
coverage separate from the audience-only baseline so provider behavior stays
visible during manual testing.

DevSpace updates the built image tags in Helm values during deployment, so this
flow can use locally built images without publishing them to the default GHCR
repository when the cluster supports DevSpace's image handling.

To verify OpenTelemetry tracing through the local Gateway, plugin, token
endpoint, OpenTelemetry Collector, and Jaeger, follow the
[Tracing Tutorial](tracing.md).

## Available Commands

```bash
devspace list commands
```

```bash
# build images
devspace run build-images
# or
devspace build
```

```bash
# Quick build (run this only inside a container, unless you have all the dependencies installed locally)
devspace run compile
```

## Troubleshooting

### Kubernetes Context
Verify you're connected to the correct cluster:
```bash
kubectl config current-context
```

### DevSpace Logs
View DevSpace logs for debugging:
```bash
devspace logs
```

### Clean Up
Remove DevSpace deployment:
```bash
devspace purge
```
