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

### Production Deployment

Deploy to production:

```bash
devspace deploy
```

The default deploy path is production-like and deploys only the plugin chart.

### Local Test Deployment

Deploy the full local demo/e2e stack:

```bash
devspace deploy -p local-test
```

The `local-test` profile assumes infrastructure already provides Istio/Gateway
and `https://httpbin.int.kube/` through the Gateway API gateway. It deploys the
plugin chart as release `ext-authz-token-exchange` in namespace
`ext-authz-token-exchange`, and the demo/e2e chart as release
`ext-authz-token-exchange-e2e` in namespace `ext-authz-token-exchange-e2e`.
The demo/e2e chart owns the fake token endpoint, color team namespaces, and
app-owned policy ConfigMaps.

Profiles are composable:

```bash
# plugin only, assumes infrastructure exists
devspace deploy

# plugin plus required infrastructure from scratch
devspace deploy -p with-infra

# plugin plus demo/e2e resources, assumes infrastructure exists
devspace deploy -p local-test

# switch the local demo/e2e resources back to the fake issuer
devspace deploy -p local-test -p with-fake-issuer

# plugin plus demo/e2e resources and required infrastructure from scratch
devspace deploy -p with-infra -p local-test

# plugin plus demo/e2e resources and a real local Keycloak issuer
devspace deploy -p local-test -p with-keycloak

# same Keycloak stack, plus Gateway/DNS/certificate infrastructure
devspace deploy -p with-infra -p local-test -p with-keycloak
```

After deployment, run the e2e assertions against the already deployed releases:

```bash
devspace run test-e2e
```

`devspace run test-e2e` inspects the deployed plugin token endpoint and runs the
matching specs: fake-token scenarios for the default `local-test` stack, or
Keycloak-gated scenarios for the `with-keycloak` stack. The active issuer profile
also self-holds for later DevSpace commands: use
`devspace deploy -p local-test -p with-keycloak` to switch to Keycloak, and
`devspace deploy -p local-test -p with-fake-issuer` to switch back to fake.

For manual Keycloak testing, start the dashboard and use the token tab's
`Fetch` button to place a fresh local Keycloak subject token in the selected
scenario's input field:

```bash
devspace run demo-dashboard
```

To run the command-line demo client, or to seed the dashboard field with an
explicit token, fetch a subject token through the local Gateway route at
`https://keycloak.int.kube`:

```bash
export DEMO_BEARER_TOKEN="$(
  curl -fsS https://keycloak.int.kube/realms/token-exchange-e2e/protocol/openid-connect/token \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d grant_type=password \
    -d client_id=tx-subject-client \
    -d client_secret=tx-subject-secret \
    -d username=token-user \
    -d password=token-user-password \
    -d scope=profile |
  jq -r .access_token
)"
```

Then run the Keycloak demo scenarios through the Gateway:

```bash
go run ./cmd/demo-scenario --config test/e2e/keycloak-demo-scenarios.yaml list
go run ./cmd/demo-scenario --config test/e2e/keycloak-demo-scenarios.yaml keycloak-audience
go run ./cmd/demo-scenario --config test/e2e/keycloak-demo-scenarios.yaml keycloak-resource
```

The dashboard also detects the deployed plugin token endpoint. It selects the
fake or Keycloak scenario file automatically and shows the selected issuer in
the header and logs panel. The token tab decodes JWT-shaped input tokens and
uses the local Keycloak profile defaults for its `Fetch` action. Those defaults
can be adjusted with
`DEMO_KEYCLOAK_BASE_URL`, `DEMO_KEYCLOAK_REALM`,
`DEMO_KEYCLOAK_SUBJECT_CLIENT_ID`, `DEMO_KEYCLOAK_SUBJECT_CLIENT_SECRET`,
`DEMO_KEYCLOAK_USER`, and `DEMO_KEYCLOAK_PASSWORD`.

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
