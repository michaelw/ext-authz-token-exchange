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

# plugin plus demo/e2e resources and required infrastructure from scratch
devspace deploy -p with-infra -p local-test
```

After deployment, run the e2e assertions against the already deployed releases:

```bash
devspace run test-e2e
```

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
