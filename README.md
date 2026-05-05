# Ext AuthZ Token Exchange Plugin

Envoy Ext-AuthZ plugin template for token exchange.

The current service intentionally keeps only the gRPC external authorization
service stub. Business logic will be added in `internal/server/grpc_authz.go`.

## Project Overview

- `cmd/ext-authz-token-exchange-service/main.go` — gRPC service entrypoint
- `internal/server/` — Envoy ext-authz gRPC server stub

For a detailed overview, refer to the [Implementation Guide](docs/implementation.md).

## Running the Services

Users who want to run the service **without modifying the code** can use DevSpace directly.

### Running with DevSpace

If you have a local Kubernetes cluster available, [DevSpace](https://devspace.sh/) is all you need.
The default deployment is production-like and deploys only the plugin chart:

For a preview of what gets deployed:

```bash
devspace deploy --render --skip-build
```

If you do not yet have Gateway API CRDs, a cluster-wide gateway named `gateway`, external-dns, cert-manager, etc. installed:

```bash
devspace deploy -p with-infra
```

The command will setup a fully functionioning self-contained demo environment.

For the local demo/e2e stack that assumes infrastructure already provides
`https://httpbin.int.kube/` through the Gateway API gateway, use:

```bash
devspace deploy -p local-test
devspace run test-e2e
```

The `local-test` profile deploys the plugin, fake token endpoint, color team
namespaces, and app-owned policy ConfigMaps from the e2e Helm chart. The color
namespaces are labeled with the default policy namespace selector
`ext-authz-token-exchange.magneticflux.net/policy=enabled`; ConfigMaps in
unlabeled namespaces are ignored by the plugin.

Profiles are composable. On a fresh cluster, use `devspace deploy -p with-infra
-p local-test` to install required infrastructure plus the local demo/e2e stack.

Refer to the [DevSpace](docs/devspace.md) and [devspace-starter-pack](https://github.com/michaelw/devspace-starter-pack) documentation
for more information.

### Uninstall

- `devspace purge`, `devspace purge -p with-infra`, `devspace purge -p local-test`, or `devspace purge -p with-infra -p local-test`

## Development Quickstart Guide

This project uses Docker-based devcontainers and a multi-stage Docker build for development.

For further information, refer to the [Development Guide](docs/development.md).

- K8s: `devspace dev`
- gRPC: `GRPC_PORT=3001 go run ./cmd/ext-authz-token-exchange-service`

### Getting Started in VSCode

Deploy a development container and connect it to VSCode

- `devspace dev --vscode`

# TODO

* Tests
* CI builds
* Persist shell history in devcontainer, dotfiles, etc.
* Inject Github credentials
