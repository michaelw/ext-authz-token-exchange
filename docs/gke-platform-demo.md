# GKE Platform Demo Quickstart

This guide deploys the complete demo into an existing GKE cluster and starts
the dashboard locally. It targets public HTTPS that terminates before an HTTP
Gateway listener.

## Prerequisites

Run the commands from the repository root. You need:

- DevSpace, `kubectl`, and [Mike Farah `yq`](https://github.com/mikefarah/yq).
- A current `kubectl` context for the target GKE cluster and cluster-admin
  permissions.
- An existing `gke-gateway/gateway` Gateway with an HTTP listener named `http`.
- A wildcard-capable listener with
  `allowedRoutes.namespaces.from: Same`.
- Gateway API and GKE Service Extensions CRDs installed in the cluster.
- Public DNS for `httpbin.example.test` and `keycloak.example.test` pointing to
  the external TLS terminator.

The TLS terminator must forward HTTP traffic to the selected Gateway listener.
The commands use public DNS for this topology; do not map these hosts directly
to the Gateway address.

## Deploy

Confirm that `kubectl` is using the intended cluster:

```sh
kubectl config current-context
```

Deploy the platform plumbing and demo:

```sh
devspace deploy -p gke-platform \
  --var GKE_DEPLOYMENT_DOMAIN=example.test \
  --var GKE_GATEWAY_SECTION_NAME=http
```

The deployment installs:

- The plugin and GKE Service Extension configuration in `gke-gateway`.
- The fake issuer and Keycloak in `txe-platform`.
- HTTPBin fixtures and policies in `txe-demo-yellow`, `txe-demo-red`, and
  `txe-demo-blue`.
- The unlabeled `txe-demo-black` namespace used by selector scenarios.
- The yellow reference application and policy in `txe-team-yellow`.
- Platform-owned routes and the required cross-namespace `ReferenceGrant`
  objects.

The deployment waits for the workloads, routes, and traffic extension, then
runs the fake-issuer and Keycloak end-to-end probes. When the command reports
success, the deployment is ready for the dashboard; no separate validation
step is required.

## Start the Dashboard

Start the dashboard on the same workstation:

```sh
devspace run demo-dashboard -p gke-platform \
  --var GKE_DEPLOYMENT_DOMAIN=example.test \
  --var GKE_GATEWAY_SECTION_NAME=http \
  -- -open
```

The dashboard runs locally at <http://127.0.0.1:8088/>. The `-open` option
opens it in the default browser. Omit `-open` to open the URL manually.

The dashboard uses the current Kubernetes credentials to read deployment
status, policies, and logs. Its HTTPBin and Keycloak requests use the public
hostnames so HTTPS reaches the external TLS terminator before the Gateway.

Press `Ctrl+C` in the dashboard terminal to stop it. This stops only the local
dashboard and leaves the cluster deployment running.

## Remove the Demo

To remove resources owned by the platform demo:

```sh
devspace purge -p gke-platform \
  --var GKE_DEPLOYMENT_DOMAIN=example.test \
  --var GKE_GATEWAY_SECTION_NAME=http
```

This removes the platform release, the `txe-demo-*` fixtures, and the yellow
reference application. It does not remove the existing Gateway or application
teams deployed independently with `gke-app`.

For listener alternatives and configuration variables, see the
[DevSpace configuration](devspace.md#existing-gateway-gke-deployment). For the
full non-stress suite and operational details, see the
[end-to-end testing guide](../test/e2e/README.md).
