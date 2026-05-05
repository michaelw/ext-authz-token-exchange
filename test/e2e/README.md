# Kubernetes E2E Tests

These tests assume the local test cluster infrastructure is already installed,
including Istio/Gateway and the shared `mccutchen/go-httpbin` backend reachable
as `https://httpbin.int.kube/` through the Gateway API gateway.

Run the suite only when the cluster and plugin image are available:

```sh
E2E_BASE_URL=https://httpbin.int.kube \
E2E_PLUGIN_IMAGE=ghcr.io/michaelw/ext-authz-token-exchange:latest \
E2E_FAKE_TOKEN_ENDPOINT_IMAGE=ghcr.io/michaelw/ext-authz-token-exchange-fake-token-endpoint:latest \
go run github.com/onsi/ginkgo/v2/ginkgo -r -v ./test/e2e
```

The Ginkgo suite installs `charts/ext-authz-token-exchange-e2e`, an umbrella
Helm chart that deploys the central plugin chart plus demo-only resources. The
test code intentionally does not construct baseline Kubernetes manifests; use
the chart values to change namespaces, credentials, images, policy entries, or
the fake token endpoint.

You can also let DevSpace deploy the full local demo stack:

```sh
devspace deploy -p local-test
devspace run test-e2e
```

`devspace run test-e2e` uses the Ginkgo runner, so repeated runs are not served
from the Go test cache. Pass Ginkgo flags directly, for example
`devspace run test-e2e -v`.

The `local-test` profile builds the plugin and fake token endpoint images, then
deploys the e2e chart. DevSpace updates the image tags in Helm values in memory,
so the local-test flow does not require pushing images to `ghcr.io/michaelw`
when your cluster can use DevSpace-built images.

The production plugin image intentionally contains only
`ext-authz-token-exchange-service`. The fake token endpoint is packaged through
the separate Dockerfile `fake-token-endpoint` target and should be pushed as its
own image.

By default the suite creates:

- `ext-authz-token-exchange-e2e` for the central ext-authz plugin and fake token endpoint.
- `service-yellow`, `service-red`, and `service-blue` for app-owned policy ConfigMaps.

Useful overrides:

- `E2E_HOST`: Host header and ConfigMap host. Defaults to the host from `E2E_BASE_URL`.
- `E2E_NAMESPACE_PREFIX`: Prefix for team namespaces. Defaults to `service`.
- `E2E_SYSTEM_NAMESPACE`: Namespace for the plugin and fake token endpoint.
- `E2E_RELEASE`: Helm release name for the plugin.
- `E2E_FAKE_TOKEN_ENDPOINT_IMAGE`: Image for the demo token endpoint.
- `E2E_HTTPBIN_RESOURCE_BASE`: Resource URI base used in demo ConfigMaps.
- `E2E_SKIP_CLEANUP=true`: Keep test namespaces for inspection.
- `E2E_SKIP_INSTALL=true`: Test an already deployed local-test chart release.
- `E2E_INSECURE_SKIP_VERIFY=false`: Enforce TLS verification for the gateway URL.

The suite skips automatically when `E2E_BASE_URL` is not set, so `go test ./...`
remains safe for ordinary unit-test runs.
