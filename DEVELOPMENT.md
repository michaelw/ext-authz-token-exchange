# Development Guide

This guide is the repository-root quickstart for building, testing, and running
`ext-authz-token-exchange`. For deeper background, see `docs/development.md`,
`docs/devspace.md`, `docs/implementation.md`, and `test/e2e/README.md`.

## Prerequisites

- Go matching the version declared in `go.mod`.
- DevSpace for Kubernetes development workflows.
- Docker or another container builder supported by DevSpace.
- A local Kubernetes cluster when running DevSpace deployments or e2e tests.
- `yq` v4, required by `devspace.yaml`.
- Optional: Helm, kubectl, and k9s for direct cluster inspection.

Do not install project-specific tools globally unless the repository
documentation explicitly asks for it. Prefer the DevSpace setup commands and
containerized development flow.

## Repository Layout

- `cmd/ext-authz-token-exchange-service`: production gRPC ext-authz service.
- `cmd/fake-token-endpoint`: demo and e2e token endpoint.
- `cmd/demo-scenario`: terminal-friendly demo runner.
- `internal/config`: runtime configuration and defaults.
- `internal/policy`: policy parsing, validation, and request matching index.
- `internal/exchange`: OAuth token exchange client behavior.
- `internal/server`: Envoy ext-authz gRPC behavior.
- `charts/ext-authz-token-exchange`: production Helm chart.
- `charts/ext-authz-token-exchange-e2e`: local demo and e2e chart.
- `test/e2e`: Kubernetes e2e suite and demo scenarios.

## Local Build

From the repository root:

```sh
go mod download
go build ./cmd/...
```

When using DevSpace:

```sh
devspace run generate
devspace run compile
```

## Running the Service

Run the gRPC service directly:

```sh
GRPC_PORT=3001 go run ./cmd/ext-authz-token-exchange-service
```

Run the Kubernetes development environment:

```sh
devspace dev
```

Start the development environment and connect VS Code:

```sh
devspace dev --vscode
```

## Testing

Run the full unit test suite:

```sh
go test ./...
```

Run a focused package while iterating:

```sh
go test ./internal/server
go test ./internal/policy
go test ./internal/exchange
go test ./internal/config
```

Run tests with verbose output:

```sh
go test -v ./...
```

Run coverage:

```sh
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

Pull requests upload Go coverage to Codecov from `coverage.out`. Configure the
repository Actions secret `CODECOV_TOKEN` after authorizing Codecov for this
repository. Coverage gates are intentionally not enforced yet; Codecov is used
for reporting, PR review context, and history.

When using DevSpace:

```sh
devspace run test
devspace run coverage
```

### Test Style

- Prefer TDD when changing behavior: write or update the failing test first,
  confirm the failure, implement the fix, then rerun the focused test.
- Use Ginkgo and Gomega in the existing package style.
- Prefer table-driven tests for validation matrices and behavioral variants.
- Keep unit tests deterministic and independent from Kubernetes, registries,
  external networks, and local secrets.
- Add e2e coverage when a change depends on Helm rendering, namespace discovery,
  Gateway/Istio behavior, or interactions between the plugin and fake token
  endpoint.

## End-to-End Testing

The e2e suite expects local cluster infrastructure and a deployed demo stack.
For the common local-test flow:

```sh
devspace run smoke
```

For a fresh cluster that also needs the supporting infrastructure:

```sh
devspace deploy -p with-infra -p local-test
devspace run test-e2e
```

Direct Ginkgo execution is documented in `test/e2e/README.md`. Use it when you
need explicit image, namespace, or base URL overrides.

## Helm and DevSpace Checks

Preview the production chart deployment:

```sh
devspace deploy --render --skip-build
```

Deploy the production chart through DevSpace:

```sh
devspace deploy
```

Deploy the local demo stack. This installs the plugin chart and demo/e2e chart
as separate Helm releases:

```sh
devspace deploy -p local-test
```

Purge deployments:

```sh
devspace purge
devspace purge -p local-test
devspace purge -p with-infra -p local-test
```

When changing chart templates, verify the affected deployment profile by
rendering or deploying it. Keep production chart changes separate from e2e-only
test fixture changes.

## GitHub Actions CI/CD

Pull requests run separate GitHub Actions checks for pre-commit hygiene, Go
tests, Go coverage, command builds, and Helm validation. Run the local
CI-equivalent validation before pushing:

```sh
devspace run verify
```

`verify` does not require a Kubernetes cluster. It runs these underlying checks:

```sh
pre-commit run --all-files
devspace run actionlint
go test ./...
go test -coverprofile=coverage.out ./...
go build ./cmd/...
helm dependency build charts/ext-authz-token-exchange
helm lint charts/ext-authz-token-exchange
helm lint charts/ext-authz-token-exchange-e2e
helm template ext-authz-token-exchange charts/ext-authz-token-exchange --namespace ext-authz-token-exchange
helm template ext-authz-token-exchange-e2e charts/ext-authz-token-exchange-e2e --namespace ext-authz-token-exchange-e2e
```

Go coverage is uploaded to Codecov and `coverage.out` remains available as a
workflow artifact for local debugging or fallback. Rendered Helm manifests are
uploaded as workflow artifacts. Cluster-backed e2e remains optional because it
requires local-test Gateway/Istio infrastructure; use
`devspace run smoke` for that smoke path.

DevSpace is the repository command runner for local validation. If it becomes
awkward for non-cluster checks, Taskfile is the next preferred option.

Releases are managed by Release Please. Conventional commits merged to `main`
update the release PR, changelog, `.release-please-manifest.json`, and the
production chart `version` and `appVersion`. The service images and chart share
one version for now; split plugin and chart versions only after chart-only
releases need their own compatibility policy.

When a Release Please release is created, GitHub Actions publishes:

- `ghcr.io/michaelw/ext-authz-token-exchange:<version>`
- `ghcr.io/michaelw/ext-authz-token-exchange:sha-<commit>`
- `ghcr.io/michaelw/ext-authz-token-exchange-fake-token-endpoint:<version>`
- `ghcr.io/michaelw/ext-authz-token-exchange-fake-token-endpoint:sha-<commit>`
- `oci://ghcr.io/michaelw/ext-authz-token-exchange:<version>`

The chart package is also attached to the GitHub Release. The release workflow
validates the published OCI chart with `helm pull`, `helm show chart`, and
`helm show values`. A manual `Test Published Chart` workflow can re-check a
specific published chart version.

Container image builds request Docker BuildKit provenance and SBOM output, and
GitHub artifact attestations are pushed for both release images. Verify
provenance with the GitHub CLI when needed:

```sh
gh attestation verify oci://ghcr.io/michaelw/ext-authz-token-exchange:<version> --repo michaelw/ext-authz-token-exchange
gh attestation verify oci://ghcr.io/michaelw/ext-authz-token-exchange-fake-token-endpoint:<version> --repo michaelw/ext-authz-token-exchange
```

## Formatting and Module Hygiene

Format changed Go files:

```sh
gofmt -w path/to/file.go
```

Tidy module metadata only when imports or dependencies intentionally changed:

```sh
go mod tidy
```

Do not commit generated environment files, kubeconfigs, local credentials,
coverage reports, or machine-local paths.

## Documentation Updates

Update docs in the same change when behavior or workflows change:

- `README.md` for user-facing run and deployment guidance.
- `DEVELOPMENT.md` for contributor setup and verification commands.
- `COMPATIBILITY.md` for externally visible compatibility behavior.
- `docs/implementation.md` for design and architecture changes.
- `test/e2e/README.md` for cluster, chart, image, or scenario changes.
