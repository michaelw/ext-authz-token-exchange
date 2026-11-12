# Development Guide

For existing paid gateways and operational settings, see [Operations](docs/operations.md).
For switching gateway integrations, see [Gateway Migration](docs/gateway-migration.md).

This guide is the repository-root quickstart for building, testing, and running
`ext-authz-token-exchange`. For deeper background, see `docs/development.md`,
`docs/devspace.md`, `docs/implementation.md`, and `test/e2e/README.md`.

## Prerequisites

For one-command GKE Gateway or managed Apigee setup, see
[Gateway Development Setup](docs/gateway-setup.md). The root DevSpace commands
select the provider and retain its non-secret settings. The older standalone
Apigee configuration is a compatibility import of the root workflow.

- Docker for the shared pinned Go/protobuf/Helm toolchain; host Go is optional.
- DevSpace for Kubernetes development workflows.
- Docker or another container builder supported by DevSpace.
- A local Kubernetes cluster when running DevSpace deployments or e2e tests.
- `yq` v4, required by `devspace.yaml`.
- Optional: Helm, kubectl, and k9s for direct cluster inspection.

Do not install project-specific tools globally unless the repository
documentation explicitly asks for it. Prefer the DevSpace setup commands and
containerized development flow.

## Shared Toolchain

Build once, then run checks from a shell in the same tooling image as CI:

```sh
docker build --target toolchain -t txe-toolchain:local .
mkdir -p .devspace/toolchain-cache
docker run --rm -it --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:/workspace" -v "$PWD/.devspace/toolchain-cache:/go-cache" \
  -w /workspace txe-toolchain:local bash
```

The Go/Helm commands below run in that shell or the DevSpace development
container. Go 1.27.4, protoc 35.0, protoc-gen-go 1.36.12,
protoc-gen-go-grpc 1.6.0, Helm 4.1.1, and helm-unittest 1.2.1 are pinned in the
Dockerfile. Runtime images do not contain those tools. Kind smoke checks use the
same Go/protobuf toolchain with their existing Helm 3.18.3 and Kubernetes pins.
The shared toolchain also pins DevSpace 6.3.15 and Terraform 1.15.5 for offline
profile and infrastructure validation. The development image installs Air and
Delve at build time. `setup` now selects the environment; the former tool-install
command remains available as `setup-tools` inside development containers.

Only the upstream protobuf schema and handwritten generation directives are
tracked. `go generate ./...` works without generated bindings; run it before Go
checks. Production Docker builds and DevSpace iteration do this automatically.
Host-only development requires those same tools on a caller-controlled PATH;
do not install project-specific generators globally on the host.

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
go generate ./...
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

Managed Apigee uses a separate, opt-in workflow. See
[Apigee development](docs/apigee.md) for trial provisioning, ExternalCallout,
synthetic fixtures, private connectivity, and externally managed clusters.
Normal tests and CI do not provision GCP resources.

The e2e suite expects starter-pack httpbin/routes and this repo's deployed demo
stack. For the common `with-test` flow:

```sh
devspace run smoke
```

For a fresh cluster that also needs the supporting infrastructure:

```sh
devspace deploy -p with-infra
devspace run test-e2e
```

Direct Ginkgo execution is documented in `test/e2e/README.md`. Use it when you
need explicit image, namespace, or base URL overrides.

## Helm and DevSpace Checks

Preview the default test deployment:

```sh
devspace deploy --render --skip-build
```

Deploy the default test stack through DevSpace:

```sh
devspace deploy
```

Purge deployments:

```sh
devspace purge
devspace purge -p with-infra
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
helm dependency build charts/keycloak
helm lint charts/ext-authz-token-exchange
helm lint charts/ext-authz-token-exchange-e2e
helm lint charts/keycloak
helm template ext-authz-token-exchange charts/ext-authz-token-exchange --namespace ext-authz-token-exchange
helm template ext-authz-token-exchange-e2e charts/ext-authz-token-exchange-e2e --namespace ext-authz-token-exchange-e2e
./scripts/verify-gke-deployment-model.sh
```

Go coverage is uploaded to Codecov and `coverage.out` remains available as a
workflow artifact for local debugging or fallback. Rendered Helm manifests are
uploaded as workflow artifacts. The `smoke` workflow runs on every pull request,
nightly, and on manual dispatch. It creates a fresh kind cluster for each
`ext_authz`, `ext_proc`, and InferencePool job. Both InferencePool jobs are
required checks on `main`: one uses Istio 1.28.0 and the other uses 1.31.3.
The workflow uses the Go smoke helper under `test/e2e/cmd/smoke` to deploy the
test stack and run `devspace run test-e2e`.

The helper clones a pinned infrastructure checkout into a temporary directory
instead of using DevSpace's shared dependency cache. It also isolates the
DevSpace, Go, Helm, and Docker buildx state, and uses local port forwards so
host DNS and certificate integration are unnecessary.

To exercise an Istio InferencePool route with the chart-owned `ext_proc`
filter outside CI, use the smoke helper's pool mode:

```sh
SMOKE_MODE=ext-proc-inferencepool go run ./test/e2e/cmd/smoke
```

This mode uses Istio 1.28.0 by default (set `SMOKE_ISTIO_VERSION=1.31.3` to
check the later route behavior), the pinned Gateway API Inference Extension v1.5.0
test component, and the e2e chart's CPU-only backend and route fixture. It runs the
Ginkgo `inferencepool` spec, including pool, weighted-backend, two-pool, and
endpoint-picker-unavailable cases, and deletes the disposable kind cluster
afterward.
The command needs kind, kubectl, Helm, DevSpace, Docker, and network access to
fetch the pinned test component and images.
For manual upgrade checks, set `SMOKE_KEEP_CLUSTER=true` to retain the cluster
and temporary kubeconfig; delete the named kind cluster and temporary directory
when finished.

DevSpace is the repository command runner for local validation. If it becomes
awkward for non-cluster checks, Taskfile is the next preferred option.

Releases are managed by Release Please. Conventional commits merged to `main`
update the release PR, changelog, `.release-please-manifest.json`, and the
production chart `version` and `appVersion`. The service images and chart share
one version for now; split plugin and chart versions only after chart-only
releases need their own compatibility policy.

The next feature release targets 0.7.0. Review the
[release notes and logging migration checklist](docs/release-0.7.0.md) before
merging its release PR. Preserve implementation/release commit separation.
Release Please is configured to use pre-1.0 minor increments for features and
breaking changes, rather than promoting these changes to 1.0 or a patch release.

PR CI runs the Go unit suite once with coverage, plus separate race/static checks.
The required `Go tests` status reflects that coverage execution without repeating
tests. The required `Go build` status now builds production/fixture containers,
not a duplicate standalone Go build. Helm/Python checks execute directly in the
shared tooling image. PR cancellation applies only to superseded PR runs.
Docker cache writes are scoped to PR/main; release builds do not read PR scopes.
When reviewing CI changes, check required status names against branch protection.
Do not remove the existing smoke matrix or introduce GCP/Apigee credentials in CI.

Merge commits are disabled for this repository. Use squash or rebase merges so
Release Please sees one conventional commit message for each change. GitHub
merge commits can repeat the PR title alongside the original commit, which makes
Release Please generate duplicate changelog entries.

Release Please uses a dedicated GitHub App token so release PRs trigger the
same required CI checks as human-authored PRs. The GitHub App should be
installed on this repository with repository permissions for contents, issues,
and pull requests set to read/write. Configure these repository secrets:

- `RELEASE_PLEASE_APP_CLIENT_ID`
- `RELEASE_PLEASE_APP_PRIVATE_KEY`

When a Release Please release is created, GitHub Actions publishes:

- `ghcr.io/michaelw/ext-authz-token-exchange:<version>`
- `ghcr.io/michaelw/ext-authz-token-exchange:sha-<commit>`
- `ghcr.io/michaelw/ext-authz-token-exchange-fake-token-endpoint:<version>`
- `ghcr.io/michaelw/ext-authz-token-exchange-fake-token-endpoint:sha-<commit>`
- `oci://ghcr.io/michaelw/charts/ext-authz-token-exchange:<version>`

The chart package is also attached to the GitHub Release. The release workflow
validates the published OCI chart with `helm pull`, `helm show chart`, and
`helm show values`. After the chart is published, run `Test Published Chart`
at the matching release tag:

```sh
gh workflow run test-published-chart.yml --ref v0.6.1 -f version=0.6.1
```

This workflow pulls the OCI package, installs it over the smoke helper's test
release with the test values retained, and checks the installed chart version.
It then checks the renamed gateway filter in xDS and runs the InferencePool
denial and token-exchange tests on Istio 1.31.3. It cannot run before the OCI
package exists. Helm pushes the chart package to
`oci://ghcr.io/michaelw/charts`; pull, install, and upgrade commands include the
chart basename, for example
`oci://ghcr.io/michaelw/charts/ext-authz-token-exchange`.

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
