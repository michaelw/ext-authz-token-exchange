# Managed Apigee ExternalCallout

Apigee uses the same policy and token-exchange engine as Envoy ext-authz and
ext-proc. Policy ConfigMaps, issuer profiles, Secret references, namespace
selection, CORS rules, and fail-closed behavior keep their existing meaning.
The service remains in GKE; Apigee does not need Kubernetes credentials.
This integration uses managed Apigee, not hybrid or Apigee Extension Processor.
See [live validation results and remaining limits](apigee-validation.md).
For interactive testing, see [manual QA and the demo dashboard](apigee-manual-qa.md).

ExternalCallout itself is a Standard policy. This bundle also uses AssignMessage,
which Google classifies as Extensible. The live trial reports the deployed proxy
as `EXTENSIBLE`; do not assume this bundle fits a Base environment entitlement.
See [AssignMessage policy](https://docs.cloud.google.com/apigee/docs/api-platform/reference/policies/assign-message-policy).

## Protocol and Security

The pinned [upstream protocol](../api/apigee/README.md) defines unary
`/apigee.ExternalCalloutService/ProcessMessage`. It is not Envoy ext-proc.
Setting `Request.headers` entries replaces values; empty entries remove headers.
Omitting an entry does not remove it. Response status is immutable, so Apigee
policies render denials. Multiple challenges use the HTTP-equivalent
comma-separated `WWW-Authenticate` form.

The request PreFlow captures original host, full URI, and scheme into
`txe.input.*` before target rewrites. The adapter requires these variables.
It returns `txe.decision`, `txe.status`, `txe.body`, and `txe.www_authenticate`.
Missing/unknown decisions, callout failures, and timeouts stop forwarding.
Bodies are excluded from the callout; request streaming preserves POST content.

| Setting | Meaning |
| --- | --- |
| `APIGEE_GRPC_PORT` | Dedicated TLS listener; unset disables it |
| `APIGEE_TLS_CERT_FILE`, `APIGEE_TLS_KEY_FILE` | Server certificate and key |
| `APIGEE_AUTH_AUDIENCE` | Exact audience in the gateway identity token |
| `APIGEE_AUTH_ALLOWED_SUBJECTS` | Numeric service-account unique IDs, comma-separated; not emails |
| `APIGEE_INSPECT_MESSAGES` | Bounded, redacted protobuf shape inspection |

This listener exposes only ExternalCallout. It verifies Google's signature,
issuer, expiry, audience, and allowed subject. The gateway token is in gRPC
metadata; the client bearer is inside MessageContext. Keep health, Envoy, and
metrics listeners private. Never disable certificate validation.

## Development Infrastructure

Run setup from this repository. Starter-pack provides generic Kubernetes
infrastructure; all new Apigee provisioning and integration stays here.

```sh
devspace run setup --gateway apigee --infrastructure provision \
  --apigee evaluation --daily-budget 25
```

Use the cluster's region. Both CLI credentials and Application Default
Credentials must be valid: `gcloud auth login --update-adc` refreshes both.
If Docker CIDR discovery fails before GKE setup, use starter-pack's documented
explicit `DOCKER_CIDR_PREFIX`. See [unified setup](gateway-setup.md) for
infrastructure modes, inputs, ownership, and recovery. Existing-infrastructure
mode preserves supplied ownership. The completed development-state transfer is
recorded in [validation evidence](apigee-validation.md).

Provisioning records and resumes its long-running operation. It refuses to
adopt an existing organization, repeat an ambiguous request, recreate an expired
trial, or fall back to paid provisioning. Before apply, check API/IAM access,
regional capacity/quotas, effective location/CMEK/network restrictions, trial
eligibility, and required Debug/PSC features. Ask Google about quota increases,
trial refusal, PSC gRPC/TLS behavior, debugging entitlements, and post-trial
migration when necessary.

The [trial lasts 60 days](https://docs.cloud.google.com/apigee/docs/api-platform/get-started/overview-eval),
is not for sensitive/production data, is not regularly patched, and cannot be
converted to paid. Export/redeploy into a new paid organization. GKE, addresses,
load balancers, PSC, storage, and transfer cost extra. `--daily-budget` records
approval, not an enforced billing cap. Preserve ignored ownership/state files.

## Tracer Bullet

Setup coordinates configuration, images, certificates, fixtures, PSC, targets,
proxy deployment, and probes. After setup succeeds:

```sh
devspace deploy
devspace dev
devspace run test-e2e
devspace run demo-dashboard -- -open
```

Project, region, registry, and context are resolved once. The demo generates
seven-day development certificates and imports their public certificates as
explicit Apigee trust anchors. Keys remain ignored/local and in Kubernetes
Secrets. Certificates are reused; expiry requires explicit rotation. No TLS
verification is bypassed. Setup issues final certificates after target IP
discovery. The demo adds both DNS and IP subject alternate
names. ExternalCallout's live gRPC TLS connection required the target IP in the
certificate even when TargetServer `commonName` was configured. Rotation restarts
only services whose certificate Secret data changed.

The demo reuses `mccutchen/go-httpbin:2.26.0`, the fake issuer, and policy
fixtures. It creates no Envoy processing route, preventing double exchange.
It can reuse only namespaces labeled as owned by this demo.

For new evaluations, setup configures HTTPS ingress using this repository's
`infra/apigee/ingress` module and records its address automatically. The load
balancer uses the Apigee northbound PSC NEG. Terraform state contains the TLS
private key and remains private under `.devspace/apigee-infra/`. The prerequisite
module grants the managed service agent token-creator access only on the dedicated
proxy account. Existing ingress and IAM remain owned by their original manager.
Smoke tests use `curl --resolve` without public DNS delegation.

```sh
devspace run preflight
devspace deploy
devspace run smoke
```

Deployment waits for an active runtime, uses content-addressed targets and
truststores, imports a deterministic proxy bundle, and waits for READY.
Unchanged bundles reuse deployment. Failures roll back to the previous revision.
Ownership records prevent overwriting existing proxies, targets, or truststores.

## Debug and Iterate

```sh
devspace run debug
# Wait at least 20 seconds for Debug activation, then:
devspace run smoke
devspace run diagnostics
devspace run debug --session SESSION_ID
devspace dev
# Stop DevSpace, then restore the normal service:
devspace run stop
devspace run smoke
devspace run test-e2e
```

Debug filters for `X-Txe-Debug: synthetic`. Gateway exports can contain full
synthetic tokens: private ignored files are not publication-safe artifacts.
Use synthetic data only. Service inspection is off by default; enable it with
`devspace run inspect-on` and restore normal
settings with `inspect-off`. It records bounded protobuf fields, header counts,
variable types, message ID, and revision, but no request locations or values.
The separate explicit token-debugging flag also works with Apigee. See
[logging controls and safety](logging.md). Remote development
syncs source and rebuilds/restarts without provisioning or redeploying Apigee.
Build the existing Dockerfile `dev` target first, as included by this config.
The dev pod uses one CPU, 4 GiB RAM, and 4 GiB ephemeral storage. GKE's default
1 GiB disk limit cannot hold this module's dependencies and build cache. Local
credentials, generated state, and Git metadata are excluded from source sync.
The first build takes several minutes. Subsequent source edits reuse caches.
The measured first one-CPU build took about ten minutes.
Run smoke tests only after startup. Failure tests temporarily change owned
fixtures and restore them in `finally` blocks; do not run them during DevSpace.
Debug session metadata records its proxy revision. Use `--revision REVISION`
when downloading an older session created before metadata recording was enabled.
For image iteration, run `devspace deploy`, followed by the same smoke test.
Source-derived tags avoid changing the image reference for unchanged sources.

### Existing Keycloak Scenarios

```sh
devspace run test-e2e
```

Setup reuses the existing Keycloak chart, realm, issuer Secret, and
eight token-exchange specs. Keycloak remains ClusterIP-only. The runner opens a
temporary localhost port forward and closes it when tests finish. API requests
still pass through Apigee and both private PSC connections. It uses the configured
CA through `E2E_CA_CERT_FILE`, never skipped TLS validation. It checks that at least
eight specs passed, so an unavailable fixture cannot silently count as success.
The core failure suite and Keycloak suite must run sequentially. The former
deliberately changes service availability and counts issuer requests.
The fixture needs about one CPU and 1.5 GiB requested memory in addition to the
core demo. Its first Java startup can take several minutes.

The shared e2e runner accepts `E2E_KEYCLOAK_DIRECT_ADDRESS` separately from
`E2E_DIRECT_ADDRESS`. Its default preserves the existing Gateway/Istio behavior;
the Apigee wrapper uses localhost only for issuer access. Normal plugin deployment
does not install Keycloak. Synthetic fixture cleanup removes its dedicated release.

## Private and External Infrastructure

New setup creates private callout/backend Services and ServiceAttachments without
public callout/backend exposure. Use one demo team and a separate NAT subnet per
attachment. The observed consumer is Apigee's **managed tenant project**, not the
visible development project. Discover it from the trial's tenant project or the
producer's `connectedEndpoints[].consumerNetwork`; do not allow all projects.

```sh
devspace run setup --gateway apigee --infrastructure existing \
  --apigee existing --inputs development-inputs.yaml
```

The PSC command waits for ACTIVE/ACCEPTED and persists private target addresses.
Audience and allowed identity stay unchanged. Public retirement requires smoke
evidence matching both current private targets. It changes primary Services to
ClusterIP and keeps the separate internal Services and attachments. Ordinary
demo redeployment preserves private routing and does not restore public exposure.

See [GKE publishing](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/internal-load-balancing-across-vpc-net)
and [Apigee PSC](https://docs.cloud.google.com/apigee/docs/api-platform/architecture/southbound-networking-patterns-endpoints).
For out-of-band infrastructure, start with `deploy/development-inputs.example.yaml`
or reference `deploy/apigee/config.example.json` from the input file. Setup can
generate owned synthetic fixture values, or use explicitly supplied values and
Secrets. Existing infrastructure mode never calls starter-pack setup. Set `rbac.create=false`
when the platform team supplies RBAC. Use a new dedicated `txe-` proxy.
Set `manage_targets=false` and each target's `name` to use platform-owned
TargetServers without modifying them. Set `base_path` for a dedicated proxy
route, and update policy paths and the test ingress URL to match it. Keep the
original client-facing host and URI in policy matching.

Cleanup uses explicit `undeploy-proxy`, `delete-proxy-resources`, and
`cleanup-fixtures` DevSpace commands with resource confirmation. Delete GKE ServiceAttachments before internal
Services/NAT subnets. Destroy ingress Terraform before the managed GKE project.
Never destroy externally supplied infrastructure. Keep the last deployed revision
and image digests in development evidence before cleanup.

## Offline Verification

Run these in the shared tooling container described in `DEVELOPMENT.md`:

```sh
go generate ./...
go test -coverprofile=coverage.out ./...
CGO_ENABLED=1 go test -race ./...
python3 -B -m unittest discover -s scripts -p apigee_test.py
helm lint charts/ext-authz-token-exchange charts/ext-authz-token-exchange-e2e charts/keycloak
helm unittest --strict charts/ext-authz-token-exchange charts/ext-authz-token-exchange-e2e charts/keycloak
sha256sum internal/apigeepb/*.pb.go > /tmp/proto.sha256
go generate ./...
sha256sum -c /tmp/proto.sha256
```

Chart suites assert specific resource fields and forbidden kinds, not combined
rendered strings. Python tests retain proxy-bundle and resource-ownership
behavior. Neither requires a cluster. The Apigee verification and generation
scripts have been replaced by these direct tool commands.

The host dashboard and Keycloak test launchers compile their host executables
with `txe-toolchain:local` (override using `TXE_TOOLCHAIN_IMAGE`), then run them on
the host so existing private port forwards and GCP authentication keep working.
Build the tooling image first; no host Go/protobuf installation is needed.

CI needs no GCP credentials and never provisions resources. Cloud tests require
explicit configuration and `--confirm PROJECT`. Local mocks and rendered manifests
do not establish live Apigee compatibility.
