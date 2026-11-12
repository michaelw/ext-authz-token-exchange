# Apigee Validation Record

## Scope

Developer-run validation completed on 2026-11-05 using a self-service managed
Apigee evaluation and the starter-pack GKE Autopilot cluster. No Support ticket
or paid Apigee provisioning was needed. All traffic and credentials were synthetic.
The source bases were plugin `1534809` and starter-pack `b98d99b`.

The final path is client HTTPS -> managed Apigee -> authenticated TLS
ExternalCallout over PSC -> private HTTPS httpbin over a second PSC connection.
Both endpoint attachments report ACTIVE/ACCEPTED. The public callout and httpbin
load balancers were removed. The only external forwarding rule is client ingress.

## Live Results

| Check | Result |
| --- | --- |
| Missing bearer | 401 with `WWW-Authenticate` |
| Successful exchange | 200; replacement bearer reached httpbin |
| Request preservation | POST JSON, query, method, and unrelated header preserved |
| Explicit deny | 403 |
| Unmatched route | 204 |
| Malformed / duplicate bearer | 401 / 401 |
| OAuth `invalid_grant` | 400, matching the existing engine |
| True unauthenticated CORS preflight | 200 |
| OPTIONS without preflight headers | 401 |
| Invalid callout identity | Unauthenticated on the live dedicated TLS listener |
| One exchange per matched request | Exactly one fake-token-endpoint request observed |
| Unknown issuer in a matched policy | 500; policy restored without restarting the service |
| Apigee callout timeout | Measured one-second failure; generic safe 500 response |
| Callout service unavailable | Generic safe 500; forwarding stopped; service restored |
| Debug | Real gateway transactions downloaded and correlated with service message IDs |
| Development update | Source synced, rebuilt, and new startup log observed without a proxy deployment |
| Repeated deployment | Two deploy/test cycles; Service and attachment UIDs unchanged |
| Supplied infrastructure mode | Separate `/oob` proxy passed the same nine smoke scenarios |
| Scoped cleanup | Temporary OOB proxy and its three policies removed; supplied targets and main deployment remained |
| Existing Keycloak specs | Eight passed through private Apigee, with TLS and signed JWT verification |

The timeout test temporarily extends the owned fixture's issuer timeouts to
five seconds. Normal defaults reject a slow issuer after 500 ms, before Apigee's
one-second limit. The test restores both the original environment and issuer
configuration. The outage test also restores the original replica count.

Final main proxy revision: `6`. Repeated deploys reused this revision.
Proxy bundle SHA-256:
`bb38fe818bd1adf529d3acd46105dbd97cd96eb6157a7be43a7371605eea91c9`.
Initial tracer-bullet production image digest:
`sha256:33c5aa54f532d624b062eba42cf8135ca68b74966d705aa2adcf223e12478c37`.

Twenty-seven synthetic Debug transactions were saved locally. Raw gateway
captures remain private and ignored. The service inspection logs include field
presence, header value counts, variable types, message ID, proxy revision, and
shape metadata. They do not contain token values or request bodies. The logging
milestone below removes all original request locations from inspection.
Mutation diagnostics identify changed header names and challenge counts, not values.
Detailed environment-specific evidence is in ignored `.devspace/apigee-*` files.

## Offline Results

- `go test ./...` and `go build ./cmd/...` passed.
- Race checks for server and configuration packages passed.
- Fourteen developer-tool tests and plugin, demo, and private Keycloak chart render checks passed.
- Existing GKE deployment-model and Istio ext-proc render checks passed.
- Pinned protobuf bindings regenerated successfully.
- Both mocked Terraform plans, Terraform validation, and provisioning safety
  tests passed. Infrastructure CI does not use GCP credentials or create resources.
- Ingress Terraform reported no changes after applying the identity binding.

## Limits

- This is evaluation-runtime proof, not production capacity or availability proof.
- The OOB test used the existing physical GKE cluster and Apigee organization as
  supplied infrastructure. It did not test a second independently provisioned cluster.
- Complete infrastructure destruction was not exercised. The environment remains
  available for development and incurs surrounding infrastructure charges.
- ExternalCallout is Standard, but this bundle's AssignMessage policies make the
  observed deployment EXTENSIBLE. Confirm the intended production entitlement.
- Certificates are seven-day development certificates. Rotate them explicitly;
  use platform-managed certificates and trust configuration for production.
- The first one-CPU development build took about ten minutes. A later source edit
  rebuilt using the same pod's caches. Disk, memory, and compiler parallelism are
  explicit in the development profile to avoid default GKE resource limits.

See [the runbook](apigee.md) for commands, ownership boundaries, and teardown order.

## Logging Milestone

Validated on 2026-11-05 with the same private PSC path and unchanged proxy revision
`6`. Development image `apigee-logging-v3` was deployed with inspection off,
token logging off, and default text output. Its tested image digest is:
`sha256:4ec1a3e8a99273664dd4bca8c9775ec8c928a82c184b01f3764852079fbe9e97`.

- Nine smoke scenarios passed with text output.
- The repeatable logging workflow passed twice across development images. The
  final run parsed 53 JSON records, including 10 unique evaluation decisions.
  Subject-token, cookie, body, path, and query canaries were absent, including
  while shape inspection was enabled. Original logging settings were restored.
- Eight Keycloak scenarios passed on the stable logging deployment. One earlier
  run overlapped the logging workflow's rollout and received a gateway 500;
  rerunning after the rollout passed. Do not overlap tests with deployment changes.
- Five failure checks passed: denial challenge, exactly one exchange,
  unhealthy-policy fail-closed, sanitized callout timeout, and sanitized callout
  unavailability. These checks restored the synthetic fixtures.
- Full Go tests, `go vet ./...`, and race tests for server, exchange, configuration,
  and logging passed. Credential-free tests cover adapter decision parity,
  explicit token debugging in both formats for every adapter, authentication
  rejection, stream failure, safe inspection, output bounds, typed diagnostics,
  legacy text summaries/defaults, and workflow restoration after failure.

Raw environment-specific evidence stays in ignored `.devspace/` reports. No
cloud infrastructure or proxy revision was created for the logging milestone.
Live Envoy gateway suites were not rerun; their adapters were covered by the
credential-free tests. Release publication and the actual Release Please PR
review remain release-time steps, targeting 0.7.0.

## JSON Default and Toolchain Milestone

Validated on 2026-11-05. The live plugin runs `apigee-json-v1`, image digest
`sha256:df4a948860ffb2c96b69f3b98dc77189150d0ddeec536b359e15615a0a7ad334`.
Its final settings are JSON output, inspection off, token logging off, and one
available replica. The proxy and private PSC infrastructure were not reprovisioned.

- All nine smoke scenarios passed after explicitly switching to text. The new
  command then restored JSON and waited for rollout.
- The repeatable JSON/privacy workflow parsed 53 valid records with 10 unique
  decisions, found no secret canaries, and restored JSON-safe settings.
- All eight Keycloak cases passed using a host test executable compiled in the
  shared toolchain container, without host Go/protobuf tools.
- All five failure checks passed and restored the owned synthetic fixtures.
- The full Go coverage and race suites passed inside the shared container, as
  did vet, workflow syntax checks, scoped pre-commit hooks, 16 Python tooling
  tests, and three dashboard token-refresh tests.
- Helm 4.1.1 and helm-unittest 1.2.1 passed 21 focused tests in six suites across
  three charts, with no snapshots. Tests also passed as a non-root CI user.
  Deliberately incorrect PSC acceptance and TLS certificate fields in disposable
  copies failed their specific assertions. Existing GKE/Istio checks also passed.
- Generated bindings were absent from the Docker context. Production and fixture
  image builds generated them successfully; repeated generation produced matching
  SHA-256 values. The generated files are ignored, not tracked.
- The minimal runtime image emitted JSON by default and text with an explicit
  format setting. The smoke tooling image's Docker connection and pinned tools
  passed checks; its runner compiled and rejected an invalid mode before creating
  any cluster.

Branch protection was inspected. Existing `Go tests` and `Go build` status names
are preserved without duplicate test execution or a standalone Go build job.
No branch-protection settings were changed. Real GitHub cache transfer,
superseded-run cancellation, and the complete kind smoke matrix still require a
PR workflow run; local checks do not establish those outcomes. No PR or release
was published during this validation.

## Unified Development Workflow Milestone

Validated on 2026-11-05 against the existing application and private PSC path.
No second environment was provisioned, no Terraform state was moved, and no
starter-pack files were changed for this milestone.

- Root setup completed using existing Kubernetes and Apigee infrastructure.
  Two unchanged deploy/test cycles preserved Service, ServiceAttachment,
  Deployment, and Pod identities, image IDs, and proxy revision `6`.
- The shared gateway contract passed all eight cases. All eight Keycloak cases,
  nine smoke cases, and five Apigee failure checks passed sequentially. The
  failure checks restored the original fixtures and replica count.
- DevSpace source synchronization rebuilt a temporary diagnostic change in
  seven seconds. Removing it triggered another rebuild in six seconds. The
  smoke suite passed after each change without a gateway revision update.
  The normal plugin image was restored afterward.
- A deliberate interruption after proxy import was recovered by comparing
  the recorded inventory and exported bundle. Revision `7` was tested, then
  rolled back to known-good revision `6`; both passed the smoke suite.
- Final privacy validation parsed 58 JSON events with 11 unique decisions.
  Sensitive canaries were absent. JSON remained enabled; inspection and token
  logging were disabled after restoration.
- The root dashboard launcher served all 16 canonical scenarios and passed its
  readiness check. It uses the shared private Keycloak access helper.
- All 39 Python tests and 23 focused Helm assertions passed without cloud
  credentials. Provider-resolution tests exercised real DevSpace profiles.
  Full Go tests, vet, Helm lint, and existing GKE/Istio render checks passed.
  Both Terraform modules validated in a fresh Linux tooling container without
  GCP credentials, using committed provider checksums.

Restored plugin image digest:
`sha256:66f517b72b6b15e33995ee6e72493bae21bbdb1c71a21a757a3bbef441a4687f`.
Development iteration image digest:
`sha256:9ca3c87e3f6a88f7cd9d16722cec5c40096493d1e44a05e62e1435f5863966a0`.
Detailed identities, timings, and sanitized results remain in ignored
`.devspace/gateway-*.json` and `.devspace/apigee-*.json` files.

These results establish repeatable updates of the current application, not a
fresh application or fresh cloud deployment. Clean-checkout cloud reconstruction,
fresh provisioning, live Istio/GKE Gateway regressions, and actual GitHub PR
execution remain separate unverified gates. No changes were committed or pushed,
and no release was published.

## Complete Ownership and Reconstruction Milestone

Validated on 2026-11-06. This milestone supersedes the earlier fresh-provisioning
limitations above. The old environment was removed before the new one was
created. Environment-specific identities and protected backups remain ignored.

### Old Environment Cleanup

- Transferred 16 managed Apigee Terraform resources into this repository without
  replacing them. Refreshed plans for generic infrastructure, Apigee
  prerequisites, and ingress each reported no changes. Nine live smoke cases
  passed before teardown.
- Removed the superseded Apigee implementation from starter-pack. Its generic
  infrastructure implementation and state location were preserved. Both the
  original checkout and the new pinned checkout are clean.
- Removed owned proxy configuration, consumer endpoint attachments, Helm
  applications, producer networking, ingress, evaluation organization, and
  prerequisites in dependency order. Component absence was checked while the
  project was still queryable. Only then did starter-pack destroy its 38 generic
  resources and request project deletion.
- Confirmed empty managed-resource states and project `DELETE_REQUESTED`.
  This confirms shutdown, not completion of Google's project-retention period.
  Protected state/configuration backups and the completed teardown journal are
  retained locally. The one-time migration implementation, command, tests, and
  legacy Terraform options were removed after acceptance.

### Fresh Reconstruction

- Root `devspace run setup --gateway apigee --infrastructure provision
  --apigee evaluation --daily-budget 25` created the replacement from a clean
  pinned starter-pack checkout. Root deployment and tests required no manual
  Terraform, certificate rotation, project copying, or preparation commands.
- Starter-pack owns 38 generic resources and no Apigee entries. This repository
  owns eight prerequisite and seven ingress resources. Helm and Kubernetes
  controllers own the application and producer networking. Evaluation and
  proxy lifecycle operations remain in the documented Python helpers.
- Self-service evaluation provisioning succeeded without a Support ticket or
  paid fallback. Final plans for all three Terraform states reported no changes.
- Confirmed one public client ingress and two internal producer load balancers.
  Both PSC connections were active and accepted. Missing and invalid gateway
  credentials were rejected over verified TLS with gRPC status 16.
- Eight shared gateway cases, eight Keycloak cases, nine smoke cases, and five
  failure cases passed. Checks included body preservation, request identity,
  denial headers, one exchange per request, and restored failure fixtures.
- Privacy checks parsed 63 JSON events and 12 unique decisions. Sensitive
  canaries were absent. JSON remains enabled; inspection and token logging are
  disabled.
- An interrupted proxy import recovered revision 2 without duplication. Its
  smoke suite passed, followed by rollback to revision 1 and another passing
  suite. Two Debug sessions captured 24 transactions; all nine transactions in
  the final session correlated with service gateway IDs. Cloud Logging was not
  enabled for this check.
- DevSpace observed a temporary source change in 8.72 seconds and its removal
  in 7.55 seconds. Nine smoke cases passed after each change. The normal
  deployment was restored, with no gateway revision change.
- Two final unchanged deploy/test cycles preserved Kubernetes identities,
  running image IDs, PSC attachment identities, and proxy revision 1.
- The root dashboard command passed its health check and served the canonical
  scenario set using private Keycloak access.

Normal running plugin digest:
`sha256:15ae01836dba1fbec6500c38620226b5860458fc303d1e429aa69a3a3797c518`.
Development iteration image digest:
`sha256:2a4f3f29ad06c84834eda5d913d2ebdbc7b7f4b0bfefbb2838772b7255c86bef`.
Detailed results remain in ignored `.devspace/gateway-*.json`,
`.devspace/apigee-*.json`, and the archived old environment journal.

Offline verification passed 55 Python tests, Go tests and vet, 23 focused Helm
assertions, Helm lint, existing GKE/Istio rendering checks, Terraform validation,
and mocked prerequisite planning. These checks require no GCP credentials.
Actual GitHub PR execution, bare-machine reconstruction, and live native
Istio/GKE Gateway regression runs remain separate gates. No changes were
committed or pushed, and no release was published.

## Readiness Milestone

Validated on 2026-11-12 against the existing private PSC environment. This
milestone did not provision another project or paid Apigee organization.

- Eight shared gateway cases, eight Keycloak cases, nine smoke cases, and five
  failure cases passed with the updated plugin. Missing and invalid gateway
  credentials were rejected over verified TLS. Failure tests restored fixtures.
- Privacy checks parsed 63 JSON events and 12 decisions. Sensitive canaries were
  absent. JSON stayed enabled; inspection and token logging were disabled.
- The live trace probe found one correlated plugin decision and the same trace
  ID at the private backend. It did not change export settings. Recorded-span
  tests verify transport-parent priority, payload fallback, sampling, and local
  RPC/evaluation/token-endpoint parentage. Native Apigee span export and policy
  span parentage were not established by this environment.
- Live ingress, callout, and backend certificates were renewed. Fresh verified
  handshakes confirmed replacement fingerprints and expiry on November 19 at
  18:07 UTC. The final proxy revision was 6. Protected rollback material remains
  local and ignored.
- Two earlier renewal attempts failed and rolled back. They exposed trust-anchor
  import and ingress-propagation issues. Independent anchors now use separate
  aliases. Renewal waits for the served fingerprint before retiring overlap
  trust. During the final attempt's monitored window, 517 of 518 fresh-connection
  requests succeeded; one connection failed. This is not zero-downtime proof.
  The single-replica environment has no production availability guarantee.
- Local checks passed 71 Python tests, 27 focused Helm assertions, lint, Go
  coverage/race/vet, and container builds. Challenge fuzzing completed 32,680
  executions. Tests cover accepted challenge values and fail-closed behavior
  across all adapters, including boundary sizes and quoted commas.

Validated plugin image digest:
`sha256:b7c5ba0eb5e2e2d95973887b82afc3d8d98e4d735f54a459146f9e7c4e0050c3`.
Later provenance-only rebuilds can have a different image-index digest.

[PR 318](https://github.com/michaelw/ext-authz-token-exchange/pull/318) contains
current CI results and subsequent deployment evidence. CI runs kind smoke tests,
not GCP provisioning or live Apigee tests. Existing paid-organization integration,
production scaling, issuer-specific renewal, and native tracing export require
operator acceptance in the target environment. No release was published.
