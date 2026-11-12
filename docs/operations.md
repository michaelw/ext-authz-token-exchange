# Operate the Plugin With Existing Infrastructure

The same policy engine serves Apigee, ext-authz, and ext-proc. Operators retain
control of Kubernetes, certificate issuance, Secret delivery, monitoring, and
trace export. The integration does not install production controllers or modify
shared organization policies. [Gateway migration](gateway-migration.md) covers
traffic cutover in either direction.

## Existing Managed Apigee

Use `--apigee existing` for a supplied paid or evaluation organization. Fresh
development setup defaults to evaluation; it never falls back to paid provision.
Saved selections remain in force unless explicitly changed. Evaluation expires
after 60 days and cannot be converted in place: export/redeploy configuration to
an existing paid organization. See [Google's evaluation restrictions](https://docs.cloud.google.com/apigee/docs/api-platform/get-started/overview-eval).

Prerequisites:

- An active organization, attached environment/runtime, and client ingress.
- A dedicated `txe-` proxy and deployment service account. Configure its immutable
  numeric subject and the exact callout ID-token audience. Apigee's service agent
  must be able to mint ID tokens for that account. The deploying identity needs
  `iam.serviceAccounts.actAs`, proxy import/revision, and environment deployment
  permissions. Target/trust/reference write permissions are needed only when
  those resources are explicitly integration-owned.
- Private callout and backend endpoints reachable by Apigee. Supplied PSC
  consumers, producer attachments, networks, and subnets keep their original
  owners. `private_active: true` records this prerequisite; it is not proof of
  connectivity. The acceptance probe checks the actual ingress path.
- Operator-managed plugin TLS Secret, issuer credential Secrets, policy
  ConfigMaps, and issuer profile values. Supply trust PEM files, not private keys
  in configuration. Use the production examples under `deploy/apigee/`.
- An unauthenticated, synthetic `acceptance_probe` path and expected status.
  A protected canary path returning 401 is suitable. Its matching policy must
  invoke the plugin. A generic load-balancer health page is insufficient.

Setup checks readiness, deployment permissions, proxy identity and certificate
expiry. API writes still enforce their own permissions; preflight is not an IAM
grant. `manage_targets: false` leaves TargetServers/trust/references to the
operator; supply the target names expected by the dedicated proxy configuration.
No synthetic namespace, issuer, Keycloak, or backend is deployed when
`synthetic_demo: false`. Test full authorization with operator-approved fixtures.

## Capacity and Safe Updates

Autoscaling is opt-in. The chart uses its existing common Helm library, not a
second controller. See `deploy/apigee/production-values.example.yaml` for:

- two to ten replicas, 65% CPU utilization, and 300-second scale-down stabilization;
- explicit CPU requests, `maxUnavailable: 0`, `maxSurge: 1`, readiness delay,
  termination grace, and connection-drain time;
- optional disruption protection and hostname topology spreading.

These are starting values, not capacity guarantees. Tune from load tests, issuer
quotas, latency objectives, and the budget. CPU HPA requires the metrics API and
CPU requests; custom concurrency/rate metrics need an operator-provided adapter.
HPA-enabled manifests omit `spec.replicas`, so Helm does not reset live scale.
Keep at least two ready replicas for production availability. Development may
retain one replica and no HPA. A disruption budget cannot create spare capacity
or guarantee availability during failures.

Long-lived gRPC connections can pin traffic to a subset of pods. Watch per-pod
request rates and in-flight work; verify load distribution before relying on HPA.
Coordinate draining with gateway/LB connection timeouts and ext-proc stream
lifetimes. Scaling the plugin does not fix a slow or rate-limited token endpoint.

## TLS Inventory and Requirements

| Connection | Serving material | Trust owner |
| --- | --- | --- |
| Client to ingress | Operator LB certificate/key or managed certificate | Client trust store |
| Apigee to callout | Kubernetes TLS Secret, mounted read-only | Apigee TargetServer trust/reference |
| Apigee to backend | Backend certificate/key, outside plugin ownership in production | Apigee backend trust/reference |
| Plugin to token endpoint | Authorization server certificate | Plugin/container trust configuration |

Use matching PEM certificate/private-key pairs, a complete serving chain, and a
SAN matching the configured SNI/verification name. Include IP SANs when the
selected connection verifies an IP. The Google ID-token audience is separate
from TLS server-name verification. Keep both exact. Never use
`ignoreValidationErrors`, curl `-k`, or insecure verification to bridge rotation.

Store keys in the operator's Secret system; restrict key/state/backup access.
Do not use Secret `subPath` mounts when expecting file updates. This process
loads TLS certificates at startup: updating files or renewing a Secret alone
does not reload its serving certificate. Restart through a controlled rolling
deployment, with enough ready replicas and connection draining.

## Production Renewal Runbook

For leaf renewal under the same trusted CA:

1. Check expiry and identity of the certificates actually served, not just files.
2. Issue a new key/certificate through the existing PKI. Validate the pair, chain,
   SANs, usages, validity dates, and clock synchronization before deployment.
3. Deliver the TLS Secret through the existing system. Use a Secret-triggered
   rolling controller if already installed, or explicitly roll the Deployment.
4. Wait for readiness and verify fresh handshakes through Apigee plus continuous
   requests. Confirm the served fingerprint changed and error/latency rates did
   not regress. Retain the old material until rollback is no longer needed.

For CA replacement, publish old+new trust to all clients first. Confirm that
trust is active, replace serving certificates second, probe every path third,
and remove old trust only after the rollback/connection-drain window. Update
Apigee trust references without adopting shared stores. The helper uses owned,
content-addressed stores and references; old stores remain until explicit cleanup.
Import independent trust anchors as separate aliases, not as one leaf chain.
See [Apigee references](https://docs.cloud.google.com/apigee/docs/api-platform/system-administration/working-references).

Optional cert-manager installations can use `renewBefore` and
`privateKey.rotationPolicy: Always` with an operator-selected Issuer. An existing
reloader can trigger rolling updates from Secret changes; otherwise automate the
rollout in the operator's delivery process. Neither component is installed by
this chart. CA rotation remains a separate trust-distribution operation.
Google-managed ingress renewal requires a compatible load balancer and valid
DNS; a local `.kube` hostname cannot use public certificate issuance.

Zero downtime is a tested outcome, not a certificate property. It requires
overlapping trust, adequate healthy capacity, readiness, connection draining,
and successful tests of both existing connections and new handshakes. A
single-replica development environment has no production availability guarantee.

## Owned Development Renewal

```sh
devspace run renew-certificates --check
devspace run renew-certificates
```

The command resolves saved context/project and verifies namespace/release and
certificate ownership. It checks live certificates, stages short-lived leaves
under a protected local development CA, adds overlap trust, rolls changed
services, updates the owned ingress, probes, and retires old trust. It retains
protected old material and a resumable journal under ignored `.devspace/`.
Client-ingress propagation can take up to 30 minutes. The command keeps overlap
trust while it waits for the new served fingerprint. See
[Google's self-managed certificate guidance](https://docs.cloud.google.com/load-balancing/docs/ssl-certificates/self-managed-certs).
On failure it restores overlap trust before old serving files and configuration.
Inspect any failed restoration before further updates. It never renews supplied
production certificates. Run separately from deployment or development processes.

Schedule renewal/checks through the developer's own task runner if desired; no
background cloud job is installed. Renew well before expiry. A development CA
with less than 14 days remaining requires an explicit new-CA operation rather
than silently changing its trust root.

## Trace Continuity

Use W3C `traceparent` and `tracestate`. The Apigee adapter prefers a valid
transport parent, then the request-header parent carried inside MessageContext.
It starts a new RPC server span, retains that parent through evaluation, and
injects the token-endpoint HTTP client span context. Backend headers remain
unchanged by token exchange. Each span has a distinct ID within the same trace.
Missing/invalid context starts a new trace; an unsampled parent stays unsampled.

Enable the plugin's existing OTLP export and collector destination as needed.
No collector is installed. Native Apigee distributed tracing is a separate,
operator-managed environment setting; its collector export uses OTLP/HTTP,
whereas this plugin uses OTLP/gRPC. Debug captures are not distributed tracing.
See [Apigee tracing](https://docs.cloud.google.com/apigee/docs/api-platform/develop/enabling-distributed-trace).

Apigee may carry only the original client trace context through ExternalCallout.
Do not claim a plugin span is a child of an Apigee policy span unless the supplied
parent proves it. Use the common trace ID and gateway message ID for correlation
when only the original parent is available. A backend/issuer must be instrumented
to emit its own spans; forwarding headers cannot create those spans for it.
Do not capture Authorization, token forms, cookies, or client secrets in spans.
Review collector redaction/sampling policy before production use.

For owned development, `devspace run test-tracing` checks a synthetic request's
trace ID on the plugin and backend legs without changing any exporter. Its report
states the distinction between header continuity, recorded local span parentage,
and actual Apigee-native span export. Do not treat the first as proof of the latter.

## Monitoring and Recovery

Alert on served certificate expiry and renewal failures; wrong certificate/SAN;
TLS handshake errors; unhealthy or unaccepted PSC connections; insufficient ready
replicas; HPA metric failures or sustained maximum scale; rollout failures;
callout timeouts/unavailability; token-endpoint latency/rejections; and policy
health. Set expiry thresholds relative to certificate lifetime (for example,
three days warning and one day critical for seven-day development leaves).

Correlate safe decision codes, gateway IDs, proxy revisions, and traces. Keep
JSON enabled and inspection/token logging off. Check per-pod traffic when one
pod is saturated. Check issuer health before increasing capacity. Roll back a
proxy through `devspace run rollback-proxy -- --revision REVISION`; restore
certificate trust in overlap order. Do not purge shared infrastructure to recover
an application. Preserve sanitized evidence and protected ownership journals.
