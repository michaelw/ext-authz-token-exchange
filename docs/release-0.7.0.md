# 0.7.0 Release Notes Draft

## Readiness and Operations

- Shared challenge validation accepts at most 32 `WWW-Authenticate` field values
  and 8 KiB combined bytes. Invalid header bytes or exceeded limits fail closed
  with sanitized `500 server_error` (`TXE-3005`), even with OAuth passthrough.
  Valid values, schemes, quoting, and ordering are preserved.
- Trace context is selected once per adapter boundary. Apigee honors transport
  context first and payload-header context second; evaluation and outbound OAuth
  spans retain the selected parent. Export destinations remain operator-owned.
- Fresh Apigee development defaults to evaluation; existing paid organizations
  use explicit existing mode with supplied identities, trust, and private endpoints.
- Optional HPA/disruption protection, production examples, a two-way gateway
  migration guide, and certificate/monitoring runbooks are included. No production
  certificate authority, renewal controller, collector, or monitoring stack is installed.
- `devspace run renew-certificates` renews only owned synthetic development
  fixtures with staged trust and retained rollback material.

## Apigee Support

Managed Apigee ExternalCallout can use the shared token-exchange engine, with
authenticated TLS, private PSC connectivity, and developer-run demo workflows.
Apigee logging is new in this release and has no released format to migrate.

## Logging Migration and Compatibility

- **JSON logging is now the default.** Existing text-log consumers must set
  `TOKEN_EXCHANGE_LOG_FORMAT=text` to retain the released RPC summary layout.
  Existing token-debugging and health-check controls retain their defaults.
- Decision diagnostics now cover successful evaluation, missing/malformed bearer,
  unhealthy policy, and exchange failures, as well as existing policy denials.
  Log volume can increase because these decisions were not all logged before.
- Structured events use the same schema across all three adapters. The developer
  `log-format` command switches formats without changing infrastructure.
- Safety change: request locations are redacted, including path segments. Raw
  error strings are replaced with safe operation/failure diagnostics. Update
  collectors and alerts that depend on those values. Unknown HTTP methods use
  `OTHER`; Apigee inspection aggregates unrecognized names.
- The existing explicit token-debugging flag remains supported and now also
  works for Apigee. It is disabled by default and never logs callout credentials.
  The demo profile no longer enables it automatically; enable it explicitly for
  temporary synthetic-token debugging.

See [Logging](logging.md) for controls, examples, schema, and migration details.
Authorization behavior, policy schemas, and gateway wire protocols are unchanged.

## Build and Chart Testing

Protobuf bindings are no longer checked in. Run `go generate ./...` before Go
checks; Docker/DevSpace workflows do this automatically with pinned tools.
Development, CI, and production compilation share the Dockerfile toolchain.
Chart checks use Helm 4.1.1 with helm-unittest 1.2.1 and focused YAML assertions.
Apigee deployments remain developer-only; CI has no GCP deployment credentials.

## Development Setup

Root `devspace run setup` selects the gateway and whether infrastructure is
supplied or provisioned. Daily development, deployment, tests, and dashboard
commands reuse that saved selection and never provision infrastructure.
The former tool-installation command is now `devspace run setup-tools`.
Apigee provisioning and integration live in this repository; starter-pack
continues to provide generic cluster infrastructure. Existing Terraform state
and supplied infrastructure keep their current owners.
See [Gateway Setup](gateway-setup.md) for inputs, recovery, and cleanup scopes.

## Re
ease Checklist

Target **0.7.0**, not a 0.6.x patch. Keep implementation and release metadata in
separate commits. Use `feat` for the additions and a `BREAKING CHANGE` footer for
the documented location/raw-error safety exceptions. Use a `Release-As: 0.7.0`
footer on the release preparation commit if needed. Review the actual Release
Please PR and ensure its manifest, chart version/appVersion, image tags, and
release title all agree before merging. Include the migration section above in
the generated changelog and GitHub release message. No release is published by
the development or test workflows.
