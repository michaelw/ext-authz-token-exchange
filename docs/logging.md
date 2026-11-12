# Plugin Logging

## Defaults and Controls

| Control | Default | Behavior |
| --- | --- | --- |
| `TOKEN_EXCHANGE_LOG_FORMAT` | `json` | `json` or `text`; unsupported values fail startup |
| `GRPC_LOG_HEALTH_CHECKS` | `true` | Existing health-check request logging control |
| `TOKEN_EXCHANGE_INSECURE_LOG_TOKENS` | `false` | Explicit subject/exchanged token diagnostics for all three adapters |
| `APIGEE_INSPECT_MESSAGES` / `apigee.inspectMessages` | `false` | Apigee protobuf shape inspection; does not enable token logging |

JSON is the new 0.7.0 default. Set the format to `text` to retain the released
Envoy layout. Existing token and health-check controls/defaults remain unchanged.
There is no new severity
filter or sampling control. JSON severity describes the cause, not just the HTTP
status. INFO includes ordinary denial and recognized OAuth rejection; WARN covers
malformed protocol input and rejected callout identity; ERROR covers unhealthy
policies, exchange infrastructure failures, and unexpected failures. Inspection
records use DEBUG severity but require only the existing explicit inspection flag.

Select legacy text output through the chart's existing environment map:

```yaml
env:
  TOKEN_EXCHANGE_LOG_FORMAT: "text"
```

## Decision Events

Each evaluation produces one decision record. Explicit text mode preserves the Envoy
`[gRPC]` prefix and RPC summary layout. Existing explicit/unmatched DENY records
are extended with diagnostics, not duplicated. Other denial cases and successful
evaluations now also produce decision records:

```text
[gRPC] 2026/01/01 12:00:00 DENY reason=explicit_policy method=GET host=[redacted] path=[redacted] policy=demo/policy adapter=ext_authz decision=deny result_class=auth_denied evaluation_id=eval-1 duration_ms=0.100 http_status=403
```

JSON uses the same schema across Apigee, ext-authz, and ext-proc:

```json
{"timestamp":"2026-01-01T12:00:00Z","severity":"INFO","event":"request_decision","adapter":"apigee","evaluation_id":"eval-1","decision":"deny","reason":"deny_exchange_error","result_class":"auth_denied","duration_ms":42.1,"http_status":400,"diagnostic_code":"TXE-2001","oauth_error":"invalid_request","upstream_http_status":400,"failure_class":"oauth_rejection"}
```

`reason` and `result_class` reuse the existing decision/metric constants.
`diagnostic_code` carries the existing stable TXE code directly from the exchange
result. It is not extracted from an error description. Failure classes distinguish
configuration, timeout, connection, TLS, cancellation, invalid response, OAuth
rejection, and non-OAuth upstream HTTP failure. Upstream status is recorded when
a response was received, including invalid HTTP 200 token responses.

Allowed decisions omit `http_status`: the eventual backend response is unknown.
Unavailable fields are omitted. `policy` identifies the configured policy source
when known. Trace/span IDs are included when a valid context is present. Apigee
also supplies bounded `gateway_id`, `gateway_id_source=apigee_message_context`,
and `proxy_revision` when available. These values are correlation data, not client
identities. Evaluation IDs are process-local; combine them with pod/process data.

`rpc_complete` records transport completion separately, with symbolic
`grpc_status`. A transport OK does not mean authorization allowed. Ext-proc
decisions appear at evaluation time; RPC duration measures the entire stream.
Malformed ext-authz requests produce `protocol_error` without an evaluation.
Apigee authentication rejection and malformed input appear in transport events.
Runtime/startup messages are separate `runtime`, `logging_settings`, and
`insecure_logging_enabled` events. JSON lines do not have text prefixes.

## Safety Exceptions to Text Compatibility

Two intentional changes apply in both JSON and explicit text modes:

- Client request locations are redacted, including host, path, query, fragment,
  and scheme. Existing text field names and URI separators remain. A path segment
  can contain a credential or personal data; dropping only its query is unsafe.
- Raw errors are not printed. RPC summaries retain their status/layout and use a
  fixed failure class for untyped failures. Lifecycle failures identify their
  failing operation instead of printing error strings that may contain locations
  or credentials. Decision events provide typed exchange diagnostics.

Collectors parsing request locations or raw errors must migrate to policy,
reason, diagnostic code, failure class, and correlation fields. Existing RPC
success summaries and immediate-peer text reporting remain. The peer is not the
original client; JSON does not include it. Unknown HTTP methods use `OTHER` to
avoid recording arbitrary input. Inspection aggregates unknown header and
variable names as `[other]`; it never records their values.
Insecure header-name diagnostics use the same bounded header-name allow-list.

## Temporary Debugging

Token logging is disabled in chart defaults and normal demo deployments. Setting
`TOKEN_EXCHANGE_INSECURE_LOG_TOKENS=true` explicitly enables token diagnostics for
Apigee, ext-authz, and ext-proc. It emits a startup warning. JSON uses a dedicated
`insecure_token_debug` event; ordinary decisions never contain tokens. Existing
bounded token output is preserved, so a long token may be truncated.

This option exposes the subject and exchanged tokens. Use synthetic credentials
only, restrict log access, and restore it to `false` afterward. It never authorizes
logging the Apigee callout ID token, cookies, client secrets, arbitrary header
values, payloads, locations, or upstream error bodies. OAuth error passthrough
changes client responses only; it does not enable raw-error logging.

For temporary Apigee shape inspection, select the configured Kubernetes context:

```sh
python3 scripts/apigee.py inspect-on --confirm PROJECT
python3 scripts/apigee.py smoke --confirm PROJECT
python3 scripts/apigee.py diagnostics --confirm PROJECT
python3 scripts/apigee.py inspect-off --confirm PROJECT
```

Switch formats for development/testing without changing infrastructure:

```sh
python3 scripts/apigee.py log-format --format text --confirm PROJECT
python3 scripts/apigee.py log-format --format json --confirm PROJECT
```

The command changes only `TOKEN_EXCHANGE_LOG_FORMAT` on the owned deployment and
waits for rollout. It does not change inspection or token-debugging controls.
Through DevSpace (select `text` or `json`):

```sh
DEVSPACE_CONFIG=devspace-apigee.yaml devspace \
  --var APIGEE_PROJECT=PROJECT run log-format --format text
```

Persistent deployments should set `env.TOKEN_EXCHANGE_LOG_FORMAT` in their local
Helm values.

The commands only update the dedicated plugin deployment and wait for rollout.
They do not provision resources. `inspect-on` leaves the token control unchanged;
`inspect-off` disables both inspection and token logging. They are temporary
deployment overrides, not edits to Helm values. Keep normal values disabled so a
later deployment does not re-enable debugging. Equivalent DevSpace commands are
available in `devspace-apigee.yaml`. Gateway Debug exports can contain full tokens
and remain a separate, sensitive debugging tool.

For repeatable developer-only QA, run
`python3 scripts/apigee_logging_test.py --confirm PROJECT`. It checks ownership
and context, temporarily selects JSON with inspection and token logging off,
runs the smoke suite plus secret canaries, validates events, and restores the
original environment in `finally`. Its sanitized report is written under ignored
`.devspace/`. Run it separately from other deployment/development workflows.
