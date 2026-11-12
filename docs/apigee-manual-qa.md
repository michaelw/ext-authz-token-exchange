# Manual QA Through Apigee

The dashboard runs on your workstation. It sends real HTTPS requests through
managed Apigee. Neither the callout service nor httpbin has public exposure.
Use synthetic data only. This evaluation environment is not production-hardened.

## Start the Dashboard

Run from the plugin repository root. Prerequisites are Python 3, kubectl, yq,
and authenticated access to the configured GKE cluster. The default launch also
needs Go on PATH. It does not provision or modify cloud infrastructure.

```sh
PROJECT=$(python3 -c 'import json; print(json.load(open(".devspace/apigee.json"))["project"])')
CONTEXT=$(python3 -c 'import json; print(json.load(open(".devspace/apigee.json"))["context"])')
kubectl config use-context "$CONTEXT"
python3 scripts/apigee_dashboard.py --confirm "$PROJECT"
```

Open `http://127.0.0.1:8088`. The launcher reads ignored environment settings,
configures CA validation and direct gateway resolution, selects the 16 installed
scenarios, and opens a temporary localhost port forward to private Keycloak.
No hosts-file or public DNS change is needed.

To use a prebuilt dashboard without Go on PATH:

```sh
go build -o .devspace/bin/demo-dashboard ./cmd/demo-dashboard
python3 scripts/apigee_dashboard.py --confirm "$PROJECT" \
  --binary .devspace/bin/demo-dashboard
```

An existing prebuilt binary is available in the current development environment.
Use `--listen 127.0.0.1:8089` if the default port is occupied. Keep the listener
on localhost: this synthetic debugging UI can display test tokens and policies.
Stop the launcher with Ctrl+C; it also closes its Keycloak port forward.

## Request Path

1. The browser sends the selected scenario to the local Go dashboard. This is
   the test client, not a replacement gateway. For Keycloak scenarios it first
   obtains a subject token through the temporary private issuer port forward.
2. The dashboard connects to the configured public HTTPS load-balancer address.
   HTTP Host and TLS SNI remain `apigee.gcp.kube`. It validates the configured CA.
3. The HTTPS load balancer uses a northbound PSC NEG to reach the managed Apigee
   runtime in Google's tenant network. Apigee is not running inside GKE.
4. Proxy `txe-development` captures the original host, full URI, and scheme into
   trusted `txe.input.*` variables. It initializes the decision to invalid.
5. ExternalCallout creates a Google-issued ID token for the dedicated proxy
   service account. It sends unary `apigee.ExternalCalloutService/ProcessMessage`
   with request headers and metadata. The request body is not sent to the plugin.
6. The gRPC request uses the callout TargetServer, Apigee endpoint attachment,
   producer ServiceAttachment, and GKE internal TCP load balancer. TLS passes
   through that load balancer to the dedicated pod listener on port 3003.
7. The service verifies the gateway ID token's signature, issuer, expiry,
   audience, and allowed numeric subject. This gateway credential is separate
   from the client's bearer token inside the protobuf request.
8. The adapter calls the shared evaluation engine. It uses cached, watched
   ConfigMap policies and operator-owned issuer configuration and Secrets.
   Matched unhealthy policies fail closed.
9. For a matched exchange, the service sends an RFC8693 token request to the
   private fake issuer or Keycloak Service. These synthetic issuer endpoints use
   explicitly enabled internal HTTP. Gateway/callout/backend TLS remains validated.
10. On allow, the service returns the replacement Authorization header and
    explicit decision variables. Apigee applies the mutation. On deny, RaiseFault
    returns the status, JSON body, and challenge without reaching httpbin.
    Transport failure or missing decisions also stop forwarding.
11. Allowed traffic uses a second endpoint attachment and ServiceAttachment to
    reach the backend's internal TCP load balancer and HTTPS httpbin listener.
    No Envoy ext-proc or Istio processing runs again on this backend route.
12. Httpbin echoes the request. Its response returns through Apigee and the
    local dashboard to the browser. POST bodies and queries stay in the main
    request path; they are not reconstructed from a callout response.

The current addresses are in ignored `.devspace/apigee.json`. Apigee endpoint
attachment IPs belong to the managed runtime network; they are different from
the GKE internal load-balancer IPs visible in `kubectl get service`.

## QA Checklist

1. Confirm **Plugin: ready**. Both `fake-issuer` and `local-keycloak` should be
   available. Click **Run all**. All 16 scenarios should show Pass; expected
   denials are successful tests, not failed requests in the test harness.
2. Select **yellow-success**, then **Run selected**. Expect 200 and an upstream
   Authorization value different from the incoming token. The fake token is
   synthetic, not a cryptographically signed production token.
3. Select **keycloak-audience**. Expect 200. Inspect the token pane and verify
   the signed token. The issuer, audience, scope, and exchanged token are visible.
4. Check **missing-bearer** (401 with challenge), **explicit-deny** (403),
   **invalid-grant** (400), and the four invalid Keycloak subject-token cases.
5. Check **cors-preflight** (200), **options-missing-bearer** (401), and
   **unmatched** (200 with the original bearer preserved).
6. Use **policy** to inspect the actual ConfigMap, **logs** for the plugin and
   selected issuer, **response** for the echoed request, and **diagram** for
   the request sequence. The curl pane retains CA validation and gateway routing.

The dashboard sends API requests from its Go server. It tests CORS headers and
gateway behavior, not a browser application's independent cross-origin setup.
Do not run the outage/failure suite during manual QA; it intentionally changes
availability and requires exclusive synthetic traffic for its exchange count.

## Correlate Gateway Debug

```sh
python3 scripts/apigee.py debug --confirm "$PROJECT"
# Wait at least 20 seconds, then run a dashboard scenario.
python3 scripts/apigee.py diagnostics --confirm "$PROJECT"
python3 scripts/apigee.py debug --confirm "$PROJECT" --session SESSION_ID
```

Dashboard scenarios send `X-Txe-Debug: synthetic`. Match Apigee's message ID with
`APIGEE_MESSAGE` and `APIGEE_MUTATION` in service logs. Debug exports are ignored,
private local files and may include full synthetic tokens. Do not publish them.

Development certificates last seven days. Rotate them with the documented
workflow if needed. Never work around expiry or trust errors by disabling TLS
validation. See [the deployment runbook](apigee.md) for rotation and cleanup.
