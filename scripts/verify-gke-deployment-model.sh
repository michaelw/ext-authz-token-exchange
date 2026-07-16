#!/usr/bin/env bash

set -euo pipefail

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

assert_manifest() {
  file="$1"
  query="$2"
  description="$3"
  if ! yq -e "$query" "$file" >/dev/null; then
    echo "E: rendered manifests do not contain $description" >&2
    return 1
  fi
}

assert_no_manifest() {
  file="$1"
  query="$2"
  description="$3"
  if yq -e "$query" "$file" >/dev/null 2>&1; then
    echo "E: rendered manifests unexpectedly contain $description" >&2
    return 1
  fi
}

echo "I: rendering legacy chart configurations"
helm template legacy-default charts/ext-authz-token-exchange-e2e \
  --namespace ext-authz-token-exchange-e2e > "$workdir/legacy-default.yaml"
assert_manifest "$workdir/legacy-default.yaml" \
  'select(.kind == "Deployment" and .metadata.name == "fake-token-endpoint")' \
  'the legacy fake token endpoint'
assert_no_manifest "$workdir/legacy-default.yaml" \
  'select(.kind == "Deployment" and .metadata.name == "httpbin")' \
  'opt-in team applications in the legacy default render'

helm template legacy-gke-keycloak charts/keycloak \
  --namespace ext-authz-token-exchange-e2e \
  --set gatewayProvider=gke-gateway > "$workdir/legacy-gke-keycloak.yaml"
assert_manifest "$workdir/legacy-gke-keycloak.yaml" \
  'select(.kind == "GCPBackendPolicy" and .spec.default.iap.enabled == true)' \
  'legacy automatic GKE IAP'
assert_manifest "$workdir/legacy-gke-keycloak.yaml" \
  'select(.kind == "HTTPRoute" and .metadata.name == "keycloak-http-redirect")' \
  'the legacy GKE HTTP redirect route'

helm template legacy-gke-plugin charts/ext-authz-token-exchange \
  --namespace gke-gateway \
  --set gatewayProvider=gke-gateway > "$workdir/legacy-gke-plugin.yaml"
assert_manifest "$workdir/legacy-gke-plugin.yaml" \
  'select(.kind == "Issuer" and .apiVersion == "cert-manager.io/v1")' \
  'the legacy cert-manager Issuer'
assert_manifest "$workdir/legacy-gke-plugin.yaml" \
  'select(.kind == "Certificate" and .apiVersion == "cert-manager.io/v1")' \
  'the legacy cert-manager Certificate'
assert_manifest "$workdir/legacy-gke-plugin.yaml" \
  'select(.kind == "BackendTLSPolicy")' \
  'the legacy authenticated backend TLS policy'
assert_no_manifest "$workdir/legacy-gke-plugin.yaml" \
  'select(.kind == "Secret" and .metadata.name == "gateway-ext-authz-tls")' \
  'the opt-in Helm-managed TLS Secret in the legacy GKE render'

echo "I: rendering platform-owned routes"
helm template gke-platform-plugin charts/ext-authz-token-exchange \
  --namespace gke-gateway \
  --set gatewayProvider=gke-gateway \
  --set extensionMode=ext_proc \
  --set gkeExtProc.enabled=true \
  --set gkeExtProc.failOpen=false \
  --set gkeExtProc.host=httpbin.example.test \
  --set gkeAuthz.callout.service.port=3000 \
  --set gkeAuthz.callout.service.targetPort=grpc-authz-tls \
  --set gkeAuthz.callout.service.appProtocol=HTTP2 \
  --set gkeAuthz.callout.tls.enabled=true \
  --set gkeAuthz.callout.tls.port=3000 \
  --set gkeAuthz.callout.tls.selfSigned.enabled=true \
  --set gkeAuthz.callout.tls.backendTLSPolicy.enabled=false \
  --set gkeAuthz.callout.tls.certificate.enabled=false \
  --set-json 'gkeAuthz.callout.tls.certificate.dnsNames=["gateway-ext-authz.gke-gateway.svc.cluster.local"]' \
  --set gkeAuthz.callout.healthCheck.enabled=true \
  --set gkeAuthz.callout.healthCheck.port=3001 \
  --set gkeAuthz.callout.healthCheck.portSpecification=USE_FIXED_PORT \
  --set gkeAuthz.callout.backendPolicy.enabled=false \
  --set env.OTEL_TRACES_EXPORTER=none \
  --set env.OTEL_METRICS_EXPORTER=none > "$workdir/platform-plugin.yaml"
assert_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "Secret" and .metadata.name == "gateway-ext-authz-tls" and .type == "kubernetes.io/tls" and .data."tls.crt" and .data."tls.key")' \
  'the Helm-managed GKE callout TLS Secret'
assert_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "Deployment") | .spec.template.spec.containers[0].ports[] | select(.name == "grpc-authz-tls" and .containerPort == 3000)' \
  'the TLS listener'
assert_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "Deployment") | .spec.template.spec.containers[0].env[] | select(.name == "GRPC_TLS_PORT" and .value == "3000")' \
  'the TLS listener environment'
assert_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "Deployment") | .spec.template.spec.containers[0].env[] | select(.name == "OTEL_TRACES_EXPORTER" and .value == "none")' \
  'the disabled OTEL trace exporter'
assert_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "Deployment") | .spec.template.spec.containers[0].env[] | select(.name == "OTEL_METRICS_EXPORTER" and .value == "none")' \
  'the disabled OTEL metrics exporter'
assert_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "Service" and .metadata.name == "gateway-ext-authz" and .spec.ports[0].port == 3000 and .spec.ports[0].targetPort == "grpc-authz-tls" and .spec.ports[0].appProtocol == "HTTP2" and .spec.ports[1].port == 3001 and .spec.ports[1].targetPort == "grpc-authz")' \
  'the TLS HTTP/2 callout and plaintext gRPC health ports'
assert_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "HealthCheckPolicy" and .spec.default.config.type == "GRPC" and .spec.default.config.grpcHealthCheck.port == 3001)' \
  'the gRPC callout HealthCheckPolicy'
assert_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "GCPTrafficExtension" and .spec.extensionChains[0].extensions[0].failOpen == false)' \
  'the fail-closed GKE traffic extension'
assert_no_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "Issuer" or .kind == "Certificate" or .kind == "BackendTLSPolicy" or .kind == "GCPBackendPolicy")' \
  'cert-manager or backend policies for the disposable self-signed callout'

yq -r 'select(.kind == "Secret" and .metadata.name == "gateway-ext-authz-tls") | .data."tls.crt"' \
  "$workdir/platform-plugin.yaml" | base64 --decode > "$workdir/platform-plugin.crt"
openssl x509 -in "$workdir/platform-plugin.crt" -noout -text > "$workdir/platform-plugin-cert.txt"
grep -q 'DNS:gateway-ext-authz.gke-gateway.svc.cluster.local' "$workdir/platform-plugin-cert.txt"
grep -q 'Digital Signature, Key Encipherment' "$workdir/platform-plugin-cert.txt"

helm template gke-platform-routes charts/ext-authz-token-exchange-e2e \
  --namespace txe-platform \
  --set fakeTokenEndpoint.enabled=true \
  --set-json 'teams=[]' \
  --set platformRoutes.enabled=true \
  --set platformRoutes.gatewayNamespace=gke-gateway \
  --set platformRoutes.gatewayName=gateway \
  --set platformRoutes.gatewaySectionName=custom-listener \
  --set platformRoutes.host=httpbin.example.test \
  --set-string 'platformRoutes.teamNames=yellow\,red\,blue\,green' \
  --set platformRoutes.teamNamespacePrefix=txe-team \
  --set platformRoutes.teamPathRoot=/anything/txe > "$workdir/platform-routes.yaml"

for team in yellow red blue green; do
  TEAM="$team" yq -e '
    select(.kind == "HTTPRoute" and .metadata.name == ("txe-team-" + strenv(TEAM))) |
    select(.metadata.namespace == "gke-gateway") |
    select(.spec.parentRefs[0].sectionName == "custom-listener") |
    select(.spec.hostnames[0] == "httpbin.example.test") |
    select(.spec.rules[0].matches[0].path.value == ("/anything/txe/" + strenv(TEAM))) |
    select(.spec.rules[0].backendRefs[0].namespace == ("txe-team-" + strenv(TEAM)))
  ' "$workdir/platform-routes.yaml" >/dev/null
done

echo "I: rendering Keycloak without GKE IAP"
# shellcheck disable=SC2016
yq -e '
  .profiles[] | select(.name == "gke-platform") |
  .merge.deployments."gke-platform-keycloak".helm.values.gateway.sectionName == "${GKE_GATEWAY_SECTION_NAME}"
' devspace.yaml >/dev/null
# shellcheck disable=SC2016
yq -e '
  .profiles[] | select(.name == "gke-platform") |
  select(
    .merge.deployments."ext-authz-token-exchange".helm.values.gkeAuthz.callout.service.port == 3000 and
    .merge.deployments."ext-authz-token-exchange".helm.values.gkeAuthz.callout.service.targetPort == "grpc-authz-tls" and
    .merge.deployments."ext-authz-token-exchange".helm.values.gkeAuthz.callout.tls.enabled == true and
    .merge.deployments."ext-authz-token-exchange".helm.values.gkeAuthz.callout.tls.selfSigned.enabled == true and
    .merge.deployments."ext-authz-token-exchange".helm.values.gkeAuthz.callout.tls.backendTLSPolicy.enabled == false and
    .merge.deployments."ext-authz-token-exchange".helm.values.env.OTEL_TRACES_EXPORTER == "none" and
    .merge.deployments."ext-authz-token-exchange".helm.values.env.OTEL_METRICS_EXPORTER == "none"
  )
' devspace.yaml >/dev/null
helm template gke-platform-keycloak charts/keycloak \
  --namespace txe-platform \
  --set gatewayProvider=gke-gateway \
  --set namespace=txe-platform \
  --set pluginNamespace=gke-gateway \
  --set gkeGatewayNamespace=gke-gateway \
  --set keycloak.externalHost=keycloak.example.test \
  --set keycloak.externalURL=https://keycloak.example.test \
  --set gateway.name=gateway \
  --set gateway.sectionName=custom-listener \
  --set gateway.routeNamespace=gke-gateway \
  --set gateway.createReferenceGrant=true \
  --set gateway.httpRedirect.forceDisabled=true \
  --set gkeIap.forceDisabled=true > "$workdir/platform-keycloak.yaml"
assert_manifest "$workdir/platform-keycloak.yaml" \
  'select(.kind == "HTTPRoute" and .metadata.namespace == "gke-gateway" and .spec.parentRefs[0].sectionName == "custom-listener" and .spec.hostnames[0] == "keycloak.example.test" and .spec.rules[0].backendRefs[0].namespace == "txe-platform")' \
  'the Gateway-namespace Keycloak route'
assert_manifest "$workdir/platform-keycloak.yaml" \
  'select(.kind == "ReferenceGrant" and .metadata.namespace == "txe-platform" and .spec.from[0].namespace == "gke-gateway" and .spec.to[0].name == "keycloak")' \
  'the exact Keycloak ReferenceGrant'
assert_no_manifest "$workdir/platform-keycloak.yaml" \
  'select(.kind == "GCPBackendPolicy")' \
  'GKE IAP in the opt-in platform model'
assert_no_manifest "$workdir/platform-keycloak.yaml" \
  'select(.kind == "HTTPRoute" and .metadata.name == "keycloak-http-redirect")' \
  'an HTTP redirect route in the opt-in platform model'

echo "I: rendering Keycloak for an HTTP-only GKE listener"
helm template gke-platform-keycloak-http charts/keycloak \
  --namespace txe-platform \
  --set gatewayProvider=gke-gateway \
  --set namespace=txe-platform \
  --set pluginNamespace=gke-gateway \
  --set gkeGatewayNamespace=gke-gateway \
  --set keycloak.externalHost=keycloak.example.test \
  --set keycloak.externalURL=http://keycloak.example.test \
  --set gateway.name=gateway \
  --set gateway.sectionName=http \
  --set gateway.routeNamespace=gke-gateway \
  --set gateway.createReferenceGrant=true \
  --set gateway.httpRedirect.forceDisabled=true \
  --set gkeIap.forceDisabled=true > "$workdir/platform-keycloak-http.yaml"
assert_manifest "$workdir/platform-keycloak-http.yaml" \
  'select(.kind == "Deployment") | .spec.template.spec.containers[0].env[] | select(.name == "KC_HOSTNAME" and .value == "http://keycloak.example.test")' \
  'the HTTP Keycloak canonical hostname'
assert_manifest "$workdir/platform-keycloak-http.yaml" \
  'select(.kind == "HTTPRoute" and .metadata.name == "keycloak" and .spec.parentRefs[0].sectionName == "http")' \
  'the HTTP-only Keycloak route listener'
assert_no_manifest "$workdir/platform-keycloak-http.yaml" \
  'select(.kind == "HTTPRoute" and .metadata.name == "keycloak-http-redirect")' \
  'an HTTP-to-HTTPS redirect for the HTTP-only platform model'
if grep -q 'https://keycloak.example.test' "$workdir/platform-keycloak-http.yaml"; then
  echo "E: HTTP-only Keycloak render contains an HTTPS external URL" >&2
  exit 1
fi

echo "I: rendering team-owned applications"
for team in yellow red blue green; do
  namespace="txe-team-$team"
  output="$workdir/team-$team.yaml"
  helm template "txe-team-$team" charts/ext-authz-token-exchange-e2e \
    --namespace "$namespace" \
    --set fakeTokenEndpoint.enabled=false \
    --set teamApp.enabled=true \
    --set teamApp.gatewayNamespace=gke-gateway \
    --set platformRoutes.enabled=false \
    --set "teams[0].color=$team" \
    --set "teams[0].namespace=$namespace" \
    --set "teams[0].pathPrefix=/anything/txe/$team" \
    --set 'teams[0].scenarios[0].name=keycloak-audience' \
    --set "teams[0].scenarios[0].pathPrefix=/anything/txe/$team/keycloak" \
    --set 'teams[0].scenarios[0].scope=profile' \
    --set 'teams[0].scenarios[0].issuerRef=local-keycloak' \
    --set-json 'teams[0].scenarios[0].resources=[]' \
    --set 'teams[0].scenarios[0].audiences[0]=tx-audience-client' > "$output"

  for kind in Deployment Service ConfigMap ReferenceGrant; do
    KIND="$kind" NAMESPACE="$namespace" yq -e \
      'select(.kind == strenv(KIND) and .metadata.namespace == strenv(NAMESPACE))' \
      "$output" >/dev/null
  done
  assert_manifest "$output" \
    'select(.kind == "ReferenceGrant" and .spec.from[0].namespace == "gke-gateway" and .spec.to[0].name == "httpbin")' \
    "the exact $team application ReferenceGrant"
  TEAM="$team" yq -e '
    select(.kind == "ConfigMap" and .metadata.name == (strenv(TEAM) + "-policy")) |
    select(.data."config.yaml" | contains("/anything/txe/" + strenv(TEAM))) |
    select(.data."config.yaml" | contains("httpbin-" + strenv(TEAM)))
  ' "$output" >/dev/null
  TEAM="$team" yq -e '
    select(.kind == "ConfigMap" and .metadata.name == "keycloak-audience-policy") |
    select(.data."config.yaml" | contains("/anything/txe/" + strenv(TEAM) + "/keycloak")) |
    select(.data."config.yaml" | contains("local-keycloak")) |
    select(.data."config.yaml" | contains("tx-audience-client"))
  ' "$output" >/dev/null
  assert_no_manifest "$output" 'select(.kind == "HTTPRoute")' \
    "a team-owned HTTPRoute for $team"
  assert_no_manifest "$output" \
    'select(.kind == "Deployment" and .metadata.name == "fake-token-endpoint")' \
    "a team-owned fake token endpoint for $team"
done

echo "I: checking Gateway hostname and /etc/hosts helpers"
(
  # shellcheck disable=SC1091
  source scripts/devspace-pipeline.sh

  listener_allows_hostname '*.example.test' httpbin.example.test
  if listener_allows_hostname '*.example.test' nested.httpbin.example.test; then
    exit 1
  fi
  listener_allows_hostname '' keycloak.example.test
  if listener_allows_hostname keycloak.example.test httpbin.example.test; then
    exit 1
  fi

  export GKE_GATEWAY_NAMESPACE=gke-gateway
  export GKE_GATEWAY_NAME=gateway
  export GKE_HTTPBIN_HOST=httpbin.example.test
  export GKE_KEYCLOAK_HOST=keycloak.example.test
  # shellcheck disable=SC2329
  kubectl() {
    case " $* " in
      *" get gcptrafficextension "*)
        printf '%s\n' 'Accepted=True:Accepted' 'Programmed=True:ProgrammingSucceeded'
        ;;
      *" get gateway "*) printf '%s\n' '203.0.113.10' ;;
      *" get httproutes "*)
        printf '%s\n' keycloak.example.test httpbin.example.test httpbin.example.test
        ;;
    esac
  }
  wait_for_gcptrafficextension_refs gke-gateway >/dev/null
  hosts_output="$(print_gke_hosts_entries)"
  printf '%s\n' "$hosts_output" | grep -Fqx 'Deployment succeeded.'
  printf '%s\n' "$hosts_output" | grep -Fqx 'Add the following to /etc/hosts:'
  printf '%s\n' "$hosts_output" | \
    grep -Fqx '203.0.113.10 httpbin.example.test keycloak.example.test'
)

echo "I: GKE platform/app chart render checks passed"
