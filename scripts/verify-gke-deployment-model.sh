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

echo "I: rendering platform-owned routes"
helm template gke-platform-plugin charts/ext-authz-token-exchange \
  --namespace gke-gateway \
  --set gatewayProvider=gke-gateway \
  --set extensionMode=ext_proc \
  --set gkeExtProc.enabled=true \
  --set gkeExtProc.failOpen=false \
  --set gkeExtProc.host=httpbin.example.test \
  --set gkeAuthz.callout.service.port=3001 \
  --set gkeAuthz.callout.service.targetPort=grpc-authz \
  --set gkeAuthz.callout.service.appProtocol=HTTP2 \
  --set gkeAuthz.callout.tls.enabled=false \
  --set gkeAuthz.callout.tls.certificate.enabled=false \
  --set gkeAuthz.callout.healthCheck.enabled=true \
  --set gkeAuthz.callout.healthCheck.port=3001 \
  --set gkeAuthz.callout.healthCheck.portSpecification=USE_FIXED_PORT \
  --set gkeAuthz.callout.backendPolicy.enabled=false > "$workdir/platform-plugin.yaml"
assert_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "Service" and .metadata.name == "gateway-ext-authz" and .spec.ports[0].port == 3001 and .spec.ports[0].appProtocol == "HTTP2")' \
  'the plaintext HTTP/2 GKE callout Service'
assert_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "HealthCheckPolicy" and .spec.default.config.type == "GRPC" and .spec.default.config.grpcHealthCheck.port == 3001)' \
  'the gRPC callout HealthCheckPolicy'
assert_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "GCPTrafficExtension" and .spec.extensionChains[0].extensions[0].failOpen == false)' \
  'the fail-closed GKE traffic extension'
assert_no_manifest "$workdir/platform-plugin.yaml" \
  'select(.kind == "BackendTLSPolicy" or .kind == "GCPBackendPolicy")' \
  'TLS or backend policies for the disposable plaintext callout'

helm template gke-platform-routes charts/ext-authz-token-exchange-e2e \
  --namespace txe-platform \
  --set fakeTokenEndpoint.enabled=true \
  --set-json 'teams=[]' \
  --set platformRoutes.enabled=true \
  --set platformRoutes.gatewayNamespace=gke-gateway \
  --set platformRoutes.gatewayName=gateway \
  --set platformRoutes.gatewaySectionName=https \
  --set platformRoutes.host=httpbin.example.test \
  --set-string 'platformRoutes.teamNames=yellow\,red\,blue\,green' \
  --set platformRoutes.teamNamespacePrefix=txe-team \
  --set platformRoutes.teamPathRoot=/anything/txe > "$workdir/platform-routes.yaml"

for team in yellow red blue green; do
  TEAM="$team" yq -e '
    select(.kind == "HTTPRoute" and .metadata.name == ("txe-team-" + strenv(TEAM))) |
    select(.metadata.namespace == "gke-gateway") |
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
helm template gke-platform-keycloak charts/keycloak \
  --namespace txe-platform \
  --set gatewayProvider=gke-gateway \
  --set namespace=txe-platform \
  --set pluginNamespace=gke-gateway \
  --set gkeGatewayNamespace=gke-gateway \
  --set keycloak.externalHost=keycloak.example.test \
  --set keycloak.externalURL=https://keycloak.example.test \
  --set gateway.name=gateway \
  --set gateway.routeNamespace=gke-gateway \
  --set gateway.createReferenceGrant=true \
  --set gateway.httpRedirect.forceDisabled=true \
  --set gkeIap.forceDisabled=true > "$workdir/platform-keycloak.yaml"
assert_manifest "$workdir/platform-keycloak.yaml" \
  'select(.kind == "HTTPRoute" and .metadata.namespace == "gke-gateway" and .spec.hostnames[0] == "keycloak.example.test" and .spec.rules[0].backendRefs[0].namespace == "txe-platform")' \
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
      *" get gateway "*) printf '%s\n' '203.0.113.10' ;;
      *" get httproutes "*)
        printf '%s\n' keycloak.example.test httpbin.example.test httpbin.example.test
        ;;
    esac
  }
  hosts_output="$(print_gke_hosts_entries)"
  printf '%s\n' "$hosts_output" | grep -Fqx 'Deployment succeeded.'
  printf '%s\n' "$hosts_output" | grep -Fqx 'Add the following to /etc/hosts:'
  printf '%s\n' "$hosts_output" | \
    grep -Fqx '203.0.113.10 httpbin.example.test keycloak.example.test'
)

echo "I: GKE platform/app chart render checks passed"
