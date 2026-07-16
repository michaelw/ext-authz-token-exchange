#!/usr/bin/env bash

devspace_pipeline_deploy() {
  if [ "$(get_flag "render")" = "true" ]; then
    run_dependencies --all
    helm dependency build charts/ext-authz-token-exchange
    create_deployments --all
    return
  fi

  run_dependencies --all

  case "$DEVSPACE_CONTEXT" in
    gke_*)
      ./scripts/starter-pack-env.sh require-gke-values "$DEVSPACE_CONTEXT"
      build_images prod fake-token-endpoint
      helm dependency build charts/ext-authz-token-exchange
      kubectl create namespace "${GATEWAY_NAMESPACE:?GATEWAY_NAMESPACE is required}" --dry-run=client -o yaml | kubectl apply -f -
      create_deployments --all
      wait_for_gke_test_stack
      ;;
    *)
      ensure_pull_secrets --all
      build_images prod fake-token-endpoint
      helm dependency build charts/ext-authz-token-exchange
      kubectl create namespace ext-authz-token-exchange --dry-run=client -o yaml | kubectl apply -f -
      for ns in service-yellow service-red service-blue; do
        kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f -
        kubectl label namespace "$ns" ext-authz-token-exchange.magneticflux.net/policy=enabled --overwrite
      done
      create_deployments --all
      ;;
  esac
}

wait_for_rollout_if_present() {
  namespace="$1"
  deployment="$2"

  if kubectl -n "$namespace" get deploy "$deployment" >/dev/null 2>&1; then
    kubectl -n "$namespace" rollout status "deploy/$deployment" --timeout=300s
  fi
}

wait_for_gke_test_stack() {
  wait_for_rollout_if_present "${GATEWAY_NAMESPACE:?GATEWAY_NAMESPACE is required}" ext-authz-token-exchange
  wait_for_rollout_if_present ext-authz-token-exchange-e2e fake-token-endpoint
  wait_for_rollout_if_present ext-authz-token-exchange-e2e keycloak
  wait_for_rollout_if_present httpbin httpbin

  if kubectl -n "$GATEWAY_NAMESPACE" get gcptrafficextension ext-authz-token-exchange >/dev/null 2>&1; then
    wait_for_gcptrafficextension_refs
    wait_for_httpbin_extension
  fi
}

wait_for_gcptrafficextension_refs() {
  namespace="${1:-${GATEWAY_NAMESPACE:?GATEWAY_NAMESPACE is required}}"
  deadline=$((SECONDS + 600))

  while [ "$SECONDS" -lt "$deadline" ]; do
    conditions="$(kubectl -n "$namespace" get gcptrafficextension ext-authz-token-exchange \
      -o jsonpath='{range .status.conditions[*]}{.type}={.status}:{.reason}{"\n"}{end}{range .status.ancestors[*].conditions[*]}{.type}={.status}:{.reason}{"\n"}{end}' \
      2>/dev/null || true)"

    if printf '%s\n' "$conditions" | grep -q '^Accepted=True:' \
      && ! printf '%s\n' "$conditions" | grep -q '^ResolvedRefs=False:' \
      && printf '%s\n' "$conditions" | grep -q '^Programmed=True:ProgrammingSucceeded$'; then
      echo "I: GCPTrafficExtension accepted and programmed."
      return 0
    fi

    echo "I: Waiting for GCPTrafficExtension programming (conditions: $(printf '%s' "$conditions" | tr '\n' ' '))"
    sleep 5
  done

  echo "E: Timed out waiting for GCPTrafficExtension refs to settle." >&2
  return 1
}

wait_for_httpbin_extension() {
  url="https://httpbin.${DEPLOYMENT_DOMAIN:?DEPLOYMENT_DOMAIN is required}/anything/yellow"
  deadline=$((SECONDS + 600))

  while [ "$SECONDS" -lt "$deadline" ]; do
    allow_code="$(curl -ksS -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer readiness-yellow' "$url" 2>/dev/null || true)"
    deny_code="$(curl -ksS -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"

    if [ "$allow_code" = "200" ] && [ "$deny_code" = "401" ]; then
      echo "I: GKE extension allows token exchange and denies no-token requests."
      return 0
    fi

    echo "I: Waiting for GKE extension enforcement at $url (allow=${allow_code:-none} deny=${deny_code:-none})..."
    sleep 5
  done

  echo "E: Timed out waiting for GKE extension enforcement at $url." >&2
  return 1
}

require_gke_model_value() {
  name="$1"
  eval "value=\${$name:-}"
  if [ -z "$value" ]; then
    echo "E: $name is required for this deployment model" >&2
    return 1
  fi
}

require_api_resource() {
  resource="$1"
  if ! kubectl api-resources -o name | grep -qx "$resource"; then
    echo "E: required Kubernetes resource $resource is not available" >&2
    return 1
  fi
}

listener_allows_hostname() {
  listener_hostname="$1"
  requested_hostname="$2"
  if [ -z "$listener_hostname" ] || [ "$listener_hostname" = "$requested_hostname" ]; then
    return 0
  fi
  case "$listener_hostname" in
    \*.*)
      suffix="${listener_hostname#\*}"
      case "$requested_hostname" in
        *"$suffix")
          prefix="${requested_hostname%"$suffix"}"
          case "$prefix" in
            ""|*.*) ;;
            *) return 0 ;;
          esac
          ;;
      esac
      ;;
  esac
  return 1
}

preflight_gke_gateway() {
  require_gke_model_value GKE_DEPLOYMENT_DOMAIN
  require_gke_model_value GKE_GATEWAY_NAMESPACE
  require_gke_model_value GKE_GATEWAY_NAME
  require_gke_model_value GKE_GATEWAY_SECTION_NAME
  require_gke_model_value GKE_GATEWAY_SCHEME
  require_gke_model_value GKE_GATEWAY_PORT
  require_gke_model_value GKE_HTTPBIN_HOST
  require_gke_model_value GKE_KEYCLOAK_HOST

  require_api_resource gateways.gateway.networking.k8s.io
  require_api_resource httproutes.gateway.networking.k8s.io
  require_api_resource referencegrants.gateway.networking.k8s.io
  require_api_resource gcptrafficextensions.networking.gke.io
  require_api_resource healthcheckpolicies.networking.gke.io

  if ! kubectl -n "$GKE_GATEWAY_NAMESPACE" get gateway "$GKE_GATEWAY_NAME" >/dev/null 2>&1; then
    echo "E: Gateway $GKE_GATEWAY_NAMESPACE/$GKE_GATEWAY_NAME does not exist" >&2
    return 1
  fi

  gateway_class="$(kubectl -n "$GKE_GATEWAY_NAMESPACE" get gateway "$GKE_GATEWAY_NAME" -o jsonpath='{.spec.gatewayClassName}')"
  case "$gateway_class" in
    gke-l7-global-external-managed|gke-l7-regional-external-managed|gke-l7-rilb) ;;
    *)
      echo "E: unsupported single-cluster GKE GatewayClass $gateway_class" >&2
      return 1
      ;;
  esac
  if ! kubectl get gatewayclass "$gateway_class" >/dev/null 2>&1; then
    echo "E: GatewayClass $gateway_class does not exist" >&2
    return 1
  fi
  class_accepted="$(kubectl get gatewayclass "$gateway_class" \
    -o jsonpath='{range .status.conditions[?(@.type=="Accepted")]}{.status}{end}')"
  if [ "$class_accepted" != "True" ]; then
    echo "E: GatewayClass $gateway_class is not Accepted (status=${class_accepted:-missing})" >&2
    return 1
  fi
  gateway_programmed="$(kubectl -n "$GKE_GATEWAY_NAMESPACE" get gateway "$GKE_GATEWAY_NAME" \
    -o jsonpath='{range .status.conditions[?(@.type=="Programmed")]}{.status}{end}')"
  if [ "$gateway_programmed" != "True" ]; then
    echo "E: Gateway $GKE_GATEWAY_NAMESPACE/$GKE_GATEWAY_NAME is not Programmed (status=${gateway_programmed:-missing})" >&2
    return 1
  fi

  listener_json="$(kubectl -n "$GKE_GATEWAY_NAMESPACE" get gateway "$GKE_GATEWAY_NAME" -o json | \
    GKE_GATEWAY_SECTION_NAME="$GKE_GATEWAY_SECTION_NAME" yq -o=json '.spec.listeners[] | select(.name == strenv(GKE_GATEWAY_SECTION_NAME))')"
  if [ -z "$listener_json" ]; then
    echo "E: listener $GKE_GATEWAY_SECTION_NAME does not exist on Gateway $GKE_GATEWAY_NAMESPACE/$GKE_GATEWAY_NAME" >&2
    return 1
  fi

  listener_port="$(printf '%s\n' "$listener_json" | yq -r '.port')"
  listener_protocol="$(printf '%s\n' "$listener_json" | yq -r '.protocol')"
  case "$listener_protocol" in
    HTTPS) expected_scheme=https ;;
    HTTP) expected_scheme=http ;;
    *) expected_scheme="" ;;
  esac
  if [ "$listener_port" != "$GKE_GATEWAY_PORT" ] || [ "$expected_scheme" != "$GKE_GATEWAY_SCHEME" ]; then
    echo "E: listener $GKE_GATEWAY_SECTION_NAME uses protocol=$listener_protocol port=$listener_port, but GKE_GATEWAY_SCHEME=$GKE_GATEWAY_SCHEME and GKE_GATEWAY_PORT=$GKE_GATEWAY_PORT" >&2
    if [ -n "$expected_scheme" ]; then
      echo "E: use --var GKE_GATEWAY_SECTION_NAME=$GKE_GATEWAY_SECTION_NAME --var GKE_GATEWAY_SCHEME=$expected_scheme --var GKE_GATEWAY_PORT=$listener_port" >&2
    fi
    return 1
  fi

  allowed_from="$(printf '%s\n' "$listener_json" | yq -r '.allowedRoutes.namespaces.from // "Same"')"
  if [ "$allowed_from" != "Same" ]; then
    echo "E: listener $GKE_GATEWAY_SECTION_NAME has allowedRoutes.namespaces.from=$allowed_from; expected Same" >&2
    return 1
  fi

  listener_hostname="$(printf '%s\n' "$listener_json" | yq -r '.hostname // ""')"
  for requested_hostname in "$GKE_HTTPBIN_HOST" "$GKE_KEYCLOAK_HOST"; do
    if ! listener_allows_hostname "$listener_hostname" "$requested_hostname"; then
      echo "E: listener hostname ${listener_hostname:-<all>} does not allow $requested_hostname" >&2
      return 1
    fi
  done
}

preflight_gke_platform() {
  preflight_gke_gateway
  require_gke_model_value GKE_PLATFORM_NAMESPACE
  require_gke_model_value GKE_PLATFORM_TEAMS
  require_gke_model_value GKE_TEAM_NAMESPACE_PREFIX
  require_gke_model_value GKE_TEAM_PATH_ROOT

  for permission in \
    "create deployments.apps $GKE_PLATFORM_NAMESPACE" \
    "create services $GKE_PLATFORM_NAMESPACE" \
    "create configmaps $GKE_PLATFORM_NAMESPACE" \
    "create deployments.apps $GKE_TEAM_NAMESPACE_PREFIX-yellow" \
    "create services $GKE_TEAM_NAMESPACE_PREFIX-yellow" \
    "create configmaps $GKE_TEAM_NAMESPACE_PREFIX-yellow" \
    "create referencegrants.gateway.networking.k8s.io $GKE_TEAM_NAMESPACE_PREFIX-yellow" \
    "create secrets $GKE_GATEWAY_NAMESPACE" \
    "create referencegrants.gateway.networking.k8s.io $GKE_PLATFORM_NAMESPACE" \
    "create httproutes.gateway.networking.k8s.io $GKE_GATEWAY_NAMESPACE" \
    "create healthcheckpolicies.networking.gke.io $GKE_GATEWAY_NAMESPACE" \
    "create gcptrafficextensions.networking.gke.io $GKE_GATEWAY_NAMESPACE"; do
    read -r verb resource namespace <<< "$permission"
    if ! kubectl auth can-i "$verb" "$resource" -n "$namespace" | grep -qx yes; then
      echo "E: current identity cannot $permission" >&2
      return 1
    fi
  done
  for permission in \
    "create namespaces" \
    "patch namespaces" \
    "create clusterroles.rbac.authorization.k8s.io" \
    "create clusterrolebindings.rbac.authorization.k8s.io"; do
    read -r verb resource <<< "$permission"
    if ! kubectl auth can-i "$verb" "$resource" | grep -qx yes; then
      echo "E: current identity cannot $permission" >&2
      return 1
    fi
  done

  conflicts="$(kubectl -n "$GKE_GATEWAY_NAMESPACE" get gcptrafficextensions -o json 2>/dev/null | \
    GKE_GATEWAY_NAME="$GKE_GATEWAY_NAME" yq -r '.items[] | select(.metadata.name != "ext-authz-token-exchange") | select(.spec.targetRefs[]?.name == strenv(GKE_GATEWAY_NAME)) | .metadata.name' 2>/dev/null || true)"
  if [ -n "$conflicts" ]; then
    echo "E: another GCPTrafficExtension already targets $GKE_GATEWAY_NAMESPACE/$GKE_GATEWAY_NAME: $conflicts" >&2
    return 1
  fi
}

preflight_gke_app() {
  preflight_gke_gateway
  require_gke_model_value GKE_TEAM_NAME
  require_gke_model_value GKE_TEAM_NAMESPACE

  if ! kubectl get namespace "$GKE_TEAM_NAMESPACE" >/dev/null 2>&1 \
    && ! kubectl auth can-i create namespaces | grep -qx yes; then
    echo "E: team namespace $GKE_TEAM_NAMESPACE does not exist and the current identity cannot create it" >&2
    return 1
  fi
  if ! kubectl auth can-i patch namespaces | grep -qx yes; then
    echo "E: current identity cannot label namespace $GKE_TEAM_NAMESPACE for policy discovery" >&2
    return 1
  fi

  for permission in \
    "create deployments.apps" \
    "create services" \
    "create configmaps" \
    "create referencegrants.gateway.networking.k8s.io"; do
    read -r verb resource <<< "$permission"
    if ! kubectl auth can-i "$verb" "$resource" -n "$GKE_TEAM_NAMESPACE" | grep -qx yes; then
      echo "E: current identity cannot $permission in namespace $GKE_TEAM_NAMESPACE" >&2
      return 1
    fi
  done

  if ! kubectl -n "$GKE_GATEWAY_NAMESPACE" get httproute "txe-team-$GKE_TEAM_NAME" >/dev/null 2>&1; then
    echo "E: platform route $GKE_GATEWAY_NAMESPACE/txe-team-$GKE_TEAM_NAME is missing" >&2
    echo "E: ask the platform team to add $GKE_TEAM_NAME to GKE_PLATFORM_TEAMS and redeploy gke-platform" >&2
    return 1
  fi
  reserved_namespace="$(kubectl -n "$GKE_GATEWAY_NAMESPACE" get httproute "txe-team-$GKE_TEAM_NAME" \
    -o jsonpath='{.spec.rules[0].backendRefs[0].namespace}')"
  if [ "$reserved_namespace" != "$GKE_TEAM_NAMESPACE" ]; then
    echo "E: platform route txe-team-$GKE_TEAM_NAME reserves namespace $reserved_namespace, not $GKE_TEAM_NAMESPACE" >&2
    return 1
  fi
  reserved_service="$(kubectl -n "$GKE_GATEWAY_NAMESPACE" get httproute "txe-team-$GKE_TEAM_NAME" \
    -o jsonpath='{.spec.rules[0].backendRefs[0].name}')"
  if [ "$reserved_service" != "httpbin" ]; then
    echo "E: platform route txe-team-$GKE_TEAM_NAME reserves Service $reserved_service, not httpbin" >&2
    return 1
  fi
  if ! kubectl -n "$GKE_GATEWAY_NAMESPACE" get deployment ext-authz-token-exchange >/dev/null 2>&1; then
    echo "E: platform plugin deployment $GKE_GATEWAY_NAMESPACE/ext-authz-token-exchange is missing" >&2
    return 1
  fi
  for platform_deployment in fake-token-endpoint keycloak; do
    if ! kubectl -n "$GKE_PLATFORM_NAMESPACE" get deployment "$platform_deployment" >/dev/null 2>&1; then
      echo "E: platform deployment $GKE_PLATFORM_NAMESPACE/$platform_deployment is missing" >&2
      return 1
    fi
  done
  issuer_profiles="$(kubectl -n "$GKE_GATEWAY_NAMESPACE" get configmap ext-authz-token-exchange-issuer-profiles -o jsonpath='{.data.issuers\.yaml}' 2>/dev/null || true)"
  for issuer in fake-issuer local-keycloak; do
    if ! printf '%s\n' "$issuer_profiles" | grep -q "name:.*$issuer"; then
      echo "E: platform issuer profile $issuer is not configured" >&2
      return 1
    fi
  done
}

create_namespace_if_needed() {
  namespace="$1"
  kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f -
}

prepare_team_namespace() {
  namespace="$1"
  create_namespace_if_needed "$namespace"
  kubectl label namespace "$namespace" \
    ext-authz-token-exchange.magneticflux.net/policy=enabled --overwrite
}

wait_for_http_route() {
  namespace="$1"
  route="$2"
  deadline=$((SECONDS + 600))
  while [ "$SECONDS" -lt "$deadline" ]; do
    conditions="$(kubectl -n "$namespace" get httproute "$route" \
      -o jsonpath='{range .status.parents[*].conditions[*]}{.type}={.status}{"\n"}{end}' 2>/dev/null || true)"
    if printf '%s\n' "$conditions" | grep -q '^Accepted=True$' \
      && printf '%s\n' "$conditions" | grep -q '^ResolvedRefs=True$'; then
      echo "I: HTTPRoute $namespace/$route is accepted and resolved."
      return 0
    fi
    echo "I: waiting for HTTPRoute $namespace/$route (conditions: $(printf '%s' "$conditions" | tr '\n' ' '))"
    sleep 5
  done
  echo "E: timed out waiting for HTTPRoute $namespace/$route" >&2
  kubectl -n "$namespace" describe httproute "$route" >&2 || true
  return 1
}

gateway_ip_address() {
  addresses="$(kubectl -n "$GKE_GATEWAY_NAMESPACE" get gateway "$GKE_GATEWAY_NAME" \
    -o jsonpath='{range .status.addresses[*]}{.value}{"\n"}{end}')"
  address="$(printf '%s\n' "$addresses" | awk '/^[0-9]+(\.[0-9]+){3}$/ { print; exit }')"
  if [ -z "$address" ]; then
    address="$(printf '%s\n' "$addresses" | awk '/:/ { print; exit }')"
  fi
  if [ -z "$address" ]; then
    address="$(printf '%s\n' "$addresses" | awk 'NF { print; exit }')"
  fi
  if [ -z "$address" ]; then
    echo "E: Gateway $GKE_GATEWAY_NAMESPACE/$GKE_GATEWAY_NAME has no status address" >&2
    return 1
  fi
  case "$address" in
    *:*) printf '%s\n' "$address"; return 0 ;;
    *[!0-9.]* ) ;;
    *) printf '%s\n' "$address"; return 0 ;;
  esac
  if command -v dig >/dev/null 2>&1; then
    resolved="$(dig +short A "$address" | head -1)"
    if [ -z "$resolved" ]; then
      resolved="$(dig +short AAAA "$address" | head -1)"
    fi
  elif command -v getent >/dev/null 2>&1; then
    resolved="$(getent ahostsv4 "$address" | awk 'NR == 1 { print $1 }')"
  else
    resolved=""
  fi
  if [ -z "$resolved" ]; then
    echo "E: could not resolve Gateway status hostname $address to an IP address" >&2
    return 1
  fi
  printf '%s\n' "$resolved"
}

curl_resolve_value() {
  host="$1"
  ip="$2"
  case "$ip" in
    *:*) printf '%s:%s:[%s]\n' "$host" "$GKE_GATEWAY_PORT" "$ip" ;;
    *) printf '%s:%s:%s\n' "$host" "$GKE_GATEWAY_PORT" "$ip" ;;
  esac
}

httpbin_authorization() {
  body_file="$1"
  yq -p=json -r '.headers.Authorization[0] // .headers.authorization[0] // .headers.Authorization // .headers.authorization // ""' "$body_file"
}

decode_jwt_payload() {
  token="$1"
  payload="$(printf '%s' "$token" | cut -d. -f2 | tr '_-' '/+')"
  case $((${#payload} % 4)) in
    2) payload="${payload}==" ;;
    3) payload="${payload}=" ;;
  esac
  if printf '%s' "$payload" | base64 --decode 2>/dev/null; then
    return 0
  fi
  printf '%s' "$payload" | base64 -D
}

print_probe_file() {
  file="$1"
  if [ -s "$file" ]; then
    cat "$file" >&2
  fi
}

probe_gke_team() {
  team="$1"
  ip="$(gateway_ip_address)"
  httpbin_resolve="$(curl_resolve_value "$GKE_HTTPBIN_HOST" "$ip")"
  keycloak_resolve="$(curl_resolve_value "$GKE_KEYCLOAK_HOST" "$ip")"
  base_url="${GKE_GATEWAY_SCHEME}://${GKE_HTTPBIN_HOST}:${GKE_GATEWAY_PORT}${GKE_TEAM_PATH_ROOT}/$team"
  tmpdir="$(mktemp -d)"

  deny_code="$(curl --noproxy '*' -ksS --resolve "$httpbin_resolve" -o "$tmpdir/deny.json" \
    -w '%{http_code}' "$base_url" 2>"$tmpdir/deny.stderr" || true)"
  if [ "$deny_code" != "401" ] || ! grep -q 'bearer_token_required' "$tmpdir/deny.json"; then
    echo "E: no-token probe failed for team $team (status=$deny_code)" >&2
    print_probe_file "$tmpdir/deny.json"
    print_probe_file "$tmpdir/deny.stderr"
    rm -rf "$tmpdir"
    return 1
  fi

  original="gke-$team-smoke"
  allow_code="$(curl --noproxy '*' -ksS --resolve "$httpbin_resolve" -H "Authorization: Bearer $original" \
    -o "$tmpdir/fake.json" -w '%{http_code}' "$base_url" 2>"$tmpdir/fake.stderr" || true)"
  exchanged="$(httpbin_authorization "$tmpdir/fake.json")"
  if [ "$allow_code" != "200" ] || [ -z "$exchanged" ] || [ "$exchanged" = "Bearer $original" ]; then
    echo "E: fake issuer exchange probe failed for team $team (status=$allow_code authorization=${exchanged:-missing})" >&2
    print_probe_file "$tmpdir/fake.json"
    print_probe_file "$tmpdir/fake.stderr"
    rm -rf "$tmpdir"
    return 1
  fi

  subject_code="$(curl --noproxy '*' -ksS --resolve "$keycloak_resolve" \
    -d grant_type=password \
    -d client_id=tx-subject-client \
    -d client_secret=tx-subject-secret \
    -d username=token-user \
    -d password=token-user-password \
    -o "$tmpdir/subject.json" -w '%{http_code}' \
    "${GKE_GATEWAY_SCHEME}://${GKE_KEYCLOAK_HOST}:${GKE_GATEWAY_PORT}/realms/token-exchange-e2e/protocol/openid-connect/token" \
    2>"$tmpdir/subject.stderr" || true)"
  subject_token="$(yq -p=json -r '.access_token // ""' "$tmpdir/subject.json" 2>/dev/null || true)"
  if [ "$subject_code" != "200" ] || [ -z "$subject_token" ]; then
    echo "E: failed to obtain a Keycloak subject token (status=$subject_code)" >&2
    print_probe_file "$tmpdir/subject.json"
    print_probe_file "$tmpdir/subject.stderr"
    rm -rf "$tmpdir"
    return 1
  fi

  keycloak_code="$(curl --noproxy '*' -ksS --resolve "$httpbin_resolve" -H "Authorization: Bearer $subject_token" \
    -o "$tmpdir/keycloak.json" -w '%{http_code}' "$base_url/keycloak" 2>"$tmpdir/keycloak.stderr" || true)"
  keycloak_auth="$(httpbin_authorization "$tmpdir/keycloak.json")"
  if [ "$keycloak_code" != "200" ] || [ -z "$keycloak_auth" ] || [ "$keycloak_auth" = "Bearer $subject_token" ]; then
    echo "E: Keycloak exchange probe failed for team $team (status=$keycloak_code)" >&2
    print_probe_file "$tmpdir/keycloak.json"
    print_probe_file "$tmpdir/keycloak.stderr"
    rm -rf "$tmpdir"
    return 1
  fi
  decode_jwt_payload "${keycloak_auth#Bearer }" > "$tmpdir/keycloak-payload.json"
  issuer="$(yq -p=json -r '.iss // ""' "$tmpdir/keycloak-payload.json")"
  audience_json="$(yq -p=json -o=json '.aud' "$tmpdir/keycloak-payload.json")"
  expected_issuer="${GKE_GATEWAY_SCHEME}://${GKE_KEYCLOAK_HOST}/realms/token-exchange-e2e"
  if [ "$issuer" != "$expected_issuer" ] || ! printf '%s\n' "$audience_json" | grep -q 'tx-audience-client'; then
    echo "E: exchanged Keycloak token has unexpected issuer or audience (issuer=$issuer audience=$audience_json)" >&2
    rm -rf "$tmpdir"
    return 1
  fi
  rm -rf "$tmpdir"
  echo "I: team $team passed bearer denial, fake exchange, and Keycloak exchange probes."
}

wait_for_gke_team_probe() {
  team="$1"
  deadline=$((SECONDS + 600))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if probe_gke_team "$team"; then
      return 0
    fi
    echo "I: waiting for GKE routing and extension propagation for team $team..."
    sleep 10
  done
  echo "E: timed out waiting for end-to-end probes for team $team" >&2
  return 1
}

print_gke_hosts_entries() {
  ip="$(gateway_ip_address)"
  hostnames="$(kubectl -n "$GKE_GATEWAY_NAMESPACE" get httproutes \
    -l ext-authz-token-exchange.magneticflux.net/deployment-model=gke-platform \
    -o jsonpath='{range .items[*].spec.hostnames[*]}{.}{"\n"}{end}' | sort -u | tr '\n' ' ')"
  if [ -z "${hostnames// }" ]; then
    hostnames="$GKE_HTTPBIN_HOST $GKE_KEYCLOAK_HOST"
  fi
  echo
  echo "Deployment succeeded."
  echo
  echo "Add the following to /etc/hosts:"
  echo
  echo "$ip ${hostnames% }"
}

collect_gke_model_diagnostics() {
  kubectl -n "$GKE_GATEWAY_NAMESPACE" get gateway,httproute,gcptrafficextension,healthcheckpolicy -o wide >&2 || true
  kubectl -n "$GKE_GATEWAY_NAMESPACE" get httproute -o yaml >&2 || true
  kubectl -n "$GKE_GATEWAY_NAMESPACE" get gcptrafficextension,healthcheckpolicy -o yaml >&2 || true
  kubectl -n "$GKE_GATEWAY_NAMESPACE" get events --sort-by=.lastTimestamp >&2 || true
  kubectl -n "$GKE_PLATFORM_NAMESPACE" get pods,svc,referencegrant -o wide >&2 || true
  kubectl -n "$GKE_TEAM_NAMESPACE" get pods,svc,configmap,referencegrant -o wide >&2 || true
  kubectl -n "$GKE_TEAM_NAMESPACE" get configmap \
    -l ext-authz-token-exchange.magneticflux.net/enabled=true -o yaml >&2 || true
  kubectl -n "$GKE_GATEWAY_NAMESPACE" logs -l app.kubernetes.io/name=ext-authz-token-exchange --tail=100 >&2 || true
  kubectl -n "$GKE_PLATFORM_NAMESPACE" logs -l app.kubernetes.io/name=fake-token-endpoint --tail=100 >&2 || true
  kubectl -n "$GKE_PLATFORM_NAMESPACE" logs -l app.kubernetes.io/name=keycloak --tail=100 >&2 || true
}

devspace_pipeline_deploy_gke_platform() {
  echo "I: target=gke-platform"
  if [ "$(get_flag "render")" = "true" ]; then
    create_deployments --all
    return
  fi
  preflight_gke_platform || { collect_gke_model_diagnostics; return 1; }
  create_namespace_if_needed "$GKE_PLATFORM_NAMESPACE" || return 1
  prepare_team_namespace "$GKE_TEAM_NAMESPACE_PREFIX-yellow" || return 1
  helm dependency build charts/ext-authz-token-exchange
  if ! create_deployments --all; then
    collect_gke_model_diagnostics
    return 1
  fi
  wait_for_rollout_if_present "$GKE_GATEWAY_NAMESPACE" ext-authz-token-exchange || { collect_gke_model_diagnostics; return 1; }
  wait_for_rollout_if_present "$GKE_PLATFORM_NAMESPACE" fake-token-endpoint || { collect_gke_model_diagnostics; return 1; }
  wait_for_rollout_if_present "$GKE_PLATFORM_NAMESPACE" keycloak || { collect_gke_model_diagnostics; return 1; }
  wait_for_rollout_if_present "$GKE_TEAM_NAMESPACE_PREFIX-yellow" httpbin || { collect_gke_model_diagnostics; return 1; }
  wait_for_gcptrafficextension_refs "$GKE_GATEWAY_NAMESPACE" || { collect_gke_model_diagnostics; return 1; }
  wait_for_http_route "$GKE_GATEWAY_NAMESPACE" keycloak || { collect_gke_model_diagnostics; return 1; }
  wait_for_http_route "$GKE_GATEWAY_NAMESPACE" txe-team-yellow || { collect_gke_model_diagnostics; return 1; }
  if ! wait_for_gke_team_probe yellow; then
    collect_gke_model_diagnostics
    return 1
  fi
  print_gke_hosts_entries
}

devspace_pipeline_deploy_gke_app() {
  echo "I: target=gke-app team=$GKE_TEAM_NAME"
  if [ "$(get_flag "render")" = "true" ]; then
    create_deployments --all
    return
  fi
  preflight_gke_app || { collect_gke_model_diagnostics; return 1; }
  wait_for_rollout_if_present "$GKE_GATEWAY_NAMESPACE" ext-authz-token-exchange || { collect_gke_model_diagnostics; return 1; }
  wait_for_rollout_if_present "$GKE_PLATFORM_NAMESPACE" fake-token-endpoint || { collect_gke_model_diagnostics; return 1; }
  wait_for_rollout_if_present "$GKE_PLATFORM_NAMESPACE" keycloak || { collect_gke_model_diagnostics; return 1; }
  wait_for_gcptrafficextension_refs "$GKE_GATEWAY_NAMESPACE" || { collect_gke_model_diagnostics; return 1; }
  wait_for_http_route "$GKE_GATEWAY_NAMESPACE" keycloak || { collect_gke_model_diagnostics; return 1; }
  prepare_team_namespace "$GKE_TEAM_NAMESPACE" || return 1
  if ! create_deployments --all; then
    collect_gke_model_diagnostics
    return 1
  fi
  wait_for_rollout_if_present "$GKE_TEAM_NAMESPACE" httpbin || { collect_gke_model_diagnostics; return 1; }
  wait_for_http_route "$GKE_GATEWAY_NAMESPACE" "txe-team-$GKE_TEAM_NAME" || { collect_gke_model_diagnostics; return 1; }
  if ! wait_for_gke_team_probe "$GKE_TEAM_NAME"; then
    collect_gke_model_diagnostics
    return 1
  fi
  print_gke_hosts_entries
}
