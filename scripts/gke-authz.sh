#!/usr/bin/env bash
set -euo pipefail

name="${GKE_AUTHZ_NAME:-ext-authz-token-exchange}"
project="${GKE_PROJECT_ID:?GKE_PROJECT_ID is required}"
region="${GKE_REGION:?GKE_REGION is required}"
gateway_namespace="${GATEWAY_NAMESPACE:-gke-gateway}"
gateway_name="${GATEWAY_NAME:-gateway}"
host="${GKE_AUTHZ_HOST:-httpbin.${DEPLOYMENT_DOMAIN:-${GKE_DNS_DOMAIN:-gcp.kube}}}"
callout_service="${GATEWAY_EXT_AUTHZ_SERVICE_NAME:-gateway-ext-authz}"
callout_namespace="${GKE_AUTHZ_CALLOUT_NAMESPACE:-ext-authz-token-exchange}"
callout_port="${GKE_AUTHZ_CALLOUT_PORT:-3000}"
lb_scheme="${GKE_AUTHZ_LB_SCHEME:-EXTERNAL_MANAGED}"
forward_headers="${GKE_AUTHZ_FORWARD_HEADERS:-authorization,cookie,origin,access-control-request-method,access-control-request-headers,x-request-id,traceparent,tracestate}"
policy_when="${GKE_AUTHZ_POLICY_WHEN:-}"

gateway_annotation() {
  local annotation
  annotation="$1"
  kubectl get gateway "$gateway_name" -n "$gateway_namespace" \
    -o "jsonpath={.metadata.annotations.${annotation}}" 2>/dev/null || true
}

split_annotation_uris() {
  tr ',' '\n' | sed -e 's/^ *//' -e 's/ *$//' -e '/^$/d'
}

compute_api_url() {
  local uri
  uri="$1"
  case "$uri" in
    https://*) printf '%s\n' "$uri" ;;
    /projects/*) printf 'https://www.googleapis.com/compute/v1%s\n' "$uri" ;;
    *) printf '%s\n' "$uri" ;;
  esac
}

backend_service_uri() {
  local services
  services="$(gateway_annotation 'networking\.gke\.io/backend-services' | split_annotation_uris)"
  printf '%s\n' "$services" \
    | grep -E "backendServices/.*(ext-authz-token|gateway-ext).*-${callout_port}-" \
    | head -n 1
}

forwarding_rule_uris() {
  gateway_annotation 'networking\.gke\.io/forwarding-rules' | split_annotation_uris
}

write_authz_extension() {
  local out backend
  out="$1"
  backend="$2"
  cat >"$out" <<EOF
name: ${name}
authority: ${callout_service}.${callout_namespace}.svc.cluster.local
loadBalancingScheme: ${lb_scheme}
service: ${backend}
failOpen: false
timeout: "1s"
wireFormat: EXT_AUTHZ_GRPC
EOF
  if [[ "$forward_headers" != "all" ]]; then
    {
      echo "forwardHeaders:"
      tr ',' '\n' <<<"$forward_headers" | sed -e 's/^ *//' -e 's/ *$//' -e '/^$/d' | while IFS= read -r header; do
        printf '  - %s\n' "$header"
      done
    } >>"$out"
  fi
}

write_authz_policy() {
  local out rules
  out="$1"
  rules="$(forwarding_rule_uris)"
  if [[ -z "$rules" ]]; then
    echo "E: no forwarding rules found on gateway ${gateway_namespace}/${gateway_name}" >&2
    exit 1
  fi

  {
    cat <<EOF
name: ${name}
target:
  loadBalancingScheme: ${lb_scheme}
  resources:
EOF
    while IFS= read -r rule; do
      printf '    - "%s"\n' "$(compute_api_url "$rule")"
    done <<<"$rules"
    cat <<EOF
policyProfile: REQUEST_AUTHZ
httpRules:
  - to:
      operations:
        - hosts:
            - exact: "${host}"
          paths:
            - prefix: "/"
EOF
    if [[ -n "$policy_when" ]]; then
      printf "    when: '%s'\n" "$policy_when"
    fi
    cat <<EOF
action: CUSTOM
customProvider:
  authzExtension:
    resources:
      - "projects/${project}/locations/${region}/authzExtensions/${name}"
EOF
  } >"$out"
}

wait_for_backend_service() {
  local deadline backend
  deadline=$((SECONDS + 600))
  while (( SECONDS < deadline )); do
    backend="$(backend_service_uri || true)"
    if [[ -n "$backend" ]]; then
      compute_api_url "$backend"
      return 0
    fi
    sleep 10
  done

  echo "E: no GKE Gateway backend service found for ${callout_namespace}/${callout_service}:${callout_port}" >&2
  echo "I: current backend-services annotation:" >&2
  gateway_annotation 'networking\.gke\.io/backend-services' >&2
  exit 1
}

apply_authz() {
  local backend tmpdir extension_yaml policy_yaml
  backend="$(wait_for_backend_service)"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir:-}"' EXIT
  extension_yaml="${tmpdir}/authz-extension.yaml"
  policy_yaml="${tmpdir}/authz-policy.yaml"
  write_authz_extension "$extension_yaml" "$backend"
  write_authz_policy "$policy_yaml"

  gcloud beta service-extensions authz-extensions import "$name" \
    --source="$extension_yaml" \
    --location="$region" \
    --project="$project"
  gcloud beta network-security authz-policies import "$name" \
    --source="$policy_yaml" \
    --location="$region" \
    --project="$project"
}

delete_authz() {
  gcloud beta network-security authz-policies delete "$name" \
    --location="$region" \
    --project="$project" \
    --quiet || true
  gcloud beta service-extensions authz-extensions delete "$name" \
    --location="$region" \
    --project="$project" \
    --quiet || true
}

case "${1:-apply}" in
  apply)
    apply_authz
    ;;
  delete)
    delete_authz
    ;;
  backend-service)
    wait_for_backend_service
    ;;
  *)
    echo "usage: $0 [apply|delete|backend-service]" >&2
    exit 2
    ;;
esac
