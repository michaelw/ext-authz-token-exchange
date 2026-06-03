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
  deadline=$((SECONDS + 600))

  while [ "$SECONDS" -lt "$deadline" ]; do
    conditions="$(kubectl -n "$GATEWAY_NAMESPACE" get gcptrafficextension ext-authz-token-exchange \
      -o jsonpath='{range .status.ancestors[*].conditions[*]}{.type}={.status}{"\n"}{end}' 2>/dev/null || true)"

    if printf '%s\n' "$conditions" | grep -q '^Accepted=True$' \
      && printf '%s\n' "$conditions" | grep -q '^ResolvedRefs=True$'; then
      echo "I: GCPTrafficExtension refs accepted and resolved."
      return 0
    fi

    echo "I: Waiting for GCPTrafficExtension refs to settle..."
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
