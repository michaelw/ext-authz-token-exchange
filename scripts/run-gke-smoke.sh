#!/usr/bin/env bash
set -euo pipefail

platform_namespace="${GKE_PLATFORM_NAMESPACE:?GKE_PLATFORM_NAMESPACE is required}"
plugin_namespace="${GKE_GATEWAY_NAMESPACE:?GKE_GATEWAY_NAMESPACE is required}"
plugin_deployment=ext-authz-token-exchange
lock_name=txe-smoke-lock
setting=TOKEN_EXCHANGE_DEFAULT_DENY_UNMATCHED
holder="$(hostname)-$$-$(date +%s)"

if kubectl -n "$platform_namespace" get configmap "$lock_name" >/dev/null 2>&1; then
  echo "E: another GKE smoke run holds ConfigMap $platform_namespace/$lock_name:" >&2
  kubectl -n "$platform_namespace" get configmap "$lock_name" -o jsonpath='{.data}' >&2 || true
  echo >&2
  echo "E: if that run is no longer active, recover with:" >&2
  echo "E: kubectl -n $platform_namespace delete configmap $lock_name" >&2
  exit 1
fi
if ! kubectl -n "$platform_namespace" create configmap "$lock_name" \
  --from-literal=holder="$holder" \
  --from-literal=startedAt="$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null 2>&1; then
  echo "E: could not acquire smoke lock ConfigMap $platform_namespace/$lock_name" >&2
  exit 1
fi

original="__ABSENT__"
snapshot_complete=false
restore() {
  status=$?
  trap - EXIT INT TERM
  current_holder="$(kubectl -n "$platform_namespace" get configmap "$lock_name" -o jsonpath='{.data.holder}' 2>/dev/null || true)"
  if [ "$current_holder" = "$holder" ]; then
    if [ "$snapshot_complete" = "true" ]; then
      if [ "$original" = "__ABSENT__" ]; then
        kubectl -n "$plugin_namespace" set env "deployment/$plugin_deployment" "$setting-" >/dev/null || true
      else
        kubectl -n "$plugin_namespace" set env "deployment/$plugin_deployment" "$setting=$original" >/dev/null || true
      fi
      kubectl -n "$plugin_namespace" rollout status "deployment/$plugin_deployment" --timeout=300s || true
    fi
    kubectl -n "$platform_namespace" delete configmap "$lock_name" --ignore-not-found >/dev/null || true
  fi
  exit "$status"
}
trap restore EXIT INT TERM

original="$(
  kubectl -n "$plugin_namespace" get deployment "$plugin_deployment" -o json |
    SETTING="$setting" yq -r '
      [.spec.template.spec.containers[]
        | select(.name == "ext-authz-token-exchange")
        | .env[]?
        | select(.name == strenv(SETTING))
        | .value][0] // "__ABSENT__"
    '
)"
snapshot_complete=true

export E2E_BASE_URL="$GKE_COMMAND_HTTPBIN_URL"
export E2E_HOST="$GKE_HTTPBIN_HOST"
export E2E_NAMESPACE_PREFIX="$GKE_DEMO_NAMESPACE_PREFIX"
export E2E_NAMESPACE="$plugin_namespace"
export E2E_RELEASE="$plugin_deployment"
export E2E_DEMO_NAMESPACE="$platform_namespace"
export E2E_DEMO_RELEASE=txe-platform
export E2E_KEYCLOAK_BASE_URL="$GKE_COMMAND_KEYCLOAK_URL"
export E2E_KEYCLOAK_ISSUER="$GKE_COMMAND_KEYCLOAK_URL/realms/token-exchange-e2e"
export E2E_DIRECT_ADDRESS="$GKE_COMMAND_DIRECT_ADDRESS"
export E2E_SKIP_INSTALL=true
export E2E_SKIP_CLEANUP=true
export E2E_EXPECT_INSECURE_TOKEN_LOGS=false

label_filter_args=()
case " $* " in
  *"--label-filter"*) ;;
  *) label_filter_args=(--label-filter=!stress) ;;
esac

go run github.com/onsi/ginkgo/v2/ginkgo -r "${label_filter_args[@]}" "$@" ./test/e2e
