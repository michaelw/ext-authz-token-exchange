#!/usr/bin/env bash
set -euo pipefail

namespace="${STARTER_PACK_ENV_NAMESPACE:-devspace-system}"
configmap="${STARTER_PACK_ENV_CONFIGMAP:-devspace-starter-pack-env}"
context_arg=""

usage() {
  echo "usage: $0 get VAR DEFAULT [DEVSPACE_CONTEXT] | gateway-provider [DEVSPACE_CONTEXT] | require-gke-values [DEVSPACE_CONTEXT]" >&2
  exit 2
}

current_context() {
  if [ -n "$context_arg" ]; then
    printf '%s\n' "$context_arg"
    return
  fi
  if [ -n "${DEVSPACE_CONTEXT:-}" ]; then
    printf '%s\n' "$DEVSPACE_CONTEXT"
    return
  fi
  printf '\n'
}

cache_root() {
  if [ -n "${DEVSPACE_TMPDIR:-}" ]; then
    printf '%s/ext-authz-token-exchange\n' "$DEVSPACE_TMPDIR"
  else
    printf '.devspace/cache\n'
  fi
}

cache_file() {
  local ctx safe_ctx run_id safe_run_id
  ctx="$(current_context)"
  safe_ctx="$(printf '%s' "${ctx:-none}" | tr -c '[:alnum:]_.-' '_')"
  run_id="${DEVSPACE_TIMESTAMP:-manual-${PPID}}"
  safe_run_id="$(printf '%s' "$run_id" | tr -c '[:alnum:]_.-' '_')"
  printf '%s/starter-pack-env-%s-%s.json\n' "$(cache_root)" "$safe_ctx" "$safe_run_id"
}

read_configmap() {
  local ctx
  ctx="$(current_context)"
  if [ -n "$ctx" ]; then
    kubectl --context "$ctx" get configmap -n "$namespace" "$configmap" -o json 2>/dev/null
  else
    kubectl get configmap -n "$namespace" "$configmap" -o json 2>/dev/null
  fi
}

write_missing_cache() {
  local path
  path="$1"
  printf '{"missing":true,"data":{}}\n' > "$path"
}

init_cache() {
  local path dir lock
  path="$(cache_file)"
  dir="$(dirname "$path")"
  lock="${path}.lock"
  mkdir -p "$dir"

  if [ -s "$path" ]; then
    printf '%s\n' "$path"
    return
  fi

  while ! mkdir "$lock" 2>/dev/null; do
    if [ -s "$path" ]; then
      printf '%s\n' "$path"
      return
    fi
    sleep 0.05
  done
  trap 'rmdir "$lock" 2>/dev/null || true' RETURN

  if [ ! -s "$path" ]; then
    if ! read_configmap > "${path}.tmp"; then
      write_missing_cache "${path}.tmp"
    fi
    mv "${path}.tmp" "$path"
  fi

  printf '%s\n' "$path"
}

json_value() {
  local path expr
  path="$1"
  expr="$2"
  yq -r "$expr // \"\"" "$path"
}

validate_configmap_version() {
  local path version missing
  path="$1"
  missing="$(json_value "$path" '.missing')"
  if [ "$missing" = "true" ]; then
    return
  fi

  version="$(json_value "$path" '.data.STARTER_PACK_ENV_VERSION')"
  if [ "$version" != "v1" ]; then
    echo "E: unsupported ${namespace}/${configmap} STARTER_PACK_ENV_VERSION=${version:-<empty>}; expected v1" >&2
    exit 1
  fi
}

get_from_cache() {
  local key default path value
  key="$1"
  default="$2"
  current_context >/dev/null

  path="$(init_cache)"
  validate_configmap_version "$path"

  case "$key" in
    REGISTRY|DEV_REGISTRY)
      value="$(json_value "$path" '.data.DEV_REGISTRY_IMAGE_PREFIX')"
      if [ -z "$value" ]; then
        value="$(json_value "$path" '.data.DEV_REGISTRY')"
      fi
      ;;
    *)
      value="$(json_value "$path" ".data.${key}")"
      ;;
  esac

  printf '%s\n' "${value:-$default}"
}

require_gke_values() {
  local missing=()

  case "$(current_context)" in
    gke_*) ;;
    *) return 0 ;;
  esac

  [ -n "${DEPLOYMENT_DOMAIN:-}" ] || missing+=("DEPLOYMENT_DOMAIN")
  [ -n "${GKE_PROJECT_ID:-}" ] || missing+=("GKE_PROJECT_ID")
  [ -n "${GKE_REGION:-}" ] || missing+=("GKE_REGION")
  [ -n "${DEV_REGISTRY_IMAGE_PREFIX:-}" ] || missing+=("DEV_REGISTRY_IMAGE_PREFIX")

  if [ "${#missing[@]}" -gt 0 ]; then
    echo "E: missing GKE starter-pack values: ${missing[*]}" >&2
    echo "E: Publish ${namespace}/${configmap} by running starter-pack infra.ensure-cluster or deploying starter-pack infra." >&2
    echo "E: Example: devspace -p with-infra run infra.ensure-cluster" >&2
    exit 1
  fi
}

gateway_provider() {
  case "$(current_context)" in
    gke_*) printf 'gke-gateway\n' ;;
    *) printf 'local-istio\n' ;;
  esac
}

case "${1:-}" in
  get)
    [ "$#" -eq 3 ] || [ "$#" -eq 4 ] || usage
    context_arg="${4:-}"
    get_from_cache "$2" "$3"
    ;;
  gateway-provider)
    [ "$#" -eq 1 ] || [ "$#" -eq 2 ] || usage
    context_arg="${2:-}"
    gateway_provider
    ;;
  require-gke-values)
    [ "$#" -eq 1 ] || [ "$#" -eq 2 ] || usage
    context_arg="${2:-}"
    require_gke_values
    ;;
  *)
    usage
    ;;
esac
