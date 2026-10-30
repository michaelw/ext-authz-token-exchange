#!/usr/bin/env bash
set -euo pipefail

chart=charts/ext-authz-token-exchange
render() {
  helm template ext-authz-token-exchange "$chart" \
    --namespace ext-authz-token-exchange \
    --set extensionMode=ext_proc \
    --set envoyFilter.enabled=true \
    --show-only templates/envoyfilter.yaml "$@"
}

field() {
  yq -r ".spec.configPatches[0].patch.value.$1"
}

rendered="$(render)"
name="$(printf '%s\n' "$rendered" | field name)"
type="$(printf '%s\n' "$rendered" | field 'typed_config."@type"')"
cluster="$(printf '%s\n' "$rendered" | field typed_config.grpc_service.envoy_grpc.cluster_name)"
failure_mode="$(printf '%s\n' "$rendered" | field typed_config.failure_mode_allow)"

[[ "$name" == ext-authz-token-exchange.ext_proc ]] || { echo "unexpected ext_proc filter name: $name" >&2; exit 1; }
[[ "$type" == type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor ]] || { echo "unexpected ext_proc type: $type" >&2; exit 1; }
[[ "$cluster" == 'outbound|3001||ext-authz-token-exchange.ext-authz-token-exchange.svc.cluster.local' ]] || { echo "unexpected ext_proc cluster: $cluster" >&2; exit 1; }
[[ "$failure_mode" == false ]] || { echo "unexpected default failure_mode_allow: $failure_mode" >&2; exit 1; }

enabled="$(render --set envoyFilter.extProc.failureModeAllow=true | field typed_config.failure_mode_allow)"
[[ "$enabled" == true ]] || { echo "failureModeAllow override was not preserved: $enabled" >&2; exit 1; }
