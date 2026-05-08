#!/bin/sh
set -eu

profiles="$(printf '%s %s' "${DEVSPACE_PROFILE:-}" "$*" | tr ',' ' ')"
explicit=""
for profile in $profiles; do
	case "$profile" in
	with-fake-issuer)
		explicit="fake"
		;;
	with-keycloak)
		explicit="keycloak"
		;;
	esac
done

if [ -n "$explicit" ]; then
	printf '%s\n' "$explicit"
	exit 0
fi

kubectl_bin="${KUBECTL:-kubectl}"
plugin_namespace="${DEMO_PLUGIN_NAMESPACE:-ext-authz-token-exchange}"
plugin_deployment="${DEMO_PLUGIN_DEPLOYMENT:-ext-authz-token-exchange}"

token_endpoint="$(
	"$kubectl_bin" -n "$plugin_namespace" get deploy "$plugin_deployment" \
		-o 'jsonpath={range .spec.template.spec.containers[*].env[?(@.name=="TOKEN_EXCHANGE_DEFAULT_TOKEN_ENDPOINT")]}{.value}{end}' \
		2>/dev/null || true
)"

case "$token_endpoint" in
*keycloak*)
	printf 'keycloak\n'
	;;
*fake-token-endpoint* | "")
	printf 'fake\n'
	;;
*)
	printf 'fake\n'
	;;
esac
