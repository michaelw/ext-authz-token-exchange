{{- define "ext-authz-token-exchange-e2e.labels" -}}
{{ .Values.labels.partOfKey }}: {{ .Values.labels.partOfValue | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end }}

{{- define "ext-authz-token-exchange-e2e.teamNamespace" -}}
{{- printf "%s-%s" $.Values.namespacePrefix .color -}}
{{- end }}

{{- define "ext-authz-token-exchange-e2e.fakeTokenEndpointConfigMapName" -}}
{{- printf "%s-routes" .Values.fakeTokenEndpoint.name -}}
{{- end }}

{{- define "ext-authz-token-exchange-e2e.gatewayProvider" -}}
{{- .Values.gatewayProvider | default "local-istio" -}}
{{- end }}

{{- define "ext-authz-token-exchange-e2e.isGKEGateway" -}}
{{- eq (include "ext-authz-token-exchange-e2e.gatewayProvider" .) "gke-gateway" -}}
{{- end }}

{{- define "ext-authz-token-exchange-e2e.fakeTokenEndpointImagePullPolicy" -}}
{{- if eq (include "ext-authz-token-exchange-e2e.isGKEGateway" .) "true" -}}
Always
{{- else -}}
{{- .Values.fakeTokenEndpoint.imagePullPolicy -}}
{{- end -}}
{{- end }}

{{- define "ext-authz-token-exchange-e2e.otelEnvironment" -}}
{{- if eq (include "ext-authz-token-exchange-e2e.isGKEGateway" .) "true" -}}
gke
{{- else -}}
local
{{- end -}}
{{- end }}

{{- define "ext-authz-token-exchange-e2e.fakeTokenEndpointRoutes" -}}
{{- range $route := .Values.fakeTokenEndpoint.routes }}
- name: {{ $route.name | quote }}
  match:
{{- with $route.match.path }}
    path: {{ . | quote }}
{{- end }}
{{- with $route.match.scope }}
    scope: {{ . | quote }}
{{- end }}
{{- with $route.match.resource }}
    resource: {{ . | quote }}
{{- else }}
{{- with $route.match.resourcePath }}
    resource: {{ printf "%s%s" $.Values.policy.httpbinResourceBase . | quote }}
{{- end }}
{{- end }}
{{- with $route.match.audience }}
    audience: {{ . | quote }}
{{- end }}
  response:
{{ toYaml $route.response | indent 4 }}
{{- end }}
{{- end }}

{{- define "ext-authz-token-exchange-e2e.policyConfig" -}}
{{- $resources := .resources }}
{{- if not (hasKey . "resources") }}
{{- $resources = list (printf "%s%s" $.Values.policy.httpbinResourceBase .pathPrefix) }}
{{- end }}
{{- $audiences := .audiences }}
{{- if and (not (hasKey . "audiences")) .audience }}
{{- $audiences = list .audience }}
{{- end }}
{{- $issuerRef := .issuerRef | default "fake-issuer" }}
version: v1
entries:
  - match:
      host: {{ $.Values.host }}
      pathPrefix: {{ .pathPrefix }}
{{- if .methods }}
      methods:
{{ .methods | toYaml | indent 8 }}
{{- end }}
{{- if eq .action "deny" }}
    action: deny
{{- else }}
{{- if .action }}
    action: {{ .action }}
{{- else }}
    action: exchange
{{- end }}
    exchange:
      issuerRef: {{ $issuerRef | quote }}
      scope: {{ .scope }}
{{- if $resources }}
      resources:
{{- range $resource := $resources }}
        - {{ $resource | quote }}
{{- end }}
{{- end }}
{{- if $audiences }}
      audiences:
{{- range $audience := $audiences }}
        - {{ $audience | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
