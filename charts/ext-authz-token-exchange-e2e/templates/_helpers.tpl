{{- define "ext-authz-token-exchange-e2e.labels" -}}
{{ .Values.labels.partOfKey }}: {{ .Values.labels.partOfValue | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end }}

{{- define "ext-authz-token-exchange-e2e.teamNamespace" -}}
{{- printf "%s-%s" $.Values.namespacePrefix .color -}}
{{- end }}

{{- define "ext-authz-token-exchange-e2e.tokenEndpointURL" -}}
{{- printf "http://%s.%s.svc.cluster.local:%v%s" $.Values.fakeTokenEndpoint.name $.Values.systemNamespace $.Values.fakeTokenEndpoint.port .tokenPath -}}
{{- end }}

{{- define "ext-authz-token-exchange-e2e.policyConfig" -}}
version: v1
entries:
  - host: {{ $.Values.host }}
    pathPrefix: {{ .pathPrefix }}
    methods: ["GET", "POST", "OPTIONS"]
    scope: {{ .scope }}
    resource: {{ $.Values.policy.httpbinResourceBase }}{{ .pathPrefix }}
    tokenEndpoint: {{ include "ext-authz-token-exchange-e2e.tokenEndpointURL" (dict "Values" $.Values "tokenPath" .tokenPath) }}
{{- end }}
