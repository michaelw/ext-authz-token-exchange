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
