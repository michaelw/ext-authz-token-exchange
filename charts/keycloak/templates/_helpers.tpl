{{- define "keycloak.labels" -}}
{{ .Values.labels.partOfKey }}: {{ .Values.labels.partOfValue | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end }}

{{- define "keycloak.realmConfigMapName" -}}
{{- printf "%s-realm" .Values.keycloak.name -}}
{{- end }}

{{- define "keycloak.gatewayProvider" -}}
{{- .Values.gatewayProvider | default "local-istio" -}}
{{- end }}

{{- define "keycloak.isGKEGateway" -}}
{{- eq (include "keycloak.gatewayProvider" .) "gke-gateway" -}}
{{- end }}

{{- define "keycloak.gatewayNamespace" -}}
{{- if eq (include "keycloak.isGKEGateway" .) "true" -}}
{{- .Values.gkeGatewayNamespace | default .Values.gateway.namespace -}}
{{- else -}}
{{- .Values.gateway.namespace -}}
{{- end -}}
{{- end }}

{{- define "keycloak.pluginNamespace" -}}
{{- if eq (include "keycloak.isGKEGateway" .) "true" -}}
{{- .Values.gkeGatewayNamespace | default .Values.pluginNamespace -}}
{{- else -}}
{{- .Values.pluginNamespace -}}
{{- end -}}
{{- end }}

{{- define "keycloak.gatewaySectionName" -}}
{{- if eq (include "keycloak.isGKEGateway" .) "true" -}}
https
{{- else -}}
{{- .Values.gateway.sectionName -}}
{{- end -}}
{{- end }}

{{- define "keycloak.httpRedirectEnabled" -}}
{{- and (not .Values.gateway.httpRedirect.forceDisabled) (or .Values.gateway.httpRedirect.enabled (eq (include "keycloak.isGKEGateway" .) "true")) -}}
{{- end }}

{{- define "keycloak.httpRedirectSectionName" -}}
{{- if eq (include "keycloak.isGKEGateway" .) "true" -}}
http
{{- else -}}
{{- .Values.gateway.httpRedirect.sectionName -}}
{{- end -}}
{{- end }}

{{- define "keycloak.gkeIapEnabled" -}}
{{- and (not .Values.gkeIap.forceDisabled) (or .Values.gkeIap.enabled (eq (include "keycloak.isGKEGateway" .) "true")) -}}
{{- end }}

{{- define "keycloak.routeNamespace" -}}
{{- .Values.gateway.routeNamespace | default .Values.namespace -}}
{{- end }}

{{- define "keycloak.gkeHealthCheckEnabled" -}}
{{- or .Values.gkeHealthCheck.enabled (eq (include "keycloak.isGKEGateway" .) "true") -}}
{{- end }}
