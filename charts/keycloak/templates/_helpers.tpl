{{- define "keycloak.labels" -}}
{{ .Values.labels.partOfKey }}: {{ .Values.labels.partOfValue | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end }}

{{- define "keycloak.realmConfigMapName" -}}
{{- printf "%s-realm" .Values.keycloak.name -}}
{{- end }}
