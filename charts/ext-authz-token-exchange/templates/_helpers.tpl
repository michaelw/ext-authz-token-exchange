{{/*
Expand the name of the chart.
*/}}
{{- define "ext-authz-token-exchange.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "ext-authz-token-exchange.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "ext-authz-token-exchange.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ext-authz-token-exchange.labels" -}}
helm.sh/chart: {{ include "ext-authz-token-exchange.chart" . }}
{{ include "ext-authz-token-exchange.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ext-authz-token-exchange.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ext-authz-token-exchange.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the Kubernetes Service rendered by common.itsumi.
*/}}
{{- define "ext-authz-token-exchange.serviceName" -}}
{{- include "ext-authz-token-exchange.fullname" . }}
{{- end }}

{{/*
Name of the issuer profile ConfigMap consumed by the plugin.
*/}}
{{- define "ext-authz-token-exchange.issuerProfilesConfigMapName" -}}
{{- .Values.issuerProfiles.configMapName | default (printf "%s-issuer-profiles" (include "ext-authz-token-exchange.fullname" .)) -}}
{{- end }}

{{/*
Name of the optional OAuth client credential Secret rendered by the chart.
*/}}
{{- define "ext-authz-token-exchange.oauthSecretName" -}}
{{- if .Values.oauth.createSecret -}}
{{- .Values.oauth.secretName -}}
{{- else -}}
{{- .Values.oauth.existingSecret.name -}}
{{- end -}}
{{- end }}

{{/*
Runtime environment rendered from operator env plus chart-owned issuer profile wiring.
*/}}
{{- define "ext-authz-token-exchange.env" -}}
{{- $env := dict
  "POD_NAMESPACE" (dict "valueFrom" (dict "fieldRef" (dict "fieldPath" "metadata.namespace")))
  "TOKEN_EXCHANGE_ISSUER_PROFILES_FILE" (printf "%s/%s" (.Values.issuerProfiles.mountPath | default "/etc/ext-authz-token-exchange") (.Values.issuerProfiles.fileName | default "issuers.yaml"))
}}
{{- with .Values.env }}
{{- $env = mergeOverwrite $env . }}
{{- end }}
{{- toYaml $env }}
{{- end }}
