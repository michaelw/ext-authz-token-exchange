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
Name of the OAuth client credential Secret consumed by the plugin.
*/}}
{{- define "ext-authz-token-exchange.oauthSecretName" -}}
{{- if .Values.oauth.createSecret -}}
{{- .Values.oauth.secretName -}}
{{- else -}}
{{- .Values.oauth.existingSecret.name -}}
{{- end -}}
{{- end }}

{{/*
Runtime environment rendered from operator env plus chart-owned OAuth refs.
*/}}
{{- define "ext-authz-token-exchange.env" -}}
{{- $secretName := include "ext-authz-token-exchange.oauthSecretName" . -}}
{{- $env := dict
  "OAUTH_CLIENT_ID" (dict "valueFrom" (dict "secretKeyRef" (dict "name" $secretName "key" .Values.oauth.existingSecret.clientIDKey)))
  "OAUTH_CLIENT_SECRET" (dict "valueFrom" (dict "secretKeyRef" (dict "name" $secretName "key" .Values.oauth.existingSecret.clientSecretKey)))
}}
{{- with .Values.env }}
{{- $env = mergeOverwrite $env . }}
{{- end }}
{{- toYaml $env }}
{{- end }}
