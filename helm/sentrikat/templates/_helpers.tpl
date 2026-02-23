{{/*
Expand the name of the chart.
*/}}
{{- define "sentrikat.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "sentrikat.fullname" -}}
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
{{- define "sentrikat.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sentrikat.labels" -}}
helm.sh/chart: {{ include "sentrikat.chart" . }}
{{ include "sentrikat.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sentrikat.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sentrikat.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
PostgreSQL fully qualified name
*/}}
{{- define "sentrikat.postgresql.fullname" -}}
{{- printf "%s-postgres" (include "sentrikat.fullname" .) }}
{{- end }}

{{/*
PostgreSQL labels
*/}}
{{- define "sentrikat.postgresql.labels" -}}
helm.sh/chart: {{ include "sentrikat.chart" . }}
{{ include "sentrikat.postgresql.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
PostgreSQL selector labels
*/}}
{{- define "sentrikat.postgresql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sentrikat.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgres
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "sentrikat.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sentrikat.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Container image with tag
*/}}
{{- define "sentrikat.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/*
Generate DATABASE_URL from components if not explicitly set
*/}}
{{- define "sentrikat.databaseUrl" -}}
{{- if .Values.secrets.databaseUrl }}
{{- .Values.secrets.databaseUrl }}
{{- else }}
{{- printf "postgresql://%s:%s@%s:5432/%s" .Values.postgresql.username .Values.secrets.dbPassword (include "sentrikat.postgresql.fullname" .) .Values.postgresql.database }}
{{- end }}
{{- end }}
