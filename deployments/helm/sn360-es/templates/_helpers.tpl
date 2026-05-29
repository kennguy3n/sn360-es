{{/*
Expand the name of the chart.
*/}}
{{- define "sn360-es.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "sn360-es.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Common labels shared by every rendered object.
*/}}
{{- define "sn360-es.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "sn360-es.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: sn360
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "sn360-es.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sn360-es.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Service account name.
*/}}
{{- define "sn360-es.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "sn360-es.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image reference (repository:tag).
*/}}
{{- define "sn360-es.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "sn360-es.migrateImage" -}}
{{- $tag := default .Chart.AppVersion .Values.migrations.image.tag -}}
{{- printf "%s:%s" .Values.migrations.image.repository $tag -}}
{{- end -}}

{{/*
Checksum of the rendered ConfigMap so Pods restart when config changes.
*/}}
{{- define "sn360-es.configChecksum" -}}
{{- $cm := include (print $.Template.BasePath "/configmap.yaml") . -}}
{{- $cm | sha256sum -}}
{{- end -}}

{{/*
Per-role fullname for the role-split topology. Appends the role
suffix to the chart's fullname so each Deployment / Service /
HPA / ScaledObject has a unique, predictable name.

Usage:
  {{ include "sn360-es.roleFullname" (dict "ctx" . "role" "api") }}

The release `sn360-es` becomes `sn360-es-api`, `sn360-es-consumers`,
`sn360-es-workers`. Operators querying `kubectl get deploy -l
app.kubernetes.io/component=consumers` get a clean role view.
*/}}
{{- define "sn360-es.roleFullname" -}}
{{- $base := include "sn360-es.fullname" .ctx -}}
{{- printf "%s-%s" $base .role | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Per-role selector labels. Adds `app.kubernetes.io/component=<role>`
on top of the shared chart selector so role-specific Deployments,
Services, and HPAs use disjoint label sets.

Usage:
  {{ include "sn360-es.roleSelectorLabels" (dict "ctx" . "role" "api") }}
*/}}
{{- define "sn360-es.roleSelectorLabels" -}}
{{ include "sn360-es.selectorLabels" .ctx }}
app.kubernetes.io/component: {{ .role }}
{{- end -}}

{{/*
Per-role full label set. Equivalent to `sn360-es.labels` plus the
role component label.

Usage:
  {{ include "sn360-es.roleLabels" (dict "ctx" . "role" "api") }}
*/}}
{{- define "sn360-es.roleLabels" -}}
{{ include "sn360-es.labels" .ctx }}
app.kubernetes.io/component: {{ .role }}
{{- end -}}
