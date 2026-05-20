# sn360-es Helm chart

Packages the SN360-ES API + listener, its migration Job, and an
optional bundled NATS JetStream cluster.

## Quick start

```bash
helm dependency build deployments/helm/sn360-es
helm install sn360-es deployments/helm/sn360-es \
  --namespace sn360 --create-namespace \
  --set secret.data.pgPassword=$PG_PASSWORD \
  --set secret.data.jwtSigningKey=$JWT_KEY
```

Override defaults with one of the per-environment files: `values.dev.yaml`,
`values.qa.yaml`, `values.uat.yaml`, or `values.prod.yaml`. The ArgoCD
`Application` selects the right file per cluster (see below).

## Values

See [`values.yaml`](./values.yaml) for the full list with inline
documentation. Key sections:

| Section            | Purpose                                                            |
|--------------------|--------------------------------------------------------------------|
| `image`            | Container image repository, tag, pull policy and pull secrets.     |
| `service`          | ClusterIP/LoadBalancer service and target port.                    |
| `ingress`          | Optional `Ingress` resource (off by default).                      |
| `resources`        | Pod CPU/memory requests + limits.                                  |
| `autoscaling`      | Horizontal Pod Autoscaler (off by default).                        |
| `probes`           | Liveness/readiness paths — see `internal/handler/health.go`.       |
| `config`           | Plain config rendered into a `ConfigMap`.                          |
| `secret`           | Sensitive config rendered into an Opaque `Secret`.                 |
| `migrations`       | Pre-install/upgrade `Job` running `sn360-es-migrate up`.           |
| `nats`             | Bundled NATS JetStream cluster (subchart).                         |
| `serviceMonitor`   | `ServiceMonitor` for Prometheus Operator scraping `/metrics`.      |

## Resources rendered

- `Deployment` (rolling update, surge 25%, max-unavailable 0)
- `Service` (ClusterIP, port 80 → container 8080)
- `ConfigMap` + `Secret`
- `ServiceAccount` (no token mount)
- `HorizontalPodAutoscaler` (when `autoscaling.enabled=true`)
- `Ingress` (when `ingress.enabled=true`)
- `ServiceMonitor` (when `serviceMonitor.enabled=true`)
- pre-install/pre-upgrade `Job` running migrations
- `nats` subchart resources

## ArgoCD

The companion ArgoCD `Application` manifest lives at
[`deployments/argocd/application.yaml`](../../argocd/application.yaml).
It points to this chart and consumes the matching
`values.{dev,qa,uat,prod}.yaml` per cluster.
