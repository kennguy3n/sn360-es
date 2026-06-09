# SN360-ES Documentation Index

The single entry point for SN360-ES documentation. SN360-ES is the
multi-tenant, privacy-first email-security data plane; this index maps
every design, operational, and reference document and points outward to
the control-plane and agent repositories it integrates with.

New to the codebase? Read in this order: **PROPOSAL** (why) →
**ARCHITECTURE** (how it fits together) → **CODEBASE_GUIDE** (where the
code lives).

## Architecture & Design

| Document | What it covers |
|---|---|
| [`PROPOSAL.md`](./PROPOSAL.md) | Design rationale: tiered ML pipeline (Tier 0/1/2), privacy architecture, zero-admin platform, resilience scoring formula. |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | Runtime topology, data flow, role split (api / consumers / workers), SLOs. |
| [`CODEBASE_GUIDE.md`](./CODEBASE_GUIDE.md) | Contributor-oriented map of the source tree (`cmd/`, `internal/`, `pkg/`). |
| [`MULTI_REGION.md`](./MULTI_REGION.md) | Multi-region Postgres routing, NATS super-cluster bridge, env-var contract, failure semantics. |
| [`SCHEMA_VERSIONING.md`](./SCHEMA_VERSIONING.md) | NATS message schema versioning, compatibility rules, upgrade choreography. |
| [`DEGRADATION_MODES.md`](./DEGRADATION_MODES.md) | What the binary does when each optional dependency (Postgres, Redis, NATS, LLM) is missing or unhealthy. |
| [`CATEGORIZER_WEIGHTS.md`](./CATEGORIZER_WEIGHTS.md) | Every weight in `evaluate.CategoryWeights`, defaults, and operator overrides. |

## Domain Guides

- **Education / training simulations** — `internal/service/education/`.
  Phishing-simulation templates live in
  `internal/service/education/templates/*.json` (24 baseline templates
  across 8 attack types × 3 difficulties, plus 8 regulatory templates
  labelled `hipaa` / `pci_dss` / `sox` for compliance reporting).
  Campaign analytics is served by `GET /v1/education/analytics`
  (`internal/handler/education_analytics.go`,
  `internal/service/education/analytics.go`) and is strictly
  tenant-scoped: the aggregator only reads interactions for campaigns
  returned by the tenant-bound `CampaignStore`, and the handler rejects
  any `tenant_id` that disagrees with the JWT-bound tenant.
- **Dashboard** — `internal/service/dashboard/` and
  `GET /v1/dashboard/summary`.
- **Evaluation pipeline** — `internal/service/evaluate/`; see
  `CATEGORIZER_WEIGHTS.md` for scoring.

## API Reference

- OpenAPI 3.1 spec: [`../api/openapi.yaml`](../api/openapi.yaml) (also
  served at `/openapi.yaml`, with Swagger UI at `/docs/`).
- The README's "Project Status" matrix lists the readiness of each
  `/v1/*` route.

## Runbooks

Operational procedures are referenced by the `runbook_url` annotations
on every alert in the PrometheusRule manifests
(`deployments/helm/sn360-es/templates/prometheusrule.yaml`,
`deployments/encoder/prometheusrule.yaml`,
`deployments/llm/prometheusrule.yaml`). They resolve to anchors in
`docs/RUNBOOKS.md`. Key entries:

| Alert | Trigger | Runbook anchor |
|---|---|---|
| `SN360ESTier1LatencyHigh` | Tier-1 encoder p99 over SLO | `RUNBOOKS.md#tier1-latency` |
| `SN360ESEncoderCapacityExhausted` | Encoder HPA at max replicas AND queue backlog > 200 for 5m | `RUNBOOKS.md#encoder-capacity-exhausted` |
| `SN360ESLLMCapacityExhausted` | Tier-2 LLM HPA at max replicas AND queue backlog > 100 for 5m | `RUNBOOKS.md#llm-capacity-exhausted` |

> **Operator adoption:** the Helm chart sets the Prometheus Operator
> `ruleSelector` label via `.Values.prometheusRule.labels`. If you apply
> the raw `deployments/encoder/` and `deployments/llm/` PrometheusRule
> manifests directly (not through Helm/an overlay), patch in the label
> your operator selects on (commonly `release: kube-prometheus-stack`),
> or the operator will silently ignore the rules and the alerts above
> will never fire.

Autoscaling reference: the encoder fleet (`deployments/encoder/`) scales
on JetStream queue depth (`nats_consumer_pending_messages`) between 2 and
12 replicas (a `minReplicas: 2` HA floor on the Tier-1 path); the Tier-2
LLM (`deployments/llm/`) is a StatefulSet with a per-pod PVC and scales
between 1 and 2 replicas. See each directory's `hpa.yaml` for the exact
thresholds and the rationale comments.

For degraded-dependency behaviour (the "what breaks and how it fails
safe" view), see [`DEGRADATION_MODES.md`](./DEGRADATION_MODES.md).

## Deployment

- Helm chart: [`../deployments/helm/sn360-es/README.md`](../deployments/helm/sn360-es/README.md).
- GitOps (ArgoCD) source of truth: `deployments/argocd/application.yaml`.
- Raw ML-inference manifests: `deployments/encoder/`, `deployments/llm/`.
- Schema migrations: [`../migrations/README.md`](../migrations/README.md).

> **Migration runbook — LLM Deployment → StatefulSet:** the Tier-2 LLM
> moved from a `Deployment` backed by one shared PVC
> (`sn360-es-llm-models`) to a `StatefulSet` with per-pod PVCs
> (`models-sn360-es-llm-<ordinal>`). Kubernetes does not reclaim the old
> PVC on a kind change, so after rollout — once the new per-pod claims
> are bound and serving — delete the orphan to reclaim storage:
> `kubectl -n sn360-es delete pvc sn360-es-llm-models`. Do not delete the
> per-pod claims.

## Integration Points

SN360-ES is the email-security data plane within the broader SN360
platform. Integration contracts (auth, tenancy, control-plane APIs) are
owned by the control plane:

| Repo | Integration |
|---|---|
| [`sn360-security-platform`](https://github.com/kennguy3n/sn360-security-platform) | Multi-tenant control plane: tenant provisioning, IAM-core JWKS (the `iam-core` issuer SN360-ES validates JWTs against), and the customer-facing console that consumes the dashboard + analytics APIs. |
| [`sn360-desktop-agent`](https://github.com/kennguy3n/sn360-desktop-agent) | Endpoint agent (Windows / Linux / macOS). |
| [`sn360-agent-vm`](https://github.com/kennguy3n/sn360-agent-vm) | Server / VM agent. |
| [`sn360-agent-k8s`](https://github.com/kennguy3n/sn360-agent-k8s) | Kubernetes agent. |

## Search

There is no doc search server — use `ripgrep` (`rg`) across the tree:

```bash
# Find where a symbol is defined or used
rg --type go 'func .*ComputeAnalytics'

# Search the docs only
rg -n 'resilience' docs/

# Find a config env var and its binding
rg -n 'AI.URL|AI_URL' internal/config

# List every /v1 route registration
rg -n 'mux.Handle' cmd/sn360-es/routes.go
```

The [`CODEBASE_GUIDE.md`](./CODEBASE_GUIDE.md) is the fastest way to know
*which directory* to point `rg` at before searching.
