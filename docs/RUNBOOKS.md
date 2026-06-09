# SN360-ES Runbooks

Operational procedures for the alerts defined in the PrometheusRule
manifests (`deployments/helm/sn360-es/templates/prometheusrule.yaml`,
`deployments/encoder/prometheusrule.yaml`,
`deployments/llm/prometheusrule.yaml`). Each alert's `runbook_url`
annotation links to the matching section below. See
[`index.md`](./index.md) for the documentation map and
[`DEGRADATION_MODES.md`](./DEGRADATION_MODES.md) for how the service
fails safe when a dependency is unhealthy.

How to use a runbook: confirm the alert is real (not a metrics gap),
find the dominant cause with the **Triage** queries, apply the smallest
**Mitigation** that restores the SLO, then capture **Follow-up** so the
condition doesn't recur.

---

## Tier1 latency

**Alert:** `SN360ESTier1LatencyHigh` — Tier-1 encoder p99 evaluation
latency is over its SLO.

**Impact:** Email risk verdicts are delayed. Inbound mail still flows
(evaluation is queue-backed via JetStream, so nothing is dropped), but
remediation actions (labelling, quarantine) lag behind delivery, which
widens the exposure window for malicious mail.

**Triage**
- Backlog vs. capacity: `max(nats_consumer_pending_messages{stream="ES_EVALUATE",consumer="es-evaluate-batch"})`
  and current/desired replicas
  `kube_horizontalpodautoscaler_status_current_replicas{horizontalpodautoscaler="sn360-es-encoder"}`.
  A climbing backlog with replicas below `maxReplicas` points at a
  scaling lag or a stuck metrics adapter; replicas pinned at the ceiling
  is capacity exhaustion — jump to
  [Encoder capacity exhausted](#encoder-capacity-exhausted).
- Per-pod health: `kubectl -n sn360-es top pods -l app.kubernetes.io/name=sn360-es-encoder`
  and check for GPU saturation, OOMKills, or CrashLoopBackOff
  (`kubectl -n sn360-es get pods -l app.kubernetes.io/name=sn360-es-encoder`).
- Adapter sanity: confirm the Prometheus adapter is still serving the
  external metric (`kubectl get --raw "/apis/external.metrics.k8s.io/v1beta1"`).
  A missing metric leaves the HPA scaling on CPU/memory only and is a
  common cause of "latency up, replicas flat".

**Mitigation**
- If the backlog is high and replicas are below the ceiling but not
  scaling, restart/repair the metrics adapter so the queue-depth signal
  drives scale-up; as a stopgap, bump `minReplicas` in
  `deployments/encoder/hpa.yaml` to add warm pods immediately.
- If a single pod is wedged (GPU stuck, not Ready), delete it so the
  Deployment reschedules a healthy replacement.
- If load is genuinely above plan, raise `maxReplicas` (and confirm node
  / GPU capacity) — see the capacity runbook below.

**Follow-up:** if max-capacity was reached under expected traffic,
revisit `maxReplicas` and the per-pod `averageValue` target in
`deployments/encoder/hpa.yaml` against the measured per-pod throughput.

---

## Encoder capacity exhausted

**Alert:** `SN360ESEncoderCapacityExhausted` — the encoder HPA has been
at its `maxReplicas` ceiling for 5m while the `es.evaluate.request`
backlog is above 200 pending messages.

**Impact:** Autoscaling has nothing left to give. Tier-1 evaluation
latency will keep climbing until the backlog is drained. No data is lost
(JetStream retains pending messages), but verdict/remediation lag grows
for every tenant.

**Triage**
- Confirm the ceiling: compare
  `kube_horizontalpodautoscaler_status_current_replicas` with
  `kube_horizontalpodautoscaler_spec_max_replicas` for
  `horizontalpodautoscaler="sn360-es-encoder"`.
- Confirm the backlog trend is rising, not a one-off spike:
  `max(nats_consumer_pending_messages{stream="ES_EVALUATE",consumer="es-evaluate-batch"})`
  over the last 30–60m.
- Rule out node/GPU starvation that prevents new pods from scheduling:
  `kubectl -n sn360-es get pods -l app.kubernetes.io/name=sn360-es-encoder`
  for `Pending` pods and `kubectl describe` for unschedulable events.

**Mitigation**
- Raise `maxReplicas` in `deployments/encoder/hpa.yaml` and apply, after
  confirming GPU node capacity (autoscale the GPU node pool if needed).
- If GPU capacity is the hard limit, shed or throttle upstream ingestion
  (pause non-critical mailbox sync / lower batch concurrency) until the
  backlog drains.

**Follow-up:** if this fires under expected traffic, the steady-state
ceiling is too low — re-baseline `maxReplicas` and the per-pod
`averageValue` target against measured per-pod throughput, and size the
GPU node pool to match.

---

## LLM capacity exhausted

**Alert:** `SN360ESLLMCapacityExhausted` — the Tier-2 LLM HPA has been at
its `maxReplicas` ceiling for 5m while its consumer backlog is above 100
pending messages.

**Impact:** Tier-2 (the slow, LLM-backed path that handles ~10–20% of
traffic — ambiguous/high-risk mail) is saturated. Tier-0/Tier-1 verdicts
are unaffected; only the cases escalated to the LLM are delayed.

**Triage**
- Confirm the ceiling for `horizontalpodautoscaler="sn360-es-llm"`
  (current vs. `spec_max_replicas`).
- Check the Tier-2 consumer backlog trend and per-pod GPU utilisation
  (`kubectl -n sn360-es top pods -l app.kubernetes.io/name=sn360-es-llm`).
- Because the LLM runs as a StatefulSet with per-pod PVCs
  (`models-sn360-es-llm-<ordinal>`), verify each replica's model volume
  is `Bound` and the model loaded — a pod stuck loading its GGUF presents
  as reduced capacity, not a crash. `kubectl -n sn360-es get pvc -l app.kubernetes.io/name=sn360-es-llm`.

**Mitigation**
- Raise `maxReplicas` in `deployments/llm/hpa.yaml` (and confirm GPU
  capacity) if Tier-2 escalation volume is legitimately high.
- If GPU is the hard limit, tighten the Tier-1→Tier-2 escalation
  threshold so fewer messages are promoted to the LLM path until the
  backlog clears.

**Follow-up:** review the escalation rate driving Tier-2 volume; a spike
often signals a tuning regression upstream rather than a true capacity
need.
