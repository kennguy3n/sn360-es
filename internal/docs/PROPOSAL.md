# SN360-ES v2 — Proposal: Tiered ML Pipeline, Privacy Architecture & Zero-Admin Platform

## Executive Summary

SN360-ES v1 (NGES) delivers a functional email security pipeline but sends every
email through a full LLM call, uses Redis Streams without durability guarantees,
stores email metadata without privacy controls, exposes a single generic "FYI"
label to end users, and requires manual admin for configuration and monitoring.

This proposal transforms the platform into a **privacy-first, zero-admin, cost-
effective email security product** for SMEs — powered by a 3-tier ML pipeline,
NATS JetStream event bus, AI agent operation, a competitor-grade tiered banner
and native-label UX, and integrated email education.

---

## 1. NATS JetStream — Replacing Redis Streams

### Why Replace Redis Streams

| Concern | Redis Streams (current) | NATS JetStream (proposed) |
|---|---|---|
| **Durability** | In-memory; data lost on Redis restart without AOF | Persistent file-based storage with configurable retention |
| **Dead-letter queue** | Manual implementation required | Built-in max delivery count → DLQ subject |
| **Message dedup** | None | Built-in dedup window (configurable, default 2min) |
| **Replay** | Only from consumer group position | Replay by time, sequence, or last per subject |
| **Backpressure** | None (unbounded stream) | Flow control + max pending per consumer |
| **Multi-tenancy** | Flat key namespace | Subject hierarchy (`es.{tenant}.evaluate.request`) |
| **Ops overhead** | Redis cluster for HA | NATS cluster with built-in Raft consensus |
| **Cost** | Redis memory = expensive at scale | NATS file storage = cheap, memory for hot path only |

### JetStream Subject Design

```
es.>                                  # All SN360-ES events
es.onboarding.>                       # Onboarding events
es.onboarding.user.created            # User created
es.onboarding.user.deleted            # User deleted
es.evaluate.>                         # Evaluation pipeline
es.evaluate.request                   # Evaluate request (ingestion → evaluate)
es.evaluate.result                    # Evaluate result (evaluate → ingestion + management)
es.evaluate.result.attachment         # Attachment scan result
es.evaluate.dlq                       # Dead-letter queue for failed evaluations
es.education.>                        # Education platform
es.education.simulation.send          # Send phishing simulation
es.education.simulation.result        # User interaction result
es.education.lesson.trigger           # Trigger micro-lesson
es.action.>                           # Post-evaluation actions
es.action.banner                      # Banner injection
es.action.label                       # Label application
es.action.quarantine                  # Quarantine action
```

### JetStream Stream Configuration

```yaml
streams:
  ES_EVALUATE:
    subjects: ["es.evaluate.>"]
    retention: WorkQueue           # Messages removed after ack
    storage: File                  # Persistent
    max_age: 24h                   # Auto-purge unprocessed after 24h
    max_msg_size: 10MB             # Max email payload
    discard: Old                   # Discard oldest when full
    num_replicas: 3                # Raft replication
    dedup_window: 2m               # Reject duplicate message IDs

  ES_ONBOARDING:
    subjects: ["es.onboarding.>"]
    retention: WorkQueue
    storage: File
    max_age: 72h
    num_replicas: 3

  ES_EDUCATION:
    subjects: ["es.education.>"]
    retention: Limits              # Keep history for analytics
    storage: File
    max_age: 90d
    num_replicas: 3

  ES_DLQ:
    subjects: ["es.evaluate.dlq", "es.action.dlq"]
    retention: Limits
    storage: File
    max_age: 30d                   # Keep failed events for investigation
    num_replicas: 3
```

### Consumer Configuration

```yaml
consumers:
  evaluate_worker:
    stream: ES_EVALUATE
    filter: "es.evaluate.request"
    deliver_policy: All
    ack_policy: Explicit
    max_deliver: 5                 # Retry 5 times before DLQ
    ack_wait: 60s                  # 60s processing timeout
    max_ack_pending: 100           # Backpressure: max 100 in-flight
    deliver_group: "evaluate-svc"  # Queue group for horizontal scaling

  action_worker:
    stream: ES_EVALUATE
    filter: "es.evaluate.result"
    deliver_policy: All
    ack_policy: Explicit
    max_deliver: 3
    ack_wait: 30s
    max_ack_pending: 50
    deliver_group: "ingestion-svc"
```

### Migration Path

1. Implement `pkg/events/nats/` with same `EventService` interface as current `pkg/events/redis/`
2. Feature-flag: `EVENT_BUS_TYPE=nats|redis` (default `redis` during transition)
3. Run dual-write during migration window
4. Cut over service-by-service
5. Remove Redis Streams code after full migration
6. Redis remains for caching (score weights, classifications, vendor lists, relationships, poller locks)

### Micro-Batching with JetStream

JetStream consumers natively support batch fetch:

```go
// Fetch up to 50 messages, wait max 200ms
msgs, err := sub.Fetch(50, nats.MaxWait(200*time.Millisecond))
```

This enables:
- Batch Tier 0 classification (rule-based, CPU-only)
- Batch Tier 1 encoder inference (GPU batch = higher throughput)
- Batch Tier 2 LLM calls (batch API endpoints)
- Single Redis pipeline for loading all tenant configs per batch

---

## 2. Privacy-Centric Architecture

### Design Principles

1. **Zero-knowledge by default** — Platform cannot read stored email content
2. **Minimize, pseudonymize, encrypt** — Collect minimum, hash PII, encrypt remainder
3. **Tenant isolation** — Cryptographic boundary between tenants
4. **Right to erasure** — Cryptographic erasure via key deletion
5. **Audit everything** — Immutable log of all data access, no PII in logs

### Data Classification

| Data Type | Classification | Handling |
|---|---|---|
| Email body (raw) | **Critical PII** | In-memory only during evaluation; never persisted |
| Email headers (From, To, Subject) | **PII** | Pseudonymized (Blake2 hash) before storage |
| Sender/receiver addresses | **PII** | Stored as `blake2(address)` for relationship tracking |
| Risk scores | **Internal** | Stored encrypted at rest |
| Detection reasons | **Sensitive** | Stored without PII references (generic descriptions) |
| Banner HTML | **Transient** | Generated in-memory, injected, not stored |
| Tenant config | **Confidential** | Encrypted at rest, per-tenant key |
| Audit logs | **Compliance** | Append-only, no PII, retained per policy |

### Privacy Architecture

```mermaid
graph TD
    subgraph "Email Provider"
        Email["Raw Email"]
    end

    subgraph "SN360-ES Processing (In-Memory Only)"
        Fetch["Fetch via API"]
        Normalize["Normalize + PII Tag"]
        Evaluate["3-Tier Detection"]
        Action["Banner/Label Action"]
    end

    subgraph "Persistent Storage (Encrypted)"
        PG["PostgreSQL"]
        Redis["Redis Cache"]
        Audit["Audit Log"]
    end

    subgraph "What Gets Stored"
        Meta["Pseudonymized metadata"]
        Score["Encrypted risk scores"]
        Rel["Hashed relationship pairs"]
        Config["Encrypted tenant config"]
    end

    Email --> Fetch
    Fetch --> Normalize
    Normalize --> Evaluate
    Evaluate --> Action
    Action -->|"Modify email in provider"| Email

    Evaluate -->|"Score + reasons only"| Meta
    Meta --> PG
    Evaluate -->|"blake2(sender):blake2(receiver)"| Rel
    Rel --> Redis
    Evaluate -->|"score, action, timestamp"| Score
    Score --> PG
    Action -->|"action_type, timestamp, no PII"| Audit
```

### Per-Tenant Encryption

```
┌─────────────────────────────────────┐
│  AWS KMS Master Key (per region)    │
│  └─ Tenant Data Key (per tenant)    │
│     └─ AES-256-GCM encryption       │
│        ├─ PostgreSQL column-level    │
│        ├─ Redis value-level          │
│        └─ S3 object-level            │
└─────────────────────────────────────┘
```

- **Tenant deletion** = delete tenant data key = **cryptographic erasure** of all tenant data
- Key rotation on configurable schedule (default quarterly)
- Keys never leave KMS; envelope encryption with data keys

### PII Pseudonymization (`pkg/privacy/`)

```go
// All email addresses stored as pseudonyms
type Pseudonymizer interface {
    // Hash returns blake2b-256 hash of input, keyed per tenant
    Hash(tenantKey []byte, input string) string
    // Pseudonymize replaces PII fields in a struct with hashes
    Pseudonymize(tenantKey []byte, data any) any
}

// Relationship tracking uses hashed pairs
// "alice@company.com" → "b2:a1b2c3d4e5f6..."
// Relationships: hash(sender) → hash(receiver) with counts
```

### Log Sanitization

All structured logging passes through a sanitizer that:
- Replaces email addresses with `***@domain` (domain kept for debugging)
- Strips email subjects entirely
- Masks tenant credentials
- Preserves correlation IDs, timestamps, and error codes

Current Rspamd already has `subject_privacy` with Blake2 hashing — extend this pattern platform-wide.

### Compliance Matrix

| Regulation | SN360-ES Coverage |
|---|---|
| **GDPR** | Right to erasure (crypto-shred), data minimization, pseudonymization, DPA-ready |
| **SOC 2 Type II** | Audit logs, access controls, encryption, availability monitoring |
| **ISO 27001** | Risk-based controls, incident management, asset classification |
| **PDPA (Thailand)** | Data residency controls, consent management, breach notification |
| **CCPA** | Data inventory, deletion on request, no sale of personal data |
| **HIPAA** | BAA-ready, encryption, access controls, audit trails (healthcare SMEs) |

---

## 3. Tiered ML Detection Pipeline

### Tier 0 — Classification Gate (cost: ~$0, latency: <1ms)

Uses existing `buildRiskSignals()` output as **gates** instead of just metadata:

| Signal | Action | Estimated Bypass |
|---|---|---|
| `IsInternal` | Skip all ML → Score 0 + "Internal" trusted chip | 30-40% of total |
| `IsFromVendor` | Skip all ML → Score 0 + "Vendor" trusted chip | 10-15% |
| `IsHighVolumeSender` | Skip ML → Rspamd-only score | 10-15% |
| `IsRecurringService` (new) | Skip ML → Score 0 (noreply@, mailer-daemon) | 5-10% |
| `RelationshipCategory == Partner/Customer` (new) | Lower Tier 1 threshold | N/A (threshold adjust) |
| `RelationshipCategory == FirstTimeExternal` (new) | Always escalate to Tier 1 | N/A (force escalation) |

**Total Tier 0 bypass: 60-70% of emails never touch ML.**

Implementation: Early return in `processEvaluate()` before launching goroutines.
Config flags: `TIER0_SKIP_INTERNAL`, `TIER0_SKIP_VENDOR`, `TIER0_SKIP_RECURRING`.

### Tier 1 — Encoder-Only Model (cost: ~$0.00005, latency: 50-200ms)

Self-hosted **XLM-RoBERTa-base** or **mDeBERTa-v3** on K8s:

- **Multilingual native**: 100+ languages, handles mixed-language (e.g., English subject + Thai body)
- **Fine-tuned** on multilingual phishing/BEC/scam datasets
- **Binary + confidence**: Outputs risk score 0-100 with calibrated confidence
- **Batch inference**: Processes up to 64 emails per GPU batch
- **CPU fallback**: ~200ms on CPU, ~20ms on GPU

Thresholds (configurable per tenant via score engine):
- Score < 20 → **PASS** (clear safe)
- Score 20-60 → **ESCALATE** to Tier 2 (ambiguous)
- Score > 60 → **FLAG** (high-confidence threat, skip LLM)

**Tier 2 escalation rate: 10-20% of Tier 1 input.**

### Tier 2 — Full LLM (cost: ~$0.001-0.01, latency: 2-10s)

Current AI service, invoked only for ambiguous emails:
- Full contextual analysis with aspect-level reasoning
- Relationship awareness (sender history, timing anomaly)
- Multilingual reasoning (language detected by Tier 1, passed as hint)
- Actionable recommendations in user's language

### Graceful Degradation

| Failure | Current Behavior | Proposed Behavior |
|---|---|---|
| AI/LLM down | **Total failure** (Rspamd discarded) | Tier 0 + Tier 1 + Rspamd continue; LLM results marked "pending" |
| Tier 1 encoder down | N/A | All external emails escalate to Tier 2 (cost spike but no outage) |
| Rspamd down | Silent skip | Log warning; ML tiers continue independently |
| NATS down | N/A (Redis currently) | Messages buffered in NATS file store; auto-recovery on reconnect |

### Combined Impact

| Metric | v1 (Current) | v2 (Proposed) |
|---|---|---|
| LLM calls/day (100 tenants × 5K emails) | ~500,000 | ~15,000-50,000 |
| Avg latency/email (p95) | 2-20s | 50-200ms |
| Monthly AI inference cost | ~$15,000 | ~$500-1,500 |
| Availability on AI outage | 0% | 95%+ |
| Languages supported | Depends on LLM | 100+ native (Tier 1) |

---

## 4. Zero-Admin AI-Agent Operation

### Design Philosophy

SMEs have no IT team. Every configuration decision, threshold tuning, and
incident response must be automated or trivially simple.

### Auto-Onboarding Flow

```mermaid
sequenceDiagram
    participant Admin as SME Admin
    participant UI as SN360 Portal
    participant Agent as AI Onboarding Agent
    participant Provider as GWS/O365
    participant Discovery as Org Discovery

    Admin->>UI: Click "Connect Email"
    UI->>Provider: OAuth consent flow
    Provider-->>UI: Access granted
    UI->>Agent: Trigger auto-onboarding
    Agent->>Provider: List users, groups, org units
    Provider-->>Agent: Directory data
    Agent->>Discovery: Build org graph
    Discovery->>Discovery: Identify high-risk groups
    Discovery->>Discovery: Map reporting hierarchy
    Discovery->>Discovery: Classify roles (C-suite, Finance, HR)
    Agent->>Agent: Configure default detection policy
    Agent->>Agent: Set per-group sensitivity thresholds
    Agent->>Agent: Generate initial vendor list from email history
    Agent-->>UI: Onboarding complete, N users protected
```

### AI Agent Capabilities

| Agent | Role | Replaces |
|---|---|---|
| **Onboarding Agent** | Auto-discover users, groups, roles; configure policies | Manual tenant setup |
| **Tuning Agent** | Analyze FP/FN rates; adjust per-tenant score weights and thresholds | Security engineer tuning |
| **Incident Agent** | Triage alerts, generate investigation summaries, suggest actions | SOC L1 analyst |
| **Education Agent** | Design phishing simulations tailored to tenant's threat profile | Security awareness program manager |
| **Compliance Agent** | Generate compliance reports, audit evidence, data retention enforcement | Compliance officer |
| **Support Agent** | Answer user questions about flagged emails, explain risk scores | IT helpdesk |

### Escalation to ShieldNet 360 SecOps

When AI agents cannot resolve:
1. **Auto-escalation triggers**: Confirmed breach indicators, account compromise, zero-day attachment
2. **Context package**: AI agent prepares investigation summary with anonymized evidence
3. **SN360 SecOps**: Human analysts take over, communicate via secure channel
4. **Resolution feedback**: Outcomes feed back into ML training pipeline

### Self-Tuning Thresholds

```mermaid
graph LR
    FP["False Positive Reports"] --> Tuning["Tuning Agent"]
    FN["Missed Threats"] --> Tuning
    Volume["Email Volume Patterns"] --> Tuning
    Tuning --> T0["Tier 0 bypass rules"]
    Tuning --> T1["Tier 1 thresholds"]
    Tuning --> Weights["Score engine weights"]
    Tuning --> Education["Education campaign difficulty"]
```

---

## 5. Email Education Platform

### Philosophy

Security awareness training fails because it's boring, infrequent, and disconnected
from real threats. SN360-ES embeds education **inside the email experience** — teaching
at the moment of relevance.

### Education Components

#### a) In-Context Micro-Lessons

When a suspicious email is detected, the banner (see Section 6 for full banner
specification) includes a contextual lesson:

```
┌──────────────────────────────────────────────────┐
│ ⚠ Warning: Likely Scam (Score: 72/100)           │
│                                                    │
│ > Sender domain "paypa1.com" mimics "paypal.com"  │
│ > Urgency language detected ("act now")            │
│                                                    │
│ 💡 Quick Lesson: Lookalike Domains                 │
│ Attackers register domains that look like trusted  │
│ brands by swapping letters (l→1, o→0). Always      │
│ check the sender's actual email address.           │
│                                                    │
│ [I understand ✓]  [Report as safe]  [Learn more]   │
└──────────────────────────────────────────────────┘
```

- Lessons are contextual to the specific threat type detected
- Available in all tenant languages (multilingual by default)
- Tracks whether user clicked "I understand" vs "Report as safe"

#### b) Automated Phishing Simulations

| Feature | Description |
|---|---|
| **Template library** | Real-world attack patterns: BEC, credential phishing, QR code, invoice fraud |
| **Auto-generation** | AI agent creates simulations based on tenant's actual threat profile |
| **Adaptive difficulty** | Easy → medium → hard based on employee performance |
| **Multilingual** | Simulations in employee's primary language |
| **Zero-setup** | Campaigns auto-scheduled; no admin configuration needed |
| **Safe landing page** | Clicked users see an instant teachable moment, not punishment |

#### c) Resilience Scoring

Per-employee and per-group resilience metrics:

```
Employee Resilience Score = f(
  simulation_performance,     # 40% — click rate on simulations
  report_rate,                # 25% — how often they report real threats
  lesson_engagement,          # 20% — interaction with micro-lessons
  incident_history,           # 15% — past involvement in real incidents
)
```

Scores feed back into:
- Detection sensitivity (lower thresholds for low-resilience users)
- Simulation frequency (more practice for those who need it)
- Aggregated tenant risk reports

#### d) Campaign Automation

```mermaid
graph TD
    subgraph "Education Engine"
        Profile["Tenant Threat Profile"]
        Templates["Simulation Templates"]
        AI["Education Agent"]
    end

    subgraph "Execution"
        Schedule["Auto-Scheduler"]
        Send["Send Simulations"]
        Track["Track Interactions"]
    end

    subgraph "Feedback Loop"
        Score["Update Resilience Scores"]
        Adapt["Adjust Difficulty"]
        Report["Generate Reports"]
    end

    Profile --> AI
    Templates --> AI
    AI --> Schedule
    Schedule --> Send
    Send --> Track
    Track --> Score
    Score --> Adapt
    Adapt --> AI
    Score --> Report
```

---

## 6. End-User Label & Banner UX — Competitor Research & Redesign

### Why the v1 "FYI Label" Is Not Enough

v1 ships a single generic `FYI` label per tenant — flat, monochrome, and devoid of
context. Users cannot tell at a glance whether an email is mildly external or an
active phishing attempt. Top-tier competitors all converged years ago on a richer
model: a **severity-tiered inline banner**, paired with a **native provider label**
(color-coded), specific **category names** instead of generic "suspicious", and
**one-click actions**. SN360-ES v2 adopts and improves on these patterns.

### Competitor Comparison

| Vendor | Inline Banner | Native Label / Tag | Severity Levels | One-Click Report | Categories Surface to User | Pre-Send Warning | URL Rewriting |
|---|---|---|---|---|---|---|---|
| **Microsoft Defender for O365** | First-contact tip + impersonation banner | "External" tag + safety tips | 2-3 (Tip / Warn / Block) | Built-in "Report message" add-in | Limited (External, First contact, Impersonation) | No (out of box) | Yes (Safe Links) |
| **Google Workspace** | External recipient warning bar | "External" label (gray) | 2 (Notice / Warn) | "Report phishing" menu | Limited (External, Encrypted notices) | Pre-send to external (Workspace add-on) | No |
| **Material Security** | Inline "Security Card" overlay | Gmail label per category | 3-4 | Yes (inline) | Yes (Phishing, BEC, Account Takeover, External) | No | Optional (selective redaction instead) |
| **Avanan / Check Point Harmony** | Color-coded severity banner | Gmail label + Outlook category | 3 (Suspected / Phishing / Malicious) | Yes (Restore / Report) | Yes (Phishing, Malware, Spam, etc.) | No | Yes (selective) |
| **Mimecast** | Header banner + footer disclaimer | "External" header tag | 3 (Notice / Caution / Hold) | "Report Phishing" add-in | Yes (Impersonation, URL, Attachment) | Yes (Outlook add-in) | Yes (URL Rewrite + Browser Isolation) |
| **Proofpoint Essentials** | "Email Warning Tag" colored banner | Subject-line prefix + label | 4 (Info / Caution / Warn / Danger) | "Report Suspicious" button | Yes (Impostor, Suspicious, Newsletter, External) | No (separate product) | Yes (URL Defense) |
| **IRONSCALES** | Themis banner | Gmail label + Outlook category | 3 (Spam / Suspicious / Phishing) | Yes (Themis bar, one-click) | Yes (Phishing, Spoofing, Impersonation) | Yes (Themis add-in) | Optional |
| **INKY** | "INKY Banner" with severity stripe | Gmail label per category | 3 (Neutral / Caution / Danger) | One-click "Mark as Phishing" | Yes (Lookalike, Stylometry, Brand Impersonation, External, etc.) | No | Yes |
| **Vade Secure (Hornetsecurity)** | Inline banner with category | Gmail label / Outlook category | 4 (Newsletter / Commercial / Suspicious / Phishing) | "Block Sender" / "Report" inline | Yes (granular categories) | No | Yes |
| **Tessian (Proofpoint)** | Real-time pop-up modal | None (modal-based) | 3 (Inform / Warn / Block) | Modal CTA + reporting | Yes (Misdirected, Impersonation, Anomaly) | **Yes — strongest** | No |
| **Abnormal Security** | Minimal / silent removal | Inbox cleaning (no end-user banner by default) | Admin tiers only | Admin console | N/A to end-user | No | No (rewrite is optional) |
| **Cofense** | Reporter add-in (no inline banner) | None | N/A | **Strongest reporter UX** | N/A | No | No |
| **SN360-ES v1** | Single static banner | Single "FYI" label | 1 (FYI only) | No | None (generic FYI) | No | No |

### What SN360-ES v2 Adopts

| Pattern | Source | Adoption |
|---|---|---|
| Severity-tiered colored banner | INKY, Proofpoint, Avanan | **Yes** — 6 tiers (Blocked / High / Warning / Caution / Info / Trusted) |
| Native provider labels per severity | Avanan, Material, INKY | **Yes** — Gmail labels + Outlook categories, color-mapped |
| Specific category in banner copy | INKY, Material, Vade | **Yes** — 16 categories (LIKELY_PHISHING, BEC_IMPERSONATION, …) |
| One-click "Report Phishing" | IRONSCALES, Cofense, Defender | **Yes** — inline button + Outlook/Gmail add-in |
| "Mark as Safe" / "Trust Sender" | Vade, Avanan | **Yes** — at Warning tier and below |
| Sender-authentication chip | Defender, INKY | **Yes** — SPF/DKIM/DMARC verdict pill |
| URL rewriting at high severity | Mimecast, Proofpoint, Defender | **Yes** — High Risk + Blocked only |
| Pre-send warning | Tessian, Mimecast | **Yes (optional add-in)** — Tessian-style |
| Pre-open confirm on Warning+ | Mimecast, Material | **Yes (optional add-in)** |
| Quarantine + release flow | All enterprise vendors | **Yes** — AI-agent or admin release |
| Subject-line tag | Proofpoint, Mimecast | **Optional** — `[SN360: WARN]` at Warning+ only, configurable |
| Multilingual banners | Vade, INKY | **Yes** — i18n per user locale |
| In-banner micro-lesson | (novel — competitor gap) | **Yes** — Education service integration |
| Privacy-preserving banner copy | (novel — competitor gap) | **Yes** — no email content quoted in stored reasons |

### Severity Tiers — Authoritative Spec

| Tier | Score | Banner Color | Banner Headline (en) | Native Label | Provider Action |
|---|---|---|---|---|---|
| **Blocked** | 85-100 | Red (filled, white text) | "This message was blocked as malicious." | `SN360 / Blocked` (red) | Auto-quarantine; user sees stub only |
| **High Risk** | 70-84 | Red (filled, white text) | "Likely phishing — do not click links or reply." | `SN360 / Warning` (red) | Banner + URLs rewritten/disabled |
| **Warning** | 50-69 | Orange (white text) | "Caution: This message has suspicious traits." | `SN360 / Caution` (orange) | Banner with reasons + actions |
| **Caution** | 30-49 | Yellow (dark text) | "Be cautious — verify the sender before acting." | `SN360 / Notice` (yellow) | Compact footer banner |
| **Informational** | 15-29 | Blue (dark text) | "External sender / First contact." | `SN360 / External` (blue) | Inline chip near sender name |
| **Trusted** | 0-14 | Green chip | "Verified internal / trusted vendor." | `SN360 / Trusted` (green) | Optional positive chip |

Score → tier mapping is configurable per tenant via the score engine.

### Category Vocabulary

Every banner above Informational includes **one** primary category and may
include up to two secondary categories:

| Category | When Applied | User-Facing Copy (en) |
|---|---|---|
| `LIKELY_PHISHING` | High Tier 1/2 score with credential-harvest signals | "Likely phishing attempt" |
| `BEC_IMPERSONATION` | Display-name mismatch + financial intent | "Business Email Compromise suspected" |
| `LOOKALIKE_DOMAIN` | Sender domain near-matches trusted brand | "Sender domain mimics a known brand" |
| `SUSPICIOUS_URL` | URL flagged by VT/URLScan/SafeBrowsing | "Contains a suspicious link" |
| `SUSPICIOUS_ATTACHMENT` | ShieldNet sandbox flagged attachment | "Attachment flagged by sandbox" |
| `FIRST_CONTACT_EXTERNAL` | Relationship category = FirstTimeExternal | "First time this sender has emailed you" |
| `ACCOUNT_TAKEOVER_SUSPECTED` | Known sender + behavioral anomaly | "Account compromise suspected" |
| `VENDOR_COMPROMISE` | Trusted vendor + anomalous content | "Vendor account may be compromised" |
| `CREDENTIAL_HARVESTING` | Form fields / credential keywords | "Asks for password or credentials" |
| `INVOICE_FRAUD` | Invoice + payment redirect signals | "Possible invoice fraud" |
| `QR_PHISHING` | QR code resolves to suspicious URL | "QR code links to a suspicious site" |
| `SCAM_FRAUD` | Generic scam pattern | "Possible scam" |
| `AUTH_FAILED` | SPF/DKIM/DMARC fail on important sender | "Sender authentication failed" |
| `INTERNAL_TRUSTED` | Same tenant domain | "From your organization" |
| `VENDOR_TRUSTED` | Approved vendor list | "From a trusted vendor" |
| `NEWSLETTER` | Bulk sender / list-unsubscribe present | "Newsletter / mailing list" |

### Banner Anatomy

```
┌──────────────────────────────────────────────────┐
│ ▌ HIGH RISK  ·  Likely phishing                  │  <- severity stripe + headline
│                                                    │
│ • Sender domain "paypa1.com" mimics paypal.com    │  <- sanitized reasons (no PII)
│ • Authentication failed (SPF, DKIM)                │
│ • Asks for password or credentials                 │
│                                                    │
│ 🔐 Sender: ⚠ Unverified  ·  SPF: fail · DKIM: fail │  <- auth chip
│                                                    │
│ [ Report Phishing ]  [ Mark as Safe ]  [ Why? ]    │  <- one-click actions
│                                                    │
│ 💡 30-sec lesson: Lookalike Domains                │  <- micro-lesson (Warning+)
└──────────────────────────────────────────────────┘
```

- **Severity stripe** is rendered as a CSS gradient (no remote image) for
  privacy and dark-mode safety.
- **Reasons** are pulled from a fixed vocabulary of `reason_codes` — never raw
  email content — so they can be safely cached, logged, and shown across
  languages.
- **Sender auth chip** condenses SPF/DKIM/DMARC into a single Verified /
  Unverified / Failed verdict.
- **Action buttons** use HTTPS callbacks signed with a short-lived per-message
  token; clicking does not require the user to be logged into a SN360 portal.
- **"Why?" expander** reveals the full category, score, and confidence —
  helping power users without overwhelming average users.

### Native Provider Labels

| Provider | Mechanism | Color Mapping |
|---|---|---|
| **Google Workspace** | Gmail label per tier (created on tenant onboarding) | Gmail label colors mapped to tier colors |
| **Microsoft 365** | Outlook Master Categories | Outlook category color closest to tier color |

Label naming convention: `SN360 / {Tier}` (e.g., `SN360 / Blocked`). Categories
are surfaced as sub-labels when supported: `SN360 / Warning / Lookalike`.

### URL Rewriting (High Risk + Blocked Only)

- URLs in `High Risk` and `Blocked` messages are rewritten to an interstitial
  `https://l.sn360.io/{token}` page that:
  - Re-checks the URL against current threat intelligence before redirecting
  - Shows the user a final confirmation page with the destination
  - Logs (anonymously) the click decision for tuning
- Below High Risk, URLs are left untouched to minimize disruption and tracking.

### Quarantine + Release Flow

```mermaid
sequenceDiagram
    participant User
    participant Inbox as Mailbox
    participant Ing as Ingestion
    participant Q as Quarantine
    participant Agent as AI Support Agent

    Ing->>Inbox: Move Blocked email to Quarantine label
    Ing->>Inbox: Replace body with stub ("This message was blocked")
    User->>Agent: "Please release this email"
    Agent->>Q: Fetch original message
    Agent->>Agent: Re-evaluate (Tier 0 + Tier 1)
    alt Re-evaluation clears
        Agent->>Inbox: Restore message
        Agent-->>User: Released + brief explanation
    else Still blocked
        Agent-->>User: Refuse + reasons + report-as-FP path
    end
```

### Pre-Send & Pre-Open Warnings (Optional Add-In)

Outlook and Gmail add-ins (Manifest v3) provide Tessian-style real-time UX:

- **Pre-send**: Detects lookalike recipient domains, unusual recipients
  (e.g., personal address from a Finance user), and external recipients on
  threads previously kept internal. Prompts confirmation with one-click
  override + reason capture.
- **Pre-open**: At `Warning+` tier, shows a modal before the body renders —
  useful on mobile clients that auto-render HTML.

### Accessibility

- All banners pass WCAG 2.1 AA contrast at every tier (color is never the only
  signal — icons and headline text carry the meaning).
- Severity is announced to screen readers via `aria-label` (`role="alert"` for
  High Risk and Blocked).
- Dark-mode safe palette (banners render correctly in Gmail/Outlook dark themes).
- Banners are pure HTML/CSS — no JavaScript, no remote fonts, no remote images.

### Privacy in the Banner Itself

- No email content is quoted in stored detection reasons.
- All reasons map to a fixed `reason_code` enum; localized copy is generated
  client-side from the code, so the same email triggers the same reason
  regardless of locale.
- Banner HTML is generated in-memory at action time and is never persisted.
- The signed action-token in Report/Mark-Safe buttons contains only:
  `tenant_id`, `pseudonymized_message_id`, `tier`, `expires_at`. No PII.

---

## 7. Enriched Onboarding Intelligence

### Organizational Graph Discovery

| Data Point | Source | Use Case |
|---|---|---|
| **Employee directory** | GWS Directory API / MS Graph `/users` | Auto-discover all users, departments, titles, managers |
| **Group memberships** | GWS Groups / MS Graph `/groups` | Identify high-risk groups (Finance, C-suite, HR) |
| **Communication patterns** | Communication history | Build "who talks to whom" baseline |
| **Typical send times** | Message timestamps | Detect timing anomalies |
| **Vendor auto-discovery** | Analyze 30-day email history | Auto-populate vendor list from recurring external senders |

### Expanded Relationship Categories

| Category | Detection | Risk | Action |
|---|---|---|---|
| **Internal** | Domain match | Lowest | Tier 0 bypass |
| **Vendor** | Admin list + auto-discovered | Low | Tier 0 bypass |
| **Partner** | Bidirectional communication | Low-medium | Lower Tier 1 threshold |
| **Customer** | Inbound-heavy pattern | Medium | Normal Tier 1 |
| **Recurring Service** | noreply@, mailer-daemon | Lowest | Tier 0 bypass |
| **First-time External** | No communication history | Highest | Always Tier 1, lower escalation threshold |
| **Lapsed Contact** | Historical but no 30d activity | High | Account takeover vector — Tier 1 with low threshold |

### Vulnerability Scoring

```
Employee Vulnerability Score = f(
  role_risk,                  # C-suite, Finance, HR = high
  external_volume,            # More external email = more exposure
  first_contact_frequency,    # More new contacts = more risk
  incident_history,           # Past targeting
  resilience_score,           # Inverse of education performance
)
```

---

## 8. Comprehensive Optimization Techniques

### From Top Competitors

| Technique | Source | SN360-ES Implementation |
|---|---|---|
| **Behavioral baselining** | Abnormal Security | Communication history + send-time patterns → anomaly score |
| **Supply chain detection** | Abnormal Security | Detect vendor account compromise via relationship + content anomaly |
| **VIP impersonation** | Abnormal Security | Detect emails impersonating C-suite using org graph |
| **Message hold/clawback** | Material Security | Add quarantine action via transport rules (GWS routing / O365 transport) |
| **Crowdsourced intel** | IRONSCALES | Aggregate anonymized threat signals across tenants (privacy-safe) |
| **User-reported phishing** | IRONSCALES, Cofense | One-click "Report Phish" button via Gmail add-on / Outlook add-in |
| **SOC-lite dashboard** | All competitors | AI-generated threat summary dashboard (auto-produced, no manual setup) |
| **Inline pre-delivery** | Avanan/Check Point | Investigate O365 journaling rules / GWS content compliance rules |
| **Selective URL rewrite** | Mimecast, Proofpoint, Defender | Rewrite only at High Risk + Blocked tiers |
| **Pre-send warnings** | Tessian, Mimecast | Outlook/Gmail add-in detects risky recipients |
| **Severity-tiered banner** | INKY, Proofpoint, Avanan | 6-tier banner with category-specific copy |
| **Native provider labels** | Avanan, Material, INKY | Gmail labels + Outlook categories color-mapped to tier |

### Infrastructure Optimizations

| Area | Current | Proposed |
|---|---|---|
| **Event bus** | Redis Streams (no DLQ, no dedup) | NATS JetStream (DLQ, dedup, replay, file storage) |
| **Graceful degradation** | AI failure = total failure | Fallback to Tier 0 + Tier 1 + Rspamd |
| **Micro-batching** | 1 email = 1 API call | Batch fetch from NATS, batch Tier 1 inference, batch LLM API |
| **AI result caching** | None | `sha256(normalized_body + sender_domain)` → TTL cache |
| **Rspamd result caching** | Rspamd internal only | App-level `sha256(raw_mail)` → 30min cache |
| **Redis pipelining** | Individual commands | Pipeline batch reads per evaluation batch |
| **Connection pooling** | New HTTP client per call | Persistent HTTP/2 pools to AI + Rspamd |
| **URL pre-scanning** | URLs sent as metadata to LLM | Parallel scan against VirusTotal, URLScan.io, Google Safe Browsing |
| **Attachment pre-screen** | ShieldNet only (disabled) | YARA + ClamAV lightweight scan → sandbox only if suspicious |
| **Distributed tracing** | Not implemented | OpenTelemetry W3C Trace Context end-to-end |

### Cost Impact Summary

| Technique | Estimated Savings |
|---|---|
| Tier 0 bypass (internal + vendor + newsletter) | 60-70% reduction in ML calls |
| Tier 1 encoder for clear cases | 80-90% reduction in LLM calls |
| AI result caching (campaign dedup) | 10-20% additional |
| Micro-batching (batch inference) | 30-50% lower per-unit cost |
| Self-hosted encoder model | Fixed cost vs per-call |
| NATS JetStream (vs Redis memory) | 50-70% lower event bus cost |
| **Total estimated cost reduction** | **90-95%** |

---

## 9. Implementation Phases

| Phase | Scope | Business Impact |
|---|---|---|
| **Phase 1** | Tier 0 gates in `prefilter.go` + graceful degradation + NATS JetStream migration | 60-70% cost reduction, improved reliability |
| **Phase 2** | Privacy layer (`pkg/privacy/`), PII stripping, per-tenant encryption | Compliance readiness (GDPR, SOC 2) |
| **Phase 3** | Tier 1 encoder model deployment + micro-batching | 90%+ total cost reduction, <200ms p95 |
| **Phase 4** | Zero-admin AI agents (onboarding, tuning, support) | SME-ready, no IT required |
| **Phase 5** | Tiered banner + native label UX (Section 6) + URL rewriting | Competitor parity on end-user UX |
| **Phase 6** | Email education platform (simulations, micro-lessons, resilience scoring) | Complete product for SME market |
| **Phase 7** | Enriched onboarding (org graph, vulnerability scoring, expanded relationships) | Superior detection accuracy |
| **Phase 8** | Pre-send / pre-open add-ins + admin dashboard + quarantine + user-reported phishing | Tessian-style UX + feature parity |
