# How Directory Intelligence Makes Email Security Smarter

*How SN360-ES uses your organisation's directory to detect threats that content-scanning alone cannot catch — and how it compares to the industry leaders.*

---

## The Problem with Content-Only Email Security

Most email security products treat every inbound message the same way: scan the text, check the links, score the attachments. This works for commodity spam, but it fails catastrophically against the attacks that actually cost SMEs money — business email compromise (BEC), vendor impersonation, and account takeover.

Why? Because these attacks don't contain obviously malicious content. A BEC email that says *"Please wire $43,000 to our new bank account — details attached"* is syntactically identical to a legitimate finance request. The difference is **who sent it, to whom, and whether that communication pattern is normal**.

Content scanning cannot answer those questions. Directory intelligence can.

---

## What Is Directory Intelligence?

Directory intelligence is the practice of integrating your organisation's identity provider — Google Workspace or Microsoft 365 — directly into the email security pipeline. Instead of treating the email as an isolated document, the security system understands:

- **Who works here** — every employee, their department, their role, their manager.
- **Who is sensitive** — C-suite, Finance, HR, Legal — the people attackers target first.
- **Who are your vendors** — the external domains your organisation regularly does business with.
- **What is normal** — the typical send hours, communication volume, and device types for each employee-sender pair.
- **How the org is structured** — the reporting hierarchy, department boundaries, nested group memberships.

SN360-ES builds this organisational context automatically, keeps it fresh through incremental sync, and feeds it into every layer of the detection pipeline — from the sub-millisecond classification gate all the way to the deep-reasoning SLM.

---

## How SN360-ES Wires Directory Into Detection

### Step 1: Continuous Directory Sync

Every six hours, the directory sync worker connects to your identity provider and pulls the latest state:

| Provider | Sync Mechanism | What Changes |
|---|---|---|
| **Microsoft 365** | MS Graph `/users/delta` API | Only users modified since last sync |
| **Google Workspace** | Admin SDK `updatedMin` filter | Only users updated since the last timestamp |

The key innovation is **delta sync** — instead of re-enumerating every user in your tenant on every cycle, SN360-ES tracks a checkpoint token and fetches only what changed. For an organisation with 500 employees, this reduces the API call volume from ~500 requests to typically 5-10, keeping well within provider rate limits and completing in seconds instead of minutes.

For Microsoft 365 tenants, the sync also resolves **nested group memberships**. If an employee belongs to "Engineering", which is a member of "All Staff", which is a member of "Company Newsletter Recipients", the system sees all three group memberships — not just the direct one. This matters because attackers increasingly target messages to broad distribution groups, and understanding the full membership graph is essential for detecting impersonation of group-specific senders.

### Step 2: Sensitivity Classification

Once directory data is synced, SN360-ES classifies every employee's sensitivity level using a tiered pipeline:

1. **Encoder model** (Tier 1) — the XLM-RoBERTa multilingual encoder analyses job titles and department names across 100+ languages.
2. **Bonsai SLM** (optional) — the Ternary-Bonsai-8B small language model provides deeper reasoning for ambiguous cases.
3. **Multilingual keyword fallback** — when ML is unavailable, a curated keyword list covering English, Japanese, Korean, Thai, Vietnamese, and Chinese maps job titles to sensitivity levels.

The result is a four-level classification:

| Level | Who | Why It Matters |
|---|---|---|
| **Max** | CEO, CFO, CTO, founders | Primary BEC targets; impersonation vectors |
| **High** | Finance, HR, Legal, Compliance | Wire-transfer authority; data access |
| **Elevated** | Executive assistants, Procurement | Indirect access to sensitive operations |
| **Default** | Everyone else | Standard protection |

This classification feeds directly into the detection pipeline: emails targeting Max-sensitivity users get lower escalation thresholds, meaning even slightly suspicious messages are pushed to the SLM for deep analysis rather than being cleared by the fast encoder alone.

### Step 3: The Org Graph

After sync, SN360-ES builds a **persistent org graph** — a queryable snapshot of your organisation's structure stored as JSONB in PostgreSQL. The graph captures:

- Reporting hierarchies (who reports to whom)
- Department boundaries
- High-risk user clusters (Finance team, C-suite)
- Group memberships (including transitive/nested)

This graph powers detection rules that content scanning cannot:

- **CEO impersonation**: An email claiming to be from the CEO but originating from an external domain is instantly flagged — because the system knows who the CEO is.
- **Cross-department anomaly**: A "Finance" sender emailing an "Engineering" recipient about an invoice is unusual if those departments have no historical communication.
- **Vendor compromise**: A known vendor sending to a recipient they've never contacted before, at an unusual hour, triggers escalation.

### Step 4: Behavioral Baselines

The relationship aggregation worker builds per-(employee, sender-domain) behavioral profiles:

- **Typical send hours** — hour-of-day distribution over the past 30 days.
- **Communication volume** — average messages per week.
- **Device types** — typical devices used for sending.

When an inbound message arrives, the timing anomaly checker compares the current message against the stored baseline. A vendor who normally emails your Finance team between 9 AM and 5 PM Tokyo time suddenly sending at 3 AM raises a flag — not because the content is suspicious, but because the **behavior** is.

### Step 5: Vendor Trust (With a Safety Net)

Vendor management in SN360-ES combines automatic discovery with admin oversight:

1. **Auto-discovery** — the weekly vendor discovery worker scans 30 days of communication history, identifies domains with high-frequency bidirectional communication, and surfaces them as candidate vendors.
2. **Admin CRUD** — admins approve, revoke, or manually add vendors through the API.
3. **Tier 0 bypass** — approved vendors skip the ML pipeline entirely, saving cost and reducing latency to near-zero.

But here's the critical safety net: the Tier 0 classification gate checks the `LooksLikeVendorCompromise` signal **before** granting vendor bypass. If the signal indicates a potential vendor account takeover — for example, the vendor's sending patterns have changed dramatically, or the email contains content inconsistent with the vendor relationship — the gate force-escalates to the full ML pipeline instead of bypassing it.

This means vendor trust is not blind trust. The system continuously validates that vendor behavior matches expectations.

---

## The 3-Tier Detection Pipeline: How the Smartness Works

Directory intelligence is the context layer. The detection pipeline is the reasoning engine. Together, they form a system where cheap rules handle 60-70% of traffic and expensive AI is reserved for the emails that actually need it.

### Tier 0: Classification Gate (<1ms, ~$0/email)

Pure CPU, pure rules, sub-millisecond. The gate checks:

- Is this an internal email? → **Trust** (score 0).
- Is this from an approved vendor (without compromise signals)? → **Trust** (score 0).
- Is this a known newsletter or recurring service? → **Rspamd heuristics only**.
- Is this from a high-volume sender with established history? → **Reduced scrutiny**.
- Is this a first-time external contact? → **Always escalate to Tier 1**.

Result: 60-70% of all email never touches the ML pipeline. This is where directory intelligence has the biggest cost impact — the system knows which senders are safe because it knows your organisation.

### Tier 1: Encoder Model (50-200ms, ~$0.00005/email)

For emails that survive Tier 0, the self-hosted XLM-RoBERTa encoder provides fast multilingual classification:

- **100+ languages native** — no translation step, no accuracy loss for non-English content.
- **Micro-batching** — up to 50 emails processed in a single inference call via NATS JetStream batch fetch.
- **Three verdicts**: Pass (<20 confidence), Flag (>60), Escalate (20-60 ambiguous range → Tier 2).

The encoder handles 80-90% of the emails that reach it. Only ambiguous cases — the 10-20% where the model isn't confident — get escalated to the expensive SLM.

### Tier 2: Small Language Model (2-10s, ~$0.001-0.005/email)

The Ternary-Bonsai-8B SLM is a self-hosted small language model that provides:

- **Aspect-level reasoning** — not just "this is phishing" but "this email exhibits urgency language, requests a wire transfer, and the sender domain is one character different from a known vendor."
- **Human-readable explanations** — the reasons are surfaced in the end-user banner so employees understand *why* an email was flagged.
- **Language hint from Tier 1** — the encoder passes its detected language to the SLM, improving accuracy on multilingual content.

### Always-On Parallel: Rspamd Heuristics

Regardless of which ML tier processes the email, Rspamd runs in parallel checking SPF, DKIM, DMARC, RBL reputation, and header anomalies. Its score is combined with the ML verdict through weighted aggregation (default: 80% ML, 20% Rspamd).

### The Cost Math

| Technique | Savings |
|---|---|
| Tier 0 bypass (internal + vendor + newsletter) | 60-70% fewer ML calls |
| Tier 1 encoder for clear cases | 80-90% fewer Tier 2 calls |
| AI result caching (campaign dedup) | 10-20% additional |
| Micro-batching | 30-50% lower per-unit cost |
| Self-hosted models | Fixed cost, no per-call API fees |
| **Total** | **90-95% cheaper than LLM-for-every-email** |

---

## How SN360-ES Compares to the Competition

### vs. Microsoft Defender for Office 365

| Capability | Defender | SN360-ES |
|---|---|---|
| **Directory integration** | Deep (native to M365) | Deep (M365 + GWS; delta sync, nested groups) |
| **Cross-platform** | M365 only | M365 + Google Workspace simultaneously |
| **ML pipeline** | Proprietary, opaque | 3-tier, transparent, self-hosted |
| **Cost model** | Per-user/month ($2-5.60) | Self-hosted, fixed infrastructure cost |
| **Privacy** | Microsoft processes content | Zero-knowledge: no PII stored, per-tenant encryption |
| **Multilingual** | Good (large model) | Native (XLM-RoBERTa 100+ languages + multilingual keywords) |
| **SME fit** | Requires E5 or add-on license | Single binary, zero-admin |
| **Behavioral baselines** | SafeLinks / Safe Attachments | Per-user send-hour, volume, device baselines |

Defender's strength is its native integration with the M365 ecosystem. SN360-ES's advantage is cross-platform support (protecting both GWS and O365 from one system), privacy-first architecture (Microsoft sees your email content; SN360-ES does not store it), and transparent detection logic that admins can understand and tune.

### vs. Proofpoint / Mimecast

| Capability | Proofpoint/Mimecast | SN360-ES |
|---|---|---|
| **Deployment** | Cloud gateway (MX record change) | API-based, no MX change |
| **Directory sync** | LDAP/AD connector | Native Graph API + Admin SDK delta sync |
| **Detection** | Proprietary ML + threat intel | 3-tier ML + Rspamd + relationship intelligence |
| **Cost** | $3-6/user/month | Self-hosted, fixed cost |
| **Admin overhead** | Significant (policy management) | Zero-admin (AI agents configure and tune) |
| **Education** | Separate product (Security Awareness Training) | Built-in (simulations, micro-lessons, resilience scoring) |
| **Privacy** | Processes and stores content | Zero-knowledge processing |

Proofpoint and Mimecast are enterprise-grade but enterprise-complex. They require MX record changes (routing all email through their gateway), dedicated admin staff to manage policies, and separate products for security awareness training. SN360-ES integrates via API (no MX change), operates autonomously via AI agents, and includes education as a native feature — making it purpose-built for SMEs without IT teams.

### vs. Abnormal Security

| Capability | Abnormal Security | SN360-ES |
|---|---|---|
| **Approach** | Behavioral AI, API-based | 3-tier ML + behavioral baselines, API-based |
| **Directory integration** | Deep (behavioral profiling) | Deep (delta sync, org graph, behavioral baselines) |
| **Cost** | Premium ($4-8/user/month) | Self-hosted, fixed cost |
| **Self-hosted option** | No (cloud only) | Yes (single binary, your infrastructure) |
| **Privacy** | Cloud-processed | Zero-knowledge, per-tenant encryption keys |
| **Multilingual** | English-primary | Native 100+ language support |
| **Education** | No built-in education | Built-in simulations + micro-lessons |
| **Open detection logic** | Opaque | Transparent 3-tier pipeline with human-readable reasons |

Abnormal Security is the closest competitor in approach — they also use behavioral AI and API-based integration. The key differences: SN360-ES is self-hostable (your data never leaves your infrastructure), natively multilingual (critical for APAC SMEs), includes built-in education, and provides transparent detection reasoning that employees and admins can understand.

### vs. Google Workspace Built-In Protection

| Capability | GWS Built-In | SN360-ES |
|---|---|---|
| **Detection** | Heuristic + ML (opaque) | 3-tier ML + relationship intelligence |
| **BEC protection** | Basic (DMARC enforcement) | Advanced (org graph, behavioral baselines, vendor compromise) |
| **Vendor trust** | No concept | Auto-discovered + admin-managed with compromise guard |
| **Education** | No | Built-in simulations + micro-lessons |
| **Cost** | Included with GWS | Additional (self-hosted) |
| **Cross-platform** | GWS only | GWS + M365 |
| **Customisation** | Minimal | Per-tenant threshold tuning, AI agent auto-optimization |

Google's built-in protection catches commodity threats well but lacks the organisational context that catches targeted attacks. SN360-ES adds the directory intelligence layer that GWS doesn't provide — knowing who your VIPs are, which vendors are trusted, and what normal communication looks like for each employee.

---

## The Privacy Advantage

Every competitor listed above processes your email content in their cloud. SN360-ES takes a fundamentally different approach:

- **Zero-knowledge processing**: Email content is analysed in-memory and never written to disk in plaintext.
- **PII pseudonymisation**: All stored metadata uses Blake2b-256 keyed hashing — email addresses become irreversible hashes.
- **Per-tenant encryption**: AES-256-GCM with per-tenant keys derived from AWS KMS. Deleting the key is cryptographic erasure — the data becomes unrecoverable.
- **Self-hosted option**: The entire system runs as a single Go binary on your own infrastructure. Your email never leaves your network.

For SMEs in regulated industries (healthcare, finance, legal) or privacy-conscious regions (EU, Japan, Southeast Asia), this is not a nice-to-have — it's a requirement.

---

## Getting Started

SN360-ES is a single `sn360-es` Go binary. To connect your directory:

1. **Google Workspace**: Create a service account with domain-wide delegation, grant `admin.directory.user.readonly` + `admin.directory.group.readonly` + `gmail.modify` scopes, and set `GWS_SERVICE_ACCOUNT_JSON` + `GWS_DELEGATED_ADMIN` + `GWS_DOMAIN` in your environment. The built-in setup wizard at `/v1/onboarding/gws-setup-status` validates each step.

2. **Microsoft 365**: Register an Azure AD application with `User.Read.All` + `Group.Read.All` + `Mail.ReadWrite` permissions, and set `O365_CLIENT_ID` + `O365_CLIENT_SECRET` + `O365_TENANT_ID`. Enable `O365_RESOLVE_NESTED_GROUPS=true` (default) for full group hierarchy resolution.

3. **Both**: SN360-ES supports both providers simultaneously — the directory sync worker handles each tenant independently with provider-specific delta sync.

Within 6 hours of configuration, SN360-ES will have synced your directory, classified employee sensitivity, built the org graph, started populating behavioral baselines, and auto-discovered your vendors. Every email flowing through the system after that point benefits from the full organisational context — no manual configuration, no policy writing, no ongoing admin work.

That's the promise of directory intelligence: **your organisation's structure becomes your strongest defense**.
