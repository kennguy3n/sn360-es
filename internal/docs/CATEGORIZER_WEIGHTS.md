# Categorizer Weights

This document explains every weight in `evaluate.CategoryWeights`, why it
has its default value, how signals stack to produce a final
`(primary, secondaries)` verdict, and how operators override the matrix
per tenant.

The canonical defaults live in
[`evaluate.DefaultCategoryWeights()`](../service/evaluate/categorizer.go).
This file is the human-readable companion to that struct — keep them in
sync when you tune a weight.

## How categorization works

The pipeline runs every message through three stages:

1. **Tier 0 — deterministic gate.** Allow-list / block-list / forced
   tiers. When Tier 0 forces a verdict, the categorizer is skipped.
2. **Fan-out — Tier 1 (encoder) + Tier 2 (LLM) + Rspamd.** Each
   downstream contributes a score, a set of reason codes, and
   (for Tier 2) one or more proposed categories.
3. **Categorize → tier.** `RuleCategorizer.Categorise` consumes the
   merged `EvaluateResult` plus the message's `RiskSignals` and
   produces:
     * a **primary** `constant.Category` — the single most likely
       category, used for tiering and reporting,
     * a slice of **secondary** categories — every other category whose
       bucket exceeded `secondaryThreshold` (currently `1.0` in
       `categorizer.go`),
     * a flat list of **reason codes** — the keywords the rule engine
       matched on; surfaced to operators and used by the banner
       renderer.

The mechanics are:

* Every signal contributes to one or more **category buckets**.
* Buckets accumulate the configured weights (additive, not max).
* The bucket with the highest total wins the **primary** slot, with
  ties broken alphabetically by category name (deterministic).
* Any bucket above the secondary threshold (excluding the primary) is
  surfaced as a secondary.

This produces a behaviour where **multiple medium-strength signals
can flip a verdict** even when no single one would. Example:

> Auth fail (+2) + suspicious URL (+3) + invoice fraud lexicon (+2)
> → InvoiceFraud bucket = 4, LikelyPhishing bucket = 1+3 = 4,
> SuspiciousURL bucket = 3. The InvoiceFraud + LikelyPhishing tie
> resolves alphabetically to **InvoiceFraud** as primary, with
> **LikelyPhishing** and **SuspiciousURL** surfaced as secondaries.

## Weight catalogue

| Field | Default | Bucket | Rationale |
|---|---|---|---|
| `HighScoreThreshold` | 70 | (gate) | Threshold above which the high-score nudge fires. Mirrors `dto.RiskTierBlock` so a "blocked" verdict and a high categorizer-confidence verdict align. |
| `HighScoreWeight` | 3 | `LikelyPhishing` | When the score is already past the block threshold, nudge phishing strongly. Three weight is enough to tilt one ambiguous bucket but not enough to overwhelm a deterministic LookalikeDomain hit. |
| `FirstContactWeight` | 2 | `FirstContactExternal` | First-contact external senders are common but cluster heavily with phishing. Two weight earns a secondary placement but rarely beats a primary. |
| `LookalikeDomainWeight` | 4 | `LookalikeDomain` | Lookalike / typosquat domains are one of the strongest deterministic signals — they almost always indicate impersonation. Four weight makes it the dominant primary on its own. |
| `LookalikeBECNudge` | 1 | `BECImpersonation` | Most lookalike senders are executive-impersonation attempts. A +1 nudge on BEC means a lookalike-only message often surfaces BEC as a secondary too. |
| `SuspiciousURLWeight` | 3 | `SuspiciousURL` | URLs flagged by Rspamd / Tier 1 are strong but not definitive (Rspamd has false positives on marketing links). Three weight matches credentials/attachments. |
| `SuspiciousURLPhishingNudge` | 1 | `LikelyPhishing` | URLs and phishing co-occur; a small co-nudge keeps phishing in the secondary list when a URL is suspect. |
| `SuspiciousAttachmentWeight` | 3 | `SuspiciousAttachment` | Suspicious attachments (.exe in disguise, macro-enabled docs, etc.) — equal-weight with URLs because the kill chains overlap. |
| `QRPhishingWeight` | 4 | `QRPhishing` | QR-code phishing is a focused attack pattern with very few false positives. Four weight makes it primary on its own. |
| `InvoiceFraudWeight` | 2 | `InvoiceFraud` | Invoice lexicon alone is noisy (legit invoices look the same). Two weight gives secondary placement; needs `InvoiceLookalikeBoost` to become primary. |
| `InvoiceLookalikeBoost` | 2 | `InvoiceFraud` | Invoice + lookalike domain = classic vendor-redirect fraud. Stacking gives InvoiceFraud bucket = 4, enough to beat LookalikeDomain alone. |
| `CredentialHarvestingWeight` | 3 | `CredentialHarvesting` | Credential-collection lexicon ("verify your account", "password expired") is mid-strength: heavy enough to surface, light enough for legit IT comms to clear. |
| `AuthFailedWeight` | 2 | `AuthFailed` | SPF/DKIM/DMARC failures are necessary-but-not-sufficient: lots of legit forwarded mail fails too. Two weight surfaces but does not dominate. |
| `AuthFailedPhishingNudge` | 1 | `LikelyPhishing` | Auth failure on a message that also looks phishy reinforces the verdict without single-handedly flipping it. |
| `AccountTakeoverWeight` | 4 | `AccountTakeoverSuspected` | Account-takeover signals (mass send, anomalous time-of-day, etc.) are high-confidence. Four weight matches LookalikeDomain. |
| `VendorCompromiseWeight` | 4 | `VendorCompromise` | Vendor compromise (a trusted vendor suddenly sending wire instructions) is rare but always serious. Four weight makes it dominant whenever the vendor risk-signal flag fires. |
| `LLMCategoryWeight` | 1.5 | (LLM categories) | The Tier 2 LLM can propose categories — we want it to **participate** but never **single-handedly overrule** a deterministic signal. 1.5 weight means the LLM can tip a tied bucket but not beat a 4-weight deterministic signal. This is the canonical "LLM advisory" weight. |
| `ReasonCodeNudge` | 0.5 | (matched reason codes) | Reason-code keyword matches are noisy free text. Half a weight per match prevents one message with five Tier-1 reason codes from creating a category mismatch. |

### Why the LLM advisory weight is 1.5

The 1.5x value is deliberate, not arbitrary. Two constraints shape it:

* **Lower bound (≥ 1).** Anything below 1 means the LLM can never
  break a tie even when it's correct; we lose the value of the LLM's
  context understanding.
* **Upper bound (< 2).** Anything ≥ 2 means a single LLM hallucination
  on a low-signal message could flip the primary category — bypassing
  the deterministic guard rails Tier 0 and the rule engine give us.

1.5 sits squarely between those: the LLM can tip a tied 4-vs-4 bucket
to 5.5-vs-4, but cannot beat a 4-weight deterministic signal on its
own (2 LLM categories = 3, still < 4).

## How signals stack — worked examples

### Example 1: Lookalike vendor with invoice

* `RiskSignals.IsLookalike = true` → LookalikeDomain += 4, BEC += 1
* `RiskSignals.IsInvoice = true` → InvoiceFraud += 2
* Lookalike + invoice combo → InvoiceFraud += 2 (boost)

Totals: InvoiceFraud=4, LookalikeDomain=4, BEC=1.
Tie → **InvoiceFraud** (alphabetical), LookalikeDomain as secondary.

### Example 2: LLM disagrees with rules

* `RiskSignals.SuspiciousURL = true` → SuspiciousURL += 3, LikelyPhishing += 1
* Tier 2 proposes `[CredentialHarvesting]` → CredentialHarvesting += 1.5

Totals: SuspiciousURL=3, LikelyPhishing=1, CredentialHarvesting=1.5.
**SuspiciousURL** wins. The LLM's secondary opinion surfaces as a
secondary only if its bucket clears 1.0 (it does), so the operator sees
both the deterministic primary and the LLM's read.

### Example 3: Multiple medium signals

* `IsFirstContactExternal = true` → FirstContactExternal += 2
* `SPF=fail` → AuthFailed += 2, LikelyPhishing += 1
* Tier 1 score = 65 (below high-score threshold of 70 — no nudge)
* Tier 2 proposes `[LikelyPhishing]` → LikelyPhishing += 1.5

Totals: AuthFailed=2, FirstContactExternal=2, LikelyPhishing=2.5.
**LikelyPhishing** wins. The LLM advisory weight tipped the tie.

## Per-tenant overrides

The default weights are applied by `NewRuleCategorizer()`. To override
per tenant, construct a categorizer with explicit weights:

```go
weights := evaluate.DefaultCategoryWeights()
weights.LLMCategoryWeight = 0.5 // operator distrusts the LLM
weights.LookalikeDomainWeight = 6 // tenant has been heavily impersonated
categorizer := evaluate.NewRuleCategorizerWithWeights(weights)
```

Recommended override patterns:

* **High-trust tenants** (e.g. enterprises with strong DMARC enforcement):
  raise `AuthFailedWeight` from 2 → 3 so SPF/DKIM/DMARC failures escalate
  faster.
* **Tenants with known impersonation history**: raise
  `LookalikeDomainWeight` and `VendorCompromiseWeight` to 5–6.
* **Tenants in regulated industries** (finance, healthcare): raise
  `CredentialHarvestingWeight` to 4 and `InvoiceFraudWeight` to 3.
* **Tenants that don't want LLM input** (regulated, audit-strict):
  set `LLMCategoryWeight` to 0; the LLM still runs and its reason codes
  still surface, but it cannot influence the primary category.

Overrides land at the same layer as `evaluate.Weights` (the score-engine
weights), so plumb them through the same per-tenant config store.

## Tuning rules of thumb

* **Never** set a deterministic-signal weight below 2 — at 1 it stops
  being a primary signal and becomes a noise source.
* **Never** set `LLMCategoryWeight ≥ 2` — that's the "LLM can overrule
  deterministic signals" zone and undermines the architecture's
  defence-in-depth properties.
* **`ReasonCodeNudge` should stay ≤ 1**. Reason codes are free text;
  five matches × 1 weight = 5 weight, easily dominating real signals.
* When adjusting one weight, **rerun the categorizer regression suite**
  (`go test ./internal/service/evaluate -run TestRuleCategorizer -count=1`)
  to make sure published-fixture verdicts still hold.
