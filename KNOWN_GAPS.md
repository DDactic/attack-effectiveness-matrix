# Known Gaps

The matrix is research output, not a finished product. This file is the canonical inventory of what each version does and does not capture.

**Status legend:** ✅ addressed and validated | 🟡 scaffolded (data model in place, shift values are reasoned defaults pending empirical validation) | 🔴 still open | ⚪ deliberately out-of-scope

| Gap | v3.0 (initial) | v3.1 (current) |
|---|---|---|
| 1. Always-on vs on-demand DDoS scrubbing | 🔴 | 🟡 scaffolded as `architecture_modifiers.engagement_mode` |
| 2. API-controllability of the protection product | 🔴 | 🟡 scaffolded as `architecture_modifiers.api_controllability` |
| 3. CDN-native unified vs bolted-on stacks | 🟡 implicit | 🟡 scaffolded as `architecture_modifiers.integration_class` |
| 4. Origin scaling class (serverless/container/ALB/API-GW/VM) | 🔴 | 🟡 scaffolded as `architecture_modifiers.origin_scaling_class` |
| 5. Account-based rate limiting (per-API-key, per-user) | 🟡 implicit | 🟡 scaffolded as `architecture_modifiers.rate_limit_basis` |
| 6. Expensive-request tagging / per-endpoint cost budgets | 🔴 | 🟡 scaffolded as `architecture_modifiers.cost_aware_throttling` |
| 7. Private tunnels (CF Tunnel, PrivateLink, etc.) | 🟡 implicit | 🟡 scaffolded as `architecture_modifiers.origin_ip_exposure` |
| 8. Caching architecture (edge / shield / app / Varnish) | 🟡 implicit (private modifier) | 🟡 scaffolded as `architecture_modifiers.caching_layers` |
| 9. IPv6 vs IPv4 reachability | 🔴 | 🟡 scaffolded as `architecture_modifiers.ipv6_origin_protection` |
| 10. Geographic / Anycast PoP distribution | 🔴 | 🟡 scaffolded as `architecture_modifiers.regional_pop_density` |
| 11. Mitigation engagement latency (seconds) | 🔴 | 🟡 scaffolded as `architecture_modifiers.engagement_latency_seconds` |
| 12. Behavioral baseline training time | 🔴 | 🟡 scaffolded as `architecture_modifiers.baseline_maturity` |
| 13. Customer billing tier within a vendor | ⚪ | ⚪ Out of scope. Internal DDactic engagements map per-vendor billing tiers to public matrix cells. |
| 14. Stateful vs stateless WAF policies | 🔴 | 🟡 scaffolded as `architecture_modifiers.policy_statefulness` |
| 15. Logging and observability latency | 🔴 | 🟡 scaffolded as `architecture_modifiers.human_response_latency` |

**Outcome:** v3.1 introduced the data model and composition rule for 14 of 15 gaps. The fifteenth (customer billing tier) is deliberately out-of-scope. None of the 14 are validated yet, hence 🟡 not ✅.

## Validation status (important)

**The shift values in `architecture_modifiers` are reasoned defaults, not empirically validated measurements.** A reader using the matrix should treat them accordingly:

- The data model and composition rule (`effective = clamp(base + sum(shifts), 0, 3)`) are stable.
- The list of options under each modifier (e.g., `serverless` / `container_kubernetes` / `alb_fronted` / `api_gateway_fronted` / `vm_or_metal` for `origin_scaling_class`) is stable.
- The numeric shifts attached to each option are derived from architectural reasoning and DDactic engagement experience, but they have not been independently re-measured against the 213 vectors x 6 base architectures.
- Per-vector overrides (where a single modifier shifts M-15 by +2 but M-19 by +1) are NOT in v3.1. v3.1 applies one shift across all `affects_mechanisms` listed for each option.

**What validation would require.** A test campaign that, for each modifier x option x affected vector x base architecture combination, runs the vector under the documented configuration and records the observed effectiveness. With 14 modifiers, ~3-5 options each, ~5 affected vectors per modifier, and 6 base architectures, that is on the order of 5,000-15,000 cells to measure. A realistic plan covers a small high-value subset (origin_ip_exposure, rate_limit_basis, origin_scaling_class) first.

**What this means for downstream users.** The `architecture_modifiers` section is useful for:

- Building a deployment-aware test plan (the modifier values are good enough to prioritize).
- Communicating architecture choices to procurement / leadership (the named options are precise).
- Comparing two deployments against the same vector set (the relative ordering of shifts is more reliable than the absolute values).

The section is NOT yet a substitute for direct testing. A `mitigated` rating after applying modifiers should still be confirmed empirically before claiming production resilience.

PRs that contribute validated shift values (with a test methodology and reproducible results) are the highest-priority contribution this repo can receive.

The detailed gap-by-gap discussion below is preserved as the historical record so contributors can see what motivated each modifier in v3.1.

---

## 1. Always-on vs on-demand DDoS scrubbing

**What's missing.** AWS Shield Standard (always-on, free, basic), Shield Advanced (always-on with manual escalation), and traditional GRE-tunnel scrubbing (on-demand, customer triggers BGP redirect) all collapse into the same `ddos_appliance` or `cloud_cdn` column today. Their effectiveness against pulse-wave attacks (30s burst / 60s pause) differs sharply: an always-on edge mitigation engages instantly, while an on-demand redirect can take 30 to 90 seconds to converge, so a short pulse attack can finish before mitigation engages.

**Where it's implicit.** Nowhere. The matrix treats both as equivalent at the architecture level.

**v2.0 proposal.** Split each protection class along an `engagement_mode` axis (`always_on` / `on_demand` / `manual_escalation`) and add a `pulse_window_seconds` modifier that captures the convergence delay.

---

## 2. API-controllability of the protection product

**What's missing.** A `tuned` cell against an API-controlled product (Cloudflare API, AWS WAF API, Azure Front Door API, Imperva API) is reachable by Terraform / Pulumi / GitOps. The same `tuned` cell against a click-ops appliance requires human console sessions, change-management tickets, and is realistically 10x slower to actually achieve. The architectural effectiveness is identical; the operational reachability of `tuned` and `hardened` is not.

**Why it matters.** A defender comparing two products with the same matrix rating but different API surfaces should know that one of them gets to `tuned` in a sprint and the other takes a quarter.

**v2.0 proposal.** Add a per-product (or per-architecture-class) `api_coverage` rating: `full` / `partial` / `none`. Optionally surface as a config-level multiplier (a click-ops product is effectively one config-level lower than its rated cell because hardening is operationally harder to reach).

---

## 3. CDN-native unified protection vs bolted-on stacks

**What's missing.** Cloudflare's WAF, DDoS, rate-limit, and bot management are unified at the edge with a shared policy plane. A traditional architecture might have a separate CDN, a separate WAF behind it, a separate DDoS appliance, and rate limits at an API gateway. Each integration boundary is its own attack surface (signed-header validation gaps, asymmetric routing, log-correlation failures).

**Where it's implicit.** `cloud_cdn` in the matrix today maps roughly to "unified CDN-native" and `hybrid` maps roughly to "bolted-on". But the distinction is not called out by name, and large CDN vendors that started as bolted-on (and partially unified over time) sit awkwardly between.

**v2.0 proposal.** Make unification explicit as an `integration_class` axis: `unified_edge` / `bolted_on_2_layer` / `bolted_on_3_plus_layer`. The cell shifts up (more deadly) for each integration boundary, because boundaries are where the assumed-trust attacks live.

---

## 4. Origin scaling class

**What's missing.** The matrix's effectiveness ratings assume an unspecified origin. Real origins differ:

- **Serverless (Lambda, Cloud Run, Functions).** Auto-scales to absorb floods. Floods cost money but rarely take the service down. M-15 (Request Flood) goes from `deadly` to `degraded` with the cost showing up on the next invoice instead of as downtime.
- **Containerized (ECS, EKS, GKE, Cloud Run).** Scales fast but with a warm-up window and a horizontal pod cap. Floods kill availability between the cap and the autoscaler reaction.
- **ALB / NLB-fronted.** Scales on connection count, not RPS. M-07 (Idle Hold) and M-11 (H/2 Stream Churn) hit ALB connection accounting differently than they hit a request-counting WAF.
- **API Gateway-fronted (AWS API Gateway, Apigee, Azure API Management).** Rate limiting at the gateway is a defense layer the matrix's `cloud_cdn` cell doesn't account for.
- **VM / bare-metal origin.** No autoscale. Floods either fit in the rated capacity or they don't.

**v2.0 proposal.** Add `origin_scaling_class` as an explicit dimension and re-rate the M-07, M-11, M-15, M-19 vectors per class.

---

## 5. Account-based rate limiting (per-API-key, per-user)

**What's missing.** Per-IP rate limiting is brittle (carpet bombing across a /24 defeats it). Per-API-key or per-authenticated-user rate limiting is a different defense class entirely and is the standard answer for B2B APIs and authenticated SaaS. v1.0 buries this inside the `tuned` and `hardened` config-level definitions for `cloud_cdn` and `security_waf`, which understates how much it matters for M-19 (Backend Query Amp) and M-15 (Request Flood) on authenticated endpoints.

**Where it's implicit.** Inside `config_levels.tuned` ("rate limits set") and `config_levels.hardened` ("custom rate limits per endpoint"). Not distinguished from per-IP limits.

**v2.0 proposal.** Surface `rate_limit_basis` as an explicit modifier with values `per_ip`, `per_api_key`, `per_session`, `per_user`. The shift against M-15 and M-19 is significant.

---

## 6. Expensive-request tagging / per-endpoint cost budgets

**What's missing.** A defender can tag specific endpoints as costly (login, search, GraphQL with deep selection, PDF generation, image resize) and assign a per-account budget across them. This is the right answer for M-19 (Backend Query Amp). Few products do it natively today (GraphQL cost analysis libraries, some API gateways), so v1.0 lumps the defense into `hardened`. As more products implement it, it deserves its own column.

**v2.0 proposal.** Add `cost_aware_throttling` as a modifier with a meaningful negative shift on M-19 and M-18 across all architectures that support it.

---

## 7. Private tunnels (origin-IP elimination)

**What's missing.** Cloudflare Tunnel, AWS PrivateLink, Azure Private Link, GCP Private Service Connect, and Tailscale-style overlay routing all eliminate the public origin IP entirely. The CDN bypass attack (`direct_origin_attack` in the matrix) goes from `deadly` to `n/a`, because there is no origin IP to discover via OSINT. This is one of the highest-leverage defensive moves a defender can make and it does not have its own row.

**Where it's implicit.** Inside the `direct_origin_attack` vector's `prerequisites` field ("Origin must accept connections from non-CDN IPs"). If the prerequisite is false (because of a private tunnel), the vector is N/A. But the matrix doesn't expose this as an architecture-level capability.

**v2.0 proposal.** Add `origin_ip_exposure` as an explicit boolean column. When false, all CDN-bypass vectors are N/A regardless of architecture rating elsewhere.

---

## 8. Caching architecture

**What's missing.** Caching is currently expressed only via the (held-back) `technique_modifiers.cache_bust_*` entries against M-16. The architecture column does not distinguish between CDN edge cache, regional shield cache, in-memory app cache (Redis, Memcached), and Varnish-style HTTP cache. They have different cache-key semantics and different bypass surfaces.

**v2.0 proposal.** Add a `caching_layers` field listing which cache layers are present, with each layer contributing an independent shift against M-16.

---

## 9. IPv6 vs IPv4 reachability

**What's missing.** Many origin-IP-leak defenses assume IPv4. An origin reachable on IPv6 but fronted by an IPv4-only CDN is an unprotected attack path: the CDN never sees IPv6 traffic, the origin happily accepts it. CT logs and DNS history routinely surface IPv6 AAAA records that the operator forgot to gate.

**v2.0 proposal.** Add `ipv6_origin_protection` as a boolean column. When false (CDN is IPv4-only and origin is dual-stack), the M-CDN-bypass effectiveness rises sharply.

---

## 10. Geographic / Anycast PoP distribution

**What's missing.** A CDN with 300 PoPs absorbs differently than one with 30. The matrix collapses both into `cloud_cdn`. Pulse attacks from a single source region against a CDN with thin coverage in that region produce different outcomes than the same attacks against a CDN with deep regional capacity.

**v2.0 proposal.** Add `regional_pop_density` as an axis (`thin` / `medium` / `dense`) that shifts volumetric ratings (M-01, M-02) per architecture.

---

## 11. Mitigation engagement latency

**What's missing.** Even an always-on edge takes some seconds to recognize and respond to a novel pattern (signature update, behavioral classifier convergence, BGP announcement propagation). For pulse-wave attacks shorter than this engagement window, the rated effectiveness overstates the real outcome. v1.0 has no clock dimension.

**v2.0 proposal.** Add `engagement_latency_seconds` as a numeric metadata field per architecture cell, plus a `pulse_window` strategy modifier that compares attack burst length against engagement latency.

---

## 12. Behavioral baseline training time

**What's missing.** A `hardened` rating presumes "behavioral baselines trained 2+ weeks". A freshly deployed site has no baseline. For the first two weeks after deployment, the architecture is operationally one config-level lower than its rated cell. The matrix does not currently surface this.

**v2.0 proposal.** Add a `baseline_maturity_required` flag on each `hardened` cell that depends on behavioral training. Defenders evaluating their actual posture should down-shift any hardened cell with this flag if they are inside the training window.

---

## 13. Customer billing tier within a vendor

**What's missing.** Cloudflare Free vs Pro vs Business vs Enterprise have very different DDoS coverage at the same architectural class. We deliberately collapsed this because the matrix is vendor-neutral, but real procurement decisions live on this axis. A buyer reading our `cloud_cdn / hardened` rating and assuming it applies to a Free-tier deployment is reading the matrix wrong.

**v2.0 proposal.** Out of scope for the public matrix. Internal DDactic engagements map per-vendor billing tiers to which cells of the public matrix actually apply. Document this expectation explicitly here so readers do not over-extrapolate.

---

## 14. Stateful vs stateless WAF policies

**What's missing.** A WAF that tracks per-session state across requests (session reputation, sliding-window counters, sequence anomalies) catches different attacks than one that evaluates each request independently. M-15 (Request Flood) and M-19 (Backend Query Amp) shift meaningfully with statefulness; the matrix lumps both into the same rating.

**v2.0 proposal.** Add `policy_statefulness` (`stateless` / `stateful_session` / `stateful_user`) as a modifier. The shift is significant against application-layer mechanisms.

---

## 15. Logging and observability latency

**What's missing.** Detection of M-18 / M-19 (application-layer attacks) often depends on slow-query logs, APM dashboards, or memory alerts. The latency from "attack starts" to "operator sees alert and acts" is a real dimension. A `hardened` rating that assumes operator response in 30 seconds reads differently than one that assumes 30 minutes.

**v2.0 proposal.** Add `human_response_latency_assumed` as an explicit assumption surfaced in the methodology section, optionally with a per-cell override when the rating presupposes faster-than-typical response.

---

## How to contribute

PRs adding any of these as explicit columns or modifier dimensions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). The bar for landing a new dimension:

- Justify why the existing fields don't capture it.
- Show that the dimension shifts at least three vectors meaningfully.
- Provide a baseline rating for at least one architecture-class x config-level combination.

A new dimension is a structural change. We will batch them into a v2.0 release rather than land them piecemeal. Until then, this file is the canonical inventory of what v1.0 doesn't cover.
