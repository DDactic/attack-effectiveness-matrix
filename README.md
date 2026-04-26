# Attack Effectiveness Matrix

A public dataset that maps **213 documented DDoS attack vectors** against **6 protection architectures** at **3 configuration levels**. For every cell in the cube it records a qualitative effectiveness rating (`deadly` / `degraded` / `mitigated` / `blocked`) and the architectural reason behind it.

This is the open subset of an internal research matrix maintained by [DDactic](https://ddactic.net). The publication is the first artifact in a series; see also [ddactic/ddos-attack-taxonomy](https://github.com/DDactic/ddos-attack-taxonomy).

## What problem this solves

Defenders pick a protection architecture (cloud CDN, on-prem WAF, DDoS appliance, hybrid, perimeter ACL, exposed origin) and then try to reason about which attacks they are still exposed to. There is no widely-agreed reference for "vector X against architecture Y at config-level Z". Every vendor publishes a self-flattering matrix; every research paper picks a slice. This dataset is an attempt at a vendor-neutral, reproducible reference that researchers, blue teams, and procurement teams can argue with.

The unit of analysis is the architectural class, not a specific product. The dataset deliberately does not name vendors in its effectiveness notes. Where vendor names appear (in the architecture and summary sections) they are illustrative examples of the class, not test results.

## Data

[`data/attack_effectiveness_matrix.json`](data/attack_effectiveness_matrix.json) is the canonical artifact.

### Top-level structure

```jsonc
{
  "_version": "3.0",
  "_published_under_license": "CC-BY-4.0 (data) + MIT (scripts)",
  "_sanitization": "...",                  // what was generalized for public release
  "architectures": { /* 6 categories */ },
  "config_levels": { /* default | tuned | hardened */ },
  "vectors": { /* 213 attack vectors */ },
  "architecture_modifiers": { /* 14 defender-side modifier categories, public in v3.1 */ },
  "_arch_modifier_computation": { /* how arch modifier shifts compose */ },
  "_modifiers_note": "...",                // pointer to attacker-side framework held back from public release
  "_summary": { /* counts and key insights */ }
}
```

> **Defender-side modifiers (`architecture_modifiers`) are now public in v3.1.** They capture deployment-time choices like always-on vs on-demand, API controllability, origin scaling class, rate-limit basis, private tunnels, IPv6 parity, and behavioral baseline maturity. See the section below.
>
> **Attacker-side modifiers (`technique_modifiers` and `strategy_modifiers`) remain held back.** They describe request-shaping tricks and traffic-fingerprint postures at a level closer to a playbook than a research dataset. Contact DDactic for the attacker-side framework under NDA.

### Architecture classes

| Key | Description |
|---|---|
| `exposed` | No CDN, WAF, or DDoS mitigation. Traffic hits origin directly. |
| `cloud_cdn` | Cloud CDN/WAF (elastic, distributed edge). |
| `security_waf` | On-prem security WAF where DPI shares CPU with IPS/AV/SSL. |
| `ddos_appliance` | Dedicated DDoS appliance (hardware-accelerated, behavioral). |
| `hybrid` | Cloud CDN + on-prem appliance. |
| `perimeter_filtered` | Firewall/ACL filtering, no DDoS-specific mitigation. |

### Config levels

| Key | Description |
|---|---|
| `default` | Vendor defaults, no custom policies. |
| `tuned` | Basic policies: rate limits set, geo-blocking enabled, WAF rules active but not customized. |
| `hardened` | Expert config: behavioral baselines trained, custom rate limits per endpoint, challenge pages, origin lockdown. |

### Effectiveness levels

| Level | Meaning |
|---|---|
| `deadly` | Service failure expected. |
| `degraded` | Partial impact, user-visible. |
| `mitigated` | Absorbed with minor impact. |
| `blocked` | No impact. |

### A vector entry

```jsonc
"l7_http2_rapid_reset": {
  "name": "HTTP/2 Rapid Reset",
  "layer": "l7",
  "category": "L7 HTTP/2",
  "mechanism": "Open HTTP/2 stream and immediately RST_STREAM. Server allocates resources for stream but client cancels before response.",
  "cve_id": "CVE-2023-44487",
  "patched_since": "2023-10",
  "effectiveness": {
    "exposed":    { "default": "deadly", "tuned": "deadly", "hardened": "degraded", "notes": "..." },
    "cloud_cdn":  { "default": "mitigated", "tuned": "blocked", "hardened": "blocked", "notes": "..." },
    /* ...four more architectures... */
  },
  "prerequisites": ["Target must support HTTP/2", "Unpatched servers most vulnerable"],
  "common_tools": {
    "script_kiddie": [ ... ],
    "intermediate":  [ ... ],
    "advanced":      [ ... ]
  }
}
```

### Architecture modifiers (defender-side, public in v3.1)

> **Status: scaffolded, not validated.** The data model and composition rule are stable. The numeric shifts attached to each option are reasoned defaults derived from architectural analysis and engagement experience, **not empirically measured** against all 213 vectors. Treat the relative ordering of shifts as more reliable than the absolute values, and confirm any production-critical claim with direct testing. See [KNOWN_GAPS.md](KNOWN_GAPS.md#validation-status-important) for the full validation status and what completing it would require.

Real architectures have more dimensions than `cloud_cdn / hardened`. The `architecture_modifiers` section captures 14 deployment-time choices that shift the base effectiveness:

| Modifier | What it captures |
|---|---|
| `engagement_mode` | always-on inline vs always-on with escalation vs on-demand BGP redirect |
| `api_controllability` | how reachable the `tuned`/`hardened` cells are operationally (Terraform/IaC vs click-ops) |
| `integration_class` | unified-edge vs bolted-on stacks (each integration boundary is its own attack surface) |
| `origin_scaling_class` | serverless / container / ALB-fronted / API-gateway-fronted / VM (each shifts request-flood and connection-flood ratings) |
| `rate_limit_basis` | per-IP / per-subnet / per-API-key / per-session / per-authenticated-user |
| `cost_aware_throttling` | per-endpoint cost budgets, GraphQL cost analysis |
| `origin_ip_exposure` | public origin / IP-allowlisted / private tunnel (CF Tunnel, PrivateLink) |
| `caching_layers` | none / CDN edge / + shield / + app-cache |
| `ipv6_origin_protection` | dual-stack protected vs IPv4-only CDN with reachable IPv6 origin |
| `regional_pop_density` | thin / medium / dense at the attack source region |
| `engagement_latency_seconds` | numeric metadata; matters for pulse-wave attacks shorter than the engagement window |
| `baseline_maturity` | behavioral baseline trained for <1w / 1-2w / 2+w |
| `policy_statefulness` | stateless / stateful-session / stateful-user WAF policy |
| `human_response_latency` | numeric metadata; what response time the hardened ratings assume |

Each modifier has options with per-option shifts on the 4-point scale (`deadly=0, degraded=1, mitigated=2, blocked=3`). The composition rule lives in `_arch_modifier_computation`:

```
effective_rating = clamp(base + sum(applicable_arch_modifier_shifts), 0, 3)
```

### Attacker-side modifiers (held back)

The full matrix internally also has two attacker-side axes that shift base effectiveness:

- **Technique modifiers** describe the request-shaping trick (cache busting, range abuse, image resize inflation, pagination abuse).
- **Strategy modifiers** describe the traffic-fingerprint posture (script-kiddie defaults, valid-browser rotation, fingerprint rotation, abnormal/chaotic).

These are not in the public release because they describe specific bypass behaviour at a level closer to a playbook than a research dataset. The companion taxonomy ([`ddactic/ddos-attack-taxonomy`](https://github.com/DDactic/ddos-attack-taxonomy)) covers technique and strategy concepts at the level of mitigation guidance for defenders.

## Methodology

The base ratings come from a mix of:

1. **Direct testing.** DDactic operates a multi-cloud bot fleet and runs end-to-end attack simulations against client architectures under explicit authorization. The authoritative ratings come from those engagements.
2. **CVE and vendor advisory review.** Where a vector is tied to a public CVE (CVE-2023-44487 Rapid Reset, CVE-2024-27316 Continuation, the H2 family from 2019, etc), the published patch state is reflected in the rating.
3. **Mechanism-first reasoning.** For combinations we have not directly tested, the rating is derived from the architectural class and the resource the vector exhausts. These cells carry a `notes` line explaining the reasoning rather than empirical data.

The matrix is **descriptive, not prescriptive**. A `mitigated` rating against `cloud_cdn / tuned` does not mean every cloud CDN at a tuned config level mitigates the vector; it means the architectural class, configured at a typical level of effort, has been observed to mitigate it across the engagements we ran. Real outcomes depend on the specific product, its tier, and traffic baselines.

See [KNOWN_GAPS.md](KNOWN_GAPS.md) for an explicit inventory of dimensions v1.0 does not capture (always-on vs on-demand, API-controllability, origin scaling class, private tunnels, IPv6 reachability, behavioral baseline training time, and others). PRs adding these as explicit columns are welcome.

## How DDactic uses it

The matrix is the kernel of our test plan generator. When a customer's architecture is detected during a scan (cloud CDN visible, or hybrid with an on-prem appliance, or unprotected origin), the scan picks the subset of vectors rated `deadly` or `degraded` for that architecture and generates a prioritized test plan. Vectors rated `blocked` or `mitigated` are skipped to keep the plan honest.

You can run the same exercise against your own architecture with our [free scan](https://ddactic.net/free-scan).

## Want to contribute?

Yes please. CVE additions, new vectors, ratings revisions, prerequisite refinements, and modifier improvements are all in scope. See [CONTRIBUTING.md](CONTRIBUTING.md).

The repository is licensed under **CC-BY-4.0 for the data** and **MIT for the scripts**. See [LICENSE](LICENSE).

If you cite this in academic work, please use [CITATION.cff](CITATION.cff).

## Related work

- [`ddactic/ddos-attack-taxonomy`](https://github.com/DDactic/ddos-attack-taxonomy) is the human-readable companion. It groups the 213 vectors into 23 fundamental mechanisms and explains the resource hierarchy and HTTP-version multiplier model. Each mechanism family file in that repo cross-references the vector IDs in this dataset.
- [DDactic](https://ddactic.net) is the commercial DDoS resilience testing platform that the matrix powers. The free scan publishes a per-domain test plan grounded in the public matrix.

## Disclaimer

This dataset describes how attack vectors interact with defensive architectures. It is intended for authorized testing, defensive planning, and academic research. Do not use it to attack systems you do not own or have written permission to test. The maintainers accept no liability for misuse.
