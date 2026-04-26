#!/usr/bin/env python3
"""
Build v3.1 of the attack effectiveness matrix.

v3.1 is additive over v3.0: it introduces an `architecture_modifiers` top-level
section that captures defender-side deployment choices that shift the base
effectiveness ratings. Unlike `technique_modifiers` and `strategy_modifiers`
(attacker-side, held back from public release), architecture modifiers are
defender-side and safe to publish.

Each modifier specifies:
- name (human-readable)
- applies_to (list of architecture keys, or "all")
- options (a dict of named choices)
- per_option shift on the 4-point scale (deadly=0, degraded=1, mitigated=2, blocked=3)
- affects_mechanisms (optional list of M-XX ids the modifier primarily moves)
- notes (one line per option explaining the shift)
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "data" / "attack_effectiveness_matrix.json"

ARCH_MODIFIERS = {
    "_description": "Defender-side modifiers that adjust base architecture effectiveness based on deployment-time choices. Compose with the base rating using _arch_modifier_computation. Unlike the attacker-side modifiers (held back from public release), these modifiers are safe to share because they help a defender characterize their own posture, not an attacker.",
    "_applicable_layers": "all",
    "engagement_mode": {
        "name": "Engagement mode",
        "applies_to": ["cloud_cdn", "ddos_appliance", "hybrid"],
        "affects_mechanisms": ["M-01", "M-02", "M-15", "M-19"],
        "options": {
            "always_on_inline": {
                "shift": 0,
                "notes": "Default assumption. Mitigation engages on first packet."
            },
            "always_on_with_escalation": {
                "shift": 1,
                "notes": "Manual escalation step required for full mitigation. Adds 60-300s of degraded posture during escalation."
            },
            "on_demand_bgp_redirect": {
                "shift": 2,
                "notes": "BGP redirect convergence ~30-90s. Pulse attacks under 30s land before mitigation engages."
            }
        }
    },
    "api_controllability": {
        "name": "API-controllability of the protection product",
        "applies_to": "all",
        "options": {
            "full_api_iac": {
                "shift": 0,
                "notes": "Tuned and hardened cells reachable via Terraform / Pulumi / GitOps. Operationally cheap to harden."
            },
            "partial_api": {
                "shift": 0,
                "notes": "Some hardening requires console sessions. Operationally slower to reach hardened."
            },
            "click_ops_only": {
                "shift": 1,
                "notes": "Hardened in practice is one config-level lower than rated because hardening is operationally too painful to maintain."
            }
        }
    },
    "integration_class": {
        "name": "Integration class (unified vs bolted-on)",
        "applies_to": ["cloud_cdn", "hybrid"],
        "options": {
            "unified_edge": {
                "shift": 0,
                "notes": "Single policy plane. WAF, DDoS, rate-limit, bot-management share state and signal."
            },
            "bolted_on_2_layer": {
                "shift": 1,
                "notes": "Edge plus behind-edge product with separate policy. Trust assumptions between layers exploitable."
            },
            "bolted_on_3_plus_layer": {
                "shift": 1,
                "notes": "Three or more independent products in line. Each integration boundary is its own attack surface."
            }
        }
    },
    "origin_scaling_class": {
        "name": "Origin scaling class",
        "applies_to": "all",
        "affects_mechanisms": ["M-07", "M-11", "M-15", "M-19"],
        "options": {
            "serverless": {
                "shift": -1,
                "notes": "Functions / Cloud Run / Lambda autoscale. Floods cost money but rarely take service down. Cell shifts toward mitigated for request floods."
            },
            "container_kubernetes": {
                "shift": 0,
                "notes": "Default assumption. Scales fast with a warm-up window and a horizontal pod cap."
            },
            "alb_fronted": {
                "shift": 0,
                "notes": "ALB / NLB scales on connection count, not RPS. M-07 (Idle Hold) and M-11 (H/2 Stream Churn) hit ALB connection accounting differently than they hit a request-counting WAF."
            },
            "api_gateway_fronted": {
                "shift": -1,
                "notes": "AWS API Gateway / Apigee / Azure APIM provide rate limiting at the gateway, before origin sees the request."
            },
            "vm_or_metal": {
                "shift": 1,
                "notes": "No autoscale. Floods either fit within rated capacity or they overwhelm it."
            }
        }
    },
    "rate_limit_basis": {
        "name": "Rate-limit basis",
        "applies_to": "all",
        "affects_mechanisms": ["M-15", "M-16", "M-19"],
        "options": {
            "per_ip": {
                "shift": 0,
                "notes": "Default assumption. Carpet bombing across a /24 defeats it."
            },
            "per_subnet_aggregated": {
                "shift": -1,
                "notes": "Limits aggregated across /24 or /23 subnets. Defeats single-block carpet bombing."
            },
            "per_api_key": {
                "shift": -1,
                "notes": "Per-API-key limits. Carpet bombing must be per-account, not per-IP. Significantly stronger for B2B APIs."
            },
            "per_session": {
                "shift": -1,
                "notes": "Session correlation across IPs. Defeats per-IP rotation."
            },
            "per_authenticated_user": {
                "shift": -2,
                "notes": "Limits keyed to an authenticated user identity. The strongest standard form. Useful for any post-login traffic."
            }
        }
    },
    "cost_aware_throttling": {
        "name": "Per-endpoint cost budgets / expensive-request tagging",
        "applies_to": "all",
        "affects_mechanisms": ["M-18", "M-19"],
        "options": {
            "absent": {
                "shift": 0,
                "notes": "Default assumption. All endpoints treated equally."
            },
            "per_endpoint_budgets": {
                "shift": -1,
                "notes": "Costly endpoints (login, search, GraphQL deep selection, PDF generation, image resize) have per-account or per-key budgets that throttle expensive operations independently of cheap ones."
            },
            "graphql_cost_analysis": {
                "shift": -1,
                "notes": "GraphQL query-cost analysis with a budget. Specifically defends GraphQL Backend Query Amp variants."
            }
        }
    },
    "origin_ip_exposure": {
        "name": "Origin IP exposure",
        "applies_to": "all",
        "affects_mechanisms": ["direct_origin_attack"],
        "options": {
            "public": {
                "shift": 0,
                "notes": "Origin IP discoverable via OSINT (DNS history, MX, SPF, certificate transparency). CDN bypass is viable."
            },
            "ip_allowlisted_to_cdn": {
                "shift": -2,
                "notes": "Origin firewall accepts traffic only from documented CDN IP ranges plus mTLS. OSINT-discovered IP is useless because origin refuses non-CDN sources."
            },
            "private_tunnel": {
                "shift": -3,
                "notes": "Cloudflare Tunnel / AWS PrivateLink / Azure Private Link / GCP Private Service Connect. Origin has no public IP. CDN bypass is N/A."
            }
        }
    },
    "caching_layers": {
        "name": "Caching layers present",
        "applies_to": "all",
        "affects_mechanisms": ["M-16"],
        "options": {
            "none": {
                "shift": 0,
                "notes": "No cache layer. Every request hits origin."
            },
            "cdn_edge_only": {
                "shift": -1,
                "notes": "CDN edge cache absorbs cache-friendly traffic. Cache-bust attacks bypass it."
            },
            "cdn_edge_plus_shield": {
                "shift": -1,
                "notes": "CDN edge plus regional shield (Cloudflare Tiered Cache, Akamai Tiered Distribution, Fastly Origin Shield). Reduces origin pull rate even under cache-bust."
            },
            "cdn_edge_plus_app_cache": {
                "shift": -2,
                "notes": "CDN edge plus in-app cache (Redis, Memcached, Varnish). Multi-layer cache absorbs cache-bust at the application layer."
            }
        }
    },
    "ipv6_origin_protection": {
        "name": "IPv6 origin protection parity",
        "applies_to": ["cloud_cdn", "hybrid"],
        "affects_mechanisms": ["direct_origin_attack"],
        "options": {
            "dual_stack_protected": {
                "shift": 0,
                "notes": "CDN protects IPv4 and IPv6 traffic equivalently. Origin firewall rejects non-CDN sources on both stacks."
            },
            "ipv4_only_cdn_dual_stack_origin": {
                "shift": 2,
                "notes": "CDN proxies only IPv4. Origin has an AAAA record reachable directly. Attackers route over IPv6, bypass the CDN entirely. This is one of the most common silent gaps."
            }
        }
    },
    "regional_pop_density": {
        "name": "Regional PoP density at attack source region",
        "applies_to": ["cloud_cdn", "hybrid"],
        "affects_mechanisms": ["M-01", "M-02"],
        "options": {
            "thin": {
                "shift": 1,
                "notes": "Fewer than 5 PoPs in the attack source region. Volumetric absorption is constrained."
            },
            "medium": {
                "shift": 0,
                "notes": "5 to 20 PoPs in region. Default assumption."
            },
            "dense": {
                "shift": -1,
                "notes": "Over 20 PoPs in region. Regional volumetric attacks absorbed at edge with margin."
            }
        }
    },
    "engagement_latency_seconds": {
        "name": "Mitigation engagement latency",
        "applies_to": "all",
        "type": "numeric_metadata",
        "interaction": "Compare with attack pulse window. If pulse_window_seconds is less than engagement_latency_seconds, downshift the cell by 1 for the duration of the pulse, because the mitigation does not engage before the burst ends.",
        "typical_values": {
            "always_on_edge_signature": "1-3s",
            "always_on_edge_behavioral": "10-60s",
            "always_on_with_escalation": "60-300s",
            "on_demand_bgp_redirect": "30-90s",
            "manual_response_only": "300s+"
        }
    },
    "baseline_maturity": {
        "name": "Behavioral baseline maturity",
        "applies_to": "all",
        "options": {
            "untrained_under_1_week": {
                "shift": 1,
                "notes": "Hardened cells are effectively tuned. Most behavioral classifiers have not seen enough traffic to flag anomalies."
            },
            "training_1_2_weeks": {
                "shift": 1,
                "notes": "Behavioral models still converging. Treat hardened ratings with caution."
            },
            "trained_2_plus_weeks": {
                "shift": 0,
                "notes": "Default hardened assumption. Behavioral baselines stable enough to flag deviations."
            }
        }
    },
    "policy_statefulness": {
        "name": "WAF policy statefulness",
        "applies_to": ["cloud_cdn", "security_waf", "hybrid"],
        "affects_mechanisms": ["M-15", "M-19"],
        "options": {
            "stateless": {
                "shift": 0,
                "notes": "Default assumption. Each request evaluated independently."
            },
            "stateful_session": {
                "shift": -1,
                "notes": "Sliding-window per-session counters. Defeats request-rate attacks that rotate IPs but reuse sessions."
            },
            "stateful_user": {
                "shift": -2,
                "notes": "Cross-session correlation per authenticated user. Strongest stateful posture for application-layer defense."
            }
        }
    },
    "human_response_latency": {
        "name": "Operator response latency assumption",
        "applies_to": "all",
        "type": "numeric_metadata",
        "default_assumption_seconds": 300,
        "interaction": "Hardened ratings against M-18 / M-19 implicitly assume the operator sees the alert and responds within ~5 minutes. Sites with longer response latency should downshift these cells. Sites with sub-minute incident response (typically 24/7 SOCs) can leave hardened as-is."
    }
}

ARCH_MODIFIER_COMPUTATION = {
    "_description": (
        "Architecture modifiers compose with the base effectiveness rating "
        "additively, like the attacker-side modifiers. The composition rule is: "
        "effective_rating = clamp(base_rating + sum(applicable_arch_modifier_shifts), 0, 3) "
        "where the 4-point scale is deadly=0, degraded=1, mitigated=2, blocked=3 "
        "and 'applicable' means the modifier's `applies_to` field includes the "
        "architecture you are evaluating, and you have selected a non-default option."
    ),
    "scale": {"deadly": 0, "degraded": 1, "mitigated": 2, "blocked": 3},
    "rule": "effective = clamp(base + sum(arch_modifier_shifts), 0, 3)",
    "notes": (
        "Numeric-metadata modifiers (engagement_latency_seconds, "
        "human_response_latency) do not contribute a numeric shift directly. "
        "They are inputs to a per-attack interaction described in their own "
        "interaction field."
    ),
}


def main() -> int:
    with PUBLIC.open() as f:
        m = json.load(f)

    m["_version"] = "3.1"
    m["_published_at"] = "2026-04-26"
    m["_changelog"] = m.get("_changelog", []) + [
        {
            "version": "3.1",
            "date": "2026-04-26",
            "change": "Added architecture_modifiers section (14 defender-side modifier categories addressing the v1.0 gaps documented in KNOWN_GAPS.md). Additive; v3.0 readers continue to work because the existing keys are untouched."
        }
    ]
    m["architecture_modifiers"] = ARCH_MODIFIERS
    m["_arch_modifier_computation"] = ARCH_MODIFIER_COMPUTATION

    # Refresh the existing _modifiers_note to reflect that defender-side
    # modifiers are now public.
    m["_modifiers_note"] = (
        "Defender-side modifiers (architecture_modifiers) are public, see that "
        "section. Attacker-side modifiers (technique_modifiers and strategy_modifiers) "
        "remain held back because they describe specific bypass behaviour at a "
        "level closer to a playbook than a research dataset. Contact DDactic if "
        "you need the attacker-side framework for academic or defensive work "
        "under NDA."
    )

    with PUBLIC.open("w") as f:
        json.dump(m, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Wrote {PUBLIC}")
    print(f"  vectors: {len(m['vectors'])}")
    print(f"  arch modifier categories: {sum(1 for k, v in ARCH_MODIFIERS.items() if not k.startswith('_'))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
