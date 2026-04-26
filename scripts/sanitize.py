#!/usr/bin/env python3
"""
Sanitize the internal attack effectiveness matrix for public release.

Input:  ../private/attack_effectiveness_matrix.json (internal copy, not committed)
Output: ../data/attack_effectiveness_matrix.json (public, sanitized)
        ../PRIVATE_OMITTED.md (audit log of what was dropped, gitignored)

Rules applied (see PRIVATE_OMITTED.md for the full list):
- Drop fields that reveal internal tooling: tool_flags, planned_tool, execution_status,
  ddactic_advantage, _tools, _escalator_roadmap, _tool_mapping_*, _execution_statuses.
- Replace proprietary tool names in `tool` and `common_tools.advanced` with neutral
  category strings.
- Generalize per-vendor names in all `notes` fields to architecture-level descriptions.
- Keep the qualitative effectiveness matrix, modifiers, prerequisites, CVE ids,
  amplification factors, and public-tool tiers intact.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
PRIVATE = ROOT / "private" / "attack_effectiveness_matrix.json"
PUBLIC = ROOT / "data" / "attack_effectiveness_matrix.json"
AUDIT = ROOT / "PRIVATE_OMITTED.md"

DROP_VECTOR_FIELDS = {
    "tool_flags",
    "planned_tool",
    "execution_status",
    "ddactic_advantage",
    "status",
}

DROP_TOP_LEVEL_FIELDS = {
    "_tools",
    "_escalator_roadmap",
    "_tool_mapping_version",
    "_tool_mapping_date",
    "_execution_statuses",
    "_common_tools_note",
}

PROPRIETARY_TOOLS = {
    "p0fping": "raw-socket-l3l4",
    "escalator": "l7-http-stress",
    "credential_stuffer": "ato-stress",
    "graphql_stress": "graphql-stress",
    "grpc_stress": "grpc-stress",
    "middlebox_attack": "middlebox-research",
}

VENDOR_REPLACEMENTS = [
    (re.compile(r"\bCloudflare\s+Bot\s+Score\b", re.I), "cloud bot management"),
    (re.compile(r"\bAkamai\s+Bot\s+Manager\b", re.I), "cloud bot management"),
    (re.compile(r"\bImperva\s+Advanced\s+Bot\s+Protection\b", re.I), "cloud bot management"),
    (re.compile(r"\bCloudflare\s+Images\b", re.I), "edge image processing"),
    (re.compile(r"\bImgix\b", re.I), "edge image processing"),
    (re.compile(r"\bF5\s+(?:ASM|BIG-?IP)\b", re.I), "on-prem WAF"),
    (re.compile(r"\bBIG-?IP\b", re.I), "on-prem WAF"),
    (re.compile(r"\bRadware\s+DefensePro\b", re.I), "DDoS appliance"),
    (re.compile(r"\bRadware\s+Cloud\b", re.I), "cloud CDN/WAF"),
    (re.compile(r"\bA10\s+Thunder\s+TPS\b", re.I), "DDoS appliance"),
    (re.compile(r"\b(?:Cloudflare|Akamai|Imperva|Incapsula)\b", re.I), "cloud CDN/WAF"),
    (re.compile(r"\b(?:F5|FortiGate|Fortinet|Check\s?Point|Palo\s+Alto)\b", re.I), "on-prem WAF"),
    (re.compile(r"\b(?:DefensePro|Arbor|A10|Radware)\b", re.I), "DDoS appliance"),
]


def neutralize_vendors(text: str) -> str:
    if not isinstance(text, str):
        return text
    out = text
    for pattern, replacement in VENDOR_REPLACEMENTS:
        out = pattern.sub(replacement, out)
    out = re.sub(
        r"\b(cloud CDN/WAF|on-prem WAF|DDoS appliance|cloud bot management)(?:\s*[/,]\s*(?:cloud CDN/WAF|on-prem WAF|DDoS appliance|cloud bot management))+",
        r"\1",
        out,
        flags=re.I,
    )
    return out


def neutralize_walk(node: Any, in_notes: bool = False) -> Any:
    if isinstance(node, dict):
        return {k: neutralize_walk(v, in_notes=(k == "notes" or in_notes)) for k, v in node.items()}
    if isinstance(node, list):
        return [neutralize_walk(item, in_notes=in_notes) for item in node]
    if isinstance(node, str) and in_notes:
        return neutralize_vendors(node)
    return node


PROPRIETARY_TOOL_DESCRIPTORS = {
    "p0fping": "raw-socket toolkit",
    "escalator": "L7 HTTP stress toolkit",
    "credential_stuffer": "ATO stress toolkit",
    "graphql_stress": "GraphQL stress toolkit",
    "grpc_stress": "gRPC stress toolkit",
    "middlebox_attack": "middlebox abuse research tool",
}

PROPRIETARY_TOOL_PATTERN = re.compile(
    r"(?i)(?:^|\bDDactic\s+)(p0fping|escalator|credential_stuffer|graphql_stress|grpc_stress|middlebox_attack)\b.*$"
)


def sanitize_common_tools(common_tools: dict) -> dict:
    if not isinstance(common_tools, dict):
        return common_tools
    out: dict[str, Any] = {}
    for tier, tools in common_tools.items():
        if not isinstance(tools, list):
            out[tier] = tools
            continue
        cleaned: list[str] = []
        seen: set[str] = set()
        for t in tools:
            if not isinstance(t, str):
                cleaned.append(t)
                continue
            t2 = re.sub(r"\s*\((?:DDactic|Cloudflare|Akamai|Google|Meta|F5|Cisco)\)\s*$", "", t).strip()
            m = PROPRIETARY_TOOL_PATTERN.match(t2)
            if m:
                t2 = PROPRIETARY_TOOL_DESCRIPTORS[m.group(1).lower()]
            if t2 and t2 not in seen:
                cleaned.append(t2)
                seen.add(t2)
        out[tier] = cleaned
    return out


def sanitize_vector(vid: str, v: dict, dropped: list[dict]) -> dict:
    out: dict[str, Any] = {}
    for k, val in v.items():
        if k in DROP_VECTOR_FIELDS:
            continue
        if k == "tool":
            if isinstance(val, str) and val in PROPRIETARY_TOOLS:
                out["tool_category"] = PROPRIETARY_TOOLS[val]
            else:
                out[k] = val
        elif k == "common_tools":
            out[k] = sanitize_common_tools(val)
        elif k == "tool_notes":
            continue
        elif k == "effectiveness":
            out[k] = neutralize_walk(val, in_notes=False)
        else:
            out[k] = val
    return out


def sanitize_matrix(m: dict) -> tuple[dict, list[str]]:
    notes: list[str] = []
    out: dict[str, Any] = {}

    out["_version"] = m.get("_version", "3.0")
    out["_generated"] = m.get("_generated", "")
    out["_published_under_license"] = "CC-BY-4.0 (data) + MIT (scripts)"
    out["_published_at"] = "2026-04-26"
    out["_sanitization"] = (
        "Public release of an internal research matrix. Vendor names in notes "
        "have been generalized to architecture categories. Internal tool flags, "
        "tool roadmap, and proprietary execution metadata have been removed. "
        "See PRIVATE_OMITTED.md in the source repo for the audit log."
    )
    out["_description"] = m.get("_description", "")
    out["_notes"] = m.get("_notes", [])
    out["architectures"] = m.get("architectures", {})
    out["config_levels"] = m.get("config_levels", {})

    vectors = m.get("vectors", {})
    cleaned_vectors: dict[str, Any] = {}
    dropped_log: list[dict] = []
    for vid, v in vectors.items():
        cleaned = sanitize_vector(vid, v, dropped_log)
        cleaned_vectors[vid] = cleaned
    out["vectors"] = cleaned_vectors
    notes.append(f"Vectors retained: {len(cleaned_vectors)} (none dropped wholesale)")

    # technique_modifiers, strategy_modifiers, and _modifier_computation are
    # deliberately NOT included in the public release. The modifier framework
    # (how techniques and strategies compose with base ratings) is the most
    # operationally sensitive part of the matrix. Defenders get the per-cell
    # ratings; the composition rules stay private. See PRIVATE_OMITTED.md.
    out["_modifiers_note"] = (
        "Technique modifiers (cache-bust, range abuse, image resize, pagination "
        "abuse, etc.) and strategy modifiers (browser fingerprint rotation, "
        "script-kiddie posture, etc.) compose with the base effectiveness ratings "
        "to predict how attack variants land against each architecture. The "
        "composition rule and per-modifier shifts are not part of the public "
        "release. Contact DDactic for the full framework."
    )

    if "_summary" in m:
        out["_summary"] = m["_summary"]

    drop_count = 0
    for k in DROP_TOP_LEVEL_FIELDS:
        if k in m:
            drop_count += 1
    notes.append(f"Top-level internal fields dropped: {drop_count}")
    modifier_drops = [k for k in ("technique_modifiers", "strategy_modifiers", "_modifier_computation") if k in m]
    if modifier_drops:
        notes.append(f"Modifier framework held back: {', '.join(modifier_drops)}")

    return out, notes


def write_audit(notes: list[str]) -> None:
    body = [
        "# PRIVATE_OMITTED.md",
        "",
        "_Audit log for the sanitization pass that produced `data/attack_effectiveness_matrix.json`._",
        "",
        "**This file is gitignored.** It exists locally so the maintainer can re-verify what",
        "was stripped, and so a future re-publication can re-apply the same rules.",
        "",
        "## Fields dropped from every vector",
        "",
        "| Field | Reason |",
        "|---|---|",
        "| `tool_flags` | Exact CLI invocations for the internal toolchain (e.g. `-c 0` infinite-count flags). Not useful as research data and reveals operational defaults. |",
        "| `planned_tool` | Internal tooling roadmap. |",
        "| `execution_status` | Internal pipeline state. |",
        "| `ddactic_advantage` | Marketing copy for the commercial offering, not research. Sometimes named non-public tool capabilities. |",
        "| `status` | Internal triage marker on a few vectors. |",
        "| `tool_notes` | Free-form internal commentary. |",
        "",
        "## Top-level sections dropped",
        "",
        "| Key | Reason |",
        "|---|---|",
        "| `_tools` | Inventory of internal binaries (escalator, p0fping, credential_stuffer, graphql_stress, middlebox_attack, grpc_stress). |",
        "| `_escalator_roadmap` | Internal feature roadmap that names upcoming bypass techniques (cookie-replay, method-rotation, multipart-range). |",
        "| `_tool_mapping_version` / `_tool_mapping_date` | Internal versioning. |",
        "| `_execution_statuses` | Internal pipeline state legend. |",
        "| `_common_tools_note` | Internal annotation about the tool tiering. |",
        "",
        "## Field-level sanitization",
        "",
        "- `tool` field with a proprietary name was renamed to `tool_category` and replaced with a neutral category string:",
        "  - `p0fping` -> `raw-socket-l3l4`",
        "  - `escalator` -> `l7-http-stress`",
        "  - `credential_stuffer` -> `ato-stress`",
        "  - `graphql_stress` -> `graphql-stress`",
        "  - `grpc_stress` -> `grpc-stress`",
        "  - `middlebox_attack` -> `middlebox-research`",
        "- `common_tools.advanced` had `(DDactic)` annotations removed and proprietary names replaced with generic toolkit categories.",
        "",
        "## Notes-field generalization",
        "",
        "Vendor brand names in the `notes` substrings of `effectiveness.*`, `technique_modifiers.*.shifts.*`, and `strategy_modifiers.*.shifts.*` were rewritten to architecture categories so the published matrix is not a per-vendor bypass cookbook. The architectural conclusion (mitigated vs deadly at default/tuned/hardened) is preserved.",
        "",
        "| Pattern (case-insensitive) | Replacement |",
        "|---|---|",
        "| Cloudflare / Akamai / Imperva / Incapsula / Radware Cloud | cloud CDN/WAF |",
        "| F5 / BIG-IP / FortiGate / Fortinet / Check Point / Palo Alto | on-prem WAF |",
        "| Radware DefensePro / Arbor / A10 Thunder TPS | DDoS appliance |",
        "| Cloudflare Bot Score / Akamai Bot Manager / Imperva ABP | cloud bot management |",
        "| Cloudflare Images / Imgix | edge image processing |",
        "",
        "## What was deliberately KEPT",
        "",
        "- The full qualitative effectiveness grid (deadly / degraded / mitigated / blocked) for each vector x architecture x config-level cell.",
        "- Public CVE references (CVE-2023-44487 Rapid Reset, CVE-2024-27316 Continuation, CVE-2009-3555 TLS Renegotiation, the H2 family CVE-2019-9512..9518).",
        "- Amplification factors for reflection vectors (these are well-published; e.g. Memcached 50,000x, NTP ~500x).",
        "- Mechanism descriptions for every vector. These are textbook attack mechanics, not novel research.",
        "- Public tool tiers (`script_kiddie`, `intermediate`) and category names for `advanced`.",
        "",
        "## Modifier framework held back",
        "",
        "The `technique_modifiers`, `strategy_modifiers`, and `_modifier_computation` sections are deliberately NOT in the public release. They describe how request-shaping techniques (cache-bust, range abuse, image-resize inflation, pagination abuse) and traffic-fingerprint strategies (browser rotation, script-kiddie defaults, abnormal/chaotic) compose with the base effectiveness ratings to predict how an attack variant will land.",
        "",
        "This is the most operationally sensitive part of the matrix. The structural ratings tell a defender 'cache-bust against cloud CDN at default config is mitigated'. The modifiers add 'apply cache_bust_params and the cell drops to deadly'. The first is research; the second is closer to a playbook.",
        "",
        "The public release retains the structural ratings and acknowledges the modifier framework exists (via the `_modifiers_note` field). The composition rule, the per-modifier shifts, and the per-architecture playbooks remain private. This keeps DDactic's defensive testing methodology intact while still giving the research community a citable dataset.",
        "",
        "## Sanitization run summary",
        "",
    ]
    for n in notes:
        body.append(f"- {n}")
    body.append("")
    AUDIT.write_text("\n".join(body), encoding="utf-8")


def main() -> int:
    if not PRIVATE.exists():
        print(f"FATAL: expected internal copy at {PRIVATE}", file=sys.stderr)
        print("Place the unsanitized matrix at scripts/../private/attack_effectiveness_matrix.json", file=sys.stderr)
        return 1
    with PRIVATE.open() as f:
        m = json.load(f)
    sanitized, notes = sanitize_matrix(m)
    PUBLIC.parent.mkdir(parents=True, exist_ok=True)
    with PUBLIC.open("w") as f:
        json.dump(sanitized, f, indent=2, ensure_ascii=False)
        f.write("\n")
    write_audit(notes)
    print(f"Wrote {PUBLIC}")
    print(f"Wrote {AUDIT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
