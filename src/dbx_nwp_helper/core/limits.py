"""Enforce Databricks account network-policy limits on ingress rule specs (warn + auto-cap).

Ported from the ingress notebook's `_enforce_limits`. Emits human-readable warnings via a callback so
the caller (CLI) controls presentation; returns the capped (allow, deny) spec lists.
"""

from __future__ import annotations

from collections.abc import Callable

from ..config import (
    MAX_CIDRS_PER_POLICY,
    MAX_IDENTITIES_PER_POLICY,
    MAX_INGRESS_RULES_PER_POLICY,
)

Warn = Callable[[str], None]


def enforce_limits(
    specs: list[dict], deny: list[dict], label: str, warn: Warn
) -> tuple[list[dict], list[dict]]:
    """Cap a target policy's rules to 50 ingress rules / 2000 CIDRs / 100 identities per policy."""
    # Identities per rule (100).
    for spec in specs:
        n = len(spec.get("identities") or [])
        if n > MAX_IDENTITIES_PER_POLICY:
            warn(
                f"[{label}] rule '{spec['label']}' has {n} identities > "
                f"{MAX_IDENTITIES_PER_POLICY} — using the first {MAX_IDENTITIES_PER_POLICY}."
            )
            spec["identities"] = spec["identities"][:MAX_IDENTITIES_PER_POLICY]

    # Ingress rules per policy (50): allow + deny combined.
    all_rules = specs + list(deny)
    if len(all_rules) > MAX_INGRESS_RULES_PER_POLICY:
        warn(
            f"[{label}] {len(all_rules)} rules (allow+deny) > {MAX_INGRESS_RULES_PER_POLICY} "
            f"— keeping the first {MAX_INGRESS_RULES_PER_POLICY} (allow rules prioritised)."
        )
        specs = specs[:MAX_INGRESS_RULES_PER_POLICY]
        remaining = MAX_INGRESS_RULES_PER_POLICY - len(specs)
        deny = deny[: max(remaining, 0)]

    def _total_cidrs(rs):
        return sum(len(r["cidrs"]) for r in rs)

    budget = MAX_CIDRS_PER_POLICY - _total_cidrs(specs)
    if budget < 0:
        warn(f"[{label}] allow CIDRs alone exceed {MAX_CIDRS_PER_POLICY} — trimming allow rules.")
        trimmed, used = [], 0
        for r in specs:
            room = MAX_CIDRS_PER_POLICY - used
            if room <= 0:
                break
            r = dict(r, cidrs=r["cidrs"][:room])
            trimmed.append(r)
            used += len(r["cidrs"])
        specs, deny = trimmed, []
    else:
        trimmed_deny, used = [], 0
        for r in deny:
            room = budget - used
            if room <= 0:
                warn(f"[{label}] deny CIDRs trimmed to fit the {MAX_CIDRS_PER_POLICY}-CIDR policy limit.")
                break
            r = dict(r, cidrs=r["cidrs"][:room])
            trimmed_deny.append(r)
            used += len(r["cidrs"])
        deny = trimmed_deny
    return specs, deny
