"""Detects privileged-group membership sprawl.

Every extra member of Domain Admins (or the other tier-0 groups) is
another account whose compromise means full domain compromise. This
detector takes a pre-collected mapping of group name -> member DNs
(collected separately, since it needs its own LDAP query per group)
rather than the user list, and flags any privileged group whose
membership exceeds a small, defensible threshold.

This detector is intentionally excluded from ALL_DETECTORS in the
package __init__ for now — running it needs one LDAP query per
privileged group rather than the single user-list query every other
detector shares, so the CLI wires it in separately once the group
membership lookups are done. See auditor.py.
"""

from __future__ import annotations

from ..risk import Finding, Impact, Likelihood

SPRAWL_THRESHOLD = 5


def detect_privileged_group_sprawl(group_members: dict[str, list[str]], **_) -> Finding | None:
    """group_members: {"Domain Admins": [dn, dn, ...], "Enterprise Admins": [...], ...}"""
    sprawling = {name: members for name, members in group_members.items() if len(members) > SPRAWL_THRESHOLD}
    if not sprawling:
        return None

    affected = [f"{name} ({len(members)} members)" for name, members in sprawling.items()]
    total_excess = sum(len(m) for m in sprawling.values())

    return Finding(
        risk_id="AD-005",
        title="Privileged group membership sprawl",
        description=(
            f"{len(sprawling)} tier-0 group(s) exceed {SPRAWL_THRESHOLD} members: "
            + ", ".join(affected)
            + ". Each additional member is a full domain-compromise path if their account is breached."
        ),
        affected_objects=affected,
        likelihood=Likelihood.MEDIUM,
        impact=Impact.HIGH,
        mitre_attack="T1078.002 — Valid Accounts: Domain Accounts",
        control_reference="NIST 800-53 AC-6(1) (Least Privilege — Authorize Access to Security Functions) / CIS Control 5.4",
        recommendation=(
            f"Review the membership of every group over the {SPRAWL_THRESHOLD}-member threshold "
            "and remove any account that doesn't require standing privileged access. Consider "
            "just-in-time privileged access (e.g. time-bound group membership) instead of "
            "permanent membership for administrators who only need it occasionally."
        ),
        detector="privileged_sprawl",
    )
