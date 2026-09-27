"""Orchestrates a full audit run: collect -> detect -> assemble the risk register.

Kept separate from cli.py so the whole pipeline can be driven directly in
tests (or from a future web UI) without going through argument parsing.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .collectors import ADUser, DomainPolicy, collect_domain_policy, collect_group_members, collect_users
from .connector import Connector, DomainTarget
from .detectors import (
    detect_asrep_roasting,
    detect_kerberoasting,
    detect_password_policy_weaknesses,
    detect_privileged_group_sprawl,
    detect_stale_accounts,
)
from .risk import RiskRegister
from .schema import PRIVILEGED_GROUPS


def run_audit_on_data(
    domain: str,
    users: list[ADUser],
    domain_policy: DomainPolicy | None = None,
    group_members: dict[str, list[str]] | None = None,
    now: datetime | None = None,
) -> RiskRegister:
    """Run every detector against already-collected data. This is the pure,
    easily-testable core — no LDAP connection required."""
    register = RiskRegister(domain=domain, users_scanned=len(users))
    now = now or datetime.now(timezone.utc)

    for finding_fn, kwargs in [
        (detect_asrep_roasting, {"users": users}),
        (detect_kerberoasting, {"users": users}),
        (detect_password_policy_weaknesses, {"domain_policy": domain_policy}),
        (detect_stale_accounts, {"users": users, "now": now}),
    ]:
        try:
            finding = finding_fn(**kwargs)
            if finding:
                register.add(finding)
        except Exception as exc:  # a single detector failing shouldn't kill the whole run
            register.errors.append(f"{finding_fn.__name__} failed: {exc}")

    if group_members:
        try:
            finding = detect_privileged_group_sprawl(group_members=group_members)
            if finding:
                register.add(finding)
        except Exception as exc:
            register.errors.append(f"detect_privileged_group_sprawl failed: {exc}")

    return register


def run_audit_live(target: DomainTarget) -> RiskRegister:
    """Connect to a real domain controller, collect everything, and run the audit."""
    connector = Connector.connect(target)
    try:
        users = collect_users(connector)
        domain_policy = collect_domain_policy(connector)
        group_members = {
            group: collect_group_members(connector, group) for group in PRIVILEGED_GROUPS
        }
        return run_audit_on_data(
            domain=target.domain,
            users=users,
            domain_policy=domain_policy,
            group_members=group_members,
        )
    finally:
        connector.close()
