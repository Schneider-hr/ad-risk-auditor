"""Detects enabled accounts that haven't logged on in a long time.

A stale enabled account (former employee, decommissioned service, a
one-off account created for a project that ended) is attack surface
that provides no business value: nobody notices if its password is
compromised, because nobody is actively using it to notice anything
looking wrong.

lastLogonTimestamp is a replicated *approximation* (AD deliberately
only replicates it every ~9-14 days to avoid replication storms), so
this detector treats it as "at least this stale", not exact, and says
so in the finding rather than implying false precision.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..collectors import ADUser
from ..risk import Finding, Impact, Likelihood
from ..schema import filetime_to_datetime, is_disabled

STALE_THRESHOLD_DAYS = 90


def detect_stale_accounts(users: list[ADUser], now: datetime | None = None, **_) -> Finding | None:
    now = now or datetime.now(timezone.utc)
    threshold = now - timedelta(days=STALE_THRESHOLD_DAYS)

    stale: list[str] = []
    never_logged_on: list[str] = []

    for u in users:
        if u.is_machine_account or is_disabled(u.user_account_control):
            continue
        last_logon = filetime_to_datetime(u.last_logon_timestamp) if u.last_logon_timestamp else None
        if last_logon is None:
            never_logged_on.append(u.sam_account_name)
        elif last_logon < threshold:
            stale.append(u.sam_account_name)

    affected = stale + never_logged_on
    if not affected:
        return None

    description_parts = []
    if stale:
        description_parts.append(
            f"{len(stale)} enabled account(s) have not logged on in over {STALE_THRESHOLD_DAYS} days "
            "(lastLogonTimestamp is a replicated approximation, so actual staleness may be greater)"
        )
    if never_logged_on:
        description_parts.append(f"{len(never_logged_on)} enabled account(s) have no recorded logon at all")

    return Finding(
        risk_id="AD-004",
        title="Stale or unused enabled accounts",
        description="; ".join(description_parts) + ".",
        affected_objects=affected,
        likelihood=Likelihood.MEDIUM,
        impact=Impact.MEDIUM,
        mitre_attack="T1078 — Valid Accounts",
        control_reference="NIST 800-53 AC-2(3) (Disable Inactive Accounts) / CIS Control 5.3",
        recommendation=(
            "Disable accounts with no legitimate recent activity, and put a periodic access "
            "review in place so stale accounts are caught and disabled automatically rather "
            "than discovered during an audit."
        ),
        detector="stale_accounts",
    )
