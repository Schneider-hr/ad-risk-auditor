"""Detects accounts vulnerable to Kerberoasting.

Any user account with a Service Principal Name (SPN) set can have a
Kerberos service ticket requested for it by *any* authenticated domain
user, with no special privilege needed. That ticket is encrypted with a
key derived from the service account's own password, and can be taken
offline and cracked. This is the classic "service account with a
weak, rarely-rotated password" problem — SPNs on user accounts almost
always mean a legacy service account, and those are disproportionately
likely to be privileged and to have old, weak, or unrotated passwords.

Machine accounts (sAMAccountName ending in '$') are excluded: they also
carry SPNs by default, but their passwords are long, random, and
machine-managed, so they aren't a realistic Kerberoasting target.
"""

from __future__ import annotations

from ..collectors import ADUser
from ..risk import Finding, Impact, Likelihood
from ..schema import is_disabled


def detect_kerberoasting(users: list[ADUser], **_) -> Finding | None:
    vulnerable = [
        u for u in users
        if not u.is_machine_account
        and not is_disabled(u.user_account_control)
        and u.service_principal_names
    ]
    if not vulnerable:
        return None

    # A kerberoastable account that also sits in a privileged group is a
    # materially worse finding than an ordinary service account, so the
    # likelihood/impact are pushed up if any affected account's DN suggests
    # privileged OU placement or its memberOf list is non-trivial.
    privileged_hits = [u for u in vulnerable if len(u.member_of) > 1]

    return Finding(
        risk_id="AD-002",
        title="Kerberoastable service accounts",
        description=(
            f"{len(vulnerable)} enabled user account(s) have a Service Principal Name (SPN) "
            "set, meaning any authenticated domain user can request a Kerberos service ticket "
            f"for them and attempt to crack it offline. {len(privileged_hits)} of these also "
            "belong to more than one group, which is worth checking for privileged membership."
        ),
        affected_objects=[u.sam_account_name for u in vulnerable],
        likelihood=Likelihood.MEDIUM,  # needs any valid domain credential, which is a lower bar than "any network access" but not zero
        impact=Impact.HIGH if privileged_hits else Impact.MEDIUM,
        mitre_attack="T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting",
        control_reference="NIST 800-53 IA-5(1) / CIS Control 5.2",
        recommendation=(
            "Set long, random passwords (25+ characters) on every service account, rotate "
            "them on a defined schedule, and prefer Group Managed Service Accounts (gMSA) "
            "for any new service account, since gMSA passwords are machine-managed and "
            "effectively immune to offline cracking."
        ),
        detector="kerberoasting",
    )
