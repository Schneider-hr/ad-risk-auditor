"""Detects accounts vulnerable to AS-REP Roasting.

An account with the DONT_REQUIRE_PREAUTH flag set skips Kerberos
pre-authentication, which means anyone on the network can request an
AS-REP for that account with no credentials at all and get back a
piece of ciphertext encrypted with a key derived from the account's
password — crackable offline. This is exactly the technique used
against the CY270 lab (via Impacket's GetNPUsers) to retrieve two
username-linked hashes with zero credentials supplied.

Real AD environments end up with these flags set almost by accident —
usually a legacy application that couldn't handle Kerberos
pre-auth had it disabled years ago and nobody ever revisited it.
"""

from __future__ import annotations

from ..collectors import ADUser
from ..risk import Finding, Impact, Likelihood
from ..schema import is_asrep_roastable, is_disabled


def detect_asrep_roasting(users: list[ADUser], **_) -> Finding | None:
    vulnerable = [
        u for u in users
        if not u.is_machine_account
        and not is_disabled(u.user_account_control)
        and is_asrep_roastable(u.user_account_control)
    ]
    if not vulnerable:
        return None

    return Finding(
        risk_id="AD-001",
        title="Accounts vulnerable to AS-REP Roasting",
        description=(
            f"{len(vulnerable)} enabled user account(s) have Kerberos pre-authentication "
            "disabled (userAccountControl DONT_REQUIRE_PREAUTH). Any unauthenticated user "
            "on the network can request an AS-REP for these accounts and attempt to crack "
            "the returned hash offline to recover the account password."
        ),
        affected_objects=[u.sam_account_name for u in vulnerable],
        likelihood=Likelihood.HIGH,  # requires no credentials, no network position beyond LDAP/Kerberos reachability
        impact=Impact.HIGH,  # direct path to a valid domain credential if the password is weak
        mitre_attack="T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting",
        control_reference="NIST 800-53 IA-5(1) (Password-Based Authentication) / CIS Control 5.2",
        recommendation=(
            "Re-enable Kerberos pre-authentication for every affected account unless a "
            "specific, documented legacy application requires it. Where it cannot be "
            "disabled, ensure the account uses a long, random password (25+ characters) "
            "that is not feasible to crack offline."
        ),
        detector="asrep_roasting",
    )
