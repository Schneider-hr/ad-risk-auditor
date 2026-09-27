"""Active Directory schema constants used across detectors.

These are real AD semantics, not guesses — userAccountControl is a bitmask
documented by Microsoft (MS-ADTS 2.2.16), and the FILETIME epoch conversion
is the standard Windows epoch (1601-01-01) used by lastLogonTimestamp,
pwdLastSet, accountExpires, etc.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

# --- userAccountControl bit flags (subset relevant to this tool) ---
UF_ACCOUNTDISABLE = 0x0002
UF_PASSWD_NOTREQD = 0x0020
UF_DONT_EXPIRE_PASSWD = 0x10000
UF_NORMAL_ACCOUNT = 0x0200
UF_DONT_REQUIRE_PREAUTH = 0x400000  # this is the AS-REP roasting flag

# --- pwdProperties bit flags on the domain object ---
DOMAIN_PASSWORD_COMPLEX = 0x1
DOMAIN_PASSWORD_NO_ANON_CHANGE = 0x2
DOMAIN_LOCKOUT_ADMINS = 0x8

# --- Well-known privileged group names (by common name, domain-relative) ---
PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
]

# FILETIME (used by lastLogonTimestamp, pwdLastSet, accountExpires) is the
# number of 100-nanosecond intervals since 1601-01-01T00:00:00Z.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_FILETIME_TICKS_PER_SECOND = 10_000_000


def filetime_to_datetime(filetime: int) -> datetime | None:
    """Convert an AD FILETIME integer (as a raw int, not the LDAP-formatted string) to a UTC datetime.

    Returns None for the two AD sentinel values that mean "never" (0 and
    0x7FFFFFFFFFFFFFFF) — treating either as a real 1601 or 30828 date would
    silently corrupt every "stale account" finding downstream.
    """
    if filetime in (0, 0x7FFFFFFFFFFFFFFF):
        return None
    seconds = filetime / _FILETIME_TICKS_PER_SECOND
    return _FILETIME_EPOCH + timedelta(seconds=seconds)


def negative_filetime_to_timedelta(value: int) -> timedelta:
    """Convert a negative-FILETIME interval attribute (maxPwdAge, lockoutDuration) to a timedelta.

    AD stores *intervals* (as opposed to points in time) as negative
    100-ns-tick integers. A value of 0 conventionally means "no expiry".
    """
    if value == 0:
        return timedelta(0)
    return timedelta(seconds=abs(value) / _FILETIME_TICKS_PER_SECOND)


def is_disabled(user_account_control: int) -> bool:
    return bool(user_account_control & UF_ACCOUNTDISABLE)


def is_asrep_roastable(user_account_control: int) -> bool:
    return bool(user_account_control & UF_DONT_REQUIRE_PREAUTH)


def is_password_not_required(user_account_control: int) -> bool:
    return bool(user_account_control & UF_PASSWD_NOTREQD)


def is_password_never_expires(user_account_control: int) -> bool:
    return bool(user_account_control & UF_DONT_EXPIRE_PASSWD)
