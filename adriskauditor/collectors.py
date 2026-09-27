"""Turns raw LDAP entries into plain Python data the detectors can work with.

Keeping this layer separate from `detectors/` means every detector can be
unit-tested against a plain `ADUser`/`DomainPolicy` object without touching
ldap3 at all — the connector and the parsing logic are the only things that
need a real (or mocked) directory.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .connector import Connector

USER_ATTRIBUTES = [
    "distinguishedName",
    "sAMAccountName",
    "displayName",
    "userAccountControl",
    "servicePrincipalName",
    "lastLogonTimestamp",
    "pwdLastSet",
    "memberOf",
]

DOMAIN_ATTRIBUTES = [
    "minPwdLength",
    "pwdProperties",
    "maxPwdAge",
    "lockoutThreshold",
]


@dataclass
class ADUser:
    dn: str
    sam_account_name: str
    display_name: str | None
    user_account_control: int
    service_principal_names: list[str] = field(default_factory=list)
    last_logon_timestamp: int | None = None
    pwd_last_set: int | None = None
    member_of: list[str] = field(default_factory=list)

    @property
    def is_machine_account(self) -> bool:
        return self.sam_account_name.endswith("$")


@dataclass
class DomainPolicy:
    min_pwd_length: int
    pwd_properties: int
    max_pwd_age_filetime: int
    lockout_threshold: int


def _first_or_none(value):
    """ldap3 single-valued attributes come back as a length-1 list; empty as []."""
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def _to_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_user_entry(entry) -> ADUser:
    """Build an ADUser from a raw ldap3 entry (or anything exposing the same attribute access)."""
    return ADUser(
        dn=str(entry.entry_dn),
        sam_account_name=str(_first_or_none(entry.sAMAccountName.value) or ""),
        display_name=_first_or_none(entry.displayName.value) if "displayName" in entry else None,
        user_account_control=_to_int(_first_or_none(entry.userAccountControl.value)) or 0,
        service_principal_names=_as_list(entry.servicePrincipalName.value) if "servicePrincipalName" in entry else [],
        last_logon_timestamp=_to_int(_first_or_none(entry.lastLogonTimestamp.value)) if "lastLogonTimestamp" in entry else None,
        pwd_last_set=_to_int(_first_or_none(entry.pwdLastSet.value)) if "pwdLastSet" in entry else None,
        member_of=_as_list(entry.memberOf.value) if "memberOf" in entry else [],
    )


def collect_users(connector: Connector) -> list[ADUser]:
    """Fetch every user object (objectCategory=person, objectClass=user) in the domain."""
    entries = connector.search(
        search_filter="(&(objectCategory=person)(objectClass=user))",
        attributes=USER_ATTRIBUTES,
    )
    return [parse_user_entry(e) for e in entries]


def collect_domain_policy(connector: Connector) -> DomainPolicy | None:
    """Fetch the default domain password/lockout policy from the domain root object."""
    entries = connector.search(
        search_filter="(objectClass=domain)",
        attributes=DOMAIN_ATTRIBUTES,
        base_dn=connector.base_dn,
    )
    if not entries:
        return None
    e = entries[0]
    return DomainPolicy(
        min_pwd_length=_to_int(_first_or_none(e.minPwdLength.value)) or 0,
        pwd_properties=_to_int(_first_or_none(e.pwdProperties.value)) or 0,
        max_pwd_age_filetime=_to_int(_first_or_none(e.maxPwdAge.value)) or 0,
        lockout_threshold=_to_int(_first_or_none(e.lockoutThreshold.value)) or 0,
    )


def collect_group_members(connector: Connector, group_cn: str) -> list[str]:
    """Fetch the DNs of direct members of a group by its common name (e.g. 'Domain Admins')."""
    entries = connector.search(
        search_filter=f"(&(objectClass=group)(cn={group_cn}))",
        attributes=["member"],
    )
    if not entries:
        return []
    return _as_list(entries[0].member.value) if "member" in entries[0] else []


def anonymous_bind_allowed(dc_ip: str, use_ssl: bool = False) -> bool:
    """Check whether the DC accepts an unauthenticated bind and returns directory data.

    A successful anonymous bind that can still read user/group attributes is
    itself a finding (it's what made the anonymous LDAP disclosure possible
    in the CY270 lab write-up) — this is a live check, not a static flag.
    """
    from ldap3 import ALL, Connection, Server

    try:
        server = Server(dc_ip, use_ssl=use_ssl, get_info=ALL)
        conn = Connection(server, auto_bind=True)
        ok = conn.search(
            search_base=server.info.naming_contexts[0] if server.info and server.info.naming_contexts else "",
            search_filter="(objectClass=user)",
            attributes=["sAMAccountName"],
        )
        conn.unbind()
        return bool(ok and conn.entries)
    except Exception:
        return False
