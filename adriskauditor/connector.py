"""LDAP connection handling for AD Risk Auditor.

Wraps ldap3 so the rest of the codebase never touches connection details
directly — detectors work against a `Connector`, which can be backed by a
real domain controller or, in tests, an in-memory mock LDAP server
(ldap3's MOCK_SYNC strategy), so the detection logic is exercised for real
without needing a live Active Directory.
"""

from __future__ import annotations

from dataclasses import dataclass

from ldap3 import ALL, NTLM, SIMPLE, SUBTREE, Connection, Server


@dataclass
class DomainTarget:
    dc_ip: str
    domain: str  # e.g. "schneider050.local"
    username: str | None = None
    password: str | None = None
    use_ssl: bool = False

    @property
    def base_dn(self) -> str:
        """Derive the LDAP base DN from a DNS-style domain name."""
        return ",".join(f"DC={part}" for part in self.domain.split("."))

    @property
    def bind_user(self) -> str | None:
        if not self.username:
            return None
        # Accept either "user" or "DOMAIN\\user" / "user@domain" as given
        if "\\" in self.username or "@" in self.username:
            return self.username
        netbios = self.domain.split(".")[0]
        return f"{netbios}\\{self.username}"


class Connector:
    """A thin, testable wrapper around an ldap3 Connection."""

    def __init__(self, connection: Connection, base_dn: str):
        self.connection = connection
        self.base_dn = base_dn

    @classmethod
    def connect(cls, target: DomainTarget) -> "Connector":
        server = Server(target.dc_ip, use_ssl=target.use_ssl, get_info=ALL)
        if target.username:
            conn = Connection(
                server,
                user=target.bind_user,
                password=target.password,
                authentication=NTLM if "\\" in (target.bind_user or "") else SIMPLE,
                auto_bind=True,
            )
        else:
            # Anonymous / unauthenticated bind — many AD environments still
            # allow anonymous LDAP reads of user/group attributes, which is
            # itself a finding worth surfacing (see collectors.anonymous_bind_allowed).
            conn = Connection(server, auto_bind=True)
        return cls(conn, target.base_dn)

    def search(self, search_filter: str, attributes: list[str], base_dn: str | None = None):
        """Run an LDAP search and return the raw ldap3 entries."""
        ok = self.connection.search(
            search_base=base_dn or self.base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
        )
        if not ok:
            return []
        return self.connection.entries

    def close(self) -> None:
        try:
            self.connection.unbind()
        except Exception:
            pass
