"""Tests the real LDAP parsing path (connector.py + collectors.py) against
an in-memory mock LDAP server (ldap3 MOCK_SYNC), not just the pure-Python
detector logic. This is what actually proves the attribute-parsing code
works against ldap3's real entry objects, since ldap3 mock entries behave
the same way as entries from a live directory."""

from ldap3 import MOCK_SYNC, Connection, Server

from adriskauditor.collectors import collect_domain_policy, collect_group_members, collect_users
from adriskauditor.connector import Connector


def build_mock_connector() -> Connector:
    server = Server("mock_server")
    conn = Connection(server, client_strategy=MOCK_SYNC)

    conn.strategy.add_entry(
        "cn=alice,dc=schneider050,dc=local",
        {
            "objectClass": ["person", "user"],
            "objectCategory": "person",
            "sAMAccountName": "alice",
            "displayName": "Alice",
            "userAccountControl": "4194816",  # NORMAL_ACCOUNT | DONT_REQUIRE_PREAUTH
            "lastLogonTimestamp": "132000000000000000",
        },
    )
    conn.strategy.add_entry(
        "cn=svc_sql,dc=schneider050,dc=local",
        {
            "objectClass": ["person", "user"],
            "objectCategory": "person",
            "sAMAccountName": "svc_sql",
            "displayName": "SQL Service",
            "userAccountControl": "512",
            "servicePrincipalName": ["MSSQLSvc/db01:1433"],
            "memberOf": ["CN=Domain Admins,dc=schneider050,dc=local"],
        },
    )
    conn.strategy.add_entry(
        "dc=schneider050,dc=local",
        {
            "objectClass": ["domain", "domainDNS"],
            "minPwdLength": "8",
            "pwdProperties": "1",
            "maxPwdAge": "0",
            "lockoutThreshold": "5",
        },
    )
    conn.strategy.add_entry(
        "cn=Domain Admins,dc=schneider050,dc=local",
        {
            "objectClass": ["group"],
            "cn": "Domain Admins",
            "member": ["cn=alice,dc=schneider050,dc=local", "cn=svc_sql,dc=schneider050,dc=local"],
        },
    )

    conn.bind()
    return Connector(conn, base_dn="dc=schneider050,dc=local")


def test_collect_users_parses_real_ldap_entries():
    connector = build_mock_connector()
    users = collect_users(connector)

    by_name = {u.sam_account_name: u for u in users}
    assert set(by_name) == {"alice", "svc_sql"}

    alice = by_name["alice"]
    assert alice.user_account_control == 4194816
    assert alice.last_logon_timestamp == 132000000000000000

    svc = by_name["svc_sql"]
    assert svc.service_principal_names == ["MSSQLSvc/db01:1433"]
    assert svc.member_of == ["CN=Domain Admins,dc=schneider050,dc=local"]


def test_collect_domain_policy_parses_real_entry():
    connector = build_mock_connector()
    policy = collect_domain_policy(connector)
    assert policy is not None
    assert policy.min_pwd_length == 8
    assert policy.pwd_properties == 1
    assert policy.max_pwd_age_filetime == 0


def test_collect_group_members_parses_real_entry():
    connector = build_mock_connector()
    members = collect_group_members(connector, "Domain Admins")
    assert members == ["cn=alice,dc=schneider050,dc=local", "cn=svc_sql,dc=schneider050,dc=local"]


def test_collect_group_members_returns_empty_for_unknown_group():
    connector = build_mock_connector()
    assert collect_group_members(connector, "Nonexistent Group") == []
