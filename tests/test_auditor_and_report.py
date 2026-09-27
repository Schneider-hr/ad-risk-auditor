"""Integration tests: run the full pipeline (detect -> risk register -> report)
against synthetic data that stands in for a real domain — no LDAP required."""

import json
from datetime import datetime, timezone

from adriskauditor.auditor import run_audit_on_data
from adriskauditor.collectors import ADUser, DomainPolicy
from adriskauditor.report import render_html, to_json_dict, write_reports
from adriskauditor.schema import DOMAIN_PASSWORD_COMPLEX, UF_DONT_REQUIRE_PREAUTH, UF_NORMAL_ACCOUNT


def _recent_logon_ticks(now: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((now - epoch).total_seconds() * 10_000_000)


def synthetic_domain(now: datetime | None = None):
    now = now or datetime(2026, 1, 1, tzinfo=timezone.utc)
    recent = _recent_logon_ticks(now)
    users = [
        ADUser(
            dn="CN=alice,DC=schneider050,DC=local",
            sam_account_name="alice",
            display_name="Alice",
            user_account_control=UF_NORMAL_ACCOUNT | UF_DONT_REQUIRE_PREAUTH,
            last_logon_timestamp=recent,
        ),
        ADUser(
            dn="CN=svc_sql,DC=schneider050,DC=local",
            sam_account_name="svc_sql",
            display_name="SQL Service",
            user_account_control=UF_NORMAL_ACCOUNT,
            service_principal_names=["MSSQLSvc/db01:1433"],
            last_logon_timestamp=recent,
        ),
        ADUser(
            dn="CN=bob,DC=schneider050,DC=local",
            sam_account_name="bob",
            display_name="Bob",
            user_account_control=UF_NORMAL_ACCOUNT,
            last_logon_timestamp=recent,
        ),
    ]
    policy = DomainPolicy(min_pwd_length=8, pwd_properties=DOMAIN_PASSWORD_COMPLEX, max_pwd_age_filetime=0, lockout_threshold=5)
    group_members = {"Domain Admins": ["administrator", "alice", "bob", "carol", "dave", "erin", "frank"]}
    return users, policy, group_members


def test_full_pipeline_produces_expected_findings():
    users, policy, group_members = synthetic_domain()
    register = run_audit_on_data(
        domain="schneider050.local",
        users=users,
        domain_policy=policy,
        group_members=group_members,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    risk_ids = {f.risk_id for f in register.findings}
    # AS-REP (alice), Kerberoasting (svc_sql), weak password policy (8 chars + never expires),
    # and privileged sprawl (7-member Domain Admins) should all fire.
    assert risk_ids == {"AD-001", "AD-002", "AD-003", "AD-005"}
    assert register.users_scanned == 3
    assert register.errors == []


def test_pipeline_with_no_findings_is_clean():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    users = [ADUser(
        dn="CN=x", sam_account_name="x", display_name="X",
        user_account_control=UF_NORMAL_ACCOUNT,
        last_logon_timestamp=_recent_logon_ticks(now),
    )]
    policy = DomainPolicy(min_pwd_length=16, pwd_properties=DOMAIN_PASSWORD_COMPLEX, max_pwd_age_filetime=-int(90 * 86400 * 10_000_000), lockout_threshold=5)
    register = run_audit_on_data(domain="clean.local", users=users, domain_policy=policy, now=now)
    assert register.findings == []
    assert register.overall_posture() == "No findings"


def test_html_report_renders_without_error():
    users, policy, group_members = synthetic_domain()
    register = run_audit_on_data(domain="schneider050.local", users=users, domain_policy=policy, group_members=group_members)
    html = render_html(register)
    assert "schneider050.local" in html
    assert "AD-001" in html
    assert "<html" in html.lower()


def test_json_export_round_trips():
    users, policy, group_members = synthetic_domain()
    register = run_audit_on_data(domain="schneider050.local", users=users, domain_policy=policy, group_members=group_members)
    data = to_json_dict(register)
    dumped = json.dumps(data)  # must be JSON-serializable
    reloaded = json.loads(dumped)
    assert reloaded["domain"] == "schneider050.local"
    assert len(reloaded["findings"]) == len(register.findings)


def test_write_reports_creates_files(tmp_path):
    users, policy, group_members = synthetic_domain()
    register = run_audit_on_data(domain="schneider050.local", users=users, domain_policy=policy, group_members=group_members)
    html_path, json_path = write_reports(register, tmp_path)
    assert html_path.exists()
    assert json_path.exists()
    assert html_path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
