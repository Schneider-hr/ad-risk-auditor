from datetime import datetime, timedelta, timezone

from adriskauditor.collectors import ADUser, DomainPolicy
from adriskauditor.detectors import (
    detect_asrep_roasting,
    detect_kerberoasting,
    detect_password_policy_weaknesses,
    detect_privileged_group_sprawl,
    detect_stale_accounts,
)
from adriskauditor.schema import (
    DOMAIN_PASSWORD_COMPLEX,
    UF_ACCOUNTDISABLE,
    UF_DONT_REQUIRE_PREAUTH,
    UF_NORMAL_ACCOUNT,
)


def make_user(**overrides) -> ADUser:
    defaults = dict(
        dn="CN=test,DC=schneider050,DC=local",
        sam_account_name="testuser",
        display_name="Test User",
        user_account_control=UF_NORMAL_ACCOUNT,
        service_principal_names=[],
        last_logon_timestamp=None,
        pwd_last_set=None,
        member_of=[],
    )
    defaults.update(overrides)
    return ADUser(**defaults)


# --- AS-REP Roasting ---

def test_asrep_roasting_flags_vulnerable_enabled_account():
    users = [make_user(sam_account_name="alice", user_account_control=UF_NORMAL_ACCOUNT | UF_DONT_REQUIRE_PREAUTH)]
    finding = detect_asrep_roasting(users=users)
    assert finding is not None
    assert "alice" in finding.affected_objects
    assert finding.risk_id == "AD-001"
    assert finding.rating == "Critical"  # HIGH likelihood x HIGH impact


def test_asrep_roasting_ignores_disabled_accounts():
    users = [make_user(sam_account_name="bob", user_account_control=UF_NORMAL_ACCOUNT | UF_DONT_REQUIRE_PREAUTH | UF_ACCOUNTDISABLE)]
    assert detect_asrep_roasting(users=users) is None


def test_asrep_roasting_ignores_machine_accounts():
    users = [make_user(sam_account_name="WORKSTATION1$", user_account_control=UF_NORMAL_ACCOUNT | UF_DONT_REQUIRE_PREAUTH)]
    assert detect_asrep_roasting(users=users) is None


def test_asrep_roasting_clean_domain_returns_none():
    users = [make_user(sam_account_name="alice"), make_user(sam_account_name="bob")]
    assert detect_asrep_roasting(users=users) is None


# --- Kerberoasting ---

def test_kerberoasting_flags_account_with_spn():
    users = [make_user(sam_account_name="svc_sql", service_principal_names=["MSSQLSvc/db01:1433"])]
    finding = detect_kerberoasting(users=users)
    assert finding is not None
    assert "svc_sql" in finding.affected_objects
    assert finding.risk_id == "AD-002"


def test_kerberoasting_excludes_machine_accounts():
    users = [make_user(sam_account_name="DC01$", service_principal_names=["HOST/dc01"])]
    assert detect_kerberoasting(users=users) is None


def test_kerberoasting_escalates_impact_for_multi_group_membership():
    users = [make_user(
        sam_account_name="svc_backup",
        service_principal_names=["Backup/svc"],
        member_of=["CN=Backup Operators,...", "CN=Domain Admins,..."],
    )]
    finding = detect_kerberoasting(users=users)
    assert finding.impact.name == "HIGH"


# --- Password policy ---

def test_password_policy_flags_short_min_length():
    policy = DomainPolicy(min_pwd_length=7, pwd_properties=DOMAIN_PASSWORD_COMPLEX, max_pwd_age_filetime=-36000000000000, lockout_threshold=5)
    finding = detect_password_policy_weaknesses(domain_policy=policy)
    assert finding is not None
    assert "7 characters" in finding.description


def test_password_policy_flags_disabled_complexity():
    policy = DomainPolicy(min_pwd_length=14, pwd_properties=0, max_pwd_age_filetime=-36000000000000, lockout_threshold=5)
    finding = detect_password_policy_weaknesses(domain_policy=policy)
    assert finding is not None
    assert "complexity" in finding.description


def test_password_policy_flags_never_expires():
    policy = DomainPolicy(min_pwd_length=14, pwd_properties=DOMAIN_PASSWORD_COMPLEX, max_pwd_age_filetime=0, lockout_threshold=5)
    finding = detect_password_policy_weaknesses(domain_policy=policy)
    assert finding is not None
    assert "never expire" in finding.description


def test_password_policy_clean_returns_none():
    # 14 chars, complexity on, 90-day max age (well under the 365-day ceiling)
    ninety_days_ticks = -1 * 90 * 24 * 60 * 60 * 10_000_000
    policy = DomainPolicy(min_pwd_length=14, pwd_properties=DOMAIN_PASSWORD_COMPLEX, max_pwd_age_filetime=ninety_days_ticks, lockout_threshold=5)
    assert detect_password_policy_weaknesses(domain_policy=policy) is None


def test_password_policy_none_policy_returns_none():
    assert detect_password_policy_weaknesses(domain_policy=None) is None


# --- Stale accounts ---

def test_stale_accounts_flags_old_logon():
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    old_logon = now - timedelta(days=200)
    ticks = int((old_logon - epoch).total_seconds() * 10_000_000)
    users = [make_user(sam_account_name="stale_user", last_logon_timestamp=ticks)]
    finding = detect_stale_accounts(users=users, now=now)
    assert finding is not None
    assert "stale_user" in finding.affected_objects


def test_stale_accounts_ignores_recent_logon():
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    recent_logon = now - timedelta(days=5)
    ticks = int((recent_logon - epoch).total_seconds() * 10_000_000)
    users = [make_user(sam_account_name="active_user", last_logon_timestamp=ticks)]
    assert detect_stale_accounts(users=users, now=now) is None


def test_stale_accounts_flags_never_logged_on():
    users = [make_user(sam_account_name="never_used", last_logon_timestamp=None)]
    finding = detect_stale_accounts(users=users)
    assert finding is not None
    assert "never_used" in finding.affected_objects


def test_stale_accounts_ignores_disabled():
    users = [make_user(sam_account_name="old_disabled", last_logon_timestamp=None, user_account_control=UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE)]
    assert detect_stale_accounts(users=users) is None


# --- Privileged group sprawl ---

def test_privileged_sprawl_flags_over_threshold():
    group_members = {"Domain Admins": [f"user{i}" for i in range(8)]}
    finding = detect_privileged_group_sprawl(group_members=group_members)
    assert finding is not None
    assert "Domain Admins" in finding.description


def test_privileged_sprawl_ignores_small_groups():
    group_members = {"Domain Admins": ["administrator", "backup_admin"]}
    assert detect_privileged_group_sprawl(group_members=group_members) is None
