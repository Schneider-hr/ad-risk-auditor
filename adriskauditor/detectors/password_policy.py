"""Detects a weak domain-wide password policy.

Checks the default domain policy object against a defensible minimum
baseline: minimum length >= 14 (NIST SP 800-63B no longer mandates a
specific number, but 14 is the widely-used practical floor for
non-MFA'd domain accounts), complexity enabled, and a bounded maximum
password age (both "never expires" and "expires too rarely to matter"
are treated as weaknesses, each with its own finding so the report
doesn't conflate two different problems into one vague one).
"""

from __future__ import annotations

from ..collectors import DomainPolicy
from ..risk import Finding, Impact, Likelihood
from ..schema import DOMAIN_PASSWORD_COMPLEX, negative_filetime_to_timedelta

MIN_ACCEPTABLE_LENGTH = 14
MAX_ACCEPTABLE_AGE_DAYS = 365


def detect_password_policy_weaknesses(domain_policy: DomainPolicy | None = None, **_) -> Finding | None:
    if domain_policy is None:
        return None

    weaknesses: list[str] = []

    if domain_policy.min_pwd_length < MIN_ACCEPTABLE_LENGTH:
        weaknesses.append(
            f"minimum password length is {domain_policy.min_pwd_length} characters "
            f"(recommended: {MIN_ACCEPTABLE_LENGTH}+)"
        )

    complexity_enabled = bool(domain_policy.pwd_properties & DOMAIN_PASSWORD_COMPLEX)
    if not complexity_enabled:
        weaknesses.append("password complexity requirements are disabled")

    max_age = negative_filetime_to_timedelta(domain_policy.max_pwd_age_filetime)
    max_age_days = max_age.days
    if max_age_days == 0:
        weaknesses.append("passwords never expire")
    elif max_age_days > MAX_ACCEPTABLE_AGE_DAYS:
        weaknesses.append(f"passwords expire only every {max_age_days} days")

    if not weaknesses:
        return None

    return Finding(
        risk_id="AD-003",
        title="Weak domain password policy",
        description="The default domain password policy has the following weaknesses: " + "; ".join(weaknesses) + ".",
        affected_objects=["Default Domain Policy"],
        likelihood=Likelihood.HIGH,  # affects every account in the domain equally
        impact=Impact.MEDIUM,
        mitre_attack="T1110 — Brute Force",
        control_reference="NIST 800-63B (Memorized Secret Verifiers) / CIS Control 5.2",
        recommendation=(
            "Raise the minimum password length to at least 14 characters, keep complexity "
            "enabled, and set a bounded maximum password age. For accounts protected by MFA, "
            "consider NIST 800-63B's guidance to favor length over forced periodic rotation."
        ),
        detector="password_policy",
    )
