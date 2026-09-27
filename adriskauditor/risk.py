"""The risk-register model: turns technical findings into GRC-style entries.

This is the piece that differentiates this tool from a plain AD enumeration
script. Every detector emits `Finding` objects; this module scores them
(likelihood x impact, the standard qualitative risk-matrix approach), and
attaches a MITRE ATT&CK technique and a NIST 800-53 / CIS Controls
reference — so the output reads like a risk register a GRC analyst would
actually produce, not a raw vulnerability dump.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Likelihood(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class Impact(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


# Standard 3x3 qualitative risk matrix. Index as MATRIX[likelihood][impact].
_RATING_MATRIX = {
    (Likelihood.LOW, Impact.LOW): "Low",
    (Likelihood.LOW, Impact.MEDIUM): "Low",
    (Likelihood.LOW, Impact.HIGH): "Medium",
    (Likelihood.MEDIUM, Impact.LOW): "Low",
    (Likelihood.MEDIUM, Impact.MEDIUM): "Medium",
    (Likelihood.MEDIUM, Impact.HIGH): "High",
    (Likelihood.HIGH, Impact.LOW): "Medium",
    (Likelihood.HIGH, Impact.MEDIUM): "High",
    (Likelihood.HIGH, Impact.HIGH): "Critical",
}

_RATING_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass
class Finding:
    """A single risk-register entry produced by one detector."""

    risk_id: str  # e.g. "AD-001"
    title: str
    description: str
    affected_objects: list[str]  # e.g. sAMAccountNames or DNs
    likelihood: Likelihood
    impact: Impact
    mitre_attack: str  # e.g. "T1558.004 - AS-REP Roasting"
    control_reference: str  # e.g. "NIST 800-53 IA-5 / CIS Control 5.2"
    recommendation: str
    detector: str  # which module produced this, for traceability

    @property
    def rating(self) -> str:
        return _RATING_MATRIX[(self.likelihood, self.impact)]

    @property
    def affected_count(self) -> int:
        return len(self.affected_objects)


@dataclass
class RiskRegister:
    """The full report: every finding from every detector, plus run metadata."""

    domain: str
    findings: list[Finding] = field(default_factory=list)
    users_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (_RATING_ORDER[f.rating], -f.affected_count))

    def summary_counts(self) -> dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in self.findings:
            counts[f.rating] += 1
        return counts

    def overall_posture(self) -> str:
        counts = self.summary_counts()
        if counts["Critical"]:
            return "Critical — immediate remediation required"
        if counts["High"]:
            return "High — remediate within a defined SLA"
        if counts["Medium"]:
            return "Medium — track and remediate on a standard cycle"
        if counts["Low"]:
            return "Low — monitor"
        return "No findings"
