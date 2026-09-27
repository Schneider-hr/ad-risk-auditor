from adriskauditor.risk import Finding, Impact, Likelihood, RiskRegister


def make_finding(risk_id, likelihood, impact, affected_count=1):
    return Finding(
        risk_id=risk_id,
        title=f"Finding {risk_id}",
        description="desc",
        affected_objects=[f"obj{i}" for i in range(affected_count)],
        likelihood=likelihood,
        impact=impact,
        mitre_attack="T0000",
        control_reference="NIST X",
        recommendation="fix it",
        detector="test",
    )


def test_rating_matrix_high_high_is_critical():
    f = make_finding("R1", Likelihood.HIGH, Impact.HIGH)
    assert f.rating == "Critical"


def test_rating_matrix_low_low_is_low():
    f = make_finding("R2", Likelihood.LOW, Impact.LOW)
    assert f.rating == "Low"


def test_rating_matrix_medium_medium_is_medium():
    f = make_finding("R3", Likelihood.MEDIUM, Impact.MEDIUM)
    assert f.rating == "Medium"


def test_register_sorts_critical_first():
    register = RiskRegister(domain="test.local")
    register.add(make_finding("LOW1", Likelihood.LOW, Impact.LOW))
    register.add(make_finding("CRIT1", Likelihood.HIGH, Impact.HIGH))
    register.add(make_finding("MED1", Likelihood.MEDIUM, Impact.MEDIUM))
    sorted_ids = [f.risk_id for f in register.sorted_findings()]
    assert sorted_ids == ["CRIT1", "MED1", "LOW1"]


def test_register_sorts_by_affected_count_within_same_rating():
    register = RiskRegister(domain="test.local")
    register.add(make_finding("SMALL", Likelihood.HIGH, Impact.HIGH, affected_count=1))
    register.add(make_finding("BIG", Likelihood.HIGH, Impact.HIGH, affected_count=10))
    sorted_ids = [f.risk_id for f in register.sorted_findings()]
    assert sorted_ids == ["BIG", "SMALL"]


def test_summary_counts():
    register = RiskRegister(domain="test.local")
    register.add(make_finding("C1", Likelihood.HIGH, Impact.HIGH))
    register.add(make_finding("C2", Likelihood.HIGH, Impact.HIGH))
    register.add(make_finding("L1", Likelihood.LOW, Impact.LOW))
    counts = register.summary_counts()
    assert counts == {"Critical": 2, "High": 0, "Medium": 0, "Low": 1}


def test_overall_posture_escalates_to_critical():
    register = RiskRegister(domain="test.local")
    register.add(make_finding("C1", Likelihood.HIGH, Impact.HIGH))
    assert "Critical" in register.overall_posture()


def test_overall_posture_no_findings():
    register = RiskRegister(domain="test.local")
    assert register.overall_posture() == "No findings"
