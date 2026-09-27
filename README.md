# AD Risk Auditor

A Python tool that scans an Active Directory domain over LDAP and outputs a **GRC-style risk register**, not a raw findings dump.

Tools like BloodHound and PingCastle are excellent at showing an attacker's path through a domain or scoring its technical hygiene. Neither one produces what a GRC analyst actually has to hand to a risk committee: a scored register with likelihood, impact, a MITRE ATT&CK mapping, and a control reference (NIST 800-53 / CIS Controls) for each finding. This tool exists to close that specific gap — turn AD misconfigurations directly into the risk-register format an audit or compliance function already works in.

[Sample report](samples/sample_report.html) · [Sample JSON export](samples/sample_report.json)

## What it detects (v1)

| Finding | How | MITRE ATT&CK | Control reference |
|---|---|---|---|
| AS-REP roastable accounts | `userAccountControl` DONT_REQUIRE_PREAUTH flag | T1558.004 | NIST 800-53 IA-5(1) / CIS 5.2 |
| Kerberoastable service accounts | User objects (not machine accounts) with a Service Principal Name set | T1558.003 | NIST 800-53 IA-5(1) / CIS 5.2 |
| Weak domain password policy | Minimum length, complexity flag, max password age on the domain policy object | T1110 | NIST 800-63B / CIS 5.2 |
| Stale or unused enabled accounts | `lastLogonTimestamp` beyond a 90-day threshold, or never set | T1078 | NIST 800-53 AC-2(3) / CIS 5.3 |
| Privileged group membership sprawl | Member count of Domain Admins / Enterprise Admins / etc. beyond a threshold | T1078.002 | NIST 800-53 AC-6(1) / CIS 5.4 |

Each finding is scored on a standard 3×3 likelihood × impact matrix (Low/Medium/High → Low/Medium/High/Critical rating) and rendered into an HTML risk register plus a JSON export for further tooling.

## Why these five, and not more, in v1

Every detection here reads directly off attributes the tool itself parses and interprets — no external dependency on an attack framework, no assumptions about what a red-team tool already flagged elsewhere. Dangerous ACL analysis (GenericAll/WriteDACL on sensitive objects) is a deliberate v2 item: it needs security-descriptor parsing that's a genuinely separate piece of work, and shipping five detectors that are fully correct beats shipping eight where three are half-right.

## Usage

```bash
pip install -r requirements.txt

python -m adriskauditor \
  --domain schneider050.local \
  --dc-ip 192.168.15.10 \
  --username readonly_svc \
  --out-dir ./reports
```

Or with an anonymous bind (also useful as its own finding — a DC that answers an anonymous LDAP query at all is worth knowing about):

```bash
python -m adriskauditor --domain schneider050.local --dc-ip 192.168.15.10 --anonymous
```

This writes `reports/report.html` and `reports/report.json`.

## How it's built and tested

- **`schema.py`** — real AD bitmask/FILETIME semantics (Microsoft's documented `userAccountControl` flags and the Windows FILETIME epoch), unit-tested against known-correct conversions rather than assumed.
- **`collectors.py`** / **`connector.py`** — LDAP query and attribute-parsing layer, kept separate from the detection logic so detectors never touch `ldap3` directly.
- **`detectors/`** — one module per finding, each a pure function over plain `ADUser`/`DomainPolicy` objects, so the detection logic is fully unit-testable without a directory.
- **`risk.py`** — the `Finding`/`RiskRegister` model and the likelihood × impact scoring.
- **`report.py`** + **`templates/report.html.j2`** — Jinja2-rendered HTML and JSON output.

43 tests cover the FILETIME/bitmask math, every detector's true/false/edge cases (disabled accounts, machine accounts, clean domains), the full pipeline end to end, and — critically — the real LDAP parsing path against an in-memory mock directory (`ldap3` `MOCK_SYNC`), not just the pure-Python detector logic in isolation:

```bash
pip install -r requirements-dev.txt
pytest
```

## Validation status

Built and fully tested against a mocked LDAP directory. The next step is a live run against my own CY270 home-lab domain (`schneider050.local` — the same Kerberos/LDAP/DNS lab from [cy270-home-lab-pentest](https://github.com/Schneider-hr/cy270-home-lab-pentest)), once those VMs are back up, to confirm the detectors flag the real, already-known misconfigurations in that lab (it has at least one AS-REP roastable account and anonymous LDAP disclosure, both documented in that repo). This README will be updated with that result and a real report once it's run.

## Roadmap

- Live validation against the CY270 lab domain
- Dangerous ACL detection (GenericAll/WriteDACL/WriteOwner on sensitive objects)
- GPO-level password/audit-policy checks (not just the default domain policy)
- PDF export
- A minimal web UI for non-CLI use

## A note on scope

This tool only reads LDAP attributes it's been explicitly authorized to query — it performs no attacks, no credential attempts, and no writes. It's built to run against a domain you own or are authorized to assess, the same rule that applies to every other tool in this portfolio.
