"""Command-line entry point.

Example:
    python -m adriskauditor --domain schneider050.local --dc-ip 192.168.15.10 \\
        --username svc_readonly --password '...' --out-dir ./reports

    python -m adriskauditor --domain schneider050.local --dc-ip 192.168.15.10 --anonymous
"""

from __future__ import annotations

import argparse
import getpass
import sys

from .auditor import run_audit_live
from .connector import DomainTarget
from .report import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adriskauditor",
        description="Scan an Active Directory domain and produce a GRC-style risk register.",
    )
    parser.add_argument("--domain", required=True, help="DNS domain name, e.g. schneider050.local")
    parser.add_argument("--dc-ip", required=True, help="IP address or hostname of a domain controller")
    parser.add_argument("--username", help="Bind username (omit for --anonymous)")
    parser.add_argument("--password", help="Bind password (omit to be prompted, or use --anonymous)")
    parser.add_argument("--anonymous", action="store_true", help="Attempt an unauthenticated LDAP bind")
    parser.add_argument("--ssl", action="store_true", help="Use LDAPS (port 636)")
    parser.add_argument("--out-dir", default="./reports", help="Directory to write report.html and report.json into")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    username = None if args.anonymous else args.username
    password = None
    if username and not args.password:
        password = getpass.getpass(f"Password for {username}: ")
    elif username:
        password = args.password

    target = DomainTarget(
        dc_ip=args.dc_ip,
        domain=args.domain,
        username=username,
        password=password,
        use_ssl=args.ssl,
    )

    print(f"[*] Connecting to {args.dc_ip} as {'anonymous' if not username else username} ...")
    try:
        register = run_audit_live(target)
    except Exception as exc:
        print(f"[!] Failed to run audit: {exc}", file=sys.stderr)
        return 1

    html_path, json_path = write_reports(register, args.out_dir)

    counts = register.summary_counts()
    print(f"[*] Scanned {register.users_scanned} user objects.")
    print(f"[*] Findings — Critical: {counts['Critical']}  High: {counts['High']}  Medium: {counts['Medium']}  Low: {counts['Low']}")
    print(f"[*] Overall posture: {register.overall_posture()}")
    if register.errors:
        print(f"[!] {len(register.errors)} detector(s) reported errors:")
        for e in register.errors:
            print(f"    - {e}")
    print(f"[*] Report written to {html_path} and {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
