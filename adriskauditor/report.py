"""Renders a RiskRegister as an HTML risk-register report and/or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .risk import RiskRegister

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

_RATING_CSS_CLASS = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}


def render_html(register: RiskRegister, generated_at: datetime | None = None) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")
    return template.render(
        domain=register.domain,
        findings=register.sorted_findings(),
        summary=register.summary_counts(),
        posture=register.overall_posture(),
        users_scanned=register.users_scanned,
        errors=register.errors,
        generated_at=(generated_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC"),
        rating_class=_RATING_CSS_CLASS,
    )


def to_json_dict(register: RiskRegister) -> dict:
    return {
        "domain": register.domain,
        "users_scanned": register.users_scanned,
        "overall_posture": register.overall_posture(),
        "summary_counts": register.summary_counts(),
        "errors": register.errors,
        "findings": [
            {**asdict(f), "likelihood": f.likelihood.name, "impact": f.impact.name, "rating": f.rating}
            for f in register.sorted_findings()
        ],
    }


def write_reports(register: RiskRegister, out_dir: str | Path, basename: str = "report") -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / f"{basename}.html"
    json_path = out_dir / f"{basename}.json"
    html_path.write_text(render_html(register), encoding="utf-8")
    json_path.write_text(json.dumps(to_json_dict(register), indent=2), encoding="utf-8")
    return html_path, json_path
