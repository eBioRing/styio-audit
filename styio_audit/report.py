from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .models import AuditContext, AuditFinding, AuditReport


REPORT_VERSION = 1


def build_audit_report(context: AuditContext, findings: list[AuditFinding]) -> AuditReport:
    return AuditReport(
        report_version=REPORT_VERSION,
        framework_name="styio-audit",
        framework_version=__version__,
        framework_root=context.framework_root,
        repo_root=context.repo_root,
        project=context.project,
        framework_only=context.framework_only,
        modules=context.modules,
        findings=findings,
    )


def render_audit_report(report: AuditReport, *, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2, sort_keys=True)

    lines = [
        f"[styio-audit] report {report.summary()['status']}",
        f"  framework: {report.framework_name} {report.framework_version}",
        f"  repo: {report.repo_root.as_posix() if report.repo_root is not None else '<none>'}",
        f"  project: {report.project or '<none>'}",
        f"  framework-only: {'yes' if report.framework_only else 'no'}",
        f"  modules: {len(report.modules)}",
        f"  findings: {report.summary()['finding_count']}",
    ]
    for module in report.modules:
        lines.append(f"    - {module.module_id} ({module.module_type})")
    for finding in report.findings:
        lines.append(f"  - [{finding.module_id}] {finding.message}")
    return "\n".join(lines)


def write_report(report: AuditReport, *, fmt: str, output: Path | None = None) -> str:
    rendered = render_audit_report(report, fmt=fmt)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    return rendered
