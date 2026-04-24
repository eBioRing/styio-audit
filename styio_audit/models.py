from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class AuditFinding:
    severity: str
    message: str
    module_id: str = "core"

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "message": self.message,
            "module_id": self.module_id,
        }


@dataclass(frozen=True)
class AuditModule:
    module_id: str
    module_type: str
    root: Path
    data: dict[str, Any]
    hook: Callable[[dict[str, Any]], list[AuditFinding]] | None = None

    def to_dict(self, *, framework_root: Path) -> dict[str, Any]:
        project_ids = self.data.get("project_ids", ["*"] if self.module_type == "default" else [])
        payload = {
            "module_id": self.module_id,
            "module_type": self.module_type,
            "root": self.root.relative_to(framework_root).as_posix(),
            "description": self.data.get("description"),
            "last_updated": self.data.get("last_updated"),
            "project_ids": list(project_ids) if isinstance(project_ids, list) else [],
        }
        inventory: dict[str, list[str]] = {}
        for key in ("technology_stack", "internal_components", "open_source_components", "dependency_manifests"):
            values = self.data.get(key)
            if isinstance(values, list):
                inventory[key] = [item for item in values if isinstance(item, str)]
        if inventory:
            payload["inventory"] = inventory
        return payload


@dataclass(frozen=True)
class AuditContext:
    framework_root: Path
    repo_root: Path | None
    project: str | None
    modules: list[AuditModule]
    framework_only: bool = False

    def as_hook_context(self) -> dict[str, Any]:
        return {
            "framework_root": self.framework_root,
            "repo_root": self.repo_root,
            "project": self.project,
            "modules": self.modules,
            "framework_only": self.framework_only,
        }


@dataclass(frozen=True)
class AuditReport:
    report_version: int
    framework_name: str
    framework_version: str
    framework_root: Path
    repo_root: Path | None
    project: str | None
    framework_only: bool
    modules: list[AuditModule]
    findings: list[AuditFinding]

    def summary(self) -> dict[str, Any]:
        severity_counts: dict[str, int] = {}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        return {
            "finding_count": len(self.findings),
            "severity_counts": severity_counts,
            "status": "failed" if self.findings else "passed",
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_version": self.report_version,
            "framework": {
                "name": self.framework_name,
                "version": self.framework_version,
                "root": self.framework_root.as_posix(),
            },
            "target": {
                "repo_root": self.repo_root.as_posix() if self.repo_root is not None else None,
                "project": self.project,
                "framework_only": self.framework_only,
            },
            "modules": [module.to_dict(framework_root=self.framework_root) for module in self.modules],
            "summary": self.summary(),
            "findings": [finding.to_dict() for finding in self.findings],
        }
