from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .checks import (
    DEFAULT_LOCAL_AUDIT_TEMPLATE_PATH,
    DEFAULT_LOCAL_AUDIT_WORKFLOW_PATH,
    DEFAULT_LOCAL_AUDIT_WORKFLOW_PROJECT_IDS,
    normalized_file_text,
    render_local_audit_workflow_template,
)


DEFAULT_FRAMEWORK_REF = "origin/stable"
DEFAULT_MODULE_PATH = "modules/default/module.json"


@dataclass(frozen=True)
class LocalAuditWorkflowPolicySpec:
    workflow_path: str
    template_path: str
    target_project_ids: tuple[str, ...]


@dataclass(frozen=True)
class LocalAuditWorkflowSyncResult:
    repo_root: Path
    workflow_path: Path
    changed: bool
    framework_ref: str


def read_framework_file(framework_root: Path, relative_path: str, framework_ref: str) -> str:
    path = PurePosixPath(relative_path).as_posix()
    if not framework_ref or framework_ref == "HEAD":
        file_path = framework_root / path
        if not file_path.is_file():
            raise FileNotFoundError(f"framework file missing at HEAD: {path}")
        return file_path.read_text(encoding="utf-8", errors="replace")
    result = subprocess.run(
        ["git", "-C", str(framework_root), "show", f"{framework_ref}:{path}"],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or "unknown git show failure"
        raise FileNotFoundError(f"framework file missing at `{framework_ref}`: {path} ({stderr})")
    return result.stdout


def load_local_audit_workflow_policy_spec(framework_root: Path, framework_ref: str = DEFAULT_FRAMEWORK_REF) -> LocalAuditWorkflowPolicySpec:
    data = json.loads(read_framework_file(framework_root, DEFAULT_MODULE_PATH, framework_ref))
    policy = data.get("local_audit_workflow_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        raise ValueError("local_audit_workflow_policy is missing or disabled in the default module")
    workflow_path = str(policy.get("workflow_path", DEFAULT_LOCAL_AUDIT_WORKFLOW_PATH)).strip()
    template_path = str(policy.get("template_path", DEFAULT_LOCAL_AUDIT_TEMPLATE_PATH)).strip()
    target_project_ids_raw = policy.get("target_project_ids", DEFAULT_LOCAL_AUDIT_WORKFLOW_PROJECT_IDS)
    if not workflow_path or not template_path:
        raise ValueError("local_audit_workflow_policy must define workflow_path and template_path")
    if not isinstance(target_project_ids_raw, list) or not all(isinstance(item, str) and item.strip() for item in target_project_ids_raw):
        raise ValueError("local_audit_workflow_policy.target_project_ids must be a non-empty list of strings")
    return LocalAuditWorkflowPolicySpec(
        workflow_path=workflow_path,
        template_path=template_path,
        target_project_ids=tuple(item.strip() for item in target_project_ids_raw),
    )


def render_authoritative_local_audit_workflow(
    framework_root: Path,
    repo_name: str,
    project: str,
    *,
    framework_ref: str = DEFAULT_FRAMEWORK_REF,
) -> tuple[LocalAuditWorkflowPolicySpec, str]:
    spec = load_local_audit_workflow_policy_spec(framework_root, framework_ref)
    template_text = read_framework_file(framework_root, spec.template_path, framework_ref)
    rendered = render_local_audit_workflow_template(template_text, repo_name, project)
    return spec, rendered


def sync_local_audit_workflow(
    framework_root: Path,
    repo_root: Path,
    project: str,
    *,
    repo_name: str | None = None,
    framework_ref: str = DEFAULT_FRAMEWORK_REF,
    check: bool = False,
) -> LocalAuditWorkflowSyncResult:
    resolved_repo_root = repo_root.resolve()
    repo_label = (repo_name or resolved_repo_root.name).strip()
    if not repo_label:
        raise ValueError("repository name cannot be empty")
    spec, expected = render_authoritative_local_audit_workflow(
        framework_root.resolve(),
        repo_label,
        project,
        framework_ref=framework_ref,
    )
    workflow_file = resolved_repo_root / spec.workflow_path
    actual = ""
    if workflow_file.is_file():
        actual = normalized_file_text(workflow_file.read_text(encoding="utf-8", errors="replace"))
    changed = actual != expected
    if check and changed:
        if workflow_file.exists():
            raise ValueError(
                f"`{workflow_file}` does not match authoritative workflow rendered from `{framework_ref}`"
            )
        raise FileNotFoundError(
            f"`{workflow_file}` is missing; sync it from authoritative workflow rendered from `{framework_ref}`"
        )
    if not check and changed:
        workflow_file.parent.mkdir(parents=True, exist_ok=True)
        workflow_file.write_text(expected, encoding="utf-8")
    return LocalAuditWorkflowSyncResult(
        repo_root=resolved_repo_root,
        workflow_path=workflow_file,
        changed=changed,
        framework_ref=framework_ref,
    )

