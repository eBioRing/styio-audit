from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checks import gate, validate_modules
from .loader import framework_root_from_here, load_all_modules, load_stack
from .local_workflow import (
    DEFAULT_FRAMEWORK_REF,
    load_local_audit_workflow_policy_spec,
    sync_local_audit_workflow,
)
from .models import AuditContext, AuditFinding
from .report import build_audit_report, write_report
from .secrets import render_history_summary, scan_history


def emit(findings: list[AuditFinding], *, fmt: str) -> int:
    if fmt == "json":
        print(json.dumps([finding.to_dict() for finding in findings], indent=2, sort_keys=True))
    elif findings:
        print("[styio-audit] failed", file=sys.stderr)
        for item in findings:
            print(f"  - [{item.module_id}] {item.message}", file=sys.stderr)
    else:
        print("[styio-audit] passed")
    return 1 if findings else 0


def command_list_modules(args: argparse.Namespace) -> int:
    root = Path(args.framework_root).resolve()
    modules = load_all_modules(root)
    for module in modules:
        project_ids = module.data.get("project_ids", ["*"] if module.module_type == "default" else [])
        print(f"{module.module_id}\t{module.module_type}\t{module.root.relative_to(root)}\t{','.join(project_ids)}")
    return 0


def command_validate_modules(args: argparse.Namespace) -> int:
    root = Path(args.framework_root).resolve()
    modules = load_all_modules(root)
    return emit(validate_modules(modules), fmt=args.format)


def command_gate(args: argparse.Namespace) -> int:
    root = Path(args.framework_root).resolve()
    repo_root = Path(args.repo).resolve()
    if not repo_root.exists():
        return emit([AuditFinding("error", f"target repo does not exist: {repo_root}")], fmt=args.format)
    modules = load_stack(root, args.project, repo_root)
    context = AuditContext(
        framework_root=root,
        repo_root=repo_root,
        project=args.project,
        modules=modules,
        framework_only=args.framework_only,
        skip_branch_governance=args.skip_branch_governance,
    )
    return emit(gate(context), fmt=args.format)


def command_report(args: argparse.Namespace) -> int:
    root = Path(args.framework_root).resolve()
    repo_root = Path(args.repo).resolve()
    if not repo_root.exists():
        findings = [AuditFinding("error", f"target repo does not exist: {repo_root}")]
        context = AuditContext(
            framework_root=root,
            repo_root=repo_root,
            project=args.project,
            modules=[],
            framework_only=args.framework_only,
            skip_branch_governance=args.skip_branch_governance,
        )
    else:
        modules = load_stack(root, args.project, repo_root)
        context = AuditContext(
            framework_root=root,
            repo_root=repo_root,
            project=args.project,
            modules=modules,
            framework_only=args.framework_only,
            skip_branch_governance=args.skip_branch_governance,
        )
        findings = gate(context)
    report = build_audit_report(context, findings)
    output = Path(args.output) if args.output else None
    if output is not None and not output.is_absolute():
        output = repo_root / output
    rendered = write_report(report, fmt=args.format, output=output)
    if output is None:
        print(rendered)
    return 1 if findings else 0


def command_secret_history(args: argparse.Namespace) -> int:
    repo_root = Path(args.repo).resolve()
    if not repo_root.exists():
        return emit([AuditFinding("error", f"target repo does not exist: {repo_root}")], fmt=args.format)
    findings = scan_history(repo_root)
    print(render_history_summary(args.project or repo_root.name, findings, fmt=args.format))
    return 1 if findings else 0


def command_sync_local_workflow(args: argparse.Namespace) -> int:
    root = Path(args.framework_root).resolve()
    repo_root = Path(args.repo).resolve()
    if not repo_root.exists():
        return emit([AuditFinding("error", f"target repo does not exist: {repo_root}")], fmt=args.format)
    try:
        result = sync_local_audit_workflow(
            root,
            repo_root,
            args.project,
            repo_name=args.repo_name,
            framework_ref=args.framework_ref,
            check=args.check,
        )
    except (FileNotFoundError, ValueError) as exc:
        return emit([AuditFinding("error", str(exc))], fmt=args.format)
    action = "verified" if args.check else ("updated" if result.changed else "already aligned")
    print(
        f"[styio-audit] {action}: {result.workflow_path} "
        f"(project={args.project}, framework_ref={result.framework_ref})"
    )
    return 0


def command_sync_upstream_local_workflows(args: argparse.Namespace) -> int:
    root = Path(args.framework_root).resolve()
    workspace_root = Path(args.workspace_root).resolve()
    if not workspace_root.exists():
        return emit([AuditFinding("error", f"workspace root does not exist: {workspace_root}")], fmt=args.format)
    try:
        spec = load_local_audit_workflow_policy_spec(root, args.framework_ref)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        return emit([AuditFinding("error", str(exc))], fmt=args.format)
    projects = args.project or list(spec.target_project_ids)
    findings: list[AuditFinding] = []
    for project in projects:
        repo_root = workspace_root / project
        if not repo_root.exists():
            findings.append(AuditFinding("error", f"target repo does not exist: {repo_root}"))
            continue
        try:
            result = sync_local_audit_workflow(
                root,
                repo_root,
                project,
                framework_ref=args.framework_ref,
                check=args.check,
            )
        except (FileNotFoundError, ValueError) as exc:
            findings.append(AuditFinding("error", f"{project}: {exc}"))
            continue
        action = "verified" if args.check else ("updated" if result.changed else "already aligned")
        print(
            f"[styio-audit] {action}: {result.workflow_path} "
            f"(project={project}, framework_ref={result.framework_ref})"
        )
    return emit(findings, fmt=args.format) if findings else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the modular Styio auditable-code framework.")
    parser.add_argument(
        "--framework-root",
        default=str(framework_root_from_here()),
        help="Path to the styio-audit repository root.",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    sub = parser.add_subparsers(dest="command", required=True)

    list_modules = sub.add_parser("list-modules", help="List dynamically loadable modules.")
    list_modules.set_defaults(func=command_list_modules)

    validate = sub.add_parser("validate-modules", help="Validate module descriptors and optional hooks.")
    validate.add_argument("--format", choices=("text", "json"), default="text")
    validate.set_defaults(func=command_validate_modules)

    gate_cmd = sub.add_parser("gate", help="Run default and project-specific modules against a target repo.")
    gate_cmd.add_argument("--repo", required=True, help="Target repository root to audit.")
    gate_cmd.add_argument("--project", required=True, help="Project id, such as styio, pafio-nightly, or vityo-nightly.")
    gate_cmd.add_argument("--framework-only", action="store_true", help="Skip active defect-record closure checks.")
    gate_cmd.add_argument(
        "--skip-branch-governance",
        action="store_true",
        help="Skip branch existence and branch-promotion governance checks while keeping the rest of the audit active.",
    )
    gate_cmd.add_argument("--format", choices=("text", "json"), default="text")
    gate_cmd.set_defaults(func=command_gate)

    report = sub.add_parser("report", help="Generate a structured external audit report for a target repo.")
    report.add_argument("--repo", required=True, help="Target repository root to audit.")
    report.add_argument("--project", required=True, help="Project id, such as styio, pafio-nightly, or vityo-nightly.")
    report.add_argument("--output", help="Write the rendered report to a file. Relative paths are resolved under the target repository.")
    report.add_argument("--framework-only", action="store_true", help="Skip active defect-record closure checks.")
    report.add_argument(
        "--skip-branch-governance",
        action="store_true",
        help="Skip branch existence and branch-promotion governance checks while keeping the rest of the audit active.",
    )
    report.add_argument("--format", choices=("text", "json"), default="json")
    report.set_defaults(func=command_report)

    secret_history = sub.add_parser("secret-history", help="Scan all reachable git history for redacted password, token, API key, and private-key findings.")
    secret_history.add_argument("--repo", required=True, help="Target repository root to scan.")
    secret_history.add_argument("--project", help="Project id to include in the report label.")
    secret_history.add_argument("--format", choices=("text", "json"), default="text")
    secret_history.set_defaults(func=command_secret_history)

    sync_local = sub.add_parser(
        "sync-local-workflow",
        help="Render or verify the authoritative repository-local styio-audit workflow for one target repository.",
    )
    sync_local.add_argument("--repo", required=True, help="Target repository root that owns `.github/workflows/styio-audit.yml`.")
    sync_local.add_argument("--project", required=True, help="Project id, such as styio, pafio-nightly, or vityo-nightly.")
    sync_local.add_argument("--repo-name", help="Override the repository name placeholder; defaults to the target directory name.")
    sync_local.add_argument(
        "--framework-ref",
        default=DEFAULT_FRAMEWORK_REF,
        help="Git ref inside styio-audit that owns the authoritative template. Use HEAD for the current worktree.",
    )
    sync_local.add_argument("--check", action="store_true", help="Fail if the target workflow drifts instead of rewriting it.")
    sync_local.add_argument("--format", choices=("text", "json"), default="text")
    sync_local.set_defaults(func=command_sync_local_workflow)

    sync_upstream = sub.add_parser(
        "sync-upstream-local-workflows",
        help="Render or verify authoritative repository-local styio-audit workflows for all managed upstream repositories under one workspace root.",
    )
    sync_upstream.add_argument("--workspace-root", required=True, help="Workspace root that contains managed upstream repositories, such as /home/unka/eBioRing.")
    sync_upstream.add_argument(
        "--framework-ref",
        default=DEFAULT_FRAMEWORK_REF,
        help="Git ref inside styio-audit that owns the authoritative template. Use HEAD for the current worktree.",
    )
    sync_upstream.add_argument("--project", action="append", help="Optional project id to sync; repeat to limit the target set.")
    sync_upstream.add_argument("--check", action="store_true", help="Fail if any target workflow drifts instead of rewriting files.")
    sync_upstream.add_argument("--format", choices=("text", "json"), default="text")
    sync_upstream.set_defaults(func=command_sync_upstream_local_workflows)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001 - CLI boundary should return a clean diagnostic.
        print(f"[styio-audit] error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
