from __future__ import annotations

import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .checks import (
    DEFAULT_INFRASTRUCTURE_ALLOWED_HOST_SUFFIXES,
    DEFAULT_INFRASTRUCTURE_ALLOWED_PLACEHOLDER_MARKERS,
    DEFAULT_INFRASTRUCTURE_CLOUD_RESOURCE_MARKERS,
    DEFAULT_INFRASTRUCTURE_DISALLOWED_DSN_SCHEMES,
    DEFAULT_INFRASTRUCTURE_DISALLOWED_HOST_MARKERS,
    DEFAULT_INFRASTRUCTURE_IGNORED_PATH_PARTS,
    DEFAULT_INFRASTRUCTURE_SCAN_GLOBS,
    DEFAULT_IP_SCAN_IGNORED_PATH_PARTS,
    DEFAULT_RESTRICTED_INFRASTRUCTURE_GLOBS,
    DEFAULT_REPO_HYGIENE_FORBIDDEN_PATH_GLOBS,
    DEFAULT_REPO_HYGIENE_IGNORED_PATH_PARTS,
    DEFAULT_REPO_HYGIENE_MAX_FILE_BYTES,
    allowed_service_ip_entries,
    default_module,
    finding,
    matches,
    normalized_file_text,
    path_has_part,
    path_matches_any_glob,
    path_matches_any_marker,
    policy_strings,
    scan_ip_exposure_file,
    scan_public_infrastructure_file,
)
from .loader import load_stack
from .models import AuditContext, AuditFinding
from .secrets import DEFAULT_MAX_FILE_BYTES, path_is_ignored, scan_text


DEFAULT_LOCAL_PRECOMMIT_HOOK_PATH = ".githooks/pre-commit"
DEFAULT_LOCAL_PRECOMMIT_TEMPLATE_PATH = "templates/hooks/pre-commit"


@dataclass(frozen=True)
class LocalPreCommitHookSyncResult:
    repo_root: Path
    hook_path: Path
    changed: bool
    hooks_path_changed: bool
    framework_ref: str


def render_local_precommit_hook_template(template_text: str, repo_name: str, project: str) -> str:
    rendered = template_text.replace("{{REPO_NAME}}", repo_name)
    rendered = rendered.replace("{{PROJECT_ID}}", project)
    return normalized_file_text(rendered)


def read_framework_hook_template(framework_root: Path, framework_ref: str) -> str:
    from .local_workflow import read_framework_file

    return read_framework_file(framework_root, DEFAULT_LOCAL_PRECOMMIT_TEMPLATE_PATH, framework_ref)


def git_config_get(repo_root: Path, key: str) -> str:
    proc = subprocess.run(["git", "config", "--get", key], cwd=repo_root, text=True, capture_output=True)
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def sync_local_precommit_hook(
    framework_root: Path,
    repo_root: Path,
    project: str,
    *,
    repo_name: str | None = None,
    framework_ref: str = "HEAD",
    check: bool = False,
    configure_git: bool = True,
) -> LocalPreCommitHookSyncResult:
    resolved_repo_root = repo_root.resolve()
    repo_label = (repo_name or resolved_repo_root.name).strip()
    if not repo_label:
        raise ValueError("repository name cannot be empty")

    template_text = read_framework_hook_template(framework_root.resolve(), framework_ref)
    expected = render_local_precommit_hook_template(template_text, repo_label, project)
    hook_file = resolved_repo_root / DEFAULT_LOCAL_PRECOMMIT_HOOK_PATH
    actual = ""
    if hook_file.is_file():
        actual = normalized_file_text(hook_file.read_text(encoding="utf-8", errors="replace"))
    changed = actual != expected

    current_hooks_path = git_config_get(resolved_repo_root, "core.hooksPath")
    hooks_path_changed = configure_git and current_hooks_path != ".githooks"

    if check:
        if changed:
            if hook_file.exists():
                raise ValueError(f"`{hook_file}` does not match authoritative pre-commit hook rendered from `{framework_ref}`")
            raise FileNotFoundError(f"`{hook_file}` is missing; sync it from authoritative pre-commit hook rendered from `{framework_ref}`")
        if hooks_path_changed:
            raise ValueError(f"`{resolved_repo_root}` core.hooksPath is `{current_hooks_path or '<unset>'}`, expected `.githooks`")
    else:
        if changed:
            hook_file.parent.mkdir(parents=True, exist_ok=True)
            hook_file.write_text(expected, encoding="utf-8")
            mode = hook_file.stat().st_mode
            hook_file.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        if hooks_path_changed:
            subprocess.run(["git", "config", "core.hooksPath", ".githooks"], cwd=resolved_repo_root, check=True)

    return LocalPreCommitHookSyncResult(
        repo_root=resolved_repo_root,
        hook_path=hook_file,
        changed=changed,
        hooks_path_changed=hooks_path_changed,
        framework_ref=framework_ref,
    )


def git_staged_files(repo_root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR", "--"],
        cwd=repo_root,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", errors="replace").strip() or "git diff --cached failed")
    return [item.decode("utf-8", errors="surrogateescape") for item in proc.stdout.split(b"\0") if item]


def git_index_files(repo_root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--exclude-standard"],
        cwd=repo_root,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", errors="replace").strip() or "git ls-files --cached failed")
    return [item.decode("utf-8", errors="surrogateescape") for item in proc.stdout.split(b"\0") if item]


def git_staged_blob(repo_root: Path, relative_path: str) -> bytes | None:
    proc = subprocess.run(["git", "show", f":{relative_path}"], cwd=repo_root, capture_output=True)
    if proc.returncode != 0:
        return None
    return proc.stdout


def policy_targets_project(policy: dict[str, object], project: str | None, repo_name: str, default_targets: list[str] | None = None) -> bool:
    target_project_ids = set(policy_strings(policy, "target_project_ids", default_targets or []))
    aliases = {item for item in (project, repo_name) if item}
    return not target_project_ids or "*" in target_project_ids or not aliases.isdisjoint(target_project_ids)


def staged_text_files(repo_root: Path, files: list[str], *, max_file_bytes: int) -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = []
    for relative in files:
        raw = git_staged_blob(repo_root, relative)
        if raw is None or len(raw) > max_file_bytes or b"\0" in raw[:4096]:
            continue
        texts.append((relative, raw.decode("utf-8", errors="replace")))
    return texts


def staged_blob_size(repo_root: Path, relative_path: str) -> int | None:
    raw = git_staged_blob(repo_root, relative_path)
    if raw is not None:
        return len(raw)
    path = repo_root / relative_path
    try:
        return path.stat().st_size
    except OSError:
        return None


def scan_staged_repo_hygiene_policy(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("repo_hygiene_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []
    if not policy_targets_project(policy, context.project, context.repo_root.name):
        return []

    ignored_parts = set(policy_strings(policy, "ignored_path_parts", sorted(DEFAULT_REPO_HYGIENE_IGNORED_PATH_PARTS)))
    forbidden_path_globs = policy_strings(
        policy,
        "forbidden_path_globs",
        DEFAULT_REPO_HYGIENE_FORBIDDEN_PATH_GLOBS,
    )
    allowed_path_globs = policy_strings(policy, "allowed_path_globs", [])
    allowed_large_file_globs = policy_strings(policy, "allowed_large_file_globs", [])
    max_file_bytes = policy.get("max_file_bytes", DEFAULT_REPO_HYGIENE_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        max_file_bytes = DEFAULT_REPO_HYGIENE_MAX_FILE_BYTES

    findings: list[AuditFinding] = []
    for relative in files:
        if path_has_part(relative, ignored_parts) or path_matches_any_glob(relative, allowed_path_globs):
            continue
        if path_matches_any_glob(relative, forbidden_path_globs):
            findings.append(
                finding(
                    f"pre-commit repo hygiene: {relative} matches a forbidden repository-junk pattern; "
                    "temporary files, caches, build outputs, logs, raw data dumps, archives, and local artifacts "
                    "must not be staged",
                    default.module_id,
                )
            )
            continue
        if path_matches_any_glob(relative, allowed_large_file_globs):
            continue
        size = staged_blob_size(context.repo_root, relative)
        if size is not None and size > max_file_bytes:
            findings.append(
                finding(
                    f"pre-commit repo hygiene: {relative} is {size} bytes, above the {max_file_bytes} byte limit; "
                    "large generated artifacts and raw data sets must stay outside the repository unless explicitly allowed",
                    default.module_id,
                )
            )
    return findings


def scan_staged_secret_policy(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("secret_scan_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []
    if not policy_targets_project(policy, context.project, context.repo_root.name):
        return []

    max_file_bytes = policy.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        max_file_bytes = DEFAULT_MAX_FILE_BYTES

    findings: list[AuditFinding] = []
    ignored_parts = set(policy_strings(policy, "ignored_path_parts", []))
    scan_files = [
        relative
        for relative in files
        if not path_is_ignored(relative) and not path_has_part(relative, ignored_parts)
    ]
    for relative, text in staged_text_files(context.repo_root, scan_files, max_file_bytes=max_file_bytes):
        for item in scan_text(text, path=relative):
            findings.append(
                finding(
                    f"pre-commit secret scan: {item.path}:{item.line} {item.rule_id} "
                    f"({item.confidence}, {item.class_name}, {item.fingerprint}, length={item.value_length}); value redacted",
                    default.module_id,
                    severity="error" if item.confidence != "medium" else "warning",
                )
            )
    return findings


def scan_staged_ip_policy(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("ip_exposure_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []
    if not policy_targets_project(policy, context.project, context.repo_root.name):
        return []

    max_file_bytes = policy.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        max_file_bytes = DEFAULT_MAX_FILE_BYTES
    ignored_parts = set(policy_strings(policy, "ignored_path_parts", sorted(DEFAULT_IP_SCAN_IGNORED_PATH_PARTS)))
    allow_loopback = bool(policy.get("allow_loopback", True))
    service_entries = allowed_service_ip_entries(policy)

    findings: list[AuditFinding] = []
    scan_files = [relative for relative in files if not path_has_part(relative, ignored_parts)]
    for relative, text in staged_text_files(context.repo_root, scan_files, max_file_bytes=max_file_bytes):
        findings.extend(
            scan_ip_exposure_file(
                relative,
                text,
                allow_loopback=allow_loopback,
                service_entries=service_entries,
                module_id=default.module_id,
            )
        )
    return findings


def scan_staged_public_infrastructure_policy(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("public_infrastructure_exposure_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []
    if not policy_targets_project(policy, context.project, context.repo_root.name):
        return []

    max_file_bytes = policy.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        max_file_bytes = DEFAULT_MAX_FILE_BYTES
    scan_globs = policy_strings(policy, "scan_globs", DEFAULT_INFRASTRUCTURE_SCAN_GLOBS)
    ignored_parts = set(policy_strings(policy, "ignored_path_parts", sorted(DEFAULT_INFRASTRUCTURE_IGNORED_PATH_PARTS)))
    restricted_path_globs = policy_strings(policy, "restricted_path_globs", DEFAULT_RESTRICTED_INFRASTRUCTURE_GLOBS)
    allowed_placeholder_markers = policy_strings(
        policy,
        "allowed_placeholder_markers",
        DEFAULT_INFRASTRUCTURE_ALLOWED_PLACEHOLDER_MARKERS,
    )
    allowed_host_suffixes = policy_strings(policy, "allowed_host_suffixes", DEFAULT_INFRASTRUCTURE_ALLOWED_HOST_SUFFIXES)
    disallowed_host_markers = policy_strings(policy, "disallowed_host_markers", DEFAULT_INFRASTRUCTURE_DISALLOWED_HOST_MARKERS)
    disallowed_dsn_schemes = [
        scheme.casefold()
        for scheme in policy_strings(policy, "disallowed_dsn_schemes", DEFAULT_INFRASTRUCTURE_DISALLOWED_DSN_SCHEMES)
    ]
    cloud_resource_markers = policy_strings(policy, "cloud_resource_markers", DEFAULT_INFRASTRUCTURE_CLOUD_RESOURCE_MARKERS)

    findings: list[AuditFinding] = []
    for relative in files:
        if path_has_part(relative, ignored_parts) or path_matches_any_marker(relative, allowed_placeholder_markers):
            continue
        if any(matches(pattern, [relative]) for pattern in restricted_path_globs):
            findings.append(
                finding(
                    f"pre-commit public infrastructure exposure: {relative} matches restricted infrastructure path policy; "
                    "production ops, private deployment, kubeconfig, Terraform variable/state, and inventory material must stay private",
                    default.module_id,
                )
            )

    scan_files: list[str] = []
    for pattern in scan_globs:
        scan_files.extend(matches(pattern, files))
    scan_files = sorted(set(relative for relative in scan_files if not path_has_part(relative, ignored_parts)))
    for relative, text in staged_text_files(context.repo_root, scan_files, max_file_bytes=max_file_bytes):
        findings.extend(
            scan_public_infrastructure_file(
                relative,
                text,
                allowed_host_suffixes=allowed_host_suffixes,
                disallowed_host_markers=disallowed_host_markers,
                disallowed_dsn_schemes=disallowed_dsn_schemes,
                cloud_resource_markers=cloud_resource_markers,
                allowed_placeholder_markers=allowed_placeholder_markers,
                module_id=default.module_id,
            )
        )
    return findings


def run_precommit_gate(framework_root: Path, repo_root: Path, project: str | None) -> list[AuditFinding]:
    resolved_repo_root = repo_root.resolve()
    staged_files = git_staged_files(resolved_repo_root)
    if not staged_files:
        return []
    files = git_index_files(resolved_repo_root)
    modules = load_stack(framework_root.resolve(), project or resolved_repo_root.name, resolved_repo_root)
    context = AuditContext(
        framework_root=framework_root.resolve(),
        repo_root=resolved_repo_root,
        project=project or resolved_repo_root.name,
        modules=modules,
        framework_only=True,
        skip_branch_governance=True,
    )
    findings: list[AuditFinding] = []
    findings.extend(scan_staged_repo_hygiene_policy(context, files))
    findings.extend(scan_staged_secret_policy(context, files))
    findings.extend(scan_staged_ip_policy(context, files))
    findings.extend(scan_staged_public_infrastructure_policy(context, files))
    return findings
