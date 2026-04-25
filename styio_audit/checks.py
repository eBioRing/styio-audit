from __future__ import annotations

import fnmatch
import re
import subprocess
from pathlib import Path
from typing import Any

from .loader import hook_findings
from .models import AuditContext, AuditFinding, AuditModule
from .secrets import DEFAULT_MAX_FILE_BYTES, SECRET_CLASS_NAMES, scan_worktree


DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
STATE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
MODULE_TYPE_VALUES = {"default", "project"}
CLOSED_STATUSES = {"closed", "resolved", "cleared"}
EMPTY_VALUES = {"", "tbd", "todo", "none", "n/a"}
REQUIRED_PROJECT_INVENTORY_FIELDS = [
    "technology_stack",
    "internal_components",
    "open_source_components",
    "dependency_manifests",
]
DEFAULT_REQUIRED_BRANCHES = ["stable", "nightly", "ai-dev"]
DEFAULT_LICENSE_FILES = ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md", "COPYING.txt"]
DEFAULT_LICENSE_METADATA_FILES = ["pyproject.toml", "package.json", "pubspec.yaml"]
DEFAULT_LICENSE_NOTICE_FILES = ["LICENSE-POLICY.md", "NOTICE", "NOTICE.md", "README.md", "docs/LICENSE-POLICY.md"]
DEFAULT_DEPENDENCY_MANIFEST_GLOBS = [
    "package.json",
    "**/package.json",
    "pyproject.toml",
    "**/pyproject.toml",
    "pubspec.yaml",
    "**/pubspec.yaml",
    "CMakeLists.txt",
    "**/CMakeLists.txt",
    "requirements*.txt",
    "**/requirements*.txt",
    "Cargo.toml",
    "**/Cargo.toml",
    "go.mod",
    "**/go.mod",
    "Package.swift",
    "**/Package.swift",
    "vcpkg.json",
    "**/vcpkg.json",
]
DEFAULT_DEPENDENCY_BOUNDARY_FILES = [
    "DEPENDENCY-USAGE.md",
    "THIRD-PARTY-NOTICES.md",
    "docs/DEPENDENCY-USAGE.md",
    "docs/dependencies.md",
    "docs/third-party.md",
]
IGNORED_DEPENDENCY_PATH_PARTS = {".git", ".dart_tool", ".pytest_cache", ".venv", "build", "dist", "node_modules", "venv"}
DEFAULT_SERVER_SECURITY_CODE_GLOBS = [
    "**/*.c",
    "**/*.cc",
    "**/*.cpp",
    "**/*.cxx",
    "**/*.h",
    "**/*.hh",
    "**/*.hpp",
    "**/*.py",
    "**/*.sh",
    "**/*.bash",
    "**/*.dart",
    "**/*.js",
    "**/*.ts",
    "**/*.go",
    "**/*.rs",
    "**/*.java",
    "**/*.kt",
    "**/*.swift",
    "**/*.yml",
    "**/*.yaml",
    "CMakeLists.txt",
    "**/CMakeLists.txt",
]
DEFAULT_SERVER_SECURITY_IGNORED_PATH_PARTS = {
    ".git",
    ".dart_tool",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "build-codex",
    "dist",
    "node_modules",
    "venv",
}
DEFAULT_SERVER_SENSITIVE_MATERIAL_GLOBS = [
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "**/*.p12",
    "**/*.pfx",
    "**/id_rsa",
    "**/id_ed25519",
    "**/private/*.key",
    "**/private/*.pem",
    "**/production/*.key",
    "**/production/*.pem",
    "**/*prod*secret*.json",
    "**/*production*secret*.json",
]
DEFAULT_ALLOWED_MATERIAL_NAME_MARKERS = [
    "example",
    "sample",
    "template",
    "test",
    "fixture",
    "fake",
    "dummy",
    "placeholder",
    "public",
]
DEFAULT_SERVER_SECURITY_MANIFEST_MARKERS = [
    "auth|authentication|authorization|identity|鉴权",
    "privacy|pii|personal data|隐私",
    "password|密码",
    "secret|token|key|credential|密钥",
    "production|offline|private material|not committed|不进仓库|离线",
    "permission matrix|route authorization|rbac|role based access|权限矩阵",
    "deployment security|deployment config|tls|cors|csrf|cookie|部署安全",
    "sbom|cve|dependency vulnerability|vulnerability scan|依赖漏洞",
    "dast|black-box|penetration|security regression|渗透",
    "runtime secret|secret manager|kms|key rotation|密钥轮换",
    "rate limit|anti replay|replay protection|nonce|idempotency|限流|重放",
    "log redaction|sensitive log|audit log|日志脱敏",
    "ssrf|egress allowlist|url allowlist|outbound request|出站",
    "command execution|shell injection|subprocess allowlist|命令执行",
]
DEFAULT_SERVER_DANGEROUS_CODE_CATEGORIES = {
    "auth_bypass_toggle": [
        "allow_anonymous=true",
        "allow_anonymous = true",
        "skip_auth=true",
        "skip_auth = true",
        "auth_disabled=true",
        "auth_disabled = true",
        "disable_auth=true",
        "disable_auth = true",
    ],
    "command_injection_surface": [
        "shell=true",
        "shell = true",
        "os.system(",
    ],
    "custom_crypto": [
        "custom crypto",
        "custom cryptography",
        "homegrown crypto",
        "roll your own crypto",
        "proprietary cipher",
        "xor cipher",
    ],
    "csrf_disabled": [
        "csrf=false",
        "csrf = false",
        "csrf_disabled=true",
        "csrf_disabled = true",
        "csrf_exempt",
        "disable_csrf=true",
        "disable_csrf = true",
    ],
    "cors_wildcard": [
        "access-control-allow-origin: *",
        "access_control_allow_origin = '*'",
        "access_control_allow_origin='*'",
        "allow_origins=['*']",
        "allow_origins = ['*']",
        "allow_origins=[\"*\"]",
        "allow_origins = [\"*\"]",
    ],
    "jwt_none_algorithm": [
        '"alg":"none"',
        '"alg": "none"',
        "'alg':'none'",
        "'alg': 'none'",
        "alg=none",
        "algorithm none",
    ],
    "disabled_verification": [
        "verify_signature=false",
        "verify_signature = false",
        '"verify_signature": false',
        "'verify_signature': false",
        "rejectunauthorized: false",
        "ssl_verify=false",
        "ssl_verify = false",
        "tls_verify=false",
        "tls_verify = false",
        "--no-check-certificate",
    ],
    "default_credential": [
        "admin:admin",
        "password=password",
        "password = password",
        "default_password",
        "default_admin_password",
    ],
    "debug_public_exposure": [
        "app.run(debug=true",
        "app.run(debug = true",
        "flask_debug=1",
        "flask_debug = 1",
        "django_debug=true",
        "django_debug = true",
    ],
    "insecure_cookie": [
        "httponly=false",
        "httponly = false",
        "http_only=false",
        "http_only = false",
        "secure=false",
        "secure = false",
        "cookie_secure=false",
        "cookie_secure = false",
    ],
    "insecure_random_secret": [
        "random.random secret",
        "random.random token",
        "random.random password",
        "math.random secret",
        "math.random token",
        "math.random password",
    ],
    "rate_limit_disabled": [
        "rate_limit=false",
        "rate_limit = false",
        "rate_limit=0",
        "rate_limit = 0",
        "disable_rate_limit=true",
        "disable_rate_limit = true",
    ],
    "ssrf_unrestricted_fetch": [
        "requests.get(url",
        "requests.post(url",
        "requests.put(url",
        "requests.delete(url",
        "urllib.request.urlopen(url",
        "fetch(url",
    ],
    "weak_password_hash": [
        "hashlib.md5(password",
        "hashlib.sha1(password",
        "md5 password",
        "sha1 password",
        "password md5",
        "password sha1",
    ],
    "plaintext_password_storage": [
        "plain text password",
        "plaintext password",
        "cleartext password",
        "store password as plain text",
        "store passwords as plain text",
        "password stored in plain text",
    ],
}
DEFAULT_SERVER_PROJECT_MARKERS = [
    "server deployment|server-deployment|server-side|backend|服务端",
    "cloud|hosted|control-plane|regional node|systemd|vm deployment|registry|worker-control",
]


def finding(message: str, module_id: str = "core", severity: str = "error") -> AuditFinding:
    return AuditFinding(severity=severity, message=message, module_id=module_id)


def require_string(obj: dict[str, Any], key: str, context: str, module_id: str) -> list[AuditFinding]:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        return [finding(f"{context}: missing non-empty `{key}`", module_id)]
    return []


def get_string_list(obj: dict[str, Any], key: str, context: str, module_id: str) -> tuple[list[str], list[AuditFinding]]:
    value = obj.get(key)
    if not isinstance(value, list) or not value:
        return [], [finding(f"{context}: `{key}` must be a non-empty list", module_id)]
    result: list[str] = []
    findings: list[AuditFinding] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            findings.append(finding(f"{context}: `{key}[{index}]` must be a non-empty string", module_id))
            continue
        result.append(item.strip())
    return result, findings


def unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def get_optional_string_list(obj: dict[str, Any], key: str, context: str, module_id: str) -> tuple[list[str], list[AuditFinding]]:
    if key not in obj:
        return [], []
    return get_string_list(obj, key, context, module_id)


def validate_license_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module license_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module license_policy.enabled must be a boolean", module_id))
    for key in ("name", "license_obligation"):
        findings.extend(require_string(policy, key, "module license_policy", module_id))
    for key in (
        "spdx_identifiers",
        "license_text_markers",
        "target_project_ids",
        "license_files",
        "metadata_files",
        "notice_files",
        "required_notice_markers",
    ):
        values, key_findings = get_optional_string_list(policy, key, "module license_policy", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"module license_policy `{key}` entries must be unique", module_id))
    return findings


def validate_commercial_risk_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module commercial_risk_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module commercial_risk_policy.enabled must be a boolean", module_id))
    for key in ("name", "source_boundary"):
        findings.extend(require_string(policy, key, "module commercial_risk_policy", module_id))
    for key in (
        "target_project_ids",
        "manifest_globs",
        "boundary_files",
        "required_boundary_markers",
        "disallowed_manifest_terms",
    ):
        values, key_findings = get_optional_string_list(policy, key, "module commercial_risk_policy", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"module commercial_risk_policy `{key}` entries must be unique", module_id))
    return findings


def validate_manifest_inventory_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module manifest_inventory_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module manifest_inventory_policy.enabled must be a boolean", module_id))
    values, value_findings = get_string_list(policy, "required_fields", "module manifest_inventory_policy", module_id)
    findings.extend(value_findings)
    missing = [item for item in REQUIRED_PROJECT_INVENTORY_FIELDS if item not in values]
    if missing:
        findings.append(finding(f"module manifest_inventory_policy.required_fields missing required entries: {', '.join(missing)}", module_id))
    return findings


def validate_branch_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module branch_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module branch_policy.enabled must be a boolean", module_id))
    for key in ("target_project_ids", "required_branches"):
        values, key_findings = get_optional_string_list(policy, key, "module branch_policy", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"module branch_policy `{key}` entries must be unique", module_id))
    required_branches = policy.get("required_branches", DEFAULT_REQUIRED_BRANCHES)
    if not isinstance(required_branches, list) or not required_branches:
        findings.append(finding("module branch_policy.required_branches must be a non-empty list", module_id))
    return findings


def validate_secret_scan_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module secret_scan_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module secret_scan_policy.enabled must be a boolean", module_id))
    values, value_findings = get_string_list(policy, "secret_classes", "module secret_scan_policy", module_id)
    findings.extend(value_findings)
    unknown = [item for item in values if item not in SECRET_CLASS_NAMES]
    if unknown:
        findings.append(finding(f"module secret_scan_policy.secret_classes has unknown entries: {', '.join(unknown)}", module_id))
    max_file_bytes = policy.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        findings.append(finding("module secret_scan_policy.max_file_bytes must be a positive integer", module_id))
    _, path_findings = get_optional_string_list(policy, "ignored_path_parts", "module secret_scan_policy", module_id)
    findings.extend(path_findings)
    return findings


def validate_server_sensitive_boundary_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module server_sensitive_boundary_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module server_sensitive_boundary_policy.enabled must be a boolean", module_id))
    for key in ("name", "source_boundary"):
        findings.extend(require_string(policy, key, "module server_sensitive_boundary_policy", module_id))
    for key in (
        "target_project_ids",
        "server_project_markers",
        "code_globs",
        "ignored_path_parts",
        "restricted_material_globs",
        "allowed_material_name_markers",
        "required_manifest_markers",
    ):
        values, key_findings = get_optional_string_list(policy, key, "module server_sensitive_boundary_policy", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"module server_sensitive_boundary_policy `{key}` entries must be unique", module_id))
    max_file_bytes = policy.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        findings.append(finding("module server_sensitive_boundary_policy.max_file_bytes must be a positive integer", module_id))

    categories = policy.get("disallowed_code_categories", DEFAULT_SERVER_DANGEROUS_CODE_CATEGORIES)
    if not isinstance(categories, dict) or not categories:
        findings.append(finding("module server_sensitive_boundary_policy.disallowed_code_categories must be a non-empty object", module_id))
        return findings
    for category, markers in categories.items():
        if not isinstance(category, str) or not STATE_RE.match(category):
            findings.append(finding(f"module server_sensitive_boundary_policy.disallowed_code_categories has invalid category `{category}`", module_id))
            continue
        if not isinstance(markers, list) or not markers:
            findings.append(finding(f"module server_sensitive_boundary_policy.disallowed_code_categories.{category} must be a non-empty list", module_id))
            continue
        seen: set[str] = set()
        for index, marker in enumerate(markers):
            if not isinstance(marker, str) or not marker.strip():
                findings.append(finding(f"module server_sensitive_boundary_policy.disallowed_code_categories.{category}[{index}] must be a non-empty string", module_id))
                continue
            if marker in seen:
                findings.append(finding(f"module server_sensitive_boundary_policy.disallowed_code_categories.{category} entries must be unique", module_id))
            seen.add(marker)
    return findings


def validate_project_inventory(module: AuditModule) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for key in REQUIRED_PROJECT_INVENTORY_FIELDS:
        values, key_findings = get_string_list(module.data, key, "project manifest inventory", module.module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"project manifest inventory `{key}` entries must be unique", module.module_id))
    return findings


def validate_module_schema(module: AuditModule) -> list[AuditFinding]:
    data = module.data
    findings: list[AuditFinding] = []
    if data.get("schema_version") != 1:
        findings.append(finding("module schema_version must be 1", module.module_id))
    for key in ("module_id", "module_type", "description", "last_updated"):
        findings.extend(require_string(data, key, "module", module.module_id))
    last_updated = data.get("last_updated")
    if isinstance(last_updated, str) and last_updated and not DATE_RE.match(last_updated):
        findings.append(finding("module last_updated must use YYYY-MM-DD", module.module_id))
    if data.get("module_id") != module.module_id:
        findings.append(finding("module_id must match loaded module id", module.module_id))
    if module.module_type not in MODULE_TYPE_VALUES:
        findings.append(finding("module_type must be `default` or `project`", module.module_id))
    if module.module_type == "default" and "project_ids" in data:
        findings.append(finding("default module must not declare project_ids", module.module_id))

    if module.module_type == "default":
        for key in ("required_audit_fields", "required_closure_fields", "required_checklist_markers"):
            values, key_findings = get_string_list(data, key, "module", module.module_id)
            findings.extend(key_findings)
            if values and len(values) != len(unique_strings(values)):
                findings.append(finding(f"module `{key}` entries must be unique", module.module_id))
        if "license_policy" in data:
            findings.extend(validate_license_policy(data["license_policy"], module.module_id))
        if "commercial_risk_policy" in data:
            findings.extend(validate_commercial_risk_policy(data["commercial_risk_policy"], module.module_id))
        if "manifest_inventory_policy" in data:
            findings.extend(validate_manifest_inventory_policy(data["manifest_inventory_policy"], module.module_id))
        if "branch_policy" in data:
            findings.extend(validate_branch_policy(data["branch_policy"], module.module_id))
        if "secret_scan_policy" in data:
            findings.extend(validate_secret_scan_policy(data["secret_scan_policy"], module.module_id))
        if "server_sensitive_boundary_policy" in data:
            findings.extend(validate_server_sensitive_boundary_policy(data["server_sensitive_boundary_policy"], module.module_id))
    else:
        project_ids, project_findings = get_string_list(data, "project_ids", "module", module.module_id)
        findings.extend(project_findings)
        if not project_ids:
            findings.append(finding("project module must declare at least one project id", module.module_id))
        elif len(project_ids) != len(unique_strings(project_ids)):
            findings.append(finding("project_ids entries must be unique", module.module_id))
        findings.extend(validate_project_inventory(module))
        findings.extend(validate_resource_classes(module, repo_files=None))
    return findings


def validate_resource_classes(module: AuditModule, repo_files: list[str] | None) -> list[AuditFinding]:
    resources = module.data.get("resource_classes")
    if not isinstance(resources, list) or not resources:
        return [finding("project module must declare non-empty resource_classes", module.module_id)]

    findings: list[AuditFinding] = []
    seen_ids: set[str] = set()
    for index, resource in enumerate(resources):
        context = f"resource_classes[{index}]"
        if not isinstance(resource, dict):
            findings.append(finding(f"{context}: must be an object", module.module_id))
            continue
        resource_id = str(resource.get("id", "")).strip()
        findings.extend(require_string(resource, "id", context, module.module_id))
        if resource_id in seen_ids:
            findings.append(finding(f"{context}: duplicate id `{resource_id}`", module.module_id))
        seen_ids.add(resource_id)
        for key in ("owner", "description", "copying_policy", "concurrency_policy", "nullability_policy", "cleanup_policy"):
            findings.extend(require_string(resource, key, context, module.module_id))
        scope_globs, scope_findings = get_string_list(resource, "scope_globs", context, module.module_id)
        findings.extend(scope_findings)
        if scope_globs and len(scope_globs) != len(unique_strings(scope_globs)):
            findings.append(finding(f"{context}: scope_globs entries must be unique", module.module_id))
        if repo_files is not None:
            for pattern in scope_globs:
                if not matches(pattern, repo_files):
                    findings.append(finding(f"{context}: scope glob matches no source file in target repo: {pattern}", module.module_id))
        for key in ("required_tests", "required_gates", "audit_risks"):
            _, key_findings = get_string_list(resource, key, context, module.module_id)
            findings.extend(key_findings)

        state_machine = resource.get("state_machine")
        if not isinstance(state_machine, dict):
            findings.append(finding(f"{context}: state_machine must be an object", module.module_id))
            continue
        findings.extend(require_string(state_machine, "source", f"{context}.state_machine", module.module_id))
        states, state_findings = get_string_list(state_machine, "states", f"{context}.state_machine", module.module_id)
        findings.extend(state_findings)
        if len(set(states)) != len(states):
            findings.append(finding(f"{context}.state_machine: states must be unique", module.module_id))
        for state in states:
            if not STATE_RE.match(state):
                findings.append(finding(f"{context}.state_machine: invalid state name `{state}`", module.module_id))
        transitions = state_machine.get("transitions")
        if not isinstance(transitions, list) or not transitions:
            findings.append(finding(f"{context}.state_machine: transitions must be a non-empty list", module.module_id))
        else:
            state_set = set(states)
            for t_index, transition in enumerate(transitions):
                t_context = f"{context}.state_machine.transitions[{t_index}]"
                if not isinstance(transition, dict):
                    findings.append(finding(f"{t_context}: must be an object", module.module_id))
                    continue
                for key in ("from", "to", "on"):
                    findings.extend(require_string(transition, key, t_context, module.module_id))
                source = transition.get("from")
                target = transition.get("to")
                if isinstance(source, str) and source not in state_set:
                    findings.append(finding(f"{t_context}: unknown source state `{source}`", module.module_id))
                if isinstance(target, str) and target not in state_set:
                    findings.append(finding(f"{t_context}: unknown target state `{target}`", module.module_id))
        _, invalid_findings = get_string_list(state_machine, "invalid_operations", f"{context}.state_machine", module.module_id)
        findings.extend(invalid_findings)
    return findings


def repo_files(repo_root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        return sorted(
            path.relative_to(repo_root).as_posix()
            for path in repo_root.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(repo_root).parts
        )
    return sorted(line for line in proc.stdout.splitlines() if line and (repo_root / line).exists())


def matches(pattern: str, files: list[str]) -> list[str]:
    if not any(ch in pattern for ch in "*?["):
        return [pattern] if pattern in files else [candidate for candidate in files if candidate.startswith(pattern.rstrip("/") + "/")]
    if pattern.endswith("/**"):
        prefix = pattern[:-3].rstrip("/") + "/"
        prefixed = [candidate for candidate in files if candidate.startswith(prefix)]
        if prefixed:
            return prefixed
    return [candidate for candidate in files if fnmatch.fnmatch(candidate, pattern)]


def default_module(modules: list[AuditModule]) -> AuditModule | None:
    defaults = [module for module in modules if module.module_type == "default"]
    return defaults[0] if defaults else None


def field_has_value(text: str, field: str) -> bool:
    return re.search(rf"^{re.escape(field)}\s*\S+", text, re.M) is not None


def normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.casefold())


def value_matches_license_policy(value: str, spdx_identifiers: list[str], text_markers: list[str]) -> bool:
    normalized = normalized_text(value)
    if any(identifier.casefold() in normalized for identifier in spdx_identifiers):
        return True
    return all(normalized_text(marker) in normalized for marker in text_markers)


def file_matches_license_policy(path: Path, spdx_identifiers: list[str], text_markers: list[str]) -> bool:
    return value_matches_license_policy(path.read_text(encoding="utf-8", errors="replace"), spdx_identifiers, text_markers)


def metadata_license_values(path: Path) -> list[str | None]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.name == "package.json":
        import json

        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, dict) or "license" not in payload:
            return [None]
        license_value = payload.get("license")
        return [license_value if isinstance(license_value, str) else str(license_value)]

    if path.name == "pubspec.yaml":
        match = re.search(r"(?m)^\s*license\s*:\s*(.+?)\s*$", text)
        return [match.group(1).strip().strip("'\"")] if match else [None]

    if path.name == "pyproject.toml":
        if re.search(r"(?m)^\s*license\s*=", text) is None:
            return [None]
        values = [
            match.group(1).strip().strip("'\"")
            for match in re.finditer(r"(?m)^\s*license\s*=\s*(.+?)\s*$", text)
        ]
        return values or [None]

    return []


def dependency_name_from_requirement(value: str) -> str | None:
    cleaned = value.strip().strip("'\"")
    if not cleaned or cleaned.startswith(("#", "-", ".")):
        return None
    cleaned = cleaned.split("#", 1)[0].split(";", 1)[0].strip()
    if " @ " in cleaned:
        cleaned = cleaned.split(" @ ", 1)[0].strip()
    match = re.match(r"([A-Za-z0-9_.-]+)", cleaned)
    return match.group(1) if match else None


def package_json_dependency_names(path: Path) -> list[str]:
    import json

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    names: list[str] = []
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "bundledDependencies", "bundleDependencies"):
        dependencies = payload.get(key)
        if isinstance(dependencies, dict):
            names.extend(name for name in dependencies if isinstance(name, str))
        elif isinstance(dependencies, list):
            names.extend(item for item in dependencies if isinstance(item, str))
    return sorted(unique_strings(names))


def pyproject_dependency_names(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        import tomllib

        payload = tomllib.loads(text)
    except Exception:
        payload = {}

    names: list[str] = []
    if isinstance(payload, dict):
        project = payload.get("project", {})
        if isinstance(project, dict):
            dependencies = project.get("dependencies", [])
            if isinstance(dependencies, list):
                names.extend(name for item in dependencies if isinstance(item, str) for name in [dependency_name_from_requirement(item)] if name)
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for group in optional.values():
                    if isinstance(group, list):
                        names.extend(name for item in group if isinstance(item, str) for name in [dependency_name_from_requirement(item)] if name)
        build_system = payload.get("build-system", {})
        if isinstance(build_system, dict):
            requires = build_system.get("requires", [])
            if isinstance(requires, list):
                names.extend(name for item in requires if isinstance(item, str) for name in [dependency_name_from_requirement(item)] if name)
        poetry = payload.get("tool", {}).get("poetry", {}) if isinstance(payload.get("tool"), dict) else {}
        if isinstance(poetry, dict):
            for section in ("dependencies", "dev-dependencies"):
                dependencies = poetry.get(section, {})
                if isinstance(dependencies, dict):
                    names.extend(name for name in dependencies if isinstance(name, str) and name.lower() != "python")
            groups = poetry.get("group", {})
            if isinstance(groups, dict):
                for group in groups.values():
                    dependencies = group.get("dependencies", {}) if isinstance(group, dict) else {}
                    if isinstance(dependencies, dict):
                        names.extend(name for name in dependencies if isinstance(name, str) and name.lower() != "python")

    if not names:
        names.extend(name for name in re.findall(r"(?m)^\s*dependencies\s*=\s*\[(.*?)\]", text) for name in [dependency_name_from_requirement(name)] if name)
    return sorted(unique_strings(names))


def pubspec_dependency_names(path: Path) -> list[str]:
    names: list[str] = []
    section: str | None = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        section_match = re.match(r"^(dependencies|dev_dependencies|dependency_overrides):\s*$", line)
        if section_match:
            section = section_match.group(1)
            continue
        if line and not line.startswith((" ", "\t")):
            section = None
        if section is None:
            continue
        dep_match = re.match(r"^\s{2,}([A-Za-z0-9_]+):", line)
        if dep_match:
            names.append(dep_match.group(1))
    return sorted(unique_strings(names))


def cmake_dependency_names(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    names: list[str] = []
    patterns = [
        r"find_package\s*\(\s*([A-Za-z0-9_.+-]+)",
        r"FetchContent_Declare\s*\(\s*([A-Za-z0-9_.+-]+)",
        r"ExternalProject_Add\s*\(\s*([A-Za-z0-9_.+-]+)",
        r"CPMAddPackage\s*\([^)]*\bNAME\s+([A-Za-z0-9_.+-]+)",
    ]
    for pattern in patterns:
        names.extend(re.findall(pattern, text, flags=re.I | re.S))
    return sorted(unique_strings(names))


def requirement_file_dependency_names(path: Path) -> list[str]:
    names: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        name = dependency_name_from_requirement(line)
        if name:
            names.append(name)
    return sorted(unique_strings(names))


def cargo_dependency_names(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        import tomllib

        payload = tomllib.loads(text)
    except Exception:
        payload = {}
    names: list[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(key, str) and key.endswith("dependencies") and isinstance(value, dict):
                names.extend(name for name in value if isinstance(name, str))
    return sorted(unique_strings(names))


def go_mod_dependency_names(path: Path) -> list[str]:
    names: list[str] = []
    in_block = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped == "require (":
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if stripped.startswith("require "):
            parts = stripped.split()
            if len(parts) >= 2:
                names.append(parts[1])
        elif in_block:
            parts = stripped.split()
            if parts:
                names.append(parts[0])
    return sorted(unique_strings(names))


def package_swift_dependency_names(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    names = re.findall(r"\.package\s*\([^)]*name\s*:\s*\"([^\"]+)\"", text)
    names.extend(re.findall(r"\.package\s*\([^)]*url\s*:\s*\"[^\"]*/([^/\".]+)(?:\.git)?\"", text))
    return sorted(unique_strings(names))


def vcpkg_dependency_names(path: Path) -> list[str]:
    import json

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    dependencies = payload.get("dependencies") if isinstance(payload, dict) else None
    names: list[str] = []
    if isinstance(dependencies, list):
        for dependency in dependencies:
            if isinstance(dependency, str):
                names.append(dependency)
            elif isinstance(dependency, dict) and isinstance(dependency.get("name"), str):
                names.append(dependency["name"])
    return sorted(unique_strings(names))


def dependency_names_for_manifest(path: Path) -> list[str]:
    name = path.name
    if name == "package.json":
        return package_json_dependency_names(path)
    if name == "pyproject.toml":
        return pyproject_dependency_names(path)
    if name == "pubspec.yaml":
        return pubspec_dependency_names(path)
    if name == "CMakeLists.txt":
        return cmake_dependency_names(path)
    if name.startswith("requirements") and name.endswith(".txt"):
        return requirement_file_dependency_names(path)
    if name == "Cargo.toml":
        return cargo_dependency_names(path)
    if name == "go.mod":
        return go_mod_dependency_names(path)
    if name == "Package.swift":
        return package_swift_dependency_names(path)
    if name == "vcpkg.json":
        return vcpkg_dependency_names(path)
    return []


def path_is_dependency_artifact(relative_path: str) -> bool:
    return any(part in IGNORED_DEPENDENCY_PATH_PARTS for part in Path(relative_path).parts)


def marker_group_matches(text: str, marker: str) -> bool:
    return any(alternative and normalized_text(alternative) in text for alternative in marker.split("|"))


def policy_strings(policy: dict[str, Any], key: str, default: list[str]) -> list[str]:
    values = policy.get(key, default)
    if not isinstance(values, list):
        return list(default)
    return [item for item in values if isinstance(item, str) and item.strip()]


def policy_categories(policy: dict[str, Any], key: str, default: dict[str, list[str]]) -> dict[str, list[str]]:
    raw = policy.get(key, default)
    if not isinstance(raw, dict):
        return {category: list(markers) for category, markers in default.items()}
    result: dict[str, list[str]] = {}
    for category, markers in raw.items():
        if not isinstance(category, str) or not isinstance(markers, list):
            continue
        clean_markers = [marker for marker in markers if isinstance(marker, str) and marker.strip()]
        if clean_markers:
            result[category] = clean_markers
    return result or {category: list(markers) for category, markers in default.items()}


def path_has_part(relative_path: str, ignored_parts: set[str]) -> bool:
    return any(part in ignored_parts for part in Path(relative_path).parts)


def module_text(module: AuditModule) -> str:
    parts: list[str] = []
    for key in (
        "description",
        "technology_stack",
        "internal_components",
        "open_source_components",
        "dependency_manifests",
        "security_boundaries",
    ):
        value = module.data.get(key)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(item for item in value if isinstance(item, str))
    resources = module.data.get("resource_classes")
    if isinstance(resources, list):
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            for key in (
                "id",
                "owner",
                "description",
                "copying_policy",
                "concurrency_policy",
                "nullability_policy",
                "cleanup_policy",
            ):
                value = resource.get(key)
                if isinstance(value, str):
                    parts.append(value)
            for key in ("scope_globs", "required_tests", "required_gates", "audit_risks"):
                value = resource.get(key)
                if isinstance(value, list):
                    parts.extend(item for item in value if isinstance(item, str))
    return normalized_text("\n".join(parts))


def project_has_server_deployment_surface(context: AuditContext, markers: list[str]) -> bool:
    for module in context.modules:
        if module.module_type == "default":
            continue
        text = module_text(module)
        if any(marker_group_matches(text, marker) for marker in markers):
            return True
    return False


def path_matches_any_marker(relative_path: str, markers: list[str]) -> bool:
    text = normalized_text(relative_path.replace("_", " ").replace("-", " ").replace("/", " "))
    for marker in markers:
        normalized_marker = marker.replace("_", " ").replace("-", " ")
        if marker_group_matches(text, normalized_marker):
            return True
    return False


def check_license_policy(context: AuditContext) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("license_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []

    target_project_ids = set(policy_strings(policy, "target_project_ids", []))
    aliases = {item for item in (context.project, context.repo_root.name) if item}
    if target_project_ids and aliases.isdisjoint(target_project_ids):
        return []

    module_id = default.module_id
    license_label = policy.get("license_label", "Apache-2.0")
    if not isinstance(license_label, str) or not license_label.strip():
        license_label = "Apache-2.0"
    spdx_identifiers = policy_strings(policy, "spdx_identifiers", ["Apache-2.0"])
    license_text_markers = policy_strings(policy, "license_text_markers", ["Apache License", "Version 2.0"])
    license_files = policy_strings(policy, "license_files", DEFAULT_LICENSE_FILES)
    metadata_files = policy_strings(policy, "metadata_files", DEFAULT_LICENSE_METADATA_FILES)
    notice_files = policy_strings(policy, "notice_files", DEFAULT_LICENSE_NOTICE_FILES)
    notice_markers = policy_strings(policy, "required_notice_markers", ["Apache", "License", "Version 2.0"])

    findings: list[AuditFinding] = []

    existing_license_files = [context.repo_root / name for name in license_files if (context.repo_root / name).is_file()]
    if not existing_license_files:
        findings.append(finding(f"license policy: missing {license_label} license file; expected one of {', '.join(license_files)}", module_id))
    elif not any(file_matches_license_policy(path, spdx_identifiers, license_text_markers) for path in existing_license_files):
        found = ", ".join(path.relative_to(context.repo_root).as_posix() for path in existing_license_files)
        findings.append(
            finding(
                f"license policy: {found} does not declare {license_label}; expected one of {', '.join(spdx_identifiers)}",
                module_id,
            )
        )

    for name in metadata_files:
        path = context.repo_root / name
        if not path.is_file():
            continue
        for value in metadata_license_values(path):
            rel = path.relative_to(context.repo_root).as_posix()
            if value is None:
                findings.append(finding(f"{rel}: missing {license_label} license metadata", module_id))
            elif not value_matches_license_policy(value, spdx_identifiers, license_text_markers):
                findings.append(finding(f"{rel}: license metadata must be {license_label}; found `{value}`", module_id))

    matching_notice = False
    lowered_markers = [marker.casefold() for marker in notice_markers]
    for name in notice_files:
        path = context.repo_root / name
        if not path.is_file():
            continue
        text = normalized_text(path.read_text(encoding="utf-8", errors="replace"))
        if all(marker in text for marker in lowered_markers):
            matching_notice = True
            break
    if not matching_notice:
        findings.append(
            finding(
                f"license policy: missing {license_label} source-distribution notice; "
                f"one of {', '.join(notice_files)} must contain markers: {', '.join(notice_markers)}",
                module_id,
            )
        )

    return findings


def check_commercial_risk_policy(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("commercial_risk_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []

    target_project_ids = set(policy_strings(policy, "target_project_ids", []))
    aliases = {item for item in (context.project, context.repo_root.name) if item}
    if target_project_ids and aliases.isdisjoint(target_project_ids):
        return []

    module_id = default.module_id
    manifest_globs = policy_strings(policy, "manifest_globs", DEFAULT_DEPENDENCY_MANIFEST_GLOBS)
    boundary_files = policy_strings(policy, "boundary_files", DEFAULT_DEPENDENCY_BOUNDARY_FILES)
    boundary_markers = policy_strings(
        policy,
        "required_boundary_markers",
        ["dependency|依赖", "commercial|商业", "authorization|授权", "usage boundary|使用边界|边界"],
    )
    disallowed_terms = policy_strings(
        policy,
        "disallowed_manifest_terms",
        [
            "commercial license",
            "commercial authorization",
            "paid license",
            "subscription",
            "membership",
            "member-only",
            "trial license",
            "evaluation only",
            "proprietary",
            "商业授权",
            "商业许可证",
            "付费授权",
            "订阅",
            "会员制",
            "试用授权",
            "专有许可证",
        ],
    )

    manifest_files: list[str] = []
    for pattern in manifest_globs:
        manifest_files.extend(matches(pattern, files))
    manifest_files = [path for path in unique_strings(sorted(manifest_files)) if not path_is_dependency_artifact(path)]

    findings: list[AuditFinding] = []
    dependency_sources: dict[str, list[str]] = {}
    for relative in manifest_files:
        path = context.repo_root / relative
        if not path.is_file():
            continue
        text = normalized_text(path.read_text(encoding="utf-8", errors="replace"))
        for term in disallowed_terms:
            if normalized_text(term) in text:
                findings.append(finding(f"{relative}: dependency manifest contains disallowed commercial-risk term `{term}`", module_id))
        for dependency in dependency_names_for_manifest(path):
            dependency_sources.setdefault(dependency, []).append(relative)

    existing_boundary_files = [context.repo_root / name for name in boundary_files if (context.repo_root / name).is_file()]
    if not existing_boundary_files:
        findings.append(
            finding(
                "commercial risk policy: missing dependency usage-boundary evidence; "
                f"expected one of {', '.join(boundary_files)}",
                module_id,
            )
        )
        return findings

    boundary_text = normalized_text(
        "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in existing_boundary_files)
    )
    for marker in boundary_markers:
        if not marker_group_matches(boundary_text, marker):
            findings.append(finding(f"commercial risk policy: usage-boundary evidence missing marker `{marker}`", module_id))

    for dependency, sources in sorted(dependency_sources.items()):
        if normalized_text(dependency) not in boundary_text:
            source_list = ", ".join(sorted(sources))
            findings.append(
                finding(
                    f"commercial risk policy: dependency `{dependency}` from {source_list} "
                    "is missing license authorization and usage-boundary evidence",
                    module_id,
                )
            )

    return findings


def check_secret_scan_policy(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("secret_scan_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []

    target_project_ids = set(policy_strings(policy, "target_project_ids", []))
    aliases = {item for item in (context.project, context.repo_root.name) if item}
    if target_project_ids and aliases.isdisjoint(target_project_ids):
        return []

    max_file_bytes = policy.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        max_file_bytes = DEFAULT_MAX_FILE_BYTES
    findings: list[AuditFinding] = []
    for item in scan_worktree(context.repo_root, files, max_file_bytes=max_file_bytes):
        findings.append(
            finding(
                f"secret scan: {item.path}:{item.line} {item.rule_id} "
                f"({item.confidence}, {item.class_name}, {item.fingerprint}, length={item.value_length}); value redacted",
                default.module_id,
                severity="error" if item.confidence != "medium" else "warning",
            )
        )
    return findings


def git_ref_exists(repo_root: Path, ref_name: str) -> bool:
    proc = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", ref_name],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    return proc.returncode == 0


def git_branch_exists(repo_root: Path, branch: str) -> tuple[bool, str | None]:
    proc = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        return False, "target repository is not a git checkout"

    if git_ref_exists(repo_root, f"refs/heads/{branch}"):
        return True, None

    proc = subprocess.run(
        ["git", "for-each-ref", "--format=%(refname)", "refs/remotes"],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        return False, proc.stderr.strip() or proc.stdout.strip() or "cannot list remote refs"
    suffix = f"/{branch}"
    for ref in proc.stdout.splitlines():
        if ref.endswith(suffix) and not ref.endswith("/HEAD"):
            return True, None
    return False, None


def check_branch_policy(context: AuditContext) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("branch_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []

    target_project_ids = set(policy_strings(policy, "target_project_ids", []))
    aliases = {item for item in (context.project, context.repo_root.name) if item}
    if target_project_ids and aliases.isdisjoint(target_project_ids):
        return []

    required_branches = policy_strings(policy, "required_branches", DEFAULT_REQUIRED_BRANCHES)
    findings: list[AuditFinding] = []
    for branch in required_branches:
        exists, error = git_branch_exists(context.repo_root, branch)
        if exists:
            continue
        if error:
            findings.append(finding(f"branch policy: {error}; required branch `{branch}` cannot be verified", default.module_id))
        else:
            findings.append(
                finding(
                    f"branch policy: missing required branch `{branch}` in local or remote-tracking git refs",
                    default.module_id,
                )
            )
    return findings


def check_server_sensitive_boundary_policy(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("server_sensitive_boundary_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []

    target_project_ids = set(policy_strings(policy, "target_project_ids", []))
    aliases = {item for item in (context.project, context.repo_root.name) if item}
    if target_project_ids and aliases.isdisjoint(target_project_ids):
        return []

    server_markers = policy_strings(policy, "server_project_markers", DEFAULT_SERVER_PROJECT_MARKERS)
    if not project_has_server_deployment_surface(context, server_markers):
        return []

    server_modules = [
        module
        for module in context.modules
        if module.module_type != "default"
        and any(marker_group_matches(module_text(module), marker) for marker in server_markers)
    ]
    code_globs = policy_strings(policy, "code_globs", DEFAULT_SERVER_SECURITY_CODE_GLOBS)
    ignored_parts = set(policy_strings(policy, "ignored_path_parts", sorted(DEFAULT_SERVER_SECURITY_IGNORED_PATH_PARTS)))
    restricted_material_globs = policy_strings(policy, "restricted_material_globs", DEFAULT_SERVER_SENSITIVE_MATERIAL_GLOBS)
    allowed_material_markers = policy_strings(policy, "allowed_material_name_markers", DEFAULT_ALLOWED_MATERIAL_NAME_MARKERS)
    manifest_markers = policy_strings(policy, "required_manifest_markers", DEFAULT_SERVER_SECURITY_MANIFEST_MARKERS)
    categories = policy_categories(policy, "disallowed_code_categories", DEFAULT_SERVER_DANGEROUS_CODE_CATEGORIES)
    max_file_bytes = policy.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        max_file_bytes = DEFAULT_MAX_FILE_BYTES

    findings: list[AuditFinding] = []
    for module in server_modules:
        boundaries = module.data.get("security_boundaries")
        if not isinstance(boundaries, list) or not any(isinstance(item, str) and item.strip() for item in boundaries):
            findings.append(
                finding(
                    f"server sensitive-boundary policy: {module.module_id} must declare non-empty "
                    "`security_boundaries` for auth, privacy, passwords, secrets, deployment security, "
                    "permission matrix, dependency vulnerability, DAST, runtime secret management, "
                    "rate limiting, log redaction, SSRF/egress control, and command execution control",
                    default.module_id,
                )
            )

    project_manifest_text = normalized_text(
        "\n".join(module_text(module) for module in context.modules if module.module_type != "default")
    )
    for marker in manifest_markers:
        if not marker_group_matches(project_manifest_text, marker):
            findings.append(
                finding(
                    "server sensitive-boundary policy: project manifest inventory missing "
                    f"security-boundary marker `{marker}`",
                    default.module_id,
                )
            )

    material_files: list[str] = []
    for pattern in restricted_material_globs:
        material_files.extend(matches(pattern, files))
    for relative in unique_strings(sorted(material_files)):
        if path_has_part(relative, ignored_parts) or path_matches_any_marker(relative, allowed_material_markers):
            continue
        findings.append(
            finding(
                f"server sensitive-boundary policy: {relative} looks like deployable secret material; "
                "production credentials, private keys, tokens, .env files, and generated key bundles must stay "
                "offline or in approved secret-management storage, not in GitHub",
                default.module_id,
            )
        )

    code_files: list[str] = []
    for pattern in code_globs:
        code_files.extend(matches(pattern, files))
    code_files = [path for path in unique_strings(sorted(code_files)) if not path_has_part(path, ignored_parts)]

    for relative in code_files:
        path = context.repo_root / relative
        if not path.is_file() or path.stat().st_size > max_file_bytes:
            continue
        text = normalized_text(path.read_text(encoding="utf-8", errors="replace"))
        for category, markers in sorted(categories.items()):
            for marker in markers:
                if not marker_group_matches(text, marker):
                    continue
                findings.append(
                    finding(
                        f"server sensitive-boundary policy: {relative} contains dangerous marker `{marker}` "
                        f"({category}); public standard implementations are allowed, but source-visible "
                        "auth bypasses, deployment-security bypasses, weak crypto/password handling, "
                        "insecure runtime-secret generation, and production-key shortcuts are forbidden",
                        default.module_id,
                    )
                )
                break
    return findings


def check_defect_records(context: AuditContext) -> list[AuditFinding]:
    if context.framework_only or context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return [finding("no default module loaded")]
    defects_dir = context.repo_root / "docs" / "audit" / "defects"
    if not defects_dir.exists():
        return []
    required_audit = [item for item in default.data.get("required_audit_fields", []) if isinstance(item, str)]
    required_closure = [item for item in default.data.get("required_closure_fields", []) if isinstance(item, str)]
    findings: list[AuditFinding] = []
    for path in sorted(defects_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(context.repo_root).as_posix()
        if path.suffix != ".md":
            findings.append(finding(f"{rel}: defect record must be markdown"))
            continue
        text = path.read_text(encoding="utf-8")
        status_match = re.search(r"^\*\*Status:\*\*\s*(.+?)\s*$", text, re.M)
        if status_match is None:
            findings.append(finding(f"{rel}: missing **Status:**"))
            continue
        for field in required_audit:
            if not field_has_value(text, field):
                findings.append(finding(f"{rel}: missing required audit field `{field}`"))
        status = status_match.group(1).strip().lower()
        if status not in CLOSED_STATUSES:
            findings.append(finding(f"{rel}: status is `{status_match.group(1).strip()}`, not closed"))
            continue
        for field in required_closure:
            if not field_has_value(text, field):
                findings.append(finding(f"{rel}: missing required closure field `{field}`"))
        closure_match = re.search(r"^\*\*Closure evidence:\*\*\s*(.+?)\s*$", text, re.M)
        if closure_match is None or closure_match.group(1).strip().lower() in EMPTY_VALUES:
            findings.append(finding(f"{rel}: closure evidence is empty"))
    return findings


def validate_modules(modules: list[AuditModule]) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    seen: set[str] = set()
    for module in modules:
        if module.module_id in seen:
            findings.append(finding(f"duplicate loaded module id `{module.module_id}`"))
        seen.add(module.module_id)
        findings.extend(validate_module_schema(module))
    if default_module(modules) is None:
        findings.append(finding("module stack must include a default module"))
    return findings


def gate(context: AuditContext) -> list[AuditFinding]:
    findings = validate_modules(context.modules)
    if context.repo_root is not None:
        files = repo_files(context.repo_root)
        for module in context.modules:
            if module.module_type != "default":
                findings.extend(validate_resource_classes(module, files))
        findings.extend(check_branch_policy(context))
        findings.extend(check_license_policy(context))
        findings.extend(check_commercial_risk_policy(context, files))
        findings.extend(check_secret_scan_policy(context, files))
        findings.extend(check_server_sensitive_boundary_policy(context, files))
        findings.extend(check_defect_records(context))
    findings.extend(hook_findings(context.modules, context.as_hook_context()))
    return findings
