from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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
AUDIT_PROFILE_VALUES = {
    "backend-operations",
    "benchmark-basic",
    "client-tooling",
    "development-environment",
    "documentation-basic",
    "ecosystem-aggregate",
    "example-basic",
    "framework-policy",
    "language-core",
    "static-website",
}
BACKEND_AUDIT_PROFILES = {"backend-operations"}
DEFAULT_REQUIRED_BRANCHES = ["release", "stable", "nightly"]
DEFAULT_LOCAL_AUDIT_WORKFLOW_PROJECT_IDS = [
    "Styio",
    "Pafio",
    "Vityo",
    "Styio-Cloud",
    "styio-cloud",
    "styio-all-in-one",
    "styio-benchmark",
    "styio-book",
    "styio-community",
    "styio-dev-doc",
    "styio-dev-env",
    "styio-example",
    "styio-ext-vsc",
    "styio.io",
]
DEFAULT_LOCAL_AUDIT_WORKFLOW_OWNERS = ["SymPolicy"]
DEFAULT_LOCAL_AUDIT_WORKFLOW_PATH = ".github/workflows/styio-audit.yml"
DEFAULT_LOCAL_AUDIT_TEMPLATE_PATH = "templates/workflows/styio-audit-local.yml"
DEFAULT_LOCAL_DELIVERY_FRAMEWORK_PROJECT_IDS = ["styio", "Styio", "styio-nightly"]
DEFAULT_LOCAL_DELIVERY_FRAMEWORK_OWNERS = ["SymPolicy"]
CI_GATE_CLASSIFICATION_RE = re.compile(r"^[a-z][a-z0-9-]*(?: / [a-z][a-z0-9-]*)+$")
LOCAL_GATE_PROFILE_ID_RE = re.compile(r"^[a-z][a-z0-9-]*(?:-[a-z0-9]+)*$")
PLATFORM_CI_GATE_RUNNER_MARKERS = {
    "linux": ("ubuntu-", "linux"),
    "macos": ("macos-",),
    "windows": ("windows-",),
}
TEST_CI_GATE_NAMES = {
    "smoke": "test / smoke",
    "golden_standard": "test / golden-standard",
}
DEFAULT_UPSTREAM_BRANCH_FLOW_OWNERS = ["SymPolicy"]
DEFAULT_UPSTREAM_DEVELOPMENT_BASE_BRANCHES = ["nightly"]
DEFAULT_UPSTREAM_REQUIRED_PULL_REQUEST_FLOWS = [
    {"head": "nightly", "base": "stable"},
    {"head": "stable", "base": "release"},
]
DEFAULT_DOWNSTREAM_BRANCH_FLOW_OWNERS = ["Unka-Malloc"]
DEFAULT_DOWNSTREAM_DEVELOPMENT_BASE_BRANCHES = ["nightly"]
DEFAULT_DOWNSTREAM_REQUIRED_PULL_REQUEST_FLOWS = [
    {"head": "nightly", "base": "stable"},
    {"head": "stable", "base": "release"},
]
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
DEFAULT_REPO_HYGIENE_MAX_FILE_BYTES = 5 * 1024 * 1024
DEFAULT_REPO_HYGIENE_IGNORED_PATH_PARTS = {".git"}
DEFAULT_REPO_HYGIENE_FORBIDDEN_PATH_GLOBS = [
    ".DS_Store",
    "**/.DS_Store",
    "Thumbs.db",
    "**/Thumbs.db",
    "Desktop.ini",
    "**/Desktop.ini",
    "*~",
    "**/*~",
    "*.tmp",
    "**/*.tmp",
    "*.temp",
    "**/*.temp",
    "*.bak",
    "**/*.bak",
    "*.orig",
    "**/*.orig",
    "*.rej",
    "**/*.rej",
    "*.swp",
    "**/*.swp",
    "*.swo",
    "**/*.swo",
    "*.log",
    "**/*.log",
    ".coverage",
    "**/.coverage",
    "coverage.xml",
    "**/coverage.xml",
    ".pytest_cache/**",
    "**/.pytest_cache/**",
    ".mypy_cache/**",
    "**/.mypy_cache/**",
    ".ruff_cache/**",
    "**/.ruff_cache/**",
    ".tox/**",
    "**/.tox/**",
    ".nox/**",
    "**/.nox/**",
    "__pycache__/**",
    "**/__pycache__/**",
    ".dart_tool/**",
    "**/.dart_tool/**",
    "node_modules/**",
    "**/node_modules/**",
    "build/**",
    "**/build/**",
    "dist/**",
    "**/dist/**",
    "out/**",
    "**/out/**",
    "DerivedData/**",
    "**/DerivedData/**",
    "*.sqlite",
    "**/*.sqlite",
    "*.sqlite3",
    "**/*.sqlite3",
    "*.db",
    "**/*.db",
    "*.db-journal",
    "**/*.db-journal",
    "*.parquet",
    "**/*.parquet",
    "*.arrow",
    "**/*.arrow",
    "*.npy",
    "**/*.npy",
    "*.npz",
    "**/*.npz",
    "*.pkl",
    "**/*.pkl",
    "*.pickle",
    "**/*.pickle",
    "*.dump",
    "**/*.dump",
    "*.dmp",
    "**/*.dmp",
    "*.profraw",
    "**/*.profraw",
    "*.profdata",
    "**/*.profdata",
    "*.gcda",
    "**/*.gcda",
    "*.gcno",
    "**/*.gcno",
    "*.zip",
    "**/*.zip",
    "*.tar",
    "**/*.tar",
    "*.tgz",
    "**/*.tgz",
    "*.tar.gz",
    "**/*.tar.gz",
    "*.7z",
    "**/*.7z",
    "*.rar",
    "**/*.rar",
]
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
    "server deployment|server-deployment|server-side|backend|backend-operations|backend operations|服务端",
    "cloud|hosted|control-plane|regional node|systemd|vm deployment|registry|worker-control|service surface",
]
DEFAULT_IP_SCAN_IGNORED_PATH_PARTS = {
    ".dart_tool",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}
DEFAULT_PUBLIC_INFRASTRUCTURE_EXPOSURE_PROJECT_IDS = [
    "styio-pafio",
    "Pafio",
    "pafio",
    "Styio-Cloud",
    "styio-cloud",
    "styio-community",
    "community",
]
DEFAULT_PUBLIC_INFRASTRUCTURE_EXPOSURE_OWNERS = ["SymPolicy"]
DEFAULT_INFRASTRUCTURE_SCAN_GLOBS = [
    "*.c",
    "*.cc",
    "*.cpp",
    "*.cxx",
    "*.h",
    "*.hh",
    "*.hpp",
    "*.md",
    "*.py",
    "*.sh",
    "*.bash",
    "*.toml",
    "*.txt",
    "*.yml",
    "*.yaml",
    "**/*.c",
    "**/*.cc",
    "**/*.cpp",
    "**/*.cxx",
    "**/*.h",
    "**/*.hh",
    "**/*.hpp",
    "**/*.md",
    "**/*.py",
    "**/*.sh",
    "**/*.bash",
    "**/*.toml",
    "**/*.txt",
    "**/*.yml",
    "**/*.yaml",
]
DEFAULT_INFRASTRUCTURE_IGNORED_PATH_PARTS = {
    ".dart_tool",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "build-codex",
    "dist",
    "node_modules",
    "venv",
}
DEFAULT_RESTRICTED_INFRASTRUCTURE_GLOBS = [
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "**/.kube/**",
    "**/*kubeconfig*",
    "**/*.tfstate",
    "**/*.tfstate.*",
    "**/*.tfvars",
    "**/ansible/**",
    "**/deploy/prod/**",
    "**/deploy/production/**",
    "**/infra/**",
    "**/inventory.ini",
    "**/ops/**",
    "**/private/**",
    "**/prod/**",
    "**/production/**",
]
DEFAULT_INFRASTRUCTURE_ALLOWED_PLACEHOLDER_MARKERS = [
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
DEFAULT_INFRASTRUCTURE_ALLOWED_HOST_SUFFIXES = [
    "example.com",
    "example.invalid",
    "example.net",
    "example.org",
    "github.com",
    "github.io",
    "localhost",
]
DEFAULT_INFRASTRUCTURE_DISALLOWED_HOST_MARKERS = [
    "admin",
    "backend",
    "bastion",
    "console",
    "control-plane",
    "database",
    "db",
    "grafana",
    "internal",
    "kibana",
    "ops",
    "private",
    "prod",
    "production",
    "prometheus",
    "redis",
    "registry",
    "sentry",
    "staging",
    "vault",
    "vpn",
]
DEFAULT_INFRASTRUCTURE_DISALLOWED_DSN_SCHEMES = [
    "amqp",
    "mongodb",
    "mongodb+srv",
    "mysql",
    "postgres",
    "postgresql",
    "redis",
    "smtp",
]
DEFAULT_INFRASTRUCTURE_CLOUD_RESOURCE_MARKERS = [
    "arn:aws:",
    "s3://",
    "gs://",
    "/subscriptions/",
    "resourcegroups/",
]
IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9.])"
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}"
    r"(?![A-Za-z0-9.])"
)
IPV6_RE = re.compile(
    r"(?<![A-Za-z0-9_:.-])"
    r"(?:::1|(?:[0-9A-Fa-f]{1,4}:){1,7}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4})"
    r"(?![A-Za-z0-9_:.-])"
)
IPV6_UNSPECIFIED_RE = re.compile(r"(?<![A-Za-z0-9_:.-])::(?![A-Za-z0-9_:.-])")
SVG_PATH_DATA_PREFIX_RE = re.compile(r"\bd\s*=\s*[\"'][^\"']*$")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>`)]+")
DSN_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>`)]+)")
DOCUMENTATION_IP_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
    )
)


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


@dataclass(frozen=True)
class WorkflowJob:
    path: str
    workflow_name: str
    job_id: str
    job_name: str
    runs_on: str


def yaml_scalar(value: str) -> str:
    value = value.strip()
    if "#" in value:
        value = value.split("#", 1)[0].rstrip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def workflow_jobs(repo_root: Path, files: list[str]) -> list[WorkflowJob]:
    jobs: list[WorkflowJob] = []
    workflow_files = sorted(
        relative
        for relative in files
        if relative.startswith(".github/workflows/") and Path(relative).suffix in {".yml", ".yaml"}
    )

    for relative in workflow_files:
        path = repo_root / relative
        workflow_name = ""
        in_jobs = False
        current_job: dict[str, str] | None = None
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            if not raw_line.startswith(" ") and raw_line.startswith("name:"):
                workflow_name = yaml_scalar(raw_line.split(":", 1)[1])
                continue
            if raw_line == "jobs:":
                in_jobs = True
                current_job = None
                continue
            if not in_jobs:
                continue
            if not raw_line.startswith(" "):
                current_job = None
                in_jobs = False
                continue
            job_match = re.match(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$", raw_line)
            if job_match:
                if current_job is not None:
                    jobs.append(
                        WorkflowJob(
                            path=relative,
                            workflow_name=workflow_name,
                            job_id=current_job["job_id"],
                            job_name=current_job.get("job_name") or current_job["job_id"],
                            runs_on=current_job.get("runs_on", ""),
                        )
                    )
                current_job = {"job_id": job_match.group(1)}
                continue
            if current_job is None:
                continue
            name_match = re.match(r"^    name:\s*(.+)$", raw_line)
            if name_match:
                current_job["job_name"] = yaml_scalar(name_match.group(1))
                continue
            runs_on_match = re.match(r"^    runs-on:\s*(.+)$", raw_line)
            if runs_on_match:
                current_job["runs_on"] = yaml_scalar(runs_on_match.group(1))
                continue
        if current_job is not None:
            jobs.append(
                WorkflowJob(
                    path=relative,
                    workflow_name=workflow_name,
                    job_id=current_job["job_id"],
                    job_name=current_job.get("job_name") or current_job["job_id"],
                    runs_on=current_job.get("runs_on", ""),
                )
            )
    return jobs


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
        "target_repository_owners",
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
        "target_repository_owners",
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


def validate_repository_module_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module repository_module_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module repository_module_policy.enabled must be a boolean", module_id))
    findings.extend(require_string(policy, "name", "module repository_module_policy", module_id))
    for key in ("required_project_ids",):
        values, key_findings = get_optional_string_list(policy, key, "module repository_module_policy", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"module repository_module_policy `{key}` entries must be unique", module_id))
    return findings


def validate_repo_hygiene_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module repo_hygiene_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module repo_hygiene_policy.enabled must be a boolean", module_id))
    for key in ("name", "source_boundary"):
        findings.extend(require_string(policy, key, "module repo_hygiene_policy", module_id))
    for key in (
        "target_project_ids",
        "ignored_path_parts",
        "forbidden_path_globs",
    ):
        values, key_findings = get_optional_string_list(policy, key, "module repo_hygiene_policy", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"module repo_hygiene_policy `{key}` entries must be unique", module_id))
    for key in ("allowed_path_globs", "allowed_large_file_globs"):
        values = policy.get(key, [])
        if not isinstance(values, list):
            findings.append(finding(f"module repo_hygiene_policy.{key} must be a list", module_id))
            continue
        seen: set[str] = set()
        for index, value in enumerate(values):
            if not isinstance(value, str) or not value.strip():
                findings.append(finding(f"module repo_hygiene_policy.{key}[{index}] must be a non-empty string", module_id))
                continue
            if value in seen:
                findings.append(finding(f"module repo_hygiene_policy `{key}` entries must be unique", module_id))
            seen.add(value)
    forbidden_path_globs = policy.get("forbidden_path_globs", DEFAULT_REPO_HYGIENE_FORBIDDEN_PATH_GLOBS)
    if not isinstance(forbidden_path_globs, list) or not forbidden_path_globs:
        findings.append(finding("module repo_hygiene_policy.forbidden_path_globs must be a non-empty list", module_id))
    max_file_bytes = policy.get("max_file_bytes", DEFAULT_REPO_HYGIENE_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        findings.append(finding("module repo_hygiene_policy.max_file_bytes must be a positive integer", module_id))
    return findings


def validate_branch_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module branch_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module branch_policy.enabled must be a boolean", module_id))
    for key in ("target_project_ids", "required_branches", "target_repository_owners"):
        values, key_findings = get_optional_string_list(policy, key, "module branch_policy", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"module branch_policy `{key}` entries must be unique", module_id))
    required_branches = policy.get("required_branches", DEFAULT_REQUIRED_BRANCHES)
    if not isinstance(required_branches, list) or not required_branches:
        findings.append(finding("module branch_policy.required_branches must be a non-empty list", module_id))
    return findings


def validate_local_audit_workflow_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module local_audit_workflow_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module local_audit_workflow_policy.enabled must be a boolean", module_id))
    for key in ("name", "workflow_path", "template_path"):
        findings.extend(require_string(policy, key, "module local_audit_workflow_policy", module_id))
    for key in ("target_project_ids", "target_repository_owners"):
        values, key_findings = get_optional_string_list(policy, key, "module local_audit_workflow_policy", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"module local_audit_workflow_policy `{key}` entries must be unique", module_id))
    return findings


def validate_local_delivery_framework_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module local_delivery_framework_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module local_delivery_framework_policy.enabled must be a boolean", module_id))
    findings.extend(require_string(policy, "name", "module local_delivery_framework_policy", module_id))
    for key in ("target_project_ids", "target_repository_owners", "required_files"):
        values, key_findings = get_optional_string_list(policy, key, "module local_delivery_framework_policy", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"module local_delivery_framework_policy `{key}` entries must be unique", module_id))

    required_files = policy.get("required_files", [])
    if not isinstance(required_files, list) or not required_files:
        findings.append(finding("module local_delivery_framework_policy.required_files must be a non-empty list", module_id))

    raw_markers = policy.get("required_markers", {})
    if not isinstance(raw_markers, dict):
        findings.append(finding("module local_delivery_framework_policy.required_markers must be an object", module_id))
        return findings
    for path, markers in raw_markers.items():
        if not isinstance(path, str) or not path.strip():
            findings.append(finding("module local_delivery_framework_policy.required_markers keys must be non-empty strings", module_id))
            continue
        if not isinstance(markers, list) or not markers:
            findings.append(finding(f"module local_delivery_framework_policy.required_markers.{path} must be a non-empty list", module_id))
            continue
        seen: set[str] = set()
        for index, marker in enumerate(markers):
            if not isinstance(marker, str) or not marker.strip():
                findings.append(
                    finding(
                        f"module local_delivery_framework_policy.required_markers.{path}[{index}] must be a non-empty string",
                        module_id,
                    )
                )
                continue
            if marker in seen:
                findings.append(finding(f"module local_delivery_framework_policy.required_markers.{path} entries must be unique", module_id))
            seen.add(marker)
    return findings


def validate_ci_gate_contract(contract: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(contract, dict):
        return [finding("project module ci_gate_contract must be an object", module_id)]

    findings: list[AuditFinding] = []
    platform_gates = contract.get("platform_adaptation", {})
    if not isinstance(platform_gates, dict):
        findings.append(finding("project module ci_gate_contract.platform_adaptation must be an object", module_id))
    else:
        seen_gate_names: set[str] = set()
        for platform, gate_name in platform_gates.items():
            if not isinstance(platform, str) or not platform.strip():
                findings.append(finding("project module ci_gate_contract.platform_adaptation keys must be non-empty strings", module_id))
                continue
            if not isinstance(gate_name, str) or not gate_name.strip():
                findings.append(
                    finding(
                        f"project module ci_gate_contract.platform_adaptation.{platform} must be a non-empty string",
                        module_id,
                    )
                )
                continue
            canonical = f"platform-adaptation / {platform.strip()}-ci-gate"
            if gate_name.strip() != canonical:
                findings.append(
                    finding(
                        f"project module ci_gate_contract.platform_adaptation.{platform} must be `{canonical}`",
                        module_id,
                    )
                )
            if gate_name in seen_gate_names:
                findings.append(finding("project module ci_gate_contract.platform_adaptation gate names must be unique", module_id))
            seen_gate_names.add(gate_name)

    classified_gates = contract.get("classified_gates", [])
    if classified_gates:
        if not isinstance(classified_gates, list):
            findings.append(finding("project module ci_gate_contract.classified_gates must be a list", module_id))
        else:
            seen: set[str] = set()
            for index, gate_name in enumerate(classified_gates):
                if not isinstance(gate_name, str) or not gate_name.strip():
                    findings.append(finding(f"project module ci_gate_contract.classified_gates[{index}] must be a non-empty string", module_id))
                    continue
                if not CI_GATE_CLASSIFICATION_RE.match(gate_name.strip()):
                    findings.append(
                        finding(
                            f"project module ci_gate_contract.classified_gates[{index}] must use `category / action` classification",
                            module_id,
                        )
                    )
                if gate_name in seen:
                    findings.append(finding("project module ci_gate_contract.classified_gates entries must be unique", module_id))
                seen.add(gate_name)

    test_gates = contract.get("test_gates", {})
    if test_gates:
        if not isinstance(test_gates, dict):
            findings.append(finding("project module ci_gate_contract.test_gates must be an object", module_id))
        else:
            for key, canonical in TEST_CI_GATE_NAMES.items():
                gate_name = test_gates.get(key)
                if not isinstance(gate_name, str) or not gate_name.strip():
                    findings.append(finding(f"project module ci_gate_contract.test_gates.{key} must be `{canonical}`", module_id))
                    continue
                if gate_name.strip() != canonical:
                    findings.append(finding(f"project module ci_gate_contract.test_gates.{key} must be `{canonical}`", module_id))
            for key, gate_name in test_gates.items():
                if key not in TEST_CI_GATE_NAMES:
                    findings.append(finding(f"project module ci_gate_contract.test_gates has unknown gate key `{key}`", module_id))
                if isinstance(gate_name, str) and gate_name.strip() and not CI_GATE_CLASSIFICATION_RE.match(gate_name.strip()):
                    findings.append(
                        finding(
                            f"project module ci_gate_contract.test_gates.{key} must use `category / action` classification",
                            module_id,
                        )
                    )
    submit_readiness = contract.get("submit_readiness")
    if test_gates or submit_readiness is not None:
        if not isinstance(submit_readiness, str) or not submit_readiness.strip():
            findings.append(finding("project module ci_gate_contract.submit_readiness must describe the submittable-version standard", module_id))
        else:
            normalized = normalized_text(submit_readiness)
            for gate_name in TEST_CI_GATE_NAMES.values():
                if normalized_text(gate_name) not in normalized:
                    findings.append(
                        finding(
                            f"project module ci_gate_contract.submit_readiness must mention `{gate_name}`",
                            module_id,
                        )
                    )
    golden_suite = contract.get("golden_standard_suite")
    if golden_suite is not None:
        findings.extend(validate_golden_standard_suite_contract(golden_suite, module_id))

    local_profile = contract.get("local_gate_profile")
    if local_profile is None:
        findings.append(finding("project module ci_gate_contract.local_gate_profile must describe the repo-owned gate adaptation", module_id))
    else:
        findings.extend(validate_local_gate_profile_contract(local_profile, module_id))

    industry_groups = contract.get("industry_gate_groups", {})
    if industry_groups:
        findings.extend(validate_industry_gate_groups_contract(industry_groups, module_id))
    return findings


def validate_golden_standard_suite_contract(suite: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(suite, dict):
        return [finding("project module ci_gate_contract.golden_standard_suite must be an object", module_id)]

    findings: list[AuditFinding] = []
    findings.extend(require_string(suite, "manifest", "project module ci_gate_contract.golden_standard_suite", module_id))

    for key in ("required_files",):
        values, key_findings = get_optional_string_list(suite, key, "project module ci_gate_contract.golden_standard_suite", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"project module ci_gate_contract.golden_standard_suite `{key}` entries must be unique", module_id))

    markers = suite.get("required_markers", {})
    if not isinstance(markers, dict):
        findings.append(finding("project module ci_gate_contract.golden_standard_suite.required_markers must be an object", module_id))
        return findings
    for path, required_markers in markers.items():
        if not isinstance(path, str) or not path.strip():
            findings.append(finding("project module ci_gate_contract.golden_standard_suite.required_markers keys must be non-empty strings", module_id))
            continue
        if not isinstance(required_markers, list) or not required_markers:
            findings.append(
                finding(
                    f"project module ci_gate_contract.golden_standard_suite.required_markers.{path} must be a non-empty list",
                    module_id,
                )
            )
            continue
        seen: set[str] = set()
        for index, marker in enumerate(required_markers):
            if not isinstance(marker, str) or not marker.strip():
                findings.append(
                    finding(
                        f"project module ci_gate_contract.golden_standard_suite.required_markers.{path}[{index}] must be a non-empty string",
                        module_id,
                    )
                )
                continue
            if marker in seen:
                findings.append(
                    finding(
                        f"project module ci_gate_contract.golden_standard_suite.required_markers.{path} entries must be unique",
                        module_id,
                    )
                )
            seen.add(marker)
    return findings


def validate_local_gate_profile_contract(profile: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(profile, dict):
        return [finding("project module ci_gate_contract.local_gate_profile must be an object", module_id)]

    findings: list[AuditFinding] = []
    for key in ("profile_id", "manifest", "covered_by"):
        findings.extend(require_string(profile, key, "project module ci_gate_contract.local_gate_profile", module_id))
    profile_id = profile.get("profile_id")
    if isinstance(profile_id, str) and profile_id.strip() and not LOCAL_GATE_PROFILE_ID_RE.match(profile_id.strip()):
        findings.append(
            finding(
                "project module ci_gate_contract.local_gate_profile.profile_id must use lowercase dash-separated id syntax",
                module_id,
            )
        )
    covered_by = profile.get("covered_by")
    if isinstance(covered_by, str) and covered_by.strip() and not CI_GATE_CLASSIFICATION_RE.match(covered_by.strip()):
        findings.append(
            finding(
                "project module ci_gate_contract.local_gate_profile.covered_by must use `category / action` classification",
                module_id,
            )
        )
    markers, marker_findings = get_string_list(
        profile,
        "required_markers",
        "project module ci_gate_contract.local_gate_profile",
        module_id,
    )
    findings.extend(marker_findings)
    if markers and len(markers) != len(unique_strings(markers)):
        findings.append(finding("project module ci_gate_contract.local_gate_profile.required_markers entries must be unique", module_id))
    return findings


def validate_industry_gate_groups_contract(groups: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(groups, dict):
        return [finding("project module ci_gate_contract.industry_gate_groups must be an object", module_id)]

    findings: list[AuditFinding] = []
    for group_name, group in groups.items():
        if not isinstance(group_name, str) or not group_name.strip():
            findings.append(finding("project module ci_gate_contract.industry_gate_groups keys must be non-empty strings", module_id))
            continue
        group_name = group_name.strip()
        if not CI_GATE_CLASSIFICATION_RE.match(group_name):
            findings.append(
                finding(
                    f"project module ci_gate_contract.industry_gate_groups `{group_name}` must use `category / action` classification",
                    module_id,
                )
            )
        if not isinstance(group, dict):
            findings.append(finding(f"project module ci_gate_contract.industry_gate_groups.{group_name} must be an object", module_id))
            continue
        covered_by = group.get("covered_by")
        if not isinstance(covered_by, str) or not covered_by.strip():
            findings.append(finding(f"project module ci_gate_contract.industry_gate_groups.{group_name}.covered_by must be a non-empty string", module_id))
        elif not CI_GATE_CLASSIFICATION_RE.match(covered_by.strip()):
            findings.append(
                finding(
                    f"project module ci_gate_contract.industry_gate_groups.{group_name}.covered_by must use `category / action` classification",
                    module_id,
                )
            )
        for key in ("industry_references", "required_markers"):
            values, key_findings = get_string_list(
                group,
                key,
                f"project module ci_gate_contract.industry_gate_groups.{group_name}",
                module_id,
            )
            findings.extend(key_findings)
            if values and len(values) != len(unique_strings(values)):
                findings.append(
                    finding(
                        f"project module ci_gate_contract.industry_gate_groups.{group_name}.{key} entries must be unique",
                        module_id,
                    )
                )
    return findings


def validate_pull_request_flow_policy(
    policy: Any,
    module_id: str,
    policy_name: str,
    default_development_base_branches: list[str],
    default_required_pull_request_flows: list[dict[str, str]],
) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding(f"module {policy_name} must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding(f"module {policy_name}.enabled must be a boolean", module_id))
    for key in ("target_project_ids", "target_repository_owners", "development_base_branches"):
        values, key_findings = get_optional_string_list(policy, key, f"module {policy_name}", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"module {policy_name} `{key}` entries must be unique", module_id))
    raw_flows = policy.get("required_pull_request_flows", default_required_pull_request_flows)
    if not isinstance(raw_flows, list) or not raw_flows:
        findings.append(finding(f"module {policy_name}.required_pull_request_flows must be a non-empty list", module_id))
    else:
        seen_heads: set[str] = set()
        for index, item in enumerate(raw_flows):
            if not isinstance(item, dict):
                findings.append(finding(f"module {policy_name}.required_pull_request_flows[{index}] must be an object", module_id))
                continue
            for key in ("head", "base"):
                value = item.get(key)
                if not isinstance(value, str) or not value.strip():
                    findings.append(
                        finding(
                            f"module {policy_name}.required_pull_request_flows[{index}].{key} must be a non-empty string",
                            module_id,
                        )
                    )
            head = item.get("head")
            if isinstance(head, str) and head.strip():
                if head in seen_heads:
                    findings.append(finding(f"module {policy_name} required flow for `{head}` must be unique", module_id))
                seen_heads.add(head)
    development_base_branches = policy.get("development_base_branches", default_development_base_branches)
    if not isinstance(development_base_branches, list) or not development_base_branches:
        findings.append(finding(f"module {policy_name}.development_base_branches must be a non-empty list", module_id))
    return findings


def validate_upstream_branch_flow_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    return validate_pull_request_flow_policy(
        policy,
        module_id,
        "upstream_branch_flow_policy",
        DEFAULT_UPSTREAM_DEVELOPMENT_BASE_BRANCHES,
        DEFAULT_UPSTREAM_REQUIRED_PULL_REQUEST_FLOWS,
    )


def validate_downstream_branch_flow_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    return validate_pull_request_flow_policy(
        policy,
        module_id,
        "downstream_branch_flow_policy",
        DEFAULT_DOWNSTREAM_DEVELOPMENT_BASE_BRANCHES,
        DEFAULT_DOWNSTREAM_REQUIRED_PULL_REQUEST_FLOWS,
    )


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


def validate_ip_exposure_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module ip_exposure_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module ip_exposure_policy.enabled must be a boolean", module_id))
    if "allow_loopback" in policy and not isinstance(policy.get("allow_loopback"), bool):
        findings.append(finding("module ip_exposure_policy.allow_loopback must be a boolean", module_id))
    for key in ("target_project_ids", "ignored_path_parts"):
        values, key_findings = get_optional_string_list(policy, key, "module ip_exposure_policy", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"module ip_exposure_policy `{key}` entries must be unique", module_id))
    max_file_bytes = policy.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        findings.append(finding("module ip_exposure_policy.max_file_bytes must be a positive integer", module_id))

    entries = policy.get("allowed_service_ip_occurrences", [])
    if not isinstance(entries, list):
        findings.append(finding("module ip_exposure_policy.allowed_service_ip_occurrences must be a list", module_id))
        return findings
    for index, entry in enumerate(entries):
        context = f"module ip_exposure_policy.allowed_service_ip_occurrences[{index}]"
        if not isinstance(entry, dict):
            findings.append(finding(f"{context} must be an object", module_id))
            continue
        for key in ("service", "reason"):
            findings.extend(require_string(entry, key, context, module_id))
        ips, ip_findings = get_string_list(entry, "ips", context, module_id)
        findings.extend(ip_findings)
        for value in ips:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                findings.append(finding(f"{context}.ips contains invalid IP address `{value}`", module_id))
        path_globs, path_findings = get_string_list(entry, "path_globs", context, module_id)
        findings.extend(path_findings)
        if path_globs and len(path_globs) != len(unique_strings(path_globs)):
            findings.append(finding(f"{context}.path_globs entries must be unique", module_id))
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


def validate_public_infrastructure_exposure_policy(policy: Any, module_id: str) -> list[AuditFinding]:
    if not isinstance(policy, dict):
        return [finding("module public_infrastructure_exposure_policy must be an object", module_id)]

    findings: list[AuditFinding] = []
    if "enabled" in policy and not isinstance(policy.get("enabled"), bool):
        findings.append(finding("module public_infrastructure_exposure_policy.enabled must be a boolean", module_id))
    findings.extend(require_string(policy, "name", "module public_infrastructure_exposure_policy", module_id))
    for key in (
        "target_project_ids",
        "target_repository_owners",
        "scan_globs",
        "ignored_path_parts",
        "restricted_path_globs",
        "allowed_placeholder_markers",
        "allowed_host_suffixes",
        "disallowed_host_markers",
        "disallowed_dsn_schemes",
        "cloud_resource_markers",
    ):
        values, key_findings = get_optional_string_list(policy, key, "module public_infrastructure_exposure_policy", module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"module public_infrastructure_exposure_policy `{key}` entries must be unique", module_id))
    max_file_bytes = policy.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        findings.append(finding("module public_infrastructure_exposure_policy.max_file_bytes must be a positive integer", module_id))
    return findings


def validate_project_inventory(module: AuditModule) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for key in REQUIRED_PROJECT_INVENTORY_FIELDS:
        values, key_findings = get_string_list(module.data, key, "project manifest inventory", module.module_id)
        findings.extend(key_findings)
        if values and len(values) != len(unique_strings(values)):
            findings.append(finding(f"project manifest inventory `{key}` entries must be unique", module.module_id))
    return findings


def validate_project_audit_profile(module: AuditModule) -> list[AuditFinding]:
    profile = module.data.get("audit_profile")
    if not isinstance(profile, str) or not profile.strip():
        return [finding("project module must declare non-empty audit_profile", module.module_id)]

    profile = profile.strip()
    findings: list[AuditFinding] = []
    if profile not in AUDIT_PROFILE_VALUES:
        allowed = ", ".join(sorted(AUDIT_PROFILE_VALUES))
        findings.append(finding(f"project module audit_profile `{profile}` must be one of: {allowed}", module.module_id))
    if profile in BACKEND_AUDIT_PROFILES:
        boundaries = module.data.get("security_boundaries")
        if not isinstance(boundaries, list) or not any(isinstance(item, str) and item.strip() for item in boundaries):
            findings.append(
                finding(
                    "backend-operations project module must declare non-empty security_boundaries",
                    module.module_id,
                )
            )
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
        if "repository_module_policy" in data:
            findings.extend(validate_repository_module_policy(data["repository_module_policy"], module.module_id))
        if "repo_hygiene_policy" in data:
            findings.extend(validate_repo_hygiene_policy(data["repo_hygiene_policy"], module.module_id))
        if "branch_policy" in data:
            findings.extend(validate_branch_policy(data["branch_policy"], module.module_id))
        if "local_audit_workflow_policy" in data:
            findings.extend(validate_local_audit_workflow_policy(data["local_audit_workflow_policy"], module.module_id))
        if "local_delivery_framework_policy" in data:
            findings.extend(validate_local_delivery_framework_policy(data["local_delivery_framework_policy"], module.module_id))
        if "upstream_branch_flow_policy" in data:
            findings.extend(validate_upstream_branch_flow_policy(data["upstream_branch_flow_policy"], module.module_id))
        if "downstream_branch_flow_policy" in data:
            findings.extend(validate_downstream_branch_flow_policy(data["downstream_branch_flow_policy"], module.module_id))
        if "secret_scan_policy" in data:
            findings.extend(validate_secret_scan_policy(data["secret_scan_policy"], module.module_id))
        if "ip_exposure_policy" in data:
            findings.extend(validate_ip_exposure_policy(data["ip_exposure_policy"], module.module_id))
        if "server_sensitive_boundary_policy" in data:
            findings.extend(validate_server_sensitive_boundary_policy(data["server_sensitive_boundary_policy"], module.module_id))
        if "public_infrastructure_exposure_policy" in data:
            findings.extend(validate_public_infrastructure_exposure_policy(data["public_infrastructure_exposure_policy"], module.module_id))
    elif module.module_type == "project":
        project_ids, project_findings = get_string_list(data, "project_ids", "module", module.module_id)
        findings.extend(project_findings)
        if not project_ids:
            findings.append(finding("project module must declare at least one project id", module.module_id))
        elif len(project_ids) != len(unique_strings(project_ids)):
            findings.append(finding("project_ids entries must be unique", module.module_id))
        findings.extend(validate_project_audit_profile(module))
        findings.extend(validate_project_inventory(module))
        if "ci_gate_contract" in data:
            findings.extend(validate_ci_gate_contract(data["ci_gate_contract"], module.module_id))
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
                if not matches_scope_glob(pattern, repo_files):
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


def matches_scope_glob(pattern: str, files: list[str]) -> list[str]:
    matched: list[str] = []
    for alternative in [item.strip() for item in pattern.split("|") if item.strip()]:
        matched.extend(matches(alternative, files))
    return unique_strings(matched)


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


def policy_branch_flows(policy: dict[str, Any], key: str, default: list[dict[str, str]]) -> dict[str, str]:
    values = policy.get(key, default)
    if not isinstance(values, list):
        values = default
    result: dict[str, str] = {}
    for item in values:
        if not isinstance(item, dict):
            continue
        head = item.get("head")
        base = item.get("base")
        if isinstance(head, str) and head.strip() and isinstance(base, str) and base.strip():
            result[head.strip()] = base.strip()
    return result


def policy_marker_map(policy: dict[str, Any], key: str) -> dict[str, list[str]]:
    raw = policy.get(key, {})
    if not isinstance(raw, dict):
        return {}
    result: dict[str, list[str]] = {}
    for path, markers in raw.items():
        if not isinstance(path, str) or not path.strip() or not isinstance(markers, list):
            continue
        clean_markers = [marker for marker in markers if isinstance(marker, str) and marker.strip()]
        if clean_markers:
            result[path.strip()] = clean_markers
    return result


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
        "audit_profile",
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
    if target_project_ids and "*" not in target_project_ids and aliases.isdisjoint(target_project_ids):
        return []

    target_repository_owners = set(policy_strings(policy, "target_repository_owners", []))
    if target_repository_owners:
        owner, error = git_repository_owner(context.repo_root)
        if owner is None:
            return [finding(f"license policy: {error}; repository owner cannot be verified", default.module_id)]
        if owner not in target_repository_owners:
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
    if target_project_ids and "*" not in target_project_ids and aliases.isdisjoint(target_project_ids):
        return []

    target_repository_owners = set(policy_strings(policy, "target_repository_owners", []))
    if target_repository_owners:
        owner, error = git_repository_owner(context.repo_root)
        if owner is None:
            return [finding(f"commercial risk policy: {error}; repository owner cannot be verified", default.module_id)]
        if owner not in target_repository_owners:
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
    if target_project_ids and "*" not in target_project_ids and aliases.isdisjoint(target_project_ids):
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


def path_matches_glob(relative_path: str, pattern: str) -> bool:
    if not any(ch in pattern for ch in "*?["):
        return relative_path == pattern or relative_path.startswith(pattern.rstrip("/") + "/")
    return fnmatch.fnmatch(relative_path, pattern)


def path_matches_any_glob(relative_path: str, patterns: list[str]) -> bool:
    return any(path_matches_glob(relative_path, pattern) for pattern in patterns)


def check_repo_hygiene_policy(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("repo_hygiene_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []

    target_project_ids = set(policy_strings(policy, "target_project_ids", []))
    aliases = {item for item in (context.project, context.repo_root.name) if item}
    if target_project_ids and "*" not in target_project_ids and aliases.isdisjoint(target_project_ids):
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
                    f"repo hygiene policy: {relative} matches a forbidden repository-junk pattern; "
                    "temporary files, caches, build outputs, logs, raw data dumps, archives, and local artifacts "
                    "must not enter pull requests",
                    default.module_id,
                )
            )
            continue
        path = context.repo_root / relative
        if not path.is_file() or path_matches_any_glob(relative, allowed_large_file_globs):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_file_bytes:
            findings.append(
                finding(
                    f"repo hygiene policy: {relative} is {size} bytes, above the {max_file_bytes} byte limit; "
                    "large generated artifacts and raw data sets must stay outside the repository unless explicitly allowed",
                    default.module_id,
                )
            )
    return findings


def allowed_service_ip_entries(policy: dict[str, Any]) -> list[dict[str, object]]:
    entries = policy.get("allowed_service_ip_occurrences", [])
    if not isinstance(entries, list):
        return []
    result: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ips: list[ipaddress._BaseAddress] = []
        for value in entry.get("ips", []):
            if not isinstance(value, str) or not value.strip():
                continue
            try:
                ips.append(ipaddress.ip_address(value.strip()))
            except ValueError:
                continue
        path_globs = [item for item in entry.get("path_globs", []) if isinstance(item, str) and item.strip()]
        service = entry.get("service", "service allowlist")
        if ips and path_globs:
            result.append({"service": str(service), "ips": ips, "path_globs": path_globs})
    return result


def ip_occurrence_is_allowed(
    ip: ipaddress._BaseAddress,
    relative_path: str,
    *,
    allow_loopback: bool,
    service_entries: list[dict[str, object]],
) -> tuple[bool, str | None]:
    if allow_loopback and ip.is_loopback:
        return True, "loopback"
    if ip.is_unspecified:
        return True, "unspecified bind address"
    if ip.version == 4 and str(ip) == "255.255.255.255":
        return True, "broadcast address"
    if any(ip in network for network in DOCUMENTATION_IP_NETWORKS):
        return True, "documentation address"
    for entry in service_entries:
        ips = entry.get("ips", [])
        path_globs = entry.get("path_globs", [])
        if not isinstance(ips, list) or not isinstance(path_globs, list):
            continue
        if ip not in ips:
            continue
        if any(isinstance(pattern, str) and path_matches_glob(relative_path, pattern) for pattern in path_globs):
            return True, str(entry.get("service", "service allowlist"))
    return False, None


def scan_ip_exposure_file(
    relative_path: str,
    text: str,
    *,
    allow_loopback: bool,
    service_entries: list[dict[str, object]],
    module_id: str,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    seen: set[tuple[str, int, str]] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        candidates: list[tuple[str, ipaddress._BaseAddress]] = []
        for match in IPV4_RE.finditer(line):
            if SVG_PATH_DATA_PREFIX_RE.search(line[: match.start()]):
                continue
            value = match.group(0)
            try:
                candidates.append((value, ipaddress.ip_address(value)))
            except ValueError:
                continue
        for match in IPV6_RE.finditer(line):
            value = match.group(0)
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            if ip.version == 6:
                candidates.append((value, ip))
        for match in IPV6_UNSPECIFIED_RE.finditer(line):
            if match.start() == 0 or match.end() >= len(line):
                continue
            if line[match.start() - 1] != "[" or line[match.end()] != "]":
                continue
            value = match.group(0)
            try:
                candidates.append((value, ipaddress.ip_address(value)))
            except ValueError:
                continue

        for value, ip in candidates:
            key = (relative_path, line_number, value)
            if key in seen:
                continue
            seen.add(key)
            allowed, _reason = ip_occurrence_is_allowed(
                ip,
                relative_path,
                allow_loopback=allow_loopback,
                service_entries=service_entries,
            )
            if allowed:
                continue
            findings.append(
                finding(
                    f"ip exposure: {relative_path}:{line_number} contains non-whitelisted IP address `{value}`; "
                    "loopback addresses and explicitly scoped service DNS records are the only allowed IP literals",
                    module_id,
                )
            )
    return findings


def check_ip_exposure_policy(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("ip_exposure_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []

    target_project_ids = set(policy_strings(policy, "target_project_ids", []))
    aliases = {item for item in (context.project, context.repo_root.name) if item}
    if target_project_ids and "*" not in target_project_ids and aliases.isdisjoint(target_project_ids):
        return []

    max_file_bytes = policy.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
        max_file_bytes = DEFAULT_MAX_FILE_BYTES
    ignored_parts = set(policy_strings(policy, "ignored_path_parts", sorted(DEFAULT_IP_SCAN_IGNORED_PATH_PARTS)))
    allow_loopback = bool(policy.get("allow_loopback", True))
    service_entries = allowed_service_ip_entries(policy)

    findings: list[AuditFinding] = []
    for relative in files:
        if path_has_part(relative, ignored_parts):
            continue
        path = context.repo_root / relative
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\0" in raw[:4096]:
            continue
        text = raw.decode("utf-8", errors="replace")
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


def clean_host(value: str) -> str:
    host = value.strip().casefold().strip("[]").rstrip(".")
    return host


def host_is_allowed(host: str, allowed_suffixes: list[str]) -> bool:
    clean = clean_host(host)
    if not clean:
        return False
    try:
        ip = ipaddress.ip_address(clean)
    except ValueError:
        ip = None
    if ip is not None:
        return ip.is_loopback
    for suffix in allowed_suffixes:
        allowed = clean_host(suffix.lstrip("*."))
        if not allowed:
            continue
        if clean == allowed or clean.endswith(f".{allowed}"):
            return True
    return False


def host_matches_marker(host: str, marker: str) -> bool:
    normalized_host = re.sub(r"[^a-z0-9]+", " ", clean_host(host))
    normalized_marker = re.sub(r"[^a-z0-9]+", " ", marker.casefold()).strip()
    if not normalized_host or not normalized_marker:
        return False
    return re.search(rf"(?<![a-z0-9]){re.escape(normalized_marker)}(?![a-z0-9])", normalized_host) is not None


def url_host(value: str) -> str | None:
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    return parsed.hostname


def text_has_placeholder_marker(text: str, markers: list[str]) -> bool:
    normalized = normalized_text(text)
    return any(marker_group_matches(normalized, marker) for marker in markers)


def connection_value_is_placeholder(value: str, markers: list[str]) -> bool:
    return "..." in value or "<" in value or ">" in value or text_has_placeholder_marker(value, markers)


def scan_public_infrastructure_file(
    relative_path: str,
    text: str,
    *,
    allowed_host_suffixes: list[str],
    disallowed_host_markers: list[str],
    disallowed_dsn_schemes: list[str],
    cloud_resource_markers: list[str],
    allowed_placeholder_markers: list[str],
    module_id: str,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    placeholder_context = path_matches_any_marker(relative_path, allowed_placeholder_markers)
    normalized = normalized_text(text)

    for line_number, line in enumerate(text.splitlines(), start=1):
        if placeholder_context or text_has_placeholder_marker(line, allowed_placeholder_markers):
            continue

        for marker in cloud_resource_markers:
            if normalized_text(marker) in normalized_text(line):
                findings.append(
                    finding(
                        f"public infrastructure exposure: {relative_path}:{line_number} contains cloud resource marker `{marker}`; "
                        "official service infrastructure identifiers must stay in private ops repositories or secret-management systems",
                        module_id,
                    )
                )

        kube_markers = ("apiVersion: v1", "clusters:", "current-context:", "users:")
        if all(normalized_text(marker) in normalized for marker in kube_markers):
            findings.append(
                finding(
                    f"public infrastructure exposure: {relative_path} looks like a kubeconfig; "
                    "cluster contexts and user material must not be committed to public backend operations repositories",
                    module_id,
                )
            )
            break

        for match in URL_RE.finditer(line):
            value = match.group(0).rstrip(".,;:")
            host = url_host(value)
            if host is None or host_is_allowed(host, allowed_host_suffixes):
                continue
            for marker in disallowed_host_markers:
                if not host_matches_marker(host, marker):
                    continue
                findings.append(
                    finding(
                        f"public infrastructure exposure: {relative_path}:{line_number} contains operational URL host `{host}` "
                        f"matching marker `{marker}`; use placeholders such as example.invalid or move official service details private",
                        module_id,
                    )
                )
                break

        for match in DSN_RE.finditer(line):
            value = match.group(1).rstrip(",;:")
            if connection_value_is_placeholder(value, allowed_placeholder_markers):
                continue
            parsed = urlparse(value)
            scheme = parsed.scheme.casefold()
            if scheme not in disallowed_dsn_schemes:
                continue
            host = parsed.hostname or ""
            if host_is_allowed(host, allowed_host_suffixes):
                continue
            findings.append(
                finding(
                f"public infrastructure exposure: {relative_path}:{line_number} contains `{scheme}` service DSN; "
                "database, queue, cache, SMTP, and broker endpoints must use placeholders in public backend operations repositories",
                module_id,
            )
            )
    return findings


def check_public_infrastructure_exposure_policy(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("public_infrastructure_exposure_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []

    target_project_ids = set(policy_strings(policy, "target_project_ids", DEFAULT_PUBLIC_INFRASTRUCTURE_EXPOSURE_PROJECT_IDS))
    aliases = {item for item in (context.project, context.repo_root.name) if item}
    if target_project_ids and aliases.isdisjoint(target_project_ids):
        return []

    target_repository_owners = set(policy_strings(policy, "target_repository_owners", DEFAULT_PUBLIC_INFRASTRUCTURE_EXPOSURE_OWNERS))
    if target_repository_owners:
        owner, error = git_repository_owner(context.repo_root)
        if owner is None:
            return [finding(f"public infrastructure exposure: {error}; repository owner cannot be verified", default.module_id)]
        if owner not in target_repository_owners:
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
    disallowed_dsn_schemes = [scheme.casefold() for scheme in policy_strings(policy, "disallowed_dsn_schemes", DEFAULT_INFRASTRUCTURE_DISALLOWED_DSN_SCHEMES)]
    cloud_resource_markers = policy_strings(policy, "cloud_resource_markers", DEFAULT_INFRASTRUCTURE_CLOUD_RESOURCE_MARKERS)

    findings: list[AuditFinding] = []
    restricted_files: list[str] = []
    for pattern in restricted_path_globs:
        restricted_files.extend(matches(pattern, files))
    for relative in unique_strings(sorted(restricted_files)):
        if path_has_part(relative, ignored_parts) or path_matches_any_marker(relative, allowed_placeholder_markers):
            continue
        findings.append(
            finding(
                f"public infrastructure exposure: {relative} matches restricted infrastructure path policy; "
                "production ops, private deployment, kubeconfig, Terraform variable/state, and inventory material must stay private",
                default.module_id,
            )
        )

    scan_files: list[str] = []
    for pattern in scan_globs:
        scan_files.extend(matches(pattern, files))
    for relative in unique_strings(sorted(scan_files)):
        if path_has_part(relative, ignored_parts):
            continue
        path = context.repo_root / relative
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\0" in raw[:4096]:
            continue
        findings.extend(
            scan_public_infrastructure_file(
                relative,
                raw.decode("utf-8", errors="replace"),
                allowed_host_suffixes=allowed_host_suffixes,
                disallowed_host_markers=disallowed_host_markers,
                disallowed_dsn_schemes=disallowed_dsn_schemes,
                cloud_resource_markers=cloud_resource_markers,
                allowed_placeholder_markers=allowed_placeholder_markers,
                module_id=default.module_id,
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


def github_owner_from_remote_url(url: str) -> str | None:
    normalized = url.strip()
    patterns = [
        r"^https://github\.com/([^/]+)/[^/]+?(?:\.git)?/?$",
        r"^git@github\.com:([^/]+)/[^/]+?(?:\.git)?$",
        r"^ssh://git@github\.com/([^/]+)/[^/]+?(?:\.git)?$",
    ]
    for pattern in patterns:
        match = re.match(pattern, normalized)
        if match:
            return match.group(1)
    return None


def git_repository_owner(repo_root: Path) -> tuple[str | None, str | None]:
    proc = subprocess.run(
        ["git", "config", "--get", "remote.origin.url"],
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        return None, "target repository has no remote.origin.url"
    owner = github_owner_from_remote_url(proc.stdout)
    if owner is None:
        return None, "target repository remote.origin.url is not a recognized GitHub URL"
    return owner, None


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


def normalized_file_text(text: str) -> str:
    normalized = text.replace("\r\n", "\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
    return normalized


def render_local_audit_workflow_template(template_text: str, repo_name: str, project: str) -> str:
    rendered = template_text.replace("{{REPO_NAME}}", repo_name)
    rendered = rendered.replace("{{PROJECT_ID}}", project)
    return normalized_file_text(rendered)


def check_local_audit_workflow_policy(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("local_audit_workflow_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []

    target_project_ids = set(policy_strings(policy, "target_project_ids", DEFAULT_LOCAL_AUDIT_WORKFLOW_PROJECT_IDS))
    aliases = {item for item in (context.project, context.repo_root.name) if item}
    if target_project_ids and aliases.isdisjoint(target_project_ids):
        return []

    target_repository_owners = set(policy_strings(policy, "target_repository_owners", DEFAULT_LOCAL_AUDIT_WORKFLOW_OWNERS))
    if target_repository_owners:
        owner, error = git_repository_owner(context.repo_root)
        if owner is None:
            return [finding(f"local audit workflow policy: {error}; repository owner cannot be verified", default.module_id)]
        if owner not in target_repository_owners:
            return []

    workflow_path = str(policy.get("workflow_path", DEFAULT_LOCAL_AUDIT_WORKFLOW_PATH)).strip()
    template_path_value = str(policy.get("template_path", DEFAULT_LOCAL_AUDIT_TEMPLATE_PATH)).strip()
    if not workflow_path or not template_path_value:
        return [finding("local audit workflow policy: missing workflow_path or template_path", default.module_id)]

    template_path = context.framework_root / template_path_value
    if not template_path.is_file():
        return [
            finding(
                f"local audit workflow policy: authoritative template `{template_path_value}` is missing from framework root",
                default.module_id,
            )
        ]

    if workflow_path not in files or not (context.repo_root / workflow_path).is_file():
        return [
            finding(
                f"local audit workflow policy: missing `{workflow_path}`; it must match authoritative template `{template_path_value}`",
                default.module_id,
            )
        ]

    project = context.project or context.repo_root.name
    expected = render_local_audit_workflow_template(
        template_path.read_text(encoding="utf-8", errors="replace"),
        context.repo_root.name,
        project,
    )
    actual = normalized_file_text((context.repo_root / workflow_path).read_text(encoding="utf-8", errors="replace"))
    if actual != expected:
        return [
            finding(
                f"local audit workflow policy: `{workflow_path}` does not match authoritative template `{template_path_value}` "
                f"for repository `{context.repo_root.name}` project `{project}`",
                default.module_id,
            )
        ]
    return []


def check_local_delivery_framework_policy(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get("local_delivery_framework_policy")
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []

    target_project_ids = set(policy_strings(policy, "target_project_ids", DEFAULT_LOCAL_DELIVERY_FRAMEWORK_PROJECT_IDS))
    aliases = {item for item in (context.project, context.repo_root.name) if item}
    if target_project_ids and aliases.isdisjoint(target_project_ids):
        return []

    target_repository_owners = set(policy_strings(policy, "target_repository_owners", DEFAULT_LOCAL_DELIVERY_FRAMEWORK_OWNERS))
    if target_repository_owners:
        owner, error = git_repository_owner(context.repo_root)
        if owner is None:
            return [finding(f"local delivery framework policy: {error}; repository owner cannot be verified", default.module_id)]
        if owner not in target_repository_owners:
            return []

    findings: list[AuditFinding] = []
    required_files = policy_strings(policy, "required_files", [])
    marker_requirements = policy_marker_map(policy, "required_markers")
    available_files = set(files)

    for relative in required_files:
        path = context.repo_root / relative
        if relative not in available_files or not path.is_file():
            findings.append(
                finding(
                    f"local delivery framework policy: missing required file `{relative}`",
                    default.module_id,
                )
            )

    for relative, markers in sorted(marker_requirements.items()):
        path = context.repo_root / relative
        if relative not in available_files or not path.is_file():
            if relative not in required_files:
                findings.append(
                    finding(
                        f"local delivery framework policy: marker target `{relative}` is missing",
                        default.module_id,
                    )
                )
            continue
        text = normalized_text(path.read_text(encoding="utf-8", errors="replace"))
        for marker in markers:
            if marker_group_matches(text, marker):
                continue
            findings.append(
                finding(
                    f"local delivery framework policy: `{relative}` missing required marker `{marker}`",
                    default.module_id,
                )
            )
    return findings


def runner_matches_platform(runs_on: str, platform: str) -> bool:
    markers = PLATFORM_CI_GATE_RUNNER_MARKERS.get(platform)
    if not markers:
        return True
    normalized = runs_on.casefold()
    return any(marker in normalized for marker in markers)


def check_ci_gate_contract(context: AuditContext, files: list[str]) -> list[AuditFinding]:
    if context.repo_root is None:
        return []
    project_modules = [module for module in context.modules if module.module_type == "project"]
    if not any(isinstance(module.data.get("ci_gate_contract"), dict) for module in project_modules):
        return []

    jobs = workflow_jobs(context.repo_root, files)
    jobs_by_name: dict[str, list[WorkflowJob]] = {}
    for job in jobs:
        jobs_by_name.setdefault(job.job_name, []).append(job)

    findings: list[AuditFinding] = []
    for module in project_modules:
        contract = module.data.get("ci_gate_contract")
        if not isinstance(contract, dict):
            continue

        platform_gates = contract.get("platform_adaptation", {})
        if isinstance(platform_gates, dict):
            for platform, gate_name in sorted(platform_gates.items()):
                if not isinstance(platform, str) or not isinstance(gate_name, str):
                    continue
                platform = platform.strip()
                gate_name = gate_name.strip()
                matches = jobs_by_name.get(gate_name, [])
                if len(matches) != 1:
                    findings.append(
                        finding(
                            f"ci gate contract: platform `{platform}` must have exactly one gate named `{gate_name}`; found {len(matches)}",
                            module.module_id,
                        )
                    )
                    continue
                job = matches[0]
                if not runner_matches_platform(job.runs_on, platform):
                    findings.append(
                        finding(
                            f"ci gate contract: `{gate_name}` in `{job.path}` runs on `{job.runs_on}`, "
                            f"which does not match platform `{platform}`",
                            module.module_id,
                        )
                    )

        classified_gates = contract.get("classified_gates", [])
        if isinstance(classified_gates, list):
            for gate_name in classified_gates:
                if not isinstance(gate_name, str):
                    continue
                gate_name = gate_name.strip()
                matches = jobs_by_name.get(gate_name, [])
                if len(matches) != 1:
                    findings.append(
                        finding(
                            f"ci gate contract: classified gate `{gate_name}` must appear exactly once; found {len(matches)}",
                            module.module_id,
                        )
                    )

        test_gates = contract.get("test_gates", {})
        if isinstance(test_gates, dict):
            for key, gate_name in sorted(test_gates.items()):
                if not isinstance(key, str) or not isinstance(gate_name, str):
                    continue
                gate_name = gate_name.strip()
                matches = jobs_by_name.get(gate_name, [])
                if len(matches) != 1:
                    findings.append(
                        finding(
                            f"ci gate contract: test gate `{key}` must appear exactly once as `{gate_name}`; found {len(matches)}",
                            module.module_id,
                        )
                    )

        golden_suite = contract.get("golden_standard_suite")
        golden_manifest_path: Path | None = None
        if isinstance(golden_suite, dict):
            manifest = golden_suite.get("manifest")
            required_files = policy_strings(golden_suite, "required_files", [])
            if isinstance(manifest, str) and manifest.strip():
                manifest = manifest.strip()
                golden_manifest_path = context.repo_root / manifest
                required_files = unique_strings([manifest, *required_files])

            for relative in required_files:
                path = context.repo_root / relative
                if path.is_file():
                    continue
                findings.append(
                    finding(
                        f"ci gate contract: golden standard suite requires `{relative}`",
                        module.module_id,
                    )
                )

            for relative, markers in policy_marker_map(golden_suite, "required_markers").items():
                path = context.repo_root / relative
                if not path.is_file():
                    findings.append(
                        finding(
                            f"ci gate contract: golden standard suite marker file `{relative}` is missing",
                            module.module_id,
                        )
                    )
                    continue
                text = normalized_text(path.read_text(encoding="utf-8", errors="replace"))
                for marker in markers:
                    if marker_group_matches(text, marker):
                        continue
                    findings.append(
                        finding(
                            f"ci gate contract: golden standard suite `{relative}` missing required marker `{marker}`",
                            module.module_id,
                        )
                    )

        local_profile = contract.get("local_gate_profile")
        if isinstance(local_profile, dict):
            profile_id = local_profile.get("profile_id")
            manifest = local_profile.get("manifest")
            covered_by = local_profile.get("covered_by")
            if isinstance(covered_by, str) and covered_by.strip():
                gate_name = covered_by.strip()
                matches = jobs_by_name.get(gate_name, [])
                if len(matches) != 1:
                    findings.append(
                        finding(
                            f"ci gate contract: local gate profile must be covered by exactly one gate named `{gate_name}`; found {len(matches)}",
                            module.module_id,
                        )
                    )
            if isinstance(manifest, str) and manifest.strip():
                relative = manifest.strip()
                path = context.repo_root / relative
                if not path.is_file():
                    findings.append(
                        finding(
                            f"ci gate contract: local gate profile requires `{relative}`",
                            module.module_id,
                        )
                    )
                else:
                    text = normalized_text(path.read_text(encoding="utf-8", errors="replace"))
                    if isinstance(profile_id, str) and profile_id.strip() and not marker_group_matches(text, profile_id.strip()):
                        findings.append(
                            finding(
                                f"ci gate contract: local gate profile `{relative}` missing profile id `{profile_id.strip()}`",
                                module.module_id,
                            )
                        )
                    if not marker_group_matches(text, "local gate profile"):
                        findings.append(
                            finding(
                                f"ci gate contract: local gate profile `{relative}` missing `local gate profile` marker",
                                module.module_id,
                            )
                        )
                    for marker in policy_strings(local_profile, "required_markers", []):
                        if marker_group_matches(text, marker):
                            continue
                        findings.append(
                            finding(
                                f"ci gate contract: local gate profile `{relative}` missing required marker `{marker}`",
                                module.module_id,
                            )
                        )

        industry_groups = contract.get("industry_gate_groups", {})
        if isinstance(industry_groups, dict):
            manifest_text = ""
            if golden_manifest_path is not None and golden_manifest_path.is_file():
                manifest_text = normalized_text(golden_manifest_path.read_text(encoding="utf-8", errors="replace"))
            for group_name, group in sorted(industry_groups.items()):
                if not isinstance(group_name, str) or not isinstance(group, dict):
                    continue
                clean_group_name = group_name.strip()
                covered_by = group.get("covered_by")
                if isinstance(covered_by, str) and covered_by.strip():
                    gate_name = covered_by.strip()
                    matches = jobs_by_name.get(gate_name, [])
                    if len(matches) != 1:
                        findings.append(
                            finding(
                                f"ci gate contract: industry gate group `{clean_group_name}` must be covered by exactly one gate named `{gate_name}`; found {len(matches)}",
                                module.module_id,
                            )
                        )
                if not manifest_text:
                    if golden_manifest_path is not None:
                        findings.append(
                            finding(
                                f"ci gate contract: industry gate group `{clean_group_name}` cannot verify missing golden manifest",
                                module.module_id,
                            )
                        )
                    continue
                if clean_group_name and not marker_group_matches(manifest_text, clean_group_name):
                    findings.append(
                        finding(
                            f"ci gate contract: golden standard suite missing industry gate group `{clean_group_name}`",
                            module.module_id,
                        )
                    )
                for marker in policy_strings(group, "required_markers", []):
                    if marker_group_matches(manifest_text, marker):
                        continue
                    findings.append(
                        finding(
                            f"ci gate contract: industry gate group `{clean_group_name}` missing required marker `{marker}`",
                            module.module_id,
                        )
                    )
    return findings


def check_branch_policy(context: AuditContext) -> list[AuditFinding]:
    if context.skip_branch_governance:
        return []
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

    target_repository_owners = set(policy_strings(policy, "target_repository_owners", []))
    if target_repository_owners:
        owner, error = git_repository_owner(context.repo_root)
        if owner is None:
            return [finding(f"branch policy: {error}; repository owner cannot be verified", default.module_id)]
        if owner not in target_repository_owners:
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


def check_pull_request_flow_policy(
    context: AuditContext,
    policy_key: str,
    label: str,
    default_target_repository_owners: list[str],
    default_development_base_branches: list[str],
    default_required_pull_request_flows: list[dict[str, str]],
) -> list[AuditFinding]:
    if context.skip_branch_governance:
        return []
    if context.repo_root is None:
        return []
    default = default_module(context.modules)
    if default is None:
        return []
    policy = default.data.get(policy_key)
    if not isinstance(policy, dict) or policy.get("enabled") is False:
        return []

    target_project_ids = set(policy_strings(policy, "target_project_ids", []))
    aliases = {item for item in (context.project, context.repo_root.name) if item}
    if target_project_ids and aliases.isdisjoint(target_project_ids):
        return []

    target_repository_owners = set(policy_strings(policy, "target_repository_owners", default_target_repository_owners))
    owner, error = git_repository_owner(context.repo_root)
    if owner is None:
        return [finding(f"{label}: {error}; repository owner cannot be verified", default.module_id)]
    if target_repository_owners and owner not in target_repository_owners:
        return []

    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    base_ref = os.environ.get("GITHUB_BASE_REF", "")
    head_ref = os.environ.get("GITHUB_HEAD_REF", "")
    development_base_branches = set(policy_strings(policy, "development_base_branches", default_development_base_branches))
    required_flows = policy_branch_flows(policy, "required_pull_request_flows", default_required_pull_request_flows)
    required_heads_by_base: dict[str, list[str]] = {}
    for head, base in required_flows.items():
        required_heads_by_base.setdefault(base, []).append(head)
    allowed_base_branches = development_base_branches | set(required_heads_by_base)
    reserved_branches = set(required_flows) | set(required_heads_by_base) | development_base_branches

    findings: list[AuditFinding] = []
    if event_name in {"pull_request", "pull_request_target"} or base_ref or head_ref:
        if not base_ref or not head_ref:
            return [
                finding(
                    f"{label}: pull request base/head refs are required for merge-flow validation",
                    default.module_id,
                )
            ]
        if allowed_base_branches and base_ref not in allowed_base_branches:
            findings.append(
                finding(
                    f"{label}: pull request target `{base_ref}` is not allowed; use {', '.join(sorted(allowed_base_branches))}",
                    default.module_id,
                )
            )
        expected_base = required_flows.get(head_ref)
        if expected_base is not None and base_ref != expected_base:
            findings.append(
                finding(
                    f"{label}: `{head_ref}` can only merge into `{expected_base}`, not `{base_ref}`",
                    default.module_id,
                )
            )
        required_heads = sorted(required_heads_by_base.get(base_ref, []))
        if expected_base is None and head_ref in reserved_branches and head_ref not in development_base_branches:
            findings.append(
                finding(
                    f"{label}: managed branch `{head_ref}` cannot target `{base_ref}` outside the declared promotion chain",
                    default.module_id,
                )
            )
        if expected_base is None and base_ref not in development_base_branches and required_heads:
            findings.append(
                finding(
                    f"{label}: `{base_ref}` only accepts pull requests from {', '.join(f'`{item}`' for item in required_heads)}",
                    default.module_id,
                )
            )
        return findings

    return []


def check_upstream_branch_flow_policy(context: AuditContext) -> list[AuditFinding]:
    return check_pull_request_flow_policy(
        context,
        "upstream_branch_flow_policy",
        "upstream branch flow",
        DEFAULT_UPSTREAM_BRANCH_FLOW_OWNERS,
        DEFAULT_UPSTREAM_DEVELOPMENT_BASE_BRANCHES,
        DEFAULT_UPSTREAM_REQUIRED_PULL_REQUEST_FLOWS,
    )


def check_downstream_branch_flow_policy(context: AuditContext) -> list[AuditFinding]:
    return check_pull_request_flow_policy(
        context,
        "downstream_branch_flow_policy",
        "downstream branch flow",
        DEFAULT_DOWNSTREAM_BRANCH_FLOW_OWNERS,
        DEFAULT_DOWNSTREAM_DEVELOPMENT_BASE_BRANCHES,
        DEFAULT_DOWNSTREAM_REQUIRED_PULL_REQUEST_FLOWS,
    )


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


def validate_modules(modules: list[AuditModule], *, enforce_repository_module_policy: bool = True) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    seen: set[str] = set()
    local_gate_profile_ids: dict[str, str] = {}
    for module in modules:
        if module.module_id in seen:
            findings.append(finding(f"duplicate loaded module id `{module.module_id}`"))
        seen.add(module.module_id)
        findings.extend(validate_module_schema(module))
        if module.module_type == "project":
            contract = module.data.get("ci_gate_contract")
            local_profile = contract.get("local_gate_profile") if isinstance(contract, dict) else None
            profile_id = local_profile.get("profile_id") if isinstance(local_profile, dict) else None
            if isinstance(profile_id, str) and profile_id.strip():
                clean_profile_id = profile_id.strip()
                previous_module = local_gate_profile_ids.get(clean_profile_id)
                if previous_module is not None:
                    findings.append(
                        finding(
                            f"local gate profile id `{clean_profile_id}` is used by both `{previous_module}` and `{module.module_id}`",
                            module.module_id,
                        )
                    )
                local_gate_profile_ids[clean_profile_id] = module.module_id
    default = default_module(modules)
    if default is None:
        findings.append(finding("module stack must include a default module"))
    elif enforce_repository_module_policy:
        policy = default.data.get("repository_module_policy")
        if isinstance(policy, dict) and policy.get("enabled") is not False:
            required_project_ids = policy_strings(policy, "required_project_ids", [])
            covered_project_ids: set[str] = set()
            for module in modules:
                if module.module_type == "default":
                    continue
                project_ids = module.data.get("project_ids", [])
                if isinstance(project_ids, list):
                    covered_project_ids.update(item for item in project_ids if isinstance(item, str) and item.strip())
            for project_id in required_project_ids:
                if project_id not in covered_project_ids:
                    findings.append(
                        finding(
                            f"repository module policy: required project id `{project_id}` has no project module coverage",
                            default.module_id,
                        )
                    )
    return findings


def gate(context: AuditContext) -> list[AuditFinding]:
    findings = validate_modules(context.modules, enforce_repository_module_policy=False)
    if context.repo_root is not None:
        files = repo_files(context.repo_root)
        findings.extend(check_local_audit_workflow_policy(context, files))
        findings.extend(check_local_delivery_framework_policy(context, files))
        findings.extend(check_ci_gate_contract(context, files))
        findings.extend(check_repo_hygiene_policy(context, files))
        for module in context.modules:
            if module.module_type != "default":
                findings.extend(validate_resource_classes(module, files))
        findings.extend(check_branch_policy(context))
        findings.extend(check_upstream_branch_flow_policy(context))
        findings.extend(check_downstream_branch_flow_policy(context))
        findings.extend(check_license_policy(context))
        findings.extend(check_commercial_risk_policy(context, files))
        findings.extend(check_ip_exposure_policy(context, files))
        findings.extend(check_public_infrastructure_exposure_policy(context, files))
        findings.extend(check_secret_scan_policy(context, files))
        findings.extend(check_server_sensitive_boundary_policy(context, files))
        findings.extend(check_defect_records(context))
    findings.extend(hook_findings(context.modules, context.as_hook_context()))
    return findings
