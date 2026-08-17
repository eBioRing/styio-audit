from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from styio_audit.cli import command_report
from styio_audit.checks import gate, validate_modules
from styio_audit.loader import hook_findings, load_all_modules, load_stack
from styio_audit.models import AuditContext
from styio_audit.secrets import scan_text


ROOT = Path(__file__).resolve().parents[1]


class FrameworkTests(unittest.TestCase):
    def _write_file(self, root: Path, relative: str, content: str) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _write_json(self, root: Path, relative: str, payload: dict) -> None:
        self._write_file(root, relative, json.dumps(payload, indent=2, sort_keys=True))

    def _init_git_repo(self, root: Path, *, branches: list[str] | None = None) -> None:
        subprocess.run(["git", "init"], cwd=root, check=True, text=True, capture_output=True)
        subprocess.run(["git", "checkout", "-b", "main"], cwd=root, check=True, text=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "audit@example.invalid"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Audit Test"], cwd=root, check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True, text=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=root, check=True, text=True, capture_output=True)
        for branch in branches or []:
            subprocess.run(["git", "branch", branch], cwd=root, check=True, text=True, capture_output=True)

    def _set_origin(self, root: Path, url: str) -> None:
        subprocess.run(["git", "remote", "add", "origin", url], cwd=root, check=True, text=True, capture_output=True)

    def _write_branch_policy_default_module(self, framework_root: Path) -> None:
        self._write_json(
            framework_root,
            "modules/default/module.json",
            {
                "schema_version": 1,
                "module_id": "default",
                "module_type": "default",
                "description": "Common audit rules.",
                "last_updated": "2026-04-25",
                "required_audit_fields": ["**Severity:**"],
                "required_closure_fields": ["**Closure evidence:**"],
                "required_checklist_markers": ["marker"],
                "branch_policy": {
                    "enabled": True,
                    "target_project_ids": ["demo"],
                    "required_branches": ["release", "stable", "nightly"],
                },
            },
        )

    def _write_downstream_flow_default_module(self, framework_root: Path) -> None:
        self._write_json(
            framework_root,
            "modules/default/module.json",
            {
                "schema_version": 1,
                "module_id": "default",
                "module_type": "default",
                "description": "Common audit rules.",
                "last_updated": "2026-04-25",
                "required_audit_fields": ["**Severity:**"],
                "required_closure_fields": ["**Closure evidence:**"],
                "required_checklist_markers": ["marker"],
                "downstream_branch_flow_policy": {
                    "enabled": True,
                    "target_repository_owners": ["Unka-Malloc"],
                    "development_base_branches": ["nightly"],
                    "required_pull_request_flows": [
                        {"head": "nightly", "base": "stable"},
                        {"head": "stable", "base": "release"},
                    ],
                },
            },
        )

    def _write_upstream_flow_default_module(self, framework_root: Path) -> None:
        self._write_json(
            framework_root,
            "modules/default/module.json",
            {
                "schema_version": 1,
                "module_id": "default",
                "module_type": "default",
                "description": "Common audit rules.",
                "last_updated": "2026-04-26",
                "required_audit_fields": ["**Severity:**"],
                "required_closure_fields": ["**Closure evidence:**"],
                "required_checklist_markers": ["marker"],
                "upstream_branch_flow_policy": {
                    "enabled": True,
                    "target_repository_owners": ["SymPolicy"],
                    "development_base_branches": ["nightly"],
                    "required_pull_request_flows": [
                        {"head": "nightly", "base": "stable"},
                        {"head": "stable", "base": "release"},
                    ],
                },
            },
        )

    def _write_demo_project_module(self, framework_root: Path) -> None:
        self._write_json(
            framework_root,
            "for-demo/module.json",
            {
                "schema_version": 1,
                "module_id": "for-demo",
                "module_type": "project",
                "description": "Demo project module.",
                "last_updated": "2026-04-25",
                "project_ids": ["demo"],
                "audit_profile": "example-basic",
                "technology_stack": ["Demo runtime"],
                "internal_components": ["Demo component"],
                "open_source_components": ["Demo OSS"],
                "dependency_manifests": ["demo.manifest"],
                "resource_classes": [
                    {
                        "id": "demo_resource",
                        "owner": "Demo owner",
                        "description": "Demo resource class.",
                        "scope_globs": ["src/**"],
                        "copying_policy": "Copies are explicit.",
                        "concurrency_policy": "Single-writer.",
                        "nullability_policy": "Nulls are explicit.",
                        "cleanup_policy": "Resources are cleaned.",
                        "state_machine": {
                            "source": "Demo source.",
                            "states": ["idle", "done"],
                            "transitions": [{"from": "idle", "to": "done", "on": "finish"}],
                            "invalid_operations": ["skip"],
                        },
                        "required_tests": ["demo test"],
                        "required_gates": ["demo gate"],
                        "audit_risks": ["demo risk"],
                    }
                ],
            },
        )

    def _write_local_audit_workflow_template(self, framework_root: Path) -> None:
        self._write_file(
            framework_root,
            "templates/workflows/styio-audit-local.yml",
            "name: styio-audit\n\n"
            "on:\n"
            "  pull_request:\n"
            "  push:\n"
            "  merge_group:\n"
            "  workflow_dispatch:\n\n"
            "permissions:\n"
            "  contents: read\n\n"
            "jobs:\n"
            "  audit:\n"
            "    name: styio-audit\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            "      - name: Checkout {{REPO_NAME}}\n"
            "        uses: actions/checkout@v5\n"
            "        with:\n"
            "          fetch-depth: 0\n"
            "          path: {{REPO_NAME}}\n"
            "      - name: Checkout released styio-audit policy\n"
            "        uses: actions/checkout@v5\n"
            "        with:\n"
            "          repository: SymPolicy/styio-audit\n"
            "          ref: stable\n"
            "          path: styio-audit\n"
            "      - name: Run released styio-audit gate\n"
            "        working-directory: {{REPO_NAME}}\n"
            "        run: python3 ../styio-audit/bin/styio-audit gate --repo . --project {{PROJECT_ID}}\n",
        )

    def _write_local_audit_workflow_default_module(self, framework_root: Path) -> None:
        self._write_json(
            framework_root,
            "modules/default/module.json",
            {
                "schema_version": 1,
                "module_id": "default",
                "module_type": "default",
                "description": "Common audit rules.",
                "last_updated": "2026-04-26",
                "required_audit_fields": ["**Severity:**"],
                "required_closure_fields": ["**Closure evidence:**"],
                "required_checklist_markers": ["marker"],
                "local_audit_workflow_policy": {
                    "enabled": True,
                    "name": "Authoritative local workflow policy.",
                    "target_project_ids": ["demo"],
                    "target_repository_owners": ["SymPolicy"],
                    "workflow_path": ".github/workflows/styio-audit.yml",
                    "template_path": "templates/workflows/styio-audit-local.yml",
                },
            },
        )

    def _write_local_delivery_framework_default_module(self, framework_root: Path) -> None:
        self._write_json(
            framework_root,
            "modules/default/module.json",
            {
                "schema_version": 1,
                "module_id": "default",
                "module_type": "default",
                "description": "Common audit rules.",
                "last_updated": "2026-04-26",
                "required_audit_fields": ["**Severity:**"],
                "required_closure_fields": ["**Closure evidence:**"],
                "required_checklist_markers": ["marker"],
                "local_delivery_framework_policy": {
                    "enabled": True,
                    "name": "Local delivery framework contract.",
                    "target_project_ids": ["demo"],
                    "target_repository_owners": ["SymPolicy"],
                    "required_files": [
                        ".github/workflows/styio-ci-gate.yml",
                        "scripts/workflow-scheduler.py",
                    ],
                    "required_markers": {
                        ".github/workflows/styio-ci-gate.yml": [
                            "workflow-scheduler.py run --profile ci-prebuild",
                        ],
                        "scripts/workflow-scheduler.py": [
                            "WORKFLOW_DOCS",
                            "PROFILES",
                        ],
                    },
                },
            },
        )

    def _write_local_delivery_framework_files(self, repo_root: Path) -> None:
        self._write_file(
            repo_root,
            ".github/workflows/styio-ci-gate.yml",
            "name: styio-ci-gate\n"
            "jobs:\n"
            "  ci:\n"
            "    steps:\n"
            "      - run: python3 scripts/workflow-scheduler.py run --profile ci-prebuild\n",
        )
        self._write_file(
            repo_root,
            "scripts/workflow-scheduler.py",
            "WORKFLOW_DOCS = ()\n"
            "PROFILES = ()\n",
        )

    def _write_ci_gate_contract_default_module(self, framework_root: Path) -> None:
        self._write_json(
            framework_root,
            "modules/default/module.json",
            {
                "schema_version": 1,
                "module_id": "default",
                "module_type": "default",
                "description": "Common audit rules.",
                "last_updated": "2026-06-29",
                "required_audit_fields": ["**Severity:**"],
                "required_closure_fields": ["**Closure evidence:**"],
                "required_checklist_markers": ["marker"],
            },
        )

    def _write_ci_gate_contract_project_module(self, framework_root: Path) -> None:
        self._write_json(
            framework_root,
            "for-demo/module.json",
            {
                "schema_version": 1,
                "module_id": "for-demo",
                "module_type": "project",
                "description": "Demo project module.",
                "last_updated": "2026-06-29",
                "project_ids": ["demo"],
                "audit_profile": "client-tooling",
                "technology_stack": ["Demo client"],
                "internal_components": ["Demo workflow"],
                "open_source_components": ["GitHub Actions"],
                "dependency_manifests": [".github/workflows/*.yml"],
                "ci_gate_contract": {
                    "platform_adaptation": {
                        "linux": "platform-adaptation / linux-ci-gate",
                        "windows": "platform-adaptation / windows-ci-gate",
                    },
                    "test_gates": {
                        "smoke": "test / smoke",
                        "golden_standard": "test / golden-standard",
                    },
                    "classified_gates": ["client / release / marketplace"],
                    "submit_readiness": "A version is submittable when `test / smoke` and `test / golden-standard` both pass.",
                    "golden_standard_suite": {
                        "manifest": "docs/specs/GOLDEN-STANDARD-TEST-SUITE.md",
                        "required_files": ["docs/specs/GOLDEN-STANDARD-TEST-SUITE.md"],
                        "required_markers": {
                            "docs/specs/GOLDEN-STANDARD-TEST-SUITE.md": [
                                "test / smoke",
                                "test / golden-standard",
                                "submit readiness",
                            ]
                        },
                    },
                    "local_gate_profile": {
                        "profile_id": "demo-extension-host-profile",
                        "manifest": "docs/specs/GOLDEN-STANDARD-TEST-SUITE.md",
                        "covered_by": "test / golden-standard",
                        "required_markers": [
                            "repo-owned adaptation",
                            "demo-extension-host-profile",
                            "extension host smoke",
                        ],
                    },
                    "industry_gate_groups": {
                        "ide / extension-quality": {
                            "covered_by": "test / golden-standard",
                            "industry_references": [
                                "VS Code extension testing",
                                "VS Code extension publishing",
                            ],
                            "required_markers": [
                                "ide / extension-quality",
                                "extension host test",
                                "packaged extension",
                                "release preflight",
                            ],
                        }
                    },
                },
                "resource_classes": [
                    {
                        "id": "workflow_gate_surface",
                        "owner": "Delivery",
                        "description": "Owns classified workflow gate names.",
                        "scope_globs": [".github/workflows/**"],
                        "copying_policy": "Workflow entries are edited directly.",
                        "concurrency_policy": "Gate names are unique.",
                        "nullability_policy": "Missing gates fail audit.",
                        "cleanup_policy": "Obsolete gates are removed.",
                        "state_machine": {
                            "source": "GitHub Actions workflows.",
                            "states": ["declared", "present"],
                            "transitions": [{"from": "declared", "to": "present", "on": "workflow job exists"}],
                            "invalid_operations": ["duplicate gate"],
                        },
                        "required_tests": ["styio-audit gate"],
                        "required_gates": ["platform-adaptation / linux-ci-gate"],
                        "audit_risks": ["missing required check"],
                    }
                ],
            },
        )

    def _write_ci_gate_contract_test_workflow(self, repo_root: Path) -> None:
        self._write_file(
            repo_root,
            ".github/workflows/tests.yml",
            "name: tests\n"
            "jobs:\n"
            "  smoke:\n"
            "    name: test / smoke\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            "      - run: true\n"
            "  golden:\n"
            "    name: test / golden-standard\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            "      - run: true\n",
        )

    def _write_ci_gate_contract_golden_manifest(self, repo_root: Path) -> None:
        self._write_file(
            repo_root,
            "docs/specs/GOLDEN-STANDARD-TEST-SUITE.md",
            "# Golden Standard Test Suite\n\n"
            "- `test / smoke` covers the fast pre-submit check.\n"
            "- `test / golden-standard` covers the full submit readiness check.\n"
            "- Local Gate Profile: repo-owned adaptation `demo-extension-host-profile` covers extension host smoke.\n"
            "- `ide / extension-quality` covers extension host test, packaged extension, and release preflight evidence.\n"
            "- Submit readiness requires both gates to pass.\n",
        )

    def _write_policy_default_module(self, framework_root: Path) -> None:
        self._write_json(
            framework_root,
            "modules/default/module.json",
            {
                "schema_version": 1,
                "module_id": "default",
                "module_type": "default",
                "description": "Common audit rules.",
                "last_updated": "2026-04-24",
                "required_audit_fields": ["**Severity:**"],
                "required_closure_fields": ["**Closure evidence:**"],
                "required_checklist_markers": ["marker"],
                "license_policy": {
                    "enabled": True,
                    "name": "Apache-2.0 policy.",
                    "license_label": "Apache-2.0",
                    "spdx_identifiers": ["Apache-2.0"],
                    "license_text_markers": ["Apache License", "Version 2.0"],
                    "target_project_ids": ["demo"],
                    "license_files": ["LICENSE"],
                    "metadata_files": ["pyproject.toml", "package.json"],
                    "notice_files": ["LICENSE-POLICY.md"],
                    "required_notice_markers": ["Apache", "License", "Version 2.0"],
                    "license_obligation": "Redistributions must preserve Apache-2.0 notices.",
                },
                "commercial_risk_policy": {
                    "enabled": True,
                    "name": "No commercial authorization dependencies.",
                    "target_project_ids": ["demo"],
                    "manifest_globs": ["package.json", "pyproject.toml"],
                    "boundary_files": ["DEPENDENCY-USAGE.md"],
                    "required_boundary_markers": ["dependency|依赖", "commercial|商业", "authorization|授权", "usage boundary|使用边界|边界"],
                    "disallowed_manifest_terms": ["commercial license", "subscription", "membership", "会员制"],
                    "source_boundary": "Dependencies must not require commercial authorization.",
                },
                "secret_scan_policy": {
                    "enabled": True,
                    "secret_classes": ["password", "token", "api_key", "private_key", "client_secret", "access_key"],
                    "max_file_bytes": 1048576,
                },
                "server_sensitive_boundary_policy": {
                    "enabled": True,
                    "name": "Server sensitive security boundary.",
                    "target_project_ids": ["demo"],
                    "server_project_markers": ["server|service|deployment"],
                    "code_globs": ["**/*.py"],
                    "ignored_path_parts": [".git", "__pycache__"],
                    "restricted_material_globs": [".env", "**/.env", "**/private/*.pem", "**/production/*.key"],
                    "allowed_material_name_markers": ["example", "test", "fixture", "fake"],
                    "required_manifest_markers": [
                        "auth|authentication|authorization|identity",
                        "privacy|pii",
                        "password",
                        "secret|token|key|credential",
                        "production|offline|private material|not committed",
                        "permission matrix|route authorization|rbac",
                        "deployment security|deployment config|tls|cors|csrf|cookie",
                        "sbom|cve|dependency vulnerability|vulnerability scan",
                        "dast|black-box|penetration|security regression",
                        "runtime secret|secret manager|kms|key rotation",
                        "rate limit|anti replay|replay protection|nonce|idempotency",
                        "log redaction|sensitive log|audit log",
                        "ssrf|egress allowlist|url allowlist|outbound request",
                        "command execution|shell injection|subprocess allowlist",
                    ],
                    "disallowed_code_categories": {
                        "auth_bypass_toggle": ["allow_anonymous=true", "skip_auth=true"],
                        "command_injection_surface": ["shell=true", "os.system("],
                        "custom_crypto": ["custom crypto"],
                        "csrf_disabled": ["csrf=false", "csrf_exempt"],
                        "cors_wildcard": ["access-control-allow-origin: *", "allow_origins=['*']"],
                        "jwt_none_algorithm": ["\"alg\":\"none\"", "\"alg\": \"none\""],
                        "disabled_verification": ["verify_signature=false", "verify_signature = false"],
                        "default_credential": ["admin:admin", "default_password"],
                        "debug_public_exposure": ["app.run(debug=true", "flask_debug=1"],
                        "insecure_cookie": ["httponly=false", "secure=false"],
                        "insecure_random_secret": ["random.random token", "math.random token"],
                        "rate_limit_disabled": ["rate_limit=false", "rate_limit=0"],
                        "ssrf_unrestricted_fetch": ["requests.get(url", "fetch(url"],
                        "weak_password_hash": ["hashlib.md5(password", "hashlib.sha1(password"],
                        "plaintext_password_storage": ["plain text password", "plaintext password"],
                    },
                    "source_boundary": "Standard implementation can be public; production secrets and dangerous auth or crypto patterns cannot.",
                },
            },
        )

    def _write_repo_hygiene_default_module(self, framework_root: Path) -> None:
        self._write_json(
            framework_root,
            "modules/default/module.json",
            {
                "schema_version": 1,
                "module_id": "default",
                "module_type": "default",
                "description": "Common audit rules.",
                "last_updated": "2026-06-29",
                "required_audit_fields": ["**Severity:**"],
                "required_closure_fields": ["**Closure evidence:**"],
                "required_checklist_markers": ["marker"],
                "repo_hygiene_policy": {
                    "enabled": True,
                    "name": "Repository hygiene.",
                    "target_project_ids": ["demo"],
                    "ignored_path_parts": [".git"],
                    "forbidden_path_globs": ["**/__pycache__/**", "**/*.tmp", "**/*.sqlite", "**/*.log"],
                    "allowed_path_globs": [],
                    "allowed_large_file_globs": [],
                    "max_file_bytes": 64,
                    "source_boundary": "Temporary files and generated data must not enter PRs.",
                },
            },
        )

    def _run_demo_gate(self, framework_root: Path, repo_root: Path, *, skip_branch_governance: bool = False):
        modules = load_stack(framework_root, "demo", repo_root)
        return gate(
            AuditContext(
                framework_root=framework_root,
                repo_root=repo_root,
                project="demo",
                modules=modules,
                skip_branch_governance=skip_branch_governance,
            )
        )

    def test_modules_validate(self) -> None:
        findings = validate_modules(load_all_modules(ROOT))
        self.assertEqual([], [finding.message for finding in findings])

    def test_project_stack_loads_default_and_project_module(self) -> None:
        stack = load_stack(ROOT, "styio-pafio", Path("/tmp/styio-pafio"))
        module_ids = [module.module_id for module in stack]
        self.assertIn("default", module_ids)
        self.assertIn("for-pafio", module_ids)
        self.assertNotIn("for-styio-view", module_ids)

    def test_current_ecosystem_repositories_load_common_and_business_modules(self) -> None:
        expected = {
            "Styio": "for-styio",
            "Pafio": "for-pafio",
            "Vityo": "for-styio-view",
            "Styio-Cloud": "for-styio-cloud",
            "styio-all-in-one": "for-styio-all-in-one",
            "styio-audit": "for-styio-audit",
            "styio-benchmark": "for-styio-benchmark",
            "styio-book": "for-styio-book",
            "styio-community": "for-styio-community",
            "styio-dev-doc": "for-styio-dev-doc",
            "styio-dev-env": "for-styio-dev-env",
            "styio-example": "for-styio-example",
            "styio-ext-vsc": "for-styio-ext-vsc",
            "styio.io": "for-styio-io",
        }
        workspace_root = ROOT.parent
        for repo_name, expected_module in expected.items():
            with self.subTest(repo_name=repo_name):
                stack = load_stack(ROOT, repo_name, workspace_root / repo_name)
                module_ids = [module.module_id for module in stack]
                self.assertEqual("default", module_ids[0])
                self.assertIn(expected_module, module_ids)

    def test_repo_hygiene_policy_rejects_junk_files_and_large_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_repo_hygiene_default_module(framework_root)
            self._write_file(repo_root, "src/main.py", "print('ok')\n")
            self._write_file(repo_root, "src/__pycache__/main.cpython-313.pyc", "bytecode\n")
            self._write_file(repo_root, "scratch/session.tmp", "temporary\n")
            self._write_file(repo_root, "data/local.sqlite", "sqlite data\n")
            self._write_file(repo_root, "docs/huge.md", "x" * 65)
            self._init_git_repo(repo_root)

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]

            self.assertTrue(any("src/__pycache__/main.cpython-313.pyc" in message for message in messages))
            self.assertTrue(any("scratch/session.tmp" in message for message in messages))
            self.assertTrue(any("data/local.sqlite" in message for message in messages))
            self.assertTrue(any("docs/huge.md is 65 bytes" in message for message in messages))

    def test_repository_module_policy_rejects_missing_business_module(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp)
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-06-29",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                    "repository_module_policy": {
                        "enabled": True,
                        "name": "Repository module coverage.",
                        "required_project_ids": ["demo"],
                    },
                },
            )

            messages = [finding.message for finding in validate_modules(load_all_modules(framework_root))]
            self.assertIn("repository module policy: required project id `demo` has no project module coverage", messages)

    def test_schema_validation_rejects_invalid_module_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp)
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-04-22",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                },
            )
            self._write_json(
                framework_root,
                "for-demo/module.json",
                {
                    "schema_version": 1,
                    "module_id": "for-demo",
                    "module_type": "bogus",
                    "description": "Broken project module.",
                    "last_updated": "2026-04-22",
                    "project_ids": ["demo"],
                    "audit_profile": "example-basic",
                },
            )
            findings = validate_modules(load_all_modules(framework_root))
            messages = [finding.message for finding in findings]
            self.assertIn("module_type must be `default` or `project`", messages)

    def test_hook_findings_normalizes_single_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp)
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-04-22",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                },
            )
            self._write_json(
                framework_root,
                "for-demo/module.json",
                {
                    "schema_version": 1,
                    "module_id": "for-demo",
                    "module_type": "project",
                    "description": "Demo module.",
                    "last_updated": "2026-04-22",
                    "project_ids": ["demo"],
                    "audit_profile": "example-basic",
                },
            )
            self._write_file(
                framework_root,
                "for-demo/checks.py",
                "from styio_audit.models import AuditFinding\n\n"
                "def run(context):\n"
                "    return AuditFinding('warning', 'single result', 'for-demo')\n",
            )
            findings = hook_findings(load_all_modules(framework_root), {"framework_root": framework_root})
            self.assertEqual(1, len(findings))
            self.assertEqual("single result", findings[0].message)
            self.assertEqual("warning", findings[0].severity)

    def test_hook_failures_are_converted_to_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp)
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-04-22",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                },
            )
            self._write_json(
                framework_root,
                "for-demo/module.json",
                {
                    "schema_version": 1,
                    "module_id": "for-demo",
                    "module_type": "project",
                    "description": "Demo module.",
                    "last_updated": "2026-04-22",
                    "project_ids": ["demo"],
                    "audit_profile": "example-basic",
                },
            )
            self._write_file(
                framework_root,
                "for-demo/checks.py",
                "def run(context):\n"
                "    raise RuntimeError('boom')\n",
            )
            findings = hook_findings(load_all_modules(framework_root), {"framework_root": framework_root})
            self.assertEqual(1, len(findings))
            self.assertIn("plugin raised RuntimeError: boom", findings[0].message)
            self.assertEqual("error", findings[0].severity)

    def test_report_command_writes_structured_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-04-22",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                },
            )
            self._write_json(
                framework_root,
                "for-demo/module.json",
                {
                    "schema_version": 1,
                    "module_id": "for-demo",
                    "module_type": "project",
                    "description": "Demo project module.",
                    "last_updated": "2026-04-22",
                    "project_ids": ["demo"],
                    "audit_profile": "example-basic",
                    "technology_stack": ["Demo runtime"],
                    "internal_components": ["Demo resource owner"],
                    "open_source_components": ["Demo OSS dependency"],
                    "dependency_manifests": ["demo.manifest"],
                    "resource_classes": [
                        {
                            "id": "demo_resource",
                            "owner": "Demo owner",
                            "description": "Demo resource class.",
                            "scope_globs": ["src/Demo/**"],
                            "copying_policy": "Copies are explicit.",
                            "concurrency_policy": "Single-writer.",
                            "nullability_policy": "Nulls are explicit.",
                            "cleanup_policy": "Resources are cleaned.",
                            "state_machine": {
                                "source": "Demo source.",
                                "states": ["idle", "ready", "done"],
                                "transitions": [
                                    {"from": "idle", "to": "ready", "on": "load"},
                                    {"from": "ready", "to": "done", "on": "finish"},
                                ],
                                "invalid_operations": ["skip cleanup"],
                            },
                            "required_tests": ["demo test"],
                            "required_gates": ["demo gate"],
                            "audit_risks": ["demo risk"],
                        }
                    ],
                },
            )
            self._write_file(repo_root, "src/Demo/file.cpp", "")
            output_path = repo_root / "audit-report.json"
            exit_code = command_report(
                argparse.Namespace(
                    framework_root=str(framework_root),
                    repo=str(repo_root),
                    project="demo",
                    output=str(output_path),
                    framework_only=False,
                    skip_branch_governance=False,
                    format="json",
                )
            )
            self.assertEqual(0, exit_code)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(1, payload["report_version"])
            self.assertEqual("styio-audit", payload["framework"]["name"])
            self.assertEqual("passed", payload["summary"]["status"])
            self.assertEqual(2, len(payload["modules"]))
            self.assertEqual("default", payload["modules"][0]["module_id"])
            self.assertEqual(["Demo runtime"], payload["modules"][1]["inventory"]["technology_stack"])
            self.assertEqual([], payload["findings"])

    def test_project_module_requires_manifest_inventory_lists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp)
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-04-24",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                    "manifest_inventory_policy": {
                        "enabled": True,
                        "required_fields": ["technology_stack", "internal_components", "open_source_components", "dependency_manifests"],
                    },
                },
            )
            self._write_json(
                framework_root,
                "for-demo/module.json",
                {
                    "schema_version": 1,
                    "module_id": "for-demo",
                    "module_type": "project",
                    "description": "Demo project module.",
                    "last_updated": "2026-04-24",
                    "project_ids": ["demo"],
                    "audit_profile": "example-basic",
                    "resource_classes": [
                        {
                            "id": "demo_resource",
                            "owner": "Demo owner",
                            "description": "Demo resource class.",
                            "scope_globs": ["src/**"],
                            "copying_policy": "Copies are explicit.",
                            "concurrency_policy": "Single-writer.",
                            "nullability_policy": "Nulls are explicit.",
                            "cleanup_policy": "Resources are cleaned.",
                            "state_machine": {
                                "source": "Demo source.",
                                "states": ["idle", "done"],
                                "transitions": [{"from": "idle", "to": "done", "on": "finish"}],
                                "invalid_operations": ["skip"],
                            },
                            "required_tests": ["demo test"],
                            "required_gates": ["demo gate"],
                            "audit_risks": ["demo risk"],
                        }
                    ],
                },
            )

            messages = [finding.message for finding in validate_modules(load_all_modules(framework_root))]
            self.assertTrue(any("`technology_stack` must be a non-empty list" in message for message in messages))
            self.assertTrue(any("`internal_components` must be a non-empty list" in message for message in messages))
            self.assertTrue(any("`open_source_components` must be a non-empty list" in message for message in messages))
            self.assertTrue(any("`dependency_manifests` must be a non-empty list" in message for message in messages))

    def test_backend_audit_profile_requires_security_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp)
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-06-29",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                },
            )
            self._write_json(
                framework_root,
                "for-demo/module.json",
                {
                    "schema_version": 1,
                    "module_id": "for-demo",
                    "module_type": "project",
                    "description": "Demo backend operations module.",
                    "last_updated": "2026-06-29",
                    "project_ids": ["demo"],
                    "audit_profile": "backend-operations",
                    "technology_stack": ["Demo backend"],
                    "internal_components": ["Demo server"],
                    "open_source_components": ["Python standard library"],
                    "dependency_manifests": ["pyproject.toml"],
                    "resource_classes": [
                        {
                            "id": "demo_backend",
                            "owner": "Backend",
                            "description": "Demo backend resource.",
                            "scope_globs": ["src/**"],
                            "copying_policy": "No secrets are copied.",
                            "concurrency_policy": "Requests are serialized in tests.",
                            "nullability_policy": "Missing config fails closed.",
                            "cleanup_policy": "Temporary state is deleted.",
                            "state_machine": {
                                "source": "Demo backend lifecycle.",
                                "states": ["idle", "running"],
                                "transitions": [{"from": "idle", "to": "running", "on": "start"}],
                                "invalid_operations": ["start without config"],
                            },
                            "required_tests": ["backend smoke test"],
                            "required_gates": ["backend gate"],
                            "audit_risks": ["missing backend boundary"],
                        }
                    ],
                },
            )

            messages = [finding.message for finding in validate_modules(load_all_modules(framework_root))]
            self.assertIn("backend-operations project module must declare non-empty security_boundaries", messages)

    def test_branch_policy_accepts_required_delivery_branches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_branch_policy_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root, branches=["release", "stable", "nightly"])

            findings = self._run_demo_gate(framework_root, repo_root)
            self.assertEqual([], [finding.message for finding in findings])

    def test_branch_policy_rejects_missing_required_delivery_branch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_branch_policy_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root, branches=["stable", "nightly"])

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("missing required branch `release`" in message for message in messages))

    def test_skip_branch_governance_suppresses_branch_policy_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_branch_policy_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root, branches=["stable", "nightly"])

            skipped = self._run_demo_gate(framework_root, repo_root, skip_branch_governance=True)
            self.assertEqual([], [finding.message for finding in skipped])

    def test_branch_policy_skips_downstream_repository_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-04-25",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                    "branch_policy": {
                        "enabled": True,
                        "target_project_ids": ["demo"],
                        "target_repository_owners": ["SymPolicy"],
                        "required_branches": ["release", "stable", "nightly"],
                    },
                },
            )
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/Unka-Malloc/demo.git")

            findings = self._run_demo_gate(framework_root, repo_root)
            self.assertEqual([], [finding.message for finding in findings])

    def test_local_audit_workflow_policy_accepts_authoritative_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_local_audit_workflow_default_module(framework_root)
            self._write_local_audit_workflow_template(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._write_file(
                repo_root,
                ".github/workflows/styio-audit.yml",
                "name: styio-audit\n\n"
                "on:\n"
                "  pull_request:\n"
                "  push:\n"
                "  merge_group:\n"
                "  workflow_dispatch:\n\n"
                "permissions:\n"
                "  contents: read\n\n"
                "jobs:\n"
                "  audit:\n"
                "    name: styio-audit\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - name: Checkout demo\n"
                "        uses: actions/checkout@v5\n"
                "        with:\n"
                "          fetch-depth: 0\n"
                "          path: demo\n"
                "      - name: Checkout released styio-audit policy\n"
                "        uses: actions/checkout@v5\n"
                "        with:\n"
                "          repository: SymPolicy/styio-audit\n"
                "          ref: stable\n"
                "          path: styio-audit\n"
                "      - name: Run released styio-audit gate\n"
                "        working-directory: demo\n"
                "        run: python3 ../styio-audit/bin/styio-audit gate --repo . --project demo\n",
            )
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/SymPolicy/demo.git")

            findings = self._run_demo_gate(framework_root, repo_root)
            self.assertEqual([], [finding.message for finding in findings])

    def test_local_audit_workflow_policy_rejects_missing_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_local_audit_workflow_default_module(framework_root)
            self._write_local_audit_workflow_template(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/SymPolicy/demo.git")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("missing `.github/workflows/styio-audit.yml`" in message for message in messages))

    def test_local_audit_workflow_policy_rejects_template_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_local_audit_workflow_default_module(framework_root)
            self._write_local_audit_workflow_template(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._write_file(
                repo_root,
                ".github/workflows/styio-audit.yml",
                "name: styio-audit\n\n"
                "on:\n"
                "  push:\n"
                "  workflow_dispatch:\n",
            )
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/SymPolicy/demo.git")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("does not match authoritative template" in message for message in messages))

    def test_local_delivery_framework_policy_accepts_required_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_local_delivery_framework_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._write_local_delivery_framework_files(repo_root)
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/SymPolicy/demo.git")

            findings = self._run_demo_gate(framework_root, repo_root)
            self.assertEqual([], [finding.message for finding in findings])

    def test_local_delivery_framework_policy_rejects_missing_ci_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_local_delivery_framework_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._write_file(repo_root, "scripts/workflow-scheduler.py", "WORKFLOW_DOCS = ()\nPROFILES = ()\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/SymPolicy/demo.git")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("missing required file `.github/workflows/styio-ci-gate.yml`" in message for message in messages))

    def test_local_delivery_framework_policy_rejects_marker_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_local_delivery_framework_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._write_file(
                repo_root,
                ".github/workflows/styio-ci-gate.yml",
                "name: styio-ci-gate\njobs:\n  ci:\n    steps:\n      - run: python3 scripts/other-gate.py\n",
            )
            self._write_file(repo_root, "scripts/workflow-scheduler.py", "WORKFLOW_DOCS = ()\nPROFILES = ()\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/SymPolicy/demo.git")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("missing required marker `workflow-scheduler.py run --profile ci-prebuild`" in message for message in messages))

    def test_ci_gate_contract_accepts_unique_classified_gates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_ci_gate_contract_default_module(framework_root)
            self._write_ci_gate_contract_project_module(framework_root)
            self._write_file(
                repo_root,
                ".github/workflows/platform-adaptation.yml",
                "name: platform-adaptation\n"
                "jobs:\n"
                "  linux:\n"
                "    name: platform-adaptation / linux-ci-gate\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n"
                "  windows:\n"
                "    name: platform-adaptation / windows-ci-gate\n"
                "    runs-on: windows-latest\n"
                "    steps:\n"
                "      - run: echo ok\n",
            )
            self._write_file(
                repo_root,
                ".github/workflows/publish.yml",
                "name: client-release\n"
                "jobs:\n"
                "  publish:\n"
                "    name: client / release / marketplace\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n",
            )
            self._write_ci_gate_contract_test_workflow(repo_root)
            self._write_ci_gate_contract_golden_manifest(repo_root)

            findings = self._run_demo_gate(framework_root, repo_root)
            self.assertEqual([], [finding.message for finding in findings])

    def test_ci_gate_contract_rejects_duplicate_platform_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_ci_gate_contract_default_module(framework_root)
            self._write_ci_gate_contract_project_module(framework_root)
            self._write_file(
                repo_root,
                ".github/workflows/platform-adaptation.yml",
                "name: platform-adaptation\n"
                "jobs:\n"
                "  linux_a:\n"
                "    name: platform-adaptation / linux-ci-gate\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n"
                "  linux_b:\n"
                "    name: platform-adaptation / linux-ci-gate\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n"
                "  windows:\n"
                "    name: platform-adaptation / windows-ci-gate\n"
                "    runs-on: windows-latest\n"
                "    steps:\n"
                "      - run: echo ok\n",
            )
            self._write_file(
                repo_root,
                ".github/workflows/publish.yml",
                "name: client-release\n"
                "jobs:\n"
                "  publish:\n"
                "    name: client / release / marketplace\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n",
            )
            self._write_ci_gate_contract_test_workflow(repo_root)
            self._write_ci_gate_contract_golden_manifest(repo_root)

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(
                any("platform `linux` must have exactly one gate named `platform-adaptation / linux-ci-gate`; found 2" in message for message in messages)
            )

    def test_ci_gate_contract_rejects_runner_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_ci_gate_contract_default_module(framework_root)
            self._write_ci_gate_contract_project_module(framework_root)
            self._write_file(
                repo_root,
                ".github/workflows/platform-adaptation.yml",
                "name: platform-adaptation\n"
                "jobs:\n"
                "  linux:\n"
                "    name: platform-adaptation / linux-ci-gate\n"
                "    runs-on: windows-latest\n"
                "    steps:\n"
                "      - run: echo ok\n"
                "  windows:\n"
                "    name: platform-adaptation / windows-ci-gate\n"
                "    runs-on: windows-latest\n"
                "    steps:\n"
                "      - run: echo ok\n",
            )
            self._write_file(
                repo_root,
                ".github/workflows/publish.yml",
                "name: client-release\n"
                "jobs:\n"
                "  publish:\n"
                "    name: client / release / marketplace\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n",
            )
            self._write_ci_gate_contract_test_workflow(repo_root)
            self._write_ci_gate_contract_golden_manifest(repo_root)

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("does not match platform `linux`" in message for message in messages))

    def test_ci_gate_contract_rejects_missing_golden_standard_test_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_ci_gate_contract_default_module(framework_root)
            self._write_ci_gate_contract_project_module(framework_root)
            self._write_file(
                repo_root,
                ".github/workflows/platform-adaptation.yml",
                "name: platform-adaptation\n"
                "jobs:\n"
                "  linux:\n"
                "    name: platform-adaptation / linux-ci-gate\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n"
                "  windows:\n"
                "    name: platform-adaptation / windows-ci-gate\n"
                "    runs-on: windows-latest\n"
                "    steps:\n"
                "      - run: echo ok\n",
            )
            self._write_file(
                repo_root,
                ".github/workflows/tests.yml",
                "name: tests\n"
                "jobs:\n"
                "  smoke:\n"
                "    name: test / smoke\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n",
            )
            self._write_file(
                repo_root,
                ".github/workflows/publish.yml",
                "name: client-release\n"
                "jobs:\n"
                "  publish:\n"
                "    name: client / release / marketplace\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n",
            )
            self._write_ci_gate_contract_golden_manifest(repo_root)

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("test gate `golden_standard` must appear exactly once as `test / golden-standard`; found 0" in message for message in messages))

    def test_ci_gate_contract_rejects_missing_golden_suite_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_ci_gate_contract_default_module(framework_root)
            self._write_ci_gate_contract_project_module(framework_root)
            self._write_file(
                repo_root,
                ".github/workflows/platform-adaptation.yml",
                "name: platform-adaptation\n"
                "jobs:\n"
                "  linux:\n"
                "    name: platform-adaptation / linux-ci-gate\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n"
                "  windows:\n"
                "    name: platform-adaptation / windows-ci-gate\n"
                "    runs-on: windows-latest\n"
                "    steps:\n"
                "      - run: echo ok\n",
            )
            self._write_file(
                repo_root,
                ".github/workflows/publish.yml",
                "name: client-release\n"
                "jobs:\n"
                "  publish:\n"
                "    name: client / release / marketplace\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n",
            )
            self._write_ci_gate_contract_test_workflow(repo_root)

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(
                any("golden standard suite requires `docs/specs/GOLDEN-STANDARD-TEST-SUITE.md`" in message for message in messages)
            )

    def test_ci_gate_contract_rejects_golden_suite_manifest_missing_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_ci_gate_contract_default_module(framework_root)
            self._write_ci_gate_contract_project_module(framework_root)
            self._write_file(
                repo_root,
                ".github/workflows/platform-adaptation.yml",
                "name: platform-adaptation\n"
                "jobs:\n"
                "  linux:\n"
                "    name: platform-adaptation / linux-ci-gate\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n"
                "  windows:\n"
                "    name: platform-adaptation / windows-ci-gate\n"
                "    runs-on: windows-latest\n"
                "    steps:\n"
                "      - run: echo ok\n",
            )
            self._write_file(
                repo_root,
                ".github/workflows/publish.yml",
                "name: client-release\n"
                "jobs:\n"
                "  publish:\n"
                "    name: client / release / marketplace\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n",
            )
            self._write_ci_gate_contract_test_workflow(repo_root)
            self._write_file(repo_root, "docs/specs/GOLDEN-STANDARD-TEST-SUITE.md", "# Golden\n\n`test / smoke`\n")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(
                any(
                    "golden standard suite `docs/specs/GOLDEN-STANDARD-TEST-SUITE.md` missing required marker `test / golden-standard`"
                    in message
                    for message in messages
                )
            )

    def test_ci_gate_contract_rejects_industry_group_missing_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_ci_gate_contract_default_module(framework_root)
            self._write_ci_gate_contract_project_module(framework_root)
            self._write_file(
                repo_root,
                ".github/workflows/platform-adaptation.yml",
                "name: platform-adaptation\n"
                "jobs:\n"
                "  linux:\n"
                "    name: platform-adaptation / linux-ci-gate\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n"
                "  windows:\n"
                "    name: platform-adaptation / windows-ci-gate\n"
                "    runs-on: windows-latest\n"
                "    steps:\n"
                "      - run: echo ok\n",
            )
            self._write_file(
                repo_root,
                ".github/workflows/publish.yml",
                "name: client-release\n"
                "jobs:\n"
                "  publish:\n"
                "    name: client / release / marketplace\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n",
            )
            self._write_ci_gate_contract_test_workflow(repo_root)
            self._write_file(
                repo_root,
                "docs/specs/GOLDEN-STANDARD-TEST-SUITE.md",
                "# Golden Standard Test Suite\n\n"
                "- `test / smoke` covers the fast pre-submit check.\n"
                "- `test / golden-standard` covers the full submit readiness check.\n"
                "- `ide / extension-quality` covers extension host test and packaged extension evidence.\n"
                "- Submit readiness requires both gates to pass.\n",
            )

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]

            self.assertTrue(
                any(
                    "industry gate group `ide / extension-quality` missing required marker `release preflight`"
                    in message
                    for message in messages
                )
            )

    def test_ci_gate_contract_rejects_local_gate_profile_missing_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "demo"
            repo_root.mkdir()
            self._write_ci_gate_contract_default_module(framework_root)
            self._write_ci_gate_contract_project_module(framework_root)
            self._write_file(
                repo_root,
                ".github/workflows/platform-adaptation.yml",
                "name: platform-adaptation\n"
                "jobs:\n"
                "  linux:\n"
                "    name: platform-adaptation / linux-ci-gate\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n"
                "  windows:\n"
                "    name: platform-adaptation / windows-ci-gate\n"
                "    runs-on: windows-latest\n"
                "    steps:\n"
                "      - run: echo ok\n",
            )
            self._write_file(
                repo_root,
                ".github/workflows/publish.yml",
                "name: client-release\n"
                "jobs:\n"
                "  publish:\n"
                "    name: client / release / marketplace\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n",
            )
            self._write_ci_gate_contract_test_workflow(repo_root)
            self._write_file(
                repo_root,
                "docs/specs/GOLDEN-STANDARD-TEST-SUITE.md",
                "# Golden Standard Test Suite\n\n"
                "- `test / smoke` covers the fast pre-submit check.\n"
                "- `test / golden-standard` covers the full submit readiness check.\n"
                "- Local Gate Profile: `demo-extension-host-profile` covers extension host smoke.\n"
                "- `ide / extension-quality` covers extension host test, packaged extension, and release preflight evidence.\n"
                "- Submit readiness requires both gates to pass.\n",
            )

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]

            self.assertTrue(
                any(
                    "local gate profile `docs/specs/GOLDEN-STANDARD-TEST-SUITE.md` missing required marker `repo-owned adaptation`"
                    in message
                    for message in messages
                )
            )

    def test_downstream_branch_flow_allows_feature_to_nightly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_downstream_flow_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/Unka-Malloc/demo.git")

            env = {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_BASE_REF": "nightly",
                "GITHUB_HEAD_REF": "feature/demo",
            }
            with patch.dict(os.environ, env, clear=False):
                findings = self._run_demo_gate(framework_root, repo_root)
            self.assertEqual([], [finding.message for finding in findings])

    def test_downstream_branch_flow_allows_version_promotion_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_downstream_flow_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/Unka-Malloc/demo.git")

            for head, base in (("nightly", "stable"), ("stable", "release")):
                env = {
                    "GITHUB_EVENT_NAME": "pull_request",
                    "GITHUB_BASE_REF": base,
                    "GITHUB_HEAD_REF": head,
                }
                with patch.dict(os.environ, env, clear=False):
                    findings = self._run_demo_gate(framework_root, repo_root)
                self.assertEqual([], [finding.message for finding in findings])

    def test_downstream_branch_flow_rejects_feature_to_stable_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_downstream_flow_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/Unka-Malloc/demo.git")

            env = {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_BASE_REF": "stable",
                "GITHUB_HEAD_REF": "feature/demo",
            }
            with patch.dict(os.environ, env, clear=False):
                messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("`stable` only accepts pull requests from `nightly`" in message for message in messages))

    def test_downstream_branch_flow_rejects_cross_lane_merge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_downstream_flow_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/Unka-Malloc/demo.git")

            env = {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_BASE_REF": "release",
                "GITHUB_HEAD_REF": "nightly",
            }
            with patch.dict(os.environ, env, clear=False):
                messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("`nightly` can only merge into `stable`, not `release`" in message for message in messages))

    def test_downstream_branch_flow_rejects_feature_to_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_downstream_flow_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/Unka-Malloc/demo.git")

            env = {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_BASE_REF": "release",
                "GITHUB_HEAD_REF": "feature/demo",
            }
            with patch.dict(os.environ, env, clear=False):
                messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("`release` only accepts pull requests from `stable`" in message for message in messages))

    def test_upstream_branch_flow_accepts_feature_to_integration_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_upstream_flow_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/SymPolicy/demo.git")

            env = {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_BASE_REF": "nightly",
                "GITHUB_HEAD_REF": "feature/demo",
            }
            with patch.dict(os.environ, env, clear=False):
                findings = self._run_demo_gate(framework_root, repo_root)
            self.assertEqual([], [finding.message for finding in findings])

    def test_upstream_branch_flow_rejects_feature_to_stable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_upstream_flow_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/SymPolicy/demo.git")

            env = {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_BASE_REF": "stable",
                "GITHUB_HEAD_REF": "feature/demo",
            }
            with patch.dict(os.environ, env, clear=False):
                messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("`stable` only accepts pull requests from `nightly`" in message for message in messages))

    def test_upstream_branch_flow_rejects_feature_to_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_upstream_flow_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/SymPolicy/demo.git")

            env = {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_BASE_REF": "release",
                "GITHUB_HEAD_REF": "feature/demo",
            }
            with patch.dict(os.environ, env, clear=False):
                messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("`release` only accepts pull requests from `stable`" in message for message in messages))

    def test_skip_branch_governance_suppresses_upstream_flow_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_upstream_flow_default_module(framework_root)
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "src/demo.txt", "demo\n")
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/SymPolicy/demo.git")

            env = {
                "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_BASE_REF": "release",
                "GITHUB_HEAD_REF": "feature/demo",
            }
            with patch.dict(os.environ, env, clear=False):
                skipped = self._run_demo_gate(framework_root, repo_root, skip_branch_governance=True)
            self.assertEqual([], [finding.message for finding in skipped])

    def test_license_and_commercial_policies_accept_valid_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_policy_default_module(framework_root)
            self._write_file(repo_root, "LICENSE", "Apache License\nVersion 2.0\n")
            self._write_file(
                repo_root,
                "LICENSE-POLICY.md",
                "Apache License Version 2.0 source distributions must preserve copyright, NOTICE, modification, and patent notices.\n",
            )
            self._write_json(
                repo_root,
                "package.json",
                {
                    "license": "Apache-2.0",
                    "dependencies": {
                        "left-pad": "1.3.0",
                    },
                },
            )
            self._write_file(
                repo_root,
                "DEPENDENCY-USAGE.md",
                "left-pad dependency usage boundary: no commercial authorization, no subscription, and no membership terms.\n",
            )

            findings = self._run_demo_gate(framework_root, repo_root)
            self.assertEqual([], [finding.message for finding in findings])

    def test_license_policy_rejects_non_apache_and_missing_notice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_policy_default_module(framework_root)
            self._write_file(repo_root, "LICENSE", "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n")
            self._write_file(repo_root, "LICENSE-POLICY.md", "Apache source policy without the required version marker.\n")
            self._write_json(repo_root, "package.json", {"license": "GPL-3.0-or-later"})
            self._write_file(repo_root, "DEPENDENCY-USAGE.md", "dependency usage boundary commercial authorization evidence.\n")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("does not declare Apache-2.0" in message for message in messages))
            self.assertTrue(any("license metadata must be Apache-2.0" in message for message in messages))
            self.assertTrue(any("missing Apache-2.0 source-distribution notice" in message for message in messages))

    def test_license_and_commercial_policies_skip_non_target_repository_owner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_policy_default_module(framework_root)
            module_path = framework_root / "modules/default/module.json"
            module = json.loads(module_path.read_text(encoding="utf-8"))
            module["license_policy"]["target_repository_owners"] = ["SymPolicy"]
            module["commercial_risk_policy"]["target_repository_owners"] = ["SymPolicy"]
            module_path.write_text(json.dumps(module, indent=2, sort_keys=True), encoding="utf-8")
            self._write_file(repo_root, "LICENSE", "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n")
            self._write_json(repo_root, "package.json", {"license": "GPL-3.0-or-later"})
            self._init_git_repo(repo_root)
            self._set_origin(repo_root, "https://github.com/Unka-Malloc/demo.git")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]

            self.assertFalse(any("license policy:" in message for message in messages))
            self.assertFalse(any("commercial risk policy:" in message for message in messages))

    def test_commercial_risk_policy_rejects_disallowed_terms_and_missing_dependency_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_policy_default_module(framework_root)
            self._write_file(repo_root, "LICENSE", "Apache License\nVersion 2.0\n")
            self._write_file(
                repo_root,
                "LICENSE-POLICY.md",
                "Apache License Version 2.0 source distributions must preserve copyright, NOTICE, modification, and patent notices.\n",
            )
            self._write_json(
                repo_root,
                "package.json",
                {
                    "license": "Apache-2.0",
                    "description": "Requires a commercial license for production use.",
                    "dependencies": {
                        "paid-widget": "2.0.0",
                    },
                },
            )
            self._write_file(repo_root, "DEPENDENCY-USAGE.md", "dependency usage boundary commercial authorization evidence.\n")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("disallowed commercial-risk term" in message for message in messages))
            self.assertTrue(any("dependency `paid-widget`" in message for message in messages))

    def test_server_sensitive_boundary_policy_allows_standard_open_implementation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_policy_default_module(framework_root)
            self._write_json(
                framework_root,
                "for-demo/module.json",
                {
                    "schema_version": 1,
                    "module_id": "for-demo",
                    "module_type": "project",
                    "description": "Demo server deployment module.",
                    "last_updated": "2026-04-24",
                    "project_ids": ["demo"],
                    "audit_profile": "backend-operations",
                    "technology_stack": ["Python server deployment service"],
                    "internal_components": ["Server authentication handler"],
                    "open_source_components": ["Python standard library"],
                    "dependency_manifests": ["package.json"],
                    "security_boundaries": [
                        "Authentication and authorization implementation can be public when it uses documented standard protocol behavior.",
                        "Privacy and PII payloads must not be committed in source, examples, or logs.",
                        "Password storage uses documented KDF behavior or is declared as not storing production passwords.",
                        "Secret, token, key, and credential material must stay private.",
                        "Production private material is offline or not committed to GitHub.",
                        "Permission matrix and route authorization behavior are covered by regression tests.",
                        "Deployment security config covers TLS, CORS, CSRF, cookie, and debug exposure boundaries.",
                        "SBOM and CVE dependency vulnerability scan evidence is required for release gates.",
                        "DAST black-box penetration security regression runs against deployed service surfaces.",
                        "Runtime secret manager or KMS key rotation owns production secret delivery.",
                        "Rate limit, anti replay nonce, and idempotency boundaries are documented for externally reachable routes.",
                        "Log redaction and audit log rules prevent sensitive request data from being written to logs.",
                        "SSRF egress allowlist and URL allowlist boundaries cover outbound request helpers.",
                        "Command execution uses subprocess allowlist boundaries and rejects shell injection surfaces.",
                    ],
                    "resource_classes": [
                        {
                            "id": "server_auth",
                            "owner": "Server",
                            "description": "Owns service login and password storage.",
                            "scope_globs": ["src/server/**"],
                            "copying_policy": "No production secrets in public source.",
                            "concurrency_policy": "Single process.",
                            "nullability_policy": "Missing users fail closed.",
                            "cleanup_policy": "No retained state.",
                            "state_machine": {
                                "source": "Demo service.",
                                "states": ["offline", "running", "failed"],
                                "transitions": [{"from": "offline", "to": "running", "on": "start"}],
                                "invalid_operations": ["publish auth code"],
                            },
                            "required_tests": ["auth boundary test"],
                            "required_gates": ["secret scan gate"],
                            "audit_risks": ["production secret leakage"],
                        }
                    ],
                },
            )
            self._write_file(repo_root, "LICENSE", "Apache License\nVersion 2.0\n")
            self._write_file(
                repo_root,
                "LICENSE-POLICY.md",
                "Apache License Version 2.0 source distributions must preserve copyright, NOTICE, modification, and patent notices.\n",
            )
            self._write_json(repo_root, "package.json", {"license": "Apache-2.0"})
            self._write_file(repo_root, "DEPENDENCY-USAGE.md", "dependency usage boundary commercial authorization evidence.\n")
            self._write_file(
                repo_root,
                "src/server/auth.py",
                "def hash_password(value):\n"
                "    return argon2.hash(value)\n\n"
                "def generate_key_directory(path):\n"
                "    return path\n",
            )

            findings = self._run_demo_gate(framework_root, repo_root)
            self.assertEqual([], [finding.message for finding in findings])

    def test_server_sensitive_boundary_policy_rejects_dangerous_patterns_and_secret_material(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_policy_default_module(framework_root)
            self._write_json(
                framework_root,
                "for-demo/module.json",
                {
                    "schema_version": 1,
                    "module_id": "for-demo",
                    "module_type": "project",
                    "description": "Demo server deployment module.",
                    "last_updated": "2026-04-24",
                    "project_ids": ["demo"],
                    "audit_profile": "backend-operations",
                    "technology_stack": ["Python server deployment service"],
                    "internal_components": ["Server authentication handler"],
                    "open_source_components": ["Python standard library"],
                    "dependency_manifests": ["package.json"],
                    "security_boundaries": [
                        "Authentication and authorization implementation can be public when it uses documented standard protocol behavior.",
                        "Privacy and PII payloads must not be committed in source, examples, or logs.",
                        "Password storage uses documented KDF behavior or is declared as not storing production passwords.",
                        "Secret, token, key, and credential material must stay private.",
                        "Production private material is offline or not committed to GitHub.",
                        "Permission matrix and route authorization behavior are covered by regression tests.",
                        "Deployment security config covers TLS, CORS, CSRF, cookie, and debug exposure boundaries.",
                        "SBOM and CVE dependency vulnerability scan evidence is required for release gates.",
                        "DAST black-box penetration security regression runs against deployed service surfaces.",
                        "Runtime secret manager or KMS key rotation owns production secret delivery.",
                        "Rate limit, anti replay nonce, and idempotency boundaries are documented for externally reachable routes.",
                        "Log redaction and audit log rules prevent sensitive request data from being written to logs.",
                        "SSRF egress allowlist and URL allowlist boundaries cover outbound request helpers.",
                        "Command execution uses subprocess allowlist boundaries and rejects shell injection surfaces.",
                    ],
                    "resource_classes": [
                        {
                            "id": "server_auth",
                            "owner": "Server",
                            "description": "Owns service authentication.",
                            "scope_globs": ["src/server/**"],
                            "copying_policy": "No production secrets in public source.",
                            "concurrency_policy": "Single process.",
                            "nullability_policy": "Missing users fail closed.",
                            "cleanup_policy": "No retained state.",
                            "state_machine": {
                                "source": "Demo service.",
                                "states": ["offline", "running", "failed"],
                                "transitions": [{"from": "offline", "to": "running", "on": "start"}],
                                "invalid_operations": ["skip signature verification"],
                            },
                            "required_tests": ["auth boundary test"],
                            "required_gates": ["secret scan gate"],
                            "audit_risks": ["production secret leakage"],
                        }
                    ],
                },
            )
            self._write_file(repo_root, "LICENSE", "Apache License\nVersion 2.0\n")
            self._write_file(
                repo_root,
                "LICENSE-POLICY.md",
                "Apache License Version 2.0 source distributions must preserve copyright, NOTICE, modification, and patent notices.\n",
            )
            self._write_json(repo_root, "package.json", {"license": "Apache-2.0"})
            self._write_file(repo_root, "DEPENDENCY-USAGE.md", "dependency usage boundary commercial authorization evidence.\n")
            self._write_file(
                repo_root,
                "src/server/auth.py",
                "import hashlib\n"
                "allow_anonymous=True\n"
                "Access-Control-Allow-Origin: *\n"
                "csrf_exempt\n"
                "httponly=False\n"
                "default_password = 'password'\n"
                "flask_debug=1\n"
                "rate_limit=False\n"
                "JWT_HEADER = '{\"alg\":\"none\"}'\n"
                "verify_signature=False\n"
                "def hash_password(password):\n"
                "    return hashlib.md5(password.encode()).hexdigest()\n",
            )
            self._write_file(
                repo_root,
                "src/server/egress.py",
                "import os\n"
                "import requests\n"
                "def run(cmd, url):\n"
                "    os.system(cmd)\n"
                "    return requests.get(url)\n",
            )
            self._write_file(repo_root, "secrets/private/service.pem", "example private key path\n")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("server sensitive-boundary policy" in message for message in messages))
            self.assertTrue(any("auth_bypass_toggle" in message for message in messages))
            self.assertTrue(any("command_injection_surface" in message for message in messages))
            self.assertTrue(any("cors_wildcard" in message for message in messages))
            self.assertTrue(any("csrf_disabled" in message for message in messages))
            self.assertTrue(any("default_credential" in message for message in messages))
            self.assertTrue(any("debug_public_exposure" in message for message in messages))
            self.assertTrue(any("insecure_cookie" in message for message in messages))
            self.assertTrue(any("jwt_none_algorithm" in message for message in messages))
            self.assertTrue(any("disabled_verification" in message for message in messages))
            self.assertTrue(any("rate_limit_disabled" in message for message in messages))
            self.assertTrue(any("ssrf_unrestricted_fetch" in message for message in messages))
            self.assertTrue(any("weak_password_hash" in message for message in messages))
            self.assertTrue(any("deployable secret material" in message for message in messages))

    def test_server_sensitive_boundary_policy_rejects_missing_manifest_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_policy_default_module(framework_root)
            self._write_json(
                framework_root,
                "for-demo/module.json",
                {
                    "schema_version": 1,
                    "module_id": "for-demo",
                    "module_type": "project",
                    "description": "Demo server deployment module.",
                    "last_updated": "2026-04-24",
                    "project_ids": ["demo"],
                    "audit_profile": "backend-operations",
                    "technology_stack": ["Python server deployment service"],
                    "internal_components": ["Server authentication handler"],
                    "open_source_components": ["Python standard library"],
                    "dependency_manifests": ["package.json"],
                    "resource_classes": [
                        {
                            "id": "server_auth",
                            "owner": "Server",
                            "description": "Owns service authentication.",
                            "scope_globs": ["src/server/**"],
                            "copying_policy": "No production secrets in public source.",
                            "concurrency_policy": "Single process.",
                            "nullability_policy": "Missing users fail closed.",
                            "cleanup_policy": "No retained state.",
                            "state_machine": {
                                "source": "Demo service.",
                                "states": ["offline", "running", "failed"],
                                "transitions": [{"from": "offline", "to": "running", "on": "start"}],
                                "invalid_operations": ["undocumented security boundary"],
                            },
                            "required_tests": ["auth boundary test"],
                            "required_gates": ["secret scan gate"],
                            "audit_risks": ["production secret leakage"],
                        }
                    ],
                },
            )
            self._write_file(repo_root, "LICENSE", "Apache License\nVersion 2.0\n")
            self._write_file(
                repo_root,
                "LICENSE-POLICY.md",
                "Apache License Version 2.0 source distributions must preserve copyright, NOTICE, modification, and patent notices.\n",
            )
            self._write_json(repo_root, "package.json", {"license": "Apache-2.0"})
            self._write_file(repo_root, "DEPENDENCY-USAGE.md", "dependency usage boundary commercial authorization evidence.\n")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("project manifest inventory missing security-boundary marker" in message for message in messages))

    def test_server_sensitive_boundary_policy_ignores_non_server_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_policy_default_module(framework_root)
            self._write_json(
                framework_root,
                "for-demo/module.json",
                {
                    "schema_version": 1,
                    "module_id": "for-demo",
                    "module_type": "project",
                    "description": "Demo local command module.",
                    "last_updated": "2026-04-24",
                    "project_ids": ["demo"],
                    "audit_profile": "example-basic",
                    "technology_stack": ["Local CLI utility"],
                    "internal_components": ["Local command parser"],
                    "open_source_components": ["Python standard library"],
                    "dependency_manifests": ["package.json"],
                    "resource_classes": [
                        {
                            "id": "local_cli",
                            "owner": "CLI",
                            "description": "Owns local-only command dispatch.",
                            "scope_globs": ["src/local/**"],
                            "copying_policy": "No large copies.",
                            "concurrency_policy": "Single process.",
                            "nullability_policy": "Missing args fail.",
                            "cleanup_policy": "No retained state.",
                            "state_machine": {
                                "source": "Demo CLI.",
                                "states": ["idle", "done"],
                                "transitions": [{"from": "idle", "to": "done", "on": "run"}],
                                "invalid_operations": ["skip args"],
                            },
                            "required_tests": ["cli test"],
                            "required_gates": ["cli gate"],
                            "audit_risks": ["bad args"],
                        }
                    ],
                },
            )
            self._write_file(repo_root, "LICENSE", "Apache License\nVersion 2.0\n")
            self._write_file(
                repo_root,
                "LICENSE-POLICY.md",
                "Apache License Version 2.0 source distributions must preserve copyright, NOTICE, modification, and patent notices.\n",
            )
            self._write_json(repo_root, "package.json", {"license": "Apache-2.0"})
            self._write_file(repo_root, "DEPENDENCY-USAGE.md", "dependency usage boundary commercial authorization evidence.\n")
            self._write_file(repo_root, "src/local/tool.py", "def hash_password(value):\n    return value\n")

            findings = self._run_demo_gate(framework_root, repo_root)
            self.assertEqual([], [finding.message for finding in findings])

    def test_secret_scanner_redacts_token_findings(self) -> None:
        token = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890ABCD"
        findings = scan_text(f"token = '{token}'\n", path="config.env")
        self.assertEqual(1, len(findings))
        self.assertEqual("github-token", findings[0].rule_id)
        self.assertTrue(findings[0].fingerprint.startswith("sha256:"))
        self.assertNotIn(token, findings[0].to_dict().values())

    def test_secret_scanner_ignores_placeholders_and_code_references(self) -> None:
        findings = scan_text(
            "secret: process.env.LICOLITE_SIGNING_SECRET\n"
            "$apiKey = $env:DEEPSEEK_API_KEY\n"
            "token: current.customHttpAdapter.token\n"
            "header = \"X-Pafio-Write-Token: dev-token\"\n"
            "secret: \"base64-encoded-secret\"\n"
            "for (const auto& token : snapshot->syntax.tokens) {\n",
            path="examples.md",
        )
        self.assertEqual([], [finding.to_dict() for finding in findings])

    def test_secret_scan_policy_wildcard_applies_to_any_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            token = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890ABCD"
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-06-29",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                    "secret_scan_policy": {
                        "enabled": True,
                        "target_project_ids": ["*"],
                        "secret_classes": ["password", "token", "api_key", "private_key", "client_secret", "access_key"],
                        "max_file_bytes": 1048576,
                    },
                },
            )
            self._write_demo_project_module(framework_root)
            self._write_file(repo_root, "docs/guide.md", f"token = '{token}'\n")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("secret scan: docs/guide.md" in message for message in messages))

    def test_ip_exposure_policy_allows_loopback_and_rejects_other_ips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            public_ip = "8.8" + ".4.4"
            documentation_ip = "203.0" + ".113.9"
            unspecified_ipv6 = "[" + "::" + "]"
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-06-29",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                    "ip_exposure_policy": {
                        "enabled": True,
                        "target_project_ids": ["demo"],
                        "allow_loopback": True,
                        "max_file_bytes": 1048576,
                    },
                },
            )
            self._write_file(
                repo_root,
                "README.md",
                "Local examples may use http://127.0.0.1:8080 and http://[::1]:8080.\n"
                f"Documentation examples may use {documentation_ip}.\n"
                f"External service address {public_ip} must not be committed.\n",
            )
            self._write_file(repo_root, "nginx.conf", f"listen {unspecified_ipv6}:80;\n")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any(public_ip in message for message in messages))
            self.assertFalse(any(documentation_ip in message for message in messages))
            self.assertFalse(any("nginx.conf" in message and "::" in message for message in messages))
            self.assertFalse(any("127.0.0.1" in message for message in messages))
            self.assertFalse(any("::1" in message for message in messages))

    def test_ip_exposure_policy_scopes_github_pages_dns_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pages_ipv4 = "185.199.108" + ".153"
            pages_ipv6 = "2606:50c0:8000:" + ":153"
            unrelated_ip = "8.8" + ".8.8"
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-06-29",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                    "ip_exposure_policy": {
                        "enabled": True,
                        "target_project_ids": ["demo"],
                        "allow_loopback": True,
                        "allowed_service_ip_occurrences": [
                            {
                                "service": "github-pages-apex-dns",
                                "reason": "GitHub Pages apex DNS records.",
                                "ips": [pages_ipv4, pages_ipv6],
                                "path_globs": ["docs/dns-and-pages.html"],
                            }
                        ],
                    },
                },
            )
            self._write_file(
                repo_root,
                "docs/dns-and-pages.html",
                f"GitHub Pages apex A {pages_ipv4} and AAAA {pages_ipv6} are documented here.\n"
                f"Unrelated DNS {unrelated_ip} still fails.\n",
            )
            self._write_file(repo_root, "src/app.txt", f"Hard-coded GitHub Pages IP {pages_ipv4} outside DNS docs.\n")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any(unrelated_ip in message and "docs/dns-and-pages.html" in message for message in messages))
            self.assertTrue(any(pages_ipv4 in message and "src/app.txt" in message for message in messages))
            self.assertFalse(any(pages_ipv6 in message for message in messages))

    def test_ip_exposure_policy_ignores_svg_path_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-06-29",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                    "ip_exposure_policy": {
                        "enabled": True,
                        "target_project_ids": ["demo"],
                        "allow_loopback": True,
                    },
                },
            )
            svg_decimal_run = "1.9" + ".95.95"
            self._write_file(
                repo_root,
                "src/Icon.tsx",
                f'export const Icon = () => <path d="M8 1.8a6.2 6.2 0 1 0 0 12.4A6.2 6.2 0 0 0 8 1.8zm0 6a.95.95 0 1 0 0 {svg_decimal_run} 0 0 0 0-1.9z" />;\n',
            )

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertFalse(any(svg_decimal_run in message for message in messages))

    def test_ip_exposure_policy_ignores_language_namespace_separator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-06-29",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                    "ip_exposure_policy": {
                        "enabled": True,
                        "target_project_ids": ["demo"],
                        "allow_loopback": True,
                    },
                },
            )
            namespace_separator = ":" + ":"
            self._write_file(repo_root, "src/main.cpp", f'unit_id += "{namespace_separator}";\n')

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertFalse(any("src/main.cpp" in message for message in messages))

    def test_public_infrastructure_exposure_policy_allows_placeholders_and_public_docs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-06-29",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                    "public_infrastructure_exposure_policy": {
                        "enabled": True,
                        "name": "Public infrastructure boundary.",
                        "target_project_ids": ["demo"],
                        "target_repository_owners": [],
                        "scan_globs": ["**/*.md", "**/*.toml", "**/*.yml"],
                        "restricted_path_globs": ["**/*kubeconfig*"],
                        "allowed_placeholder_markers": ["example", "sample", "template", "localhost"],
                        "allowed_host_suffixes": ["example.invalid", "github.com", "localhost"],
                        "disallowed_host_markers": ["admin", "prod", "internal", "db"],
                        "disallowed_dsn_schemes": ["postgres", "redis"],
                        "cloud_resource_markers": ["arn:aws:", "s3://"],
                    },
                },
            )
            self._write_file(
                repo_root,
                "docs/guide.md",
                "Public examples may use https://api.example.invalid and https://github.com/SymPolicy/Styio.\n"
                "Local examples may use redis://localhost/cache.\n"
                "Language syntax examples may use redis://... as a placeholder.\n",
            )
            self._write_file(
                repo_root,
                "configs/sample-kubeconfig.yml",
                "apiVersion: v1\nclusters: []\nusers: []\ncurrent-context: sample\n",
            )

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertFalse(any("public infrastructure exposure" in message for message in messages))

    def test_public_infrastructure_exposure_policy_rejects_ops_material(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-06-29",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                    "public_infrastructure_exposure_policy": {
                        "enabled": True,
                        "name": "Public infrastructure boundary.",
                        "target_project_ids": ["demo"],
                        "target_repository_owners": [],
                        "scan_globs": ["**/*.md", "**/*.sh", "**/*.yml"],
                        "restricted_path_globs": ["**/*kubeconfig*", "**/ops/**", "**/prod/**"],
                        "allowed_placeholder_markers": ["example", "sample", "template", "localhost"],
                        "allowed_host_suffixes": ["example.invalid", "github.com", "localhost"],
                        "disallowed_host_markers": ["admin", "prod", "internal", "db"],
                        "disallowed_dsn_schemes": ["postgres", "redis"],
                        "cloud_resource_markers": ["arn:aws:", "s3://"],
                    },
                },
            )
            self._write_file(
                repo_root,
                "docs/runbook.md",
                "Production console: https://admin.prod.styio.io\n"
                "Database DSN: postgres://styio:secret@db.internal:5432/styio\n",
            )
            self._write_file(
                repo_root,
                "scripts/deploy.sh",
                "aws_role=arn:aws:iam::123456789012:role/styio-prod\n"
                "bucket=s3://styio-prod-private-config\n",
            )
            self._write_file(
                repo_root,
                "ops/prod/kubeconfig.yml",
                "apiVersion: v1\nclusters: []\nusers: []\ncurrent-context: production\n",
            )

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertTrue(any("operational URL host" in message for message in messages))
            self.assertTrue(any("service DSN" in message for message in messages))
            self.assertTrue(any("cloud resource marker" in message for message in messages))
            self.assertTrue(any("restricted infrastructure path policy" in message for message in messages))
            self.assertTrue(any("looks like a kubeconfig" in message for message in messages))

    def test_public_infrastructure_exposure_policy_ignores_non_target_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_json(
                framework_root,
                "modules/default/module.json",
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-06-29",
                    "required_audit_fields": ["**Severity:**"],
                    "required_closure_fields": ["**Closure evidence:**"],
                    "required_checklist_markers": ["marker"],
                    "public_infrastructure_exposure_policy": {
                        "enabled": True,
                        "name": "Public infrastructure boundary.",
                        "target_project_ids": ["styio"],
                        "target_repository_owners": [],
                        "scan_globs": ["**/*.md"],
                        "disallowed_host_markers": ["admin", "prod"],
                    },
                },
            )
            self._write_file(repo_root, "docs/runbook.md", "Production console: https://admin.prod.styio.io\n")

            messages = [finding.message for finding in self._run_demo_gate(framework_root, repo_root)]
            self.assertFalse(any("public infrastructure exposure" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
