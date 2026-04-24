from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

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

    def _run_demo_gate(self, framework_root: Path, repo_root: Path):
        modules = load_stack(framework_root, "demo", repo_root)
        return gate(
            AuditContext(
                framework_root=framework_root,
                repo_root=repo_root,
                project="demo",
                modules=modules,
            )
        )

    def test_modules_validate(self) -> None:
        findings = validate_modules(load_all_modules(ROOT))
        self.assertEqual([], [finding.message for finding in findings])

    def test_project_stack_loads_default_and_project_module(self) -> None:
        stack = load_stack(ROOT, "styio-spio", Path("/tmp/styio-spio"))
        module_ids = [module.module_id for module in stack]
        self.assertIn("default", module_ids)
        self.assertIn("for-styio-spio", module_ids)
        self.assertNotIn("for-styio-view", module_ids)

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


if __name__ == "__main__":
    unittest.main()
