from __future__ import annotations

import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from styio_audit.local_hooks import run_precommit_gate, sync_local_precommit_hook


class LocalHookTests(unittest.TestCase):
    def _write_file(self, root: Path, relative: str, text: str) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _write_default_module(self, framework_root: Path) -> None:
        self._write_file(
            framework_root,
            "modules/default/module.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-06-29",
                    "required_audit_fields": ["marker"],
                    "required_closure_fields": ["marker"],
                    "required_checklist_markers": ["marker"],
                    "secret_scan_policy": {
                        "enabled": True,
                        "target_project_ids": ["*"],
                        "secret_classes": ["password", "token", "api_key", "private_key", "client_secret", "access_key"],
                        "ignored_path_parts": ["node_modules", "build"],
                        "max_file_bytes": 1048576,
                    },
                    "repo_hygiene_policy": {
                        "enabled": True,
                        "name": "Repository hygiene.",
                        "target_project_ids": ["*"],
                        "ignored_path_parts": [".git"],
                        "forbidden_path_globs": ["**/__pycache__/**", "**/*.tmp", "**/*.sqlite", "**/*.log"],
                        "allowed_path_globs": [],
                        "allowed_large_file_globs": [],
                        "max_file_bytes": 1048576,
                        "source_boundary": "Temporary files and generated data must not be staged.",
                    },
                    "ip_exposure_policy": {
                        "enabled": True,
                        "target_project_ids": ["*"],
                        "allow_loopback": True,
                        "max_file_bytes": 1048576,
                    },
                    "public_infrastructure_exposure_policy": {
                        "enabled": True,
                        "name": "Backend infrastructure exposure.",
                        "target_project_ids": ["Pafio"],
                        "target_repository_owners": ["SymPolicy"],
                        "scan_globs": ["**/*.md", "**/*.toml"],
                        "restricted_path_globs": ["**/ops/**", "**/*kubeconfig*"],
                        "allowed_placeholder_markers": ["example", "sample", "template", "test"],
                        "allowed_host_suffixes": ["example.invalid", "localhost"],
                        "disallowed_host_markers": ["admin", "prod", "internal", "db"],
                        "disallowed_dsn_schemes": ["postgres", "redis"],
                        "cloud_resource_markers": ["arn:aws:", "s3://"],
                        "max_file_bytes": 1048576,
                    },
                }
            ),
        )

    def _init_git_repo(self, repo_root: Path) -> None:
        subprocess.run(["git", "init"], cwd=repo_root, check=True, capture_output=True, text=True)
        subprocess.run(["git", "config", "user.name", "Codex"], cwd=repo_root, check=True, capture_output=True, text=True)
        subprocess.run(["git", "config", "user.email", "codex@example.com"], cwd=repo_root, check=True, capture_output=True, text=True)

    def test_precommit_scans_staged_content_without_printing_secret_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_default_module(framework_root)
            self._init_git_repo(repo_root)
            token = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890ABCD"
            public_ip = "8.8" + ".4.4"
            self._write_file(
                repo_root,
                "docs/runbook.md",
                f"token = '{token}'\n"
                f"External service address {public_ip}\n"
                "Production database postgres://styio:secret@db.prod.internal:5432/styio\n",
            )
            subprocess.run(["git", "add", "docs/runbook.md"], cwd=repo_root, check=True, capture_output=True, text=True)

            messages = [finding.message for finding in run_precommit_gate(framework_root, repo_root, "Pafio")]

            self.assertTrue(any("pre-commit secret scan: docs/runbook.md" in message for message in messages))
            self.assertTrue(any(public_ip in message for message in messages))
            self.assertTrue(any("service DSN" in message for message in messages))
            self.assertFalse(any(token in message for message in messages))

    def test_precommit_blocks_staged_repository_junk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_default_module(framework_root)
            self._init_git_repo(repo_root)
            self._write_file(repo_root, "src/__pycache__/demo.cpython-313.pyc", "bytecode\n")
            self._write_file(repo_root, "scratch/session.tmp", "temporary\n")
            self._write_file(repo_root, "data/local.sqlite", "sqlite data\n")
            subprocess.run(
                ["git", "add", "src/__pycache__/demo.cpython-313.pyc", "scratch/session.tmp", "data/local.sqlite"],
                cwd=repo_root,
                check=True,
                capture_output=True,
                text=True,
            )

            messages = [finding.message for finding in run_precommit_gate(framework_root, repo_root, "Pafio")]

            self.assertTrue(any("pre-commit repo hygiene: src/__pycache__/demo.cpython-313.pyc" in message for message in messages))
            self.assertTrue(any("pre-commit repo hygiene: scratch/session.tmp" in message for message in messages))
            self.assertTrue(any("pre-commit repo hygiene: data/local.sqlite" in message for message in messages))

    def test_precommit_scans_existing_index_files_when_unrelated_file_is_staged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_default_module(framework_root)
            self._init_git_repo(repo_root)
            token = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcd"
            self._write_file(repo_root, "legacy.md", f"token = '{token}'\n")
            self._write_file(repo_root, "notes.md", "initial\n")
            subprocess.run(["git", "add", "legacy.md", "notes.md"], cwd=repo_root, check=True, capture_output=True, text=True)
            subprocess.run(["git", "commit", "-m", "baseline"], cwd=repo_root, check=True, capture_output=True, text=True)
            self._write_file(repo_root, "notes.md", "initial\nunrelated change\n")
            subprocess.run(["git", "add", "notes.md"], cwd=repo_root, check=True, capture_output=True, text=True)

            messages = [finding.message for finding in run_precommit_gate(framework_root, repo_root, "Pafio")]

            self.assertTrue(any("pre-commit secret scan: legacy.md" in message for message in messages))
            self.assertFalse(any(token in message for message in messages))

    def test_sync_local_precommit_hook_writes_executable_and_configures_hooks_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "repo"
            repo_root.mkdir()
            self._write_file(
                framework_root,
                "templates/hooks/pre-commit",
                "#!/bin/sh\n"
                "echo {{REPO_NAME}} {{PROJECT_ID}}\n",
            )
            self._init_git_repo(repo_root)

            result = sync_local_precommit_hook(framework_root, repo_root, "Pafio", framework_ref="HEAD")

            hook_path = repo_root / ".githooks/pre-commit"
            self.assertTrue(result.changed)
            self.assertTrue(hook_path.is_file())
            self.assertTrue(hook_path.stat().st_mode & stat.S_IXUSR)
            self.assertEqual("echo repo Pafio", hook_path.read_text(encoding="utf-8").splitlines()[1])
            config = subprocess.run(
                ["git", "config", "--get", "core.hooksPath"],
                cwd=repo_root,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(".githooks", config.stdout.strip())


if __name__ == "__main__":
    unittest.main()
