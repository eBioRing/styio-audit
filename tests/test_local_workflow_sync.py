from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from styio_audit.local_workflow import (
    load_local_audit_workflow_policy_spec,
    render_authoritative_local_audit_workflow,
    sync_local_audit_workflow,
)


class LocalWorkflowSyncTests(unittest.TestCase):
    def _write_file(self, root: Path, relative: str, text: str) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _write_default_module(self, root: Path) -> None:
        self._write_file(
            root,
            "modules/default/module.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "module_id": "default",
                    "module_type": "default",
                    "description": "Common audit rules.",
                    "last_updated": "2026-04-26",
                    "required_audit_fields": ["marker"],
                    "required_closure_fields": ["marker"],
                    "required_checklist_markers": ["marker"],
                    "local_audit_workflow_policy": {
                        "enabled": True,
                        "name": "Authoritative local workflow policy.",
                        "target_project_ids": ["styio", "styio-spio"],
                        "target_repository_owners": ["eBioRing"],
                        "workflow_path": ".github/workflows/styio-audit.yml",
                        "template_path": "templates/workflows/styio-audit-local.yml",
                    },
                }
            ),
        )

    def _init_git_repo(self, root: Path) -> None:
        subprocess.run(["git", "-C", str(root), "init"], check=True, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Codex"], check=True, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "codex@example.com"], check=True, capture_output=True, text=True)

    def test_sync_local_workflow_writes_rendered_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "styio"
            repo_root.mkdir()
            self._write_default_module(framework_root)
            self._write_file(
                framework_root,
                "templates/workflows/styio-audit-local.yml",
                "name: styio-audit\njobs:\n  audit:\n    name: styio-audit\n    steps:\n      - run: echo {{REPO_NAME}} {{PROJECT_ID}}\n",
            )

            result = sync_local_audit_workflow(framework_root, repo_root, "styio", framework_ref="HEAD")

            self.assertTrue(result.changed)
            self.assertEqual(
                "name: styio-audit\njobs:\n  audit:\n    name: styio-audit\n    steps:\n      - run: echo styio styio\n",
                (repo_root / ".github/workflows/styio-audit.yml").read_text(encoding="utf-8"),
            )

    def test_sync_local_workflow_check_mode_detects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            repo_root = Path(tmp) / "styio"
            repo_root.mkdir()
            self._write_default_module(framework_root)
            self._write_file(
                framework_root,
                "templates/workflows/styio-audit-local.yml",
                "name: styio-audit\njobs:\n  audit:\n    name: styio-audit\n    steps:\n      - run: echo {{REPO_NAME}} {{PROJECT_ID}}\n",
            )
            self._write_file(repo_root, ".github/workflows/styio-audit.yml", "name: drift\n")

            with self.assertRaisesRegex(ValueError, "does not match authoritative workflow"):
                sync_local_audit_workflow(framework_root, repo_root, "styio", framework_ref="HEAD", check=True)

    def test_render_authoritative_local_workflow_uses_requested_git_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            framework_root = Path(tmp) / "framework"
            framework_root.mkdir()
            self._write_default_module(framework_root)
            self._write_file(
                framework_root,
                "templates/workflows/styio-audit-local.yml",
                "name: stable-template\njobs:\n  audit:\n    steps:\n      - run: echo stable {{REPO_NAME}} {{PROJECT_ID}}\n",
            )
            self._init_git_repo(framework_root)
            subprocess.run(["git", "-C", str(framework_root), "checkout", "-b", "stable"], check=True, capture_output=True, text=True)
            subprocess.run(["git", "-C", str(framework_root), "add", "."], check=True, capture_output=True, text=True)
            subprocess.run(["git", "-C", str(framework_root), "commit", "-m", "stable template"], check=True, capture_output=True, text=True)

            self._write_file(
                framework_root,
                "templates/workflows/styio-audit-local.yml",
                "name: head-template\njobs:\n  audit:\n    steps:\n      - run: echo head {{REPO_NAME}} {{PROJECT_ID}}\n",
            )

            spec = load_local_audit_workflow_policy_spec(framework_root, "stable")
            self.assertEqual(".github/workflows/styio-audit.yml", spec.workflow_path)

            _, rendered = render_authoritative_local_audit_workflow(
                framework_root,
                "styio",
                "styio",
                framework_ref="stable",
            )
            self.assertIn("stable styio styio", rendered)
            self.assertNotIn("head styio styio", rendered)


if __name__ == "__main__":
    unittest.main()
