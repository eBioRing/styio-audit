from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from collections.abc import Iterable
from typing import Any

from .models import AuditFinding, AuditModule


MODULE_FILE = "module.json"


def framework_root_from_here() -> Path:
    return Path(__file__).resolve().parents[1]


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: module JSON must be an object")
    return data


def load_hook(module_root: Path):
    hook_path = module_root / "checks.py"
    if not hook_path.exists():
        return None
    spec = importlib.util.spec_from_file_location(f"styio_audit_plugin_{module_root.name}", hook_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"{hook_path}: cannot load checks.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run = getattr(module, "run", None)
    if run is None or not callable(run):
        raise ValueError(f"{hook_path}: plugin must expose callable run(context)")
    return run


def load_module(module_root: Path) -> AuditModule:
    data = load_json(module_root / MODULE_FILE)
    module_id = str(data.get("module_id", "")).strip()
    module_type = str(data.get("module_type", "")).strip()
    if not module_id:
        raise ValueError(f"{module_root / MODULE_FILE}: missing module_id")
    if not module_type:
        raise ValueError(f"{module_root / MODULE_FILE}: missing module_type")
    return AuditModule(
        module_id=module_id,
        module_type=module_type,
        root=module_root,
        data=data,
        hook=load_hook(module_root),
    )


def iter_module_dirs(framework_root: Path) -> list[Path]:
    candidates: list[Path] = []
    modules_dir = framework_root / "modules"
    if modules_dir.exists():
        candidates.extend(path for path in modules_dir.iterdir() if (path / MODULE_FILE).exists())
    candidates.extend(
        path
        for path in framework_root.iterdir()
        if path.is_dir() and path.name.startswith("for-") and (path / MODULE_FILE).exists()
    )
    return sorted(candidates, key=lambda path: path.as_posix())


def load_all_modules(framework_root: Path) -> list[AuditModule]:
    return [load_module(path) for path in iter_module_dirs(framework_root)]


def module_matches_project(module: AuditModule, project: str | None, repo_name: str | None) -> bool:
    if module.module_type == "default":
        return True
    project_ids = module.data.get("project_ids", [])
    if not isinstance(project_ids, list):
        return False
    aliases = {item for item in (project, repo_name) if item}
    return any(isinstance(item, str) and (item in aliases or item == "*") for item in project_ids)


def load_stack(framework_root: Path, project: str | None, repo_root: Path | None) -> list[AuditModule]:
    repo_name = repo_root.name if repo_root is not None else None
    modules = load_all_modules(framework_root)
    selected = [module for module in modules if module_matches_project(module, project, repo_name)]
    selected.sort(key=lambda module: (0 if module.module_type == "default" else 1, module.module_id))
    return selected


def hook_findings(modules: list[AuditModule], context: dict[str, Any]) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for module in modules:
        if module.hook is None:
            continue
        try:
            result = module.hook(context)
        except Exception as exc:  # noqa: BLE001 - hook failures are converted into audit findings.
            findings.append(AuditFinding("error", f"plugin raised {exc.__class__.__name__}: {exc}", module.module_id))
            continue
        if result is None:
            continue
        if isinstance(result, AuditFinding):
            findings.append(result)
            continue
        if isinstance(result, (str, bytes)) or not isinstance(result, Iterable):
            findings.append(AuditFinding("error", f"plugin returned invalid result: {result!r}", module.module_id))
            continue
        for finding in result:
            if isinstance(finding, AuditFinding):
                findings.append(finding)
            else:
                findings.append(AuditFinding("error", f"plugin returned non-finding: {finding!r}", module.module_id))
    return findings
