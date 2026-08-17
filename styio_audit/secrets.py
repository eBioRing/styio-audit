from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SECRET_CLASS_NAMES = ["password", "token", "api_key", "private_key", "client_secret", "access_key"]
DEFAULT_MAX_FILE_BYTES = 1024 * 1024
IGNORED_PATH_PARTS = {
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
IGNORED_FILE_SUFFIXES = {
    ".a",
    ".dll",
    ".dylib",
    ".exe",
    ".gif",
    ".ico",
    ".jpg",
    ".jpeg",
    ".lock",
    ".o",
    ".pdf",
    ".png",
    ".pyc",
    ".so",
    ".ttf",
    ".woff",
    ".woff2",
    ".zip",
}
PLACEHOLDER_TERMS = {
    "changeme",
    "base64-encoded",
    "base64_encoded",
    "development",
    "dev-",
    "dummy",
    "example-token",
    "dev-token",
    "dev_token",
    "example",
    "fake",
    "local-token",
    "local_token",
    "placeholder",
    "redacted",
    "sample",
    "secret-value",
    "secret_value",
    "test",
    "token-value",
    "token_value",
    "todo",
    "your_",
    "xxxxx",
}


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    class_name: str
    pattern: re.Pattern[str]
    confidence: str = "high"
    value_group: str = "value"
    allow_placeholder: bool = False


@dataclass(frozen=True)
class SecretMatch:
    rule_id: str
    class_name: str
    confidence: str
    path: str
    line: int
    fingerprint: str
    value_length: int
    commit: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "rule_id": self.rule_id,
            "class_name": self.class_name,
            "confidence": self.confidence,
            "path": self.path,
            "line": self.line,
            "fingerprint": self.fingerprint,
            "value_length": self.value_length,
        }
        if self.commit is not None:
            payload["commit"] = self.commit
        return payload


SECRET_RULES = [
    SecretRule(
        "private-key-header",
        "private_key",
        re.compile(r"(?P<value>-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)"),
        confidence="critical",
        allow_placeholder=True,
    ),
    SecretRule("aws-access-key-id", "access_key", re.compile(r"(?P<value>\b(?:AKIA|ASIA)[0-9A-Z]{16}\b)")),
    SecretRule("github-token", "token", re.compile(r"(?P<value>\bgh[pousr]_[A-Za-z0-9_]{30,}\b)")),
    SecretRule("openai-api-key", "api_key", re.compile(r"(?P<value>\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b)")),
    SecretRule("google-api-key", "api_key", re.compile(r"(?P<value>\bAIza[0-9A-Za-z_-]{30,}\b)")),
    SecretRule("slack-token", "token", re.compile(r"(?P<value>\bxox[baprs]-[A-Za-z0-9-]{20,}\b)")),
    SecretRule("stripe-secret-key", "api_key", re.compile(r"(?P<value>\bsk_live_[0-9A-Za-z]{20,}\b)")),
    SecretRule(
        "jwt-token",
        "token",
        re.compile(r"(?P<value>\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b)"),
    ),
    SecretRule(
        "credential-assignment",
        "password",
        re.compile(
            r"(?ix)"
            r"\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|auth[_-]?token|access[_-]?token|"
            r"client[_-]?secret|private[_-]?key)\b"
            r"\s*[:=]\s*"
            r"(?P<quote>[\"']?)"
            r"(?P<value>[A-Za-z0-9_./+=:@%$!#-]{8,})"
            r"(?P=quote)"
        ),
        confidence="medium",
    ),
]

HISTORY_CANDIDATE_PATTERN = (
    r"password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key|"
    r"BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"xox[baprs]-|AIza[0-9A-Za-z_-]{20,}|sk-(proj-)?[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{20,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
)


def fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def is_placeholder(value: str, line: str) -> bool:
    lowered_value = value.casefold()
    lowered_line = line.casefold()
    if any(term in lowered_value for term in PLACEHOLDER_TERMS):
        return True
    if any(
        term in lowered_line
        for term in ("example only", "example.internal", "example.test", "path/to", "placeholder", "redacted", "dummy", "fake secret")
    ):
        return True
    if len(set(value)) <= 2:
        return True
    return value in {"null", "none", "undefined", "localhost", "127.0.0.1"}


def path_is_ignored(path: str) -> bool:
    parsed = Path(path)
    if any(part in IGNORED_PATH_PARTS for part in parsed.parts):
        return True
    return parsed.suffix.casefold() in IGNORED_FILE_SUFFIXES


def should_accept(rule: SecretRule, value: str, line: str) -> bool:
    if not rule.allow_placeholder and is_placeholder(value, line):
        return False
    if rule.rule_id == "credential-assignment" and entropy(value) < 2.5:
        return False
    return True


def is_non_secret_reference(value: str) -> bool:
    lowered = value.casefold()
    return lowered.startswith(
        (
            "$env:",
            "env:",
            "process.env.",
            "import.meta.env.",
            "os.environ",
            "current.",
            "this.",
            "settings.",
        )
    )


def is_probable_source_identifier(value: str) -> bool:
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", value) is not None


def scan_line(text: str, *, path: str, line_number: int, commit: str | None = None) -> list[SecretMatch]:
    findings: list[SecretMatch] = []
    seen: set[tuple[str, str]] = set()
    seen_fingerprints: set[str] = set()
    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            value = match.group(rule.value_group)
            quote = match.groupdict().get("quote", "")
            if rule.rule_id == "credential-assignment" and not quote and match.end() < len(text) and text[match.end()] == ">":
                continue
            if rule.rule_id == "credential-assignment" and not quote and (
                is_probable_source_identifier(value) or is_non_secret_reference(value)
            ):
                continue
            if not should_accept(rule, value, text):
                continue
            value_fingerprint = fingerprint(value)
            if value_fingerprint in seen_fingerprints:
                continue
            key = (rule.rule_id, value_fingerprint)
            if key in seen:
                continue
            seen.add(key)
            seen_fingerprints.add(value_fingerprint)
            findings.append(
                SecretMatch(
                    rule_id=rule.rule_id,
                    class_name=rule.class_name,
                    confidence=rule.confidence,
                    path=path,
                    line=line_number,
                    fingerprint=value_fingerprint,
                    value_length=len(value),
                    commit=commit,
                )
            )
    return findings


def scan_text(text: str, *, path: str, commit: str | None = None) -> list[SecretMatch]:
    findings: list[SecretMatch] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        findings.extend(scan_line(line, path=path, line_number=line_number, commit=commit))
    return findings


def scan_worktree(repo_root: Path, files: Iterable[str], *, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> list[SecretMatch]:
    findings: list[SecretMatch] = []
    for relative in files:
        if path_is_ignored(relative):
            continue
        path = repo_root / relative
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
        findings.extend(scan_text(text, path=relative))
    return findings


def git_commits(repo_root: Path) -> list[str]:
    proc = subprocess.run(["git", "rev-list", "--all"], cwd=repo_root, text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git rev-list --all failed")
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def scan_history(repo_root: Path) -> list[dict[str, object]]:
    by_key: dict[tuple[str, int, str, str], dict[str, object]] = {}
    for commit in git_commits(repo_root):
        proc = subprocess.run(
            ["git", "grep", "-I", "-n", "-E", HISTORY_CANDIDATE_PATTERN, commit, "--"],
            cwd=repo_root,
            text=True,
            capture_output=True,
        )
        if proc.returncode not in (0, 1):
            raise RuntimeError(proc.stderr.strip() or f"git grep failed for {commit}")
        if proc.returncode == 1:
            continue
        for raw in proc.stdout.splitlines():
            if len(raw) < 42 or raw[40] != ":":
                continue
            raw_commit = raw[:40]
            remainder = raw[41:]
            try:
                path, line_text, content = remainder.split(":", 2)
                line_number = int(line_text)
            except ValueError:
                continue
            if path_is_ignored(path):
                continue
            for match in scan_line(content, path=path, line_number=line_number, commit=raw_commit):
                key = (match.path, match.line, match.rule_id, match.fingerprint)
                if key not in by_key:
                    by_key[key] = {
                        **match.to_dict(),
                        "first_commit": raw_commit,
                        "last_commit": raw_commit,
                        "commit_count": 1,
                    }
                    by_key[key].pop("commit", None)
                else:
                    by_key[key]["last_commit"] = raw_commit
                    by_key[key]["commit_count"] = int(by_key[key]["commit_count"]) + 1
    return sorted(by_key.values(), key=lambda item: (str(item["path"]), int(item["line"]), str(item["rule_id"])))


def render_history_summary(repo: str, findings: list[dict[str, object]], *, fmt: str) -> str:
    if fmt == "json":
        return json.dumps({"repo": repo, "finding_count": len(findings), "findings": findings}, indent=2, sort_keys=True)
    lines = [f"[styio-audit] secret-history {repo}: {'failed' if findings else 'passed'} ({len(findings)} findings)"]
    for item in findings:
        lines.append(
            "  - "
            f"{item['path']}:{item['line']} "
            f"{item['rule_id']} {item['confidence']} {item['fingerprint']} "
            f"commits={item['commit_count']} first={str(item['first_commit'])[:12]} last={str(item['last_commit'])[:12]}"
        )
    return "\n".join(lines)
