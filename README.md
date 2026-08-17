# Styio Audit

**Centralized, modular auditable-code framework for Styio-family
repositories.**
Part of the [Styio](https://styio.io) ecosystem.

[![License](https://img.shields.io/github/license/SymPolicy/styio-audit?style=flat-square)](LICENSE)

---

Styio Audit loads a common audit base first, then dynamically loads the
repository-specific business module for the target repository. The target
project does not provide an audit API, wrapper, plugin, or gate integration;
the auditor runs this repository externally against a filesystem path.

## Quick Start

```sh
python3 -m styio_audit.cli list-modules
python3 -m styio_audit.cli validate-modules
python3 -m styio_audit.cli gate --repo /path/to/repo --project Pafio
python3 -m styio_audit.cli pre-commit --repo /path/to/repo --project Pafio
python3 -m styio_audit.cli report --repo /path/to/repo --project Pafio --output audit-report.json
python3 -m styio_audit.cli secret-history --repo /path/to/repo --project Pafio --format json
```

Use `--framework-only` to validate module structure and target scope globs
without requiring active audit defects to be closed.

## Module Layout

- `modules/default/` — common audit base loaded by every target repository.

Per-repository modules:

| Directory | Covers |
|---|---|
| `for-styio/` | Styio |
| `for-pafio/` | Pafio |
| `for-styio-view/` | Vityo |
| `for-styio-cloud/` | Styio Cloud |
| `for-styio-community/` | Styio Community |
| `for-styio-audit/` | Styio Audit |
| `for-styio-all-in-one/` | Styio All-in-One |
| `for-styio-benchmark/` | Styio Benchmark |
| `for-styio-book/` | The Styio Book |
| `for-styio-dev-doc/` | Styio Developer Manual |
| `for-styio-dev-env/` | Styio Dev Environment |
| `for-styio-example/` | Styio Examples |
| `for-styio-ext-vsc/` | Styio for VS Code |
| `for-styio-io/` | styio.io |

Each module is loaded from `module.json` and can define `checks.py` with
`run(context)` for custom dynamic checks.

## Cross-Repo Execution

Every Styio-family target repository runs a dedicated `styio-audit` GitHub
Actions workflow on pull requests, pushes, and manual dispatch. That workflow
checks out `SymPolicy/styio-audit` at `stable` and runs
`../styio-audit/bin/styio-audit gate` directly.

### Workflows

| Workflow | Purpose |
|---|---|
| `self-audit-baseline.yml` | Validates `styio-audit` on every branch. |
| `self-promotion-gate.yml` | Required for `nightly`, `stable`, and `release` promotion. |
| `ecosystem-audit.yml` | Upstream SymPolicy ecosystem patrol on managed branches. |

## Local Pre-Commit Gate

Install a tracked `.githooks/pre-commit` hook that scans staged content before
every local commit:

```sh
python3 -m styio_audit.cli sync-local-precommit-hook \
  --repo <repo-root> --project <project-id> --framework-ref HEAD
```

Sync repository-local workflows with the released external standard:

```sh
python3 -m styio_audit.cli sync-local-workflow \
  --repo <workspace-root>/styio --project styio --framework-ref origin/stable
```

## Default Policy Gates

The default module provides a common baseline plus profile-scoped gates:

| Profile | Repositories | Additional controls |
|---|---|---|
| `language-core` | Styio | Compiler delivery, license, dependency, secret, IP |
| `backend-operations` | Pafio, Styio Cloud, Styio Community | Server security boundaries, infrastructure exposure |
| `client-tooling` | Vityo, Styio for VS Code | Source/tooling checks |
| `documentation-basic` | Styio Developer Manual, The Styio Book | Lightweight baseline |
| `example-basic` | Styio Examples | Lightweight baseline |
| `benchmark-basic` | Styio Benchmark | Lightweight baseline |
| `static-website` | styio.io | Lightweight baseline |
| `development-environment` | Styio Dev Environment | Lightweight baseline |
| `ecosystem-aggregate` | Styio All-in-One | Lightweight baseline |
| `framework-policy` | Styio Audit | Source/tooling checks |

### Key Policies

- **License** — Apache-2.0 license file required; package metadata must declare
  Apache-2.0.
- **Commercial risk** — Dependency manifests scanned for commercial
  authorization terms; usage-boundary evidence required in
  `DEPENDENCY-USAGE.md`.
- **Secrets** — Current worktrees scanned for passwords, tokens, API keys,
  private keys. Findings never print suspected values.
- **IP exposure** — IPv4/IPv6 literals scanned; non-loopback addresses blocked
  unless explicitly allowlisted.
- **Backend operations** — Backend repos must not contain production ops paths,
  real database DSNs, cloud resource identifiers, or operational hosts.
- **Branch governance** — Core product repos must expose `release`, `stable`,
  and `nightly` branches, with every other branch treated as temporary. Details in
  [BRANCH-GOVERNANCE.md](docs/specs/BRANCH-GOVERNANCE.md).

## Report Format

`report` emits a versioned JSON payload with: `report_version`, `framework`,
`target`, `modules`, `summary`, and `findings`. The `summary` block includes
finding counts, severity counts, and a pass/fail status.

## Evolution Rule

Add new audit capability as a module first. Keep the core loader small.
Repository-specific policy belongs in `for-.../module.json` or an optional
`for-.../checks.py`. Do not require target repositories to invent their own
audit entry points.

## License

Apache-2.0. See [LICENSE](LICENSE).
