# styio-audit

**Purpose:** Provide the centralized, modular auditable-code framework for Styio-family repositories.

**Last updated:** 2026-04-24

`styio-audit` loads common audit rules first, then dynamically loads one or more project-specific modules for the target repository. The target project does not provide an audit API, wrapper, plugin, or gate integration; the auditor runs this repository externally against a filesystem path.

## Module Layout

- `modules/default/` contains the default common audit module.
- `for-styio/` contains compiler/runtime/parser/IDE/LSP audit resources.
- `for-styio-spio/` contains package, registry, resolver, toolchain, process, and control-plane audit resources.
- `for-styio-view/` contains Flutter workspace, adapter, module, runtime, and platform audit resources.
- `for-styio-platform/` contains cloud service, native contract, registry distribution, regional node, and delivery-gate audit resources.
- `for-styio-audit/` contains audit-framework, report, license-policy, and dependency-risk audit resources.
- `for-.../` directories can be added for future repositories without changing the core loader.

Each module is loaded from `module.json`. A module can also define `checks.py` with `run(context)` for custom dynamic checks.

## Commands

```sh
python3 -m styio_audit.cli list-modules
python3 -m styio_audit.cli validate-modules
python3 -m styio_audit.cli gate --repo /path/to/repo --project styio-spio
python3 -m styio_audit.cli report --repo /path/to/repo --project styio-spio --output audit-report.json
python3 -m styio_audit.cli secret-history --repo /path/to/repo --project styio-spio --format json
```

Use `--framework-only` to validate module structure and target scope globs without requiring active audit defects to be closed.

`gate` prints findings only. `report` emits a structured external-audit result and can write either JSON or plain text output; JSON is the preferred interchange format for downstream tooling.

## Cross-Repo Execution

Every Styio-family target repository must run a dedicated `styio-audit` GitHub Actions workflow on pull requests, pushes, and manual dispatch. That workflow checks out `eBioRing/styio-audit` at `ai-dev` and runs `../styio-audit/bin/styio-audit gate` directly, so CI does not depend on an installed `styio-audit` from `PATH`.

This repository also owns `.github/workflows/ecosystem-audit.yml`. On every `ai-dev` push to `styio-audit`, it checks out the latest target repositories on `ai-dev` and runs the current audit framework against `styio`, `styio-spio`, `styio-view`, `styio-platform`, and `styio-audit`.

Audit logs print the `styio-audit` commit SHA and the target commit SHA. A target repository should treat its `styio-audit` workflow as a required status check before merging protected branches.

## Project Mapping

The loader always selects `modules/default`. It then selects project modules whose `project_ids` contain the requested `--project` value or the target repository directory name.

Examples:

```sh
python3 -m styio_audit.cli gate --repo ../styio-nightly --project styio
python3 -m styio_audit.cli gate --repo ../styio-spio --project styio-spio
python3 -m styio_audit.cli gate --repo ../styio-view --project styio-view
python3 -m styio_audit.cli gate --repo ../styio-platform --project styio-platform
python3 -m styio_audit.cli gate --repo . --project styio-audit
```

## Default Policy Gates

The default module applies repository-wide policy gates to all Styio-family projects: `styio`, `styio-nightly`, `styio-spio`, `styio-view`, `styio-platform`, and `styio-audit`.

Manifest inventory policy:

- Every project module manifest must list `technology_stack`, `internal_components`, `open_source_components`, and `dependency_manifests`.
- Missing inventory lists are schema failures because license, commercial-risk, ownership, and usage-boundary checks cannot be trusted without them.
- The baseline inventory is documented in `docs/specs/TECHNOLOGY-COMPONENT-INVENTORY.md`.

License policy:

- The repository must carry an Apache-2.0 license file.
- Package metadata such as `pyproject.toml`, `package.json`, or `pubspec.yaml` must declare Apache-2.0 when the metadata file exists.
- A notice file must state that source-derived distributions must preserve Apache-2.0 license, copyright, NOTICE, modification, and patent-license notices.

Commercial-risk policy:

- Dependency manifests are scanned for commercial authorization, paid-license, subscription, membership, trial-only, or proprietary-use terms.
- The repository must carry dependency usage-boundary evidence in `DEPENDENCY-USAGE.md`, `THIRD-PARTY-NOTICES.md`, or a documented `docs/` equivalent.
- Every declared dependency discovered in common manifests must be covered by that usage-boundary evidence before the gate can pass.

Server sensitive-boundary policy:

- Open-source repositories whose project module declares server-deployment, server-side, backend, cloud, hosted, control-plane, registry, regional-node, systemd, VM deployment, or worker-control surfaces are treated as server-deployment repositories.
- Server-deployment project manifests must document authentication/authorization, privacy or PII, password, secret/token/key, production/offline-material, permission-matrix, deployment-security, dependency-vulnerability, DAST/penetration-regression, runtime-secret-management, rate-limit/anti-replay, log-redaction, SSRF/egress, and command-execution boundaries.
- Standard protocol and algorithm implementations may be public. The gate blocks committed deployable secret material, production `.env` files, private keys, generated key bundles, custom cryptography, auth-bypass toggles, JWT `none` shortcuts, disabled verification, wildcard CORS, disabled CSRF, insecure cookies, weak password hashing, insecure random secret generation, plaintext password handling, command-injection surfaces, unrestricted SSRF-prone fetches, default credentials, public debug exposure, and disabled rate limits.
- Findings report paths and matched policy categories only; suspected secret values are handled by the redacted secret scanner.

Secret-scan policy:

- Current worktrees are scanned for passwords, tokens, API keys, private keys, client secrets, and access keys.
- Git history can be scanned with `secret-history`; findings are redacted and report only rule id, location, fingerprint, value length, and first/last commit.
- Findings must never print the suspected secret value.

## Report Format

`report` emits a versioned payload with these top-level keys:

- `report_version`
- `framework`
- `target`
- `modules`
- `summary`
- `findings`

The `summary` block includes finding counts, severity counts, and a pass/fail status. Module entries are relative to the framework root so the report stays portable across machines.

## Evolution Rule

Add new audit capability as a module first. Keep the core loader small: it validates schema, state machines, scope coverage, checklist markers, and defect-record evidence. Repository-specific policy belongs in `for-.../module.json` or an optional `for-.../checks.py`.

Do not require target repositories to add audit entrypoints. Integrations such as pre-commit hooks, CI jobs, or project-local wrapper scripts belong outside the audited project unless the project owner explicitly requests them.
