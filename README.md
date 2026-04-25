# styio-audit

**Purpose:** Provide the centralized, modular auditable-code framework for Styio-family repositories.

**Last updated:** 2026-04-26

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

Every Styio-family target repository must run a dedicated `styio-audit` GitHub Actions workflow on pull requests, pushes, and manual dispatch for managed delivery branches. That workflow checks out `eBioRing/styio-audit` at `stable` and runs `../styio-audit/bin/styio-audit gate` directly, so CI does not depend on an installed `styio-audit` from `PATH`.

This repository owns two separate workflows:

- `.github/workflows/audit-self-essential.yml` validates `styio-audit` on every branch. It keeps module, documentation, schema, and security checks active on temporary branches while skipping branch-governance enforcement.
- `.github/workflows/audit-self-complete.yml` validates `styio-audit` for `stable` and `main` promotion. This is the only workflow that should be required for `styio-audit` promotion into `stable` and `main`.
- `.github/workflows/ecosystem-audit.yml` is an upstream eBioRing ecosystem patrol. On pushes to `main`, `stable`, `nightly`, and `ai-dev`, plus manual dispatch, it checks out `eBioRing/styio-audit@stable` as the released policy source, then checks out the configured eBioRing Styio-family repositories across their delivery branches and runs that released audit framework against `styio`, `styio-spio`, `styio-view`, `styio-platform`, `styio-community`, and `styio-audit` scopes. Downstream forks are not scanned by this upstream fan-out workflow; they must run their own repository-local `styio-audit` workflow during pull requests and protected-branch delivery.

Audit logs print the `styio-audit` commit SHA and the target commit SHA. A target repository should treat its repository-local `styio-audit` workflow as a required status check before merging protected branches.

Required status checks are governed through GitHub Rulesets, not legacy classic branch protection. Maintainers must inspect effective branch rules for `ai-dev` and protected release/default branches, such as `GET /repos/{owner}/{repo}/rules/branches/{branch}`, when auditing delivery gates. The legacy `branches/{branch}/protection/required_status_checks` endpoint is not authoritative for Styio delivery governance and can return 404 when the Ruleset gate is correctly active.

Upstream and downstream repositories both allow temporary branches to target `ai-dev` or `nightly`, but promotion must preserve the managed chain `temporary branch -> ai-dev -> nightly -> stable -> main`. Temporary branches must not target `stable` or `main`, and `ai-dev` must not bypass `nightly` when promoting toward `stable`. AI agent temporary branches are expected to target `ai-dev` first even when branch naming cannot be hard-enforced.

Temporary branches and `ai-dev` are the places where new commits are created, pushed, and audited first. `audit-self-essential` runs there and produces the status evidence for the exact commit SHA. Promotion into `nightly` must happen through a pull request and must reuse a SHA that has already completed `audit-self-essential` in the same repository. Promotion into `stable` and `main` must also happen through pull requests. Target repositories should require the repository-local `audit` check for promotion into `stable` and `main`. The `styio-audit` repository itself should require only `audit-self-complete` for promotion into `stable` and `main`. `ecosystem-audit` failures must be triaged as ecosystem findings, not as automatic blockers for `styio-audit` self-promotion.

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

Branch policy:

- Every eBioRing upstream repository in audit scope must expose `stable`, `nightly`, and `ai-dev` branches.
- The gate accepts either local `refs/heads/<branch>` refs or remote-tracking `refs/remotes/*/<branch>` refs in the target checkout.
- Missing any required delivery branch is a delivery blocker for upstream repositories because audit, CI, and cross-repository handoff rules must have stable release, nightly, and integration lanes.
- Downstream repositories are not required to prove long-lived branch existence before merge. Their pull request flow is restricted instead: arbitrary feature branches may target `ai-dev`, `ai-dev` may only merge into `nightly`, `nightly` may only merge into `stable`, and `stable` may only merge into `main`.
- Direct updates to downstream `main`, `stable`, and `nightly` must be blocked by GitHub Rulesets that require pull requests; `styio-audit` validates the pull request head/base pair before merge.

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
