# styio-audit

**Purpose:** Provide the centralized, modular auditable-code framework for Styio-family repositories.

**Last updated:** 2026-07-30

`styio-audit` loads common audit rules first, then dynamically loads one or more project-specific modules for the target repository. The target project does not provide an audit API, wrapper, plugin, or gate integration; the auditor runs this repository externally against a filesystem path.

## Module Layout

- `modules/default/` contains the default common audit module.
- `for-styio/` contains compiler/runtime/parser/IDE/LSP audit resources.
- `for-pafio/` contains manifest, lock, resolution, cache, metadata/workflow, vendor, pack, publish-client, and external-Styio audit resources.
- `for-vityo/` contains Flutter editor/runtime resources and the Pafio, system Styio, and Platform owner-adapter boundaries.
- `for-styio-platform/` contains hosted workspace, cloud execution, worker, registry/control-plane, regional node, and delivery-gate audit resources.
- `for-styio-audit/` contains audit-framework, report, license-policy, and dependency-risk audit resources.
- `for-.../` directories can be added for future repositories without changing the core loader.

Each module is loaded from `module.json`. A module can also define `checks.py` with `run(context)` for custom dynamic checks.

## Commands

```sh
python3 -m styio_audit.cli list-modules
python3 -m styio_audit.cli validate-modules
python3 -m styio_audit.cli gate --repo /path/to/repo --project pafio-nightly
python3 -m styio_audit.cli report --repo /path/to/repo --project pafio-nightly --output audit-report.json
python3 -m styio_audit.cli secret-history --repo /path/to/repo --project pafio-nightly --format json
```

Use `--framework-only` to validate module structure and target scope globs without requiring active audit defects to be closed.

`gate` prints findings only. `report` emits a structured external-audit result and can write either JSON or plain text output; JSON is the preferred interchange format for downstream tooling.

## Cross-Repo Execution

Every Styio-family target repository must run a dedicated `styio-audit` GitHub Actions workflow on pull requests, pushes, and manual dispatch for managed delivery branches. That workflow checks out `eBioRing/styio-audit` at `stable` and runs `../styio-audit/bin/styio-audit gate` directly, so CI does not depend on an installed `styio-audit` from `PATH`.

This repository owns three separate workflows:

- `.github/workflows/self-audit-baseline.yml` validates `styio-audit` on every branch. It keeps module, documentation, schema, and security checks active on temporary branches while skipping branch-governance enforcement.
- `.github/workflows/self-promotion-gate.yml` validates `styio-audit` for `nightly`, `stable`, and `main` promotion. This is the workflow that should be required for `styio-audit` promotion into protected promotion branches.
- `.github/workflows/ecosystem-audit.yml` is the configured ecosystem patrol. On pushes to `main`, `stable`, `nightly`, and `ai-dev`, plus manual dispatch, it checks out `eBioRing/styio-audit@stable` as the released policy source, then audits the configured Styio-family repositories across their delivery branches. Pafio and Vityo use their current repository owners and project IDs; downstream forks outside the matrix must run their own repository-local workflow.

Audit logs print the `styio-audit` commit SHA and the target commit SHA. A target repository should treat its repository-local `styio-audit` workflow as a required status check before merging protected branches.

The authoritative repository-local audit workflow template is stored in [templates/workflows/styio-audit-local.yml](templates/workflows/styio-audit-local.yml). Upstream eBioRing repositories must keep their `.github/workflows/styio-audit.yml` file identical to that template after rendering repository and project placeholders. That template reports the repository-local required check name `styio-audit`, and `styio-audit gate` validates the exact workflow match during submission.

For compiler repositories, `styio-audit` also audits the local delivery-framework contract. The target repository still owns its build, test, parser, runtime, and documentation checks, but the external gate verifies that the local CI entrypoint, workflow scheduler, delivery gate, syntax workflow documents, and scheduler tests remain present and wired through the registered scheduler. This prevents a repository from silently bypassing or replacing its quality framework while still leaving implementation-specific checks inside that repository.

To align repository-local workflows with the released external standard, sync them from `styio-audit@origin/stable`:

```sh
python3 -m styio_audit.cli sync-local-workflow --repo /home/unka/eBioRing/styio --project styio --framework-ref origin/stable
python3 -m styio_audit.cli sync-upstream-local-workflows --workspace-root /home/unka/eBioRing --framework-ref origin/stable
python3 -m styio_audit.cli sync-upstream-local-workflows --workspace-root /home/unka/eBioRing --framework-ref origin/stable --check
./scripts/sync-upstream-local-workflows.sh --workspace-root /home/unka/eBioRing --framework-ref origin/stable
```

Use `--framework-ref HEAD` only when preparing an unreleased workflow-template change on `ai-dev`; protected-branch delivery should continue to consume the released `origin/stable` template.

Required status checks are governed through GitHub Rulesets, not legacy classic branch protection. Maintainers must inspect effective branch rules for `ai-dev` and protected release/default branches, such as `GET /repos/{owner}/{repo}/rules/branches/{branch}`, when auditing delivery gates. The legacy `branches/{branch}/protection/required_status_checks` endpoint is not authoritative for Styio delivery governance and can return 404 when the Ruleset gate is correctly active.

Branch-flow and Ruleset details are maintained in [BRANCH-GOVERNANCE.md](docs/specs/BRANCH-GOVERNANCE.md). In summary: temporary branches and `ai-dev` are writable audit lanes, while `nightly`, `stable`, and `main` are pull-request-only promotion gates that require `self-promotion-gate`. `ecosystem-audit` failures remain ecosystem findings and must not be used as `styio-audit` self-promotion blockers.

## Project Mapping

The loader always selects `modules/default`. It then selects project modules whose `project_ids` contain the requested `--project` value or the target repository directory name.

Examples:

```sh
python3 -m styio_audit.cli gate --repo ../styio-nightly --project styio
python3 -m styio_audit.cli gate --repo ../pafio-nightly --project pafio-nightly
python3 -m styio_audit.cli gate --repo ../vityo-nightly --project vityo-nightly
python3 -m styio_audit.cli gate --repo ../styio-platform --project styio-platform
python3 -m styio_audit.cli gate --repo . --project styio-audit
```

## Default Policy Gates

The default module applies repository-wide policy gates to all Styio-family projects: `styio`, `styio-nightly`, `pafio`, `pafio-nightly`, `vityo`, `vityo-nightly`, `styio-platform`, and `styio-audit`.

The product-owner split is explicit: Vityo consumes **Pafio metadata/workflow** contracts for local projects, system Styio contracts for compiler and language services, and **Platform hosted/registry** contracts for hosted workspaces and cloud execution.

Manifest inventory policy:

- Every project module manifest must list `technology_stack`, `internal_components`, `open_source_components`, and `dependency_manifests`.
- Missing inventory lists are schema failures because license, commercial-risk, ownership, and usage-boundary checks cannot be trusted without them.
- The baseline inventory is documented in `docs/specs/TECHNOLOGY-COMPONENT-INVENTORY.md`.

Branch policy:

- Every eBioRing upstream repository in audit scope must expose `stable`, `nightly`, and `ai-dev` branches.
- The gate accepts either local `refs/heads/<branch>` refs or remote-tracking `refs/remotes/*/<branch>` refs in the target checkout.
- Missing any required delivery branch is a delivery blocker for upstream repositories because audit, CI, and cross-repository handoff rules must have stable release, nightly, and integration lanes.
- The detailed promotion model and protected-branch policy are maintained in [BRANCH-GOVERNANCE.md](docs/specs/BRANCH-GOVERNANCE.md).

Local delivery-framework policy:

- Styio compiler repositories must keep `styio-ci-gate`, `workflow-scheduler.py`, `delivery-gate.sh`, runtime-surface checks, workflow-orchestration docs, syntax-addition workflow docs, delivery-gate docs, and scheduler tests in the audited worktree.
- The external audit checks required markers that prove CI and delivery scripts call the scheduler profiles instead of hand-rolled or bypassed commands.
- This policy constrains the framework entrypoints and ordering contract. Repository-local tools remain responsible for executing compiler-specific build, test, syntax, runtime, hygiene, and documentation checks.

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
