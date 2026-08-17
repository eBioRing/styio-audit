# Audit Framework

**Purpose:** Define how `styio-audit` stays generic while supporting project-specific auditable-code modules.

**Last updated:** 2026-06-29

## Loading Model

The CLI loads modules in this order:

1. All `modules/*/module.json` entries with `module_type: "default"`.
2. All top-level `for-*/module.json` entries whose `project_ids` match `--project` or the target repository directory name.
3. Optional `checks.py` files next to loaded module descriptors.

`modules/default` is the common audit base and must stay applicable to every Styio-family repository. Each SymPolicy repository in the Styio ecosystem must also have a dedicated `for-*` project module that describes that repository's business line, resource taxonomy, state machines, tests, and gates. The default `repository_module_policy` makes module coverage a validation error, so a repository cannot silently run only the common base without a business module.

The audited repository does not provide an audit interface. `styio-audit` reads the target worktree externally and applies its own modules.

## Execution Contract

Each Styio-family repository must own a dedicated `styio-audit` GitHub Actions workflow. The workflow must run on pull requests, pushes, and manual dispatch for managed delivery branches, check out `SymPolicy/styio-audit` from `stable`, execute that checkout's `bin/styio-audit` entrypoint directly against the target repository, and report the repository-local check name `styio-audit`. SymPolicy core checks must also fetch the target repository's `release`, `stable`, and `nightly` branch evidence before running the gate. The authoritative repository-local workflow template is stored in [../templates/workflows/styio-audit-local.yml](../../templates/workflows/styio-audit-local.yml), and upstream repository-local workflows must match that template after rendering repository/project placeholders.

Local checkouts may also install the authoritative `.githooks/pre-commit` hook rendered from [../../templates/hooks/pre-commit](../../templates/hooks/pre-commit). This hook runs before every local commit on every branch and scans staged content only. It blocks newly staged repository-junk files, oversized generated artifacts, redacted secret findings, non-loopback IP literals, and backend operations infrastructure exposure findings before they enter any upstream or downstream branch. It is intentionally branch-agnostic: downstream personal repositories with a single maintained branch and temporary feature branches receive the same staged-content protection.

For maintenance automation, `styio-audit` provides repository-local workflow sync commands:

- `python3 -m styio_audit.cli sync-local-workflow --repo <repo-root> --project <project-id> --framework-ref origin/stable`
- `python3 -m styio_audit.cli sync-upstream-local-workflows --workspace-root <workspace-root> --framework-ref origin/stable`
- `python3 -m styio_audit.cli sync-upstream-local-workflows --workspace-root <workspace-root> --framework-ref origin/stable --check`
- `./scripts/sync-upstream-local-workflows.sh --workspace-root <workspace-root> --framework-ref origin/stable`
- `python3 -m styio_audit.cli sync-local-precommit-hook --repo <repo-root> --project <project-id> --framework-ref HEAD`
- `python3 -m styio_audit.cli sync-local-precommit-hook --repo <repo-root> --project <project-id> --framework-ref HEAD --check`

These commands render the same authoritative template that protected-branch delivery consumes from `styio-audit@stable`. `--check` mode is intended for automation and fails on workflow drift without rewriting files.

External audit and repository-local quality gates are separate layers. Repository-local workflows still execute project-specific build, test, parser, runtime, hygiene, and documentation tools because only the target repository owns those implementation details. `styio-audit` owns the contract around that framework: upstream compiler repositories must keep the CI gate, workflow scheduler, delivery gate, runtime-surface check, workflow-orchestration documentation, syntax-addition workflow documentation, delivery documentation, and scheduler tests present and wired through registered scheduler profiles. The gate fails when those contract files or required scheduler markers drift, even if the repository's local tests would otherwise pass.

`styio-audit` separates self-promotion from ecosystem patrols. `.github/workflows/self-audit-baseline.yml` runs on pull requests, pushes, merge queue entries, and manual dispatch for all branches. It validates module schema, unit tests, and the `styio-audit` self gate with branch-governance checks disabled, so temporary branches still receive documentation, schema, and security coverage. `.github/workflows/self-promotion-gate.yml` runs on the framework repository's configured protected branches and validates the same framework plus branch-governance checks. `self-promotion-gate` is the self-promotion status check for `styio-audit` itself, not the product promotion check for `Styio`, `Pafio`, or `Vityo`.

`styio-audit` also runs `.github/workflows/ecosystem-audit.yml` on protected-framework pushes plus manual dispatch. That fan-out workflow checks out `SymPolicy/styio-audit@stable` as the released audit-policy source, then checks configured SymPolicy target repositories. Fully governed core product repositories are audited across `release`, `stable`, and `nightly`; documentation, example, website, development-environment, and benchmark repositories receive the common baseline on their active baseline branch. Ecosystem findings must be triaged separately and must not be configured as required `styio-audit` self-promotion checks.

Detailed branch roles, promotion paths, downstream submission rules, and live GitHub Ruleset expectations are maintained in [BRANCH-GOVERNANCE.md](BRANCH-GOVERNANCE.md). This framework document references that policy and keeps only the framework-facing constraints:

1. Every core SymPolicy repository in scope must expose `release`, `stable`, and `nightly` branch evidence.
2. `styio-audit` must run `self-audit-baseline` on every branch so writable branches always produce current audit evidence.
3. Core product repositories must require repository-local `styio-audit` and grouped product CI gates for promotion into `nightly`, `stable`, and `release`.
4. `ecosystem-audit` must remain visible but must not block `styio-audit` self-promotion.
5. Downstream repositories must run repository-local `styio-audit` workflows for their own pull-request and protected-branch delivery.
6. Upstream SymPolicy repositories must keep `.github/workflows/styio-audit.yml` identical to the authoritative template rendered from `templates/workflows/styio-audit-local.yml`, and `styio-audit gate` must fail if that file drifts.

Audit execution must record both the audit framework commit SHA and the target repository commit SHA in the workflow log. CI must not rely on a `styio-audit` binary found on `PATH`, because that can be older than the repository policy.

## GitHub Ruleset Governance

Styio delivery gates are governed through GitHub Rulesets. Maintainers must not treat legacy classic branch protection required-status-check configuration as the source of truth for audit enforcement. The full protected-branch policy lives in [BRANCH-GOVERNANCE.md](BRANCH-GOVERNANCE.md). Audit tooling and manual reviews must inspect effective rules, for example `GET /repos/{owner}/{repo}/rules/branches/{branch}`. The legacy classic endpoint `GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks` is informational only for Styio governance and can return 404 when Rulesets are correctly enforcing the gate.

## Module Contract

A project module must define:

1. `project_ids`.
2. `audit_profile`.
3. `technology_stack`.
4. `internal_components`.
5. `open_source_components`.
6. `dependency_manifests`.
7. Optional `ci_gate_contract` when the repository owns platform, client release, industry-specific, or other classified CI gates.
8. `resource_classes`.
9. For each resource class: owner, scope globs, copying policy, concurrency policy, nullability policy, cleanup policy, state machine, required tests, required gates, and audit risks.

The state machine must define stable state names, transitions, and invalid operations. A resource class without a state machine is not auditable.

The manifest inventory fields are blocking audit inputs. If a project module does not provide the technology stack, internal component, open-source component, and dependency manifest lists, the module cannot pass validation.

`audit_profile` selects the extra gate burden for the repository:

1. `language-core`: used by `Styio`; keeps compiler delivery, license, dependency, secret, and IP checks, but avoids backend operations controls so the open language implementation stays lightweight.
2. `backend-operations`: used by `Pafio`, `Styio-Cloud`, and `styio-community`; requires declared `security_boundaries`, server hardening checks, and infrastructure exposure checks.
3. `documentation-basic`, `example-basic`, `benchmark-basic`, `static-website`, and `development-environment`: common baseline scans only.
4. `client-tooling`, `ecosystem-aggregate`, and `framework-policy`: source/tooling checks without backend operations controls unless the module is reclassified.

The repository-module policy is the coverage guard for the ecosystem. When adding a new SymPolicy repository, add a new `for-*` module directory and add the repository's project id or repository name to `modules/default/module.json` under `repository_module_policy.required_project_ids` in the same change.

The default `repo_hygiene_policy` is the cleanup guard for the whole ecosystem. It applies to every project id by default and blocks repository-junk paths before PR submission: operating-system junk, editor swap/backup files, local caches, dependency directories, build and distribution outputs, logs, coverage/profiling products, raw database/data dumps, compressed archives, and oversized generated artifacts. A repository that truly needs a large source fixture must declare a narrow `allowed_large_file_globs` exception in the policy-bearing change; unplanned local artifacts must not be committed.

## CI Gate Classification Contract

Repositories that adapt platform-specific behavior must declare those required checks in their project module under `ci_gate_contract.platform_adaptation`. Platform gate names are canonical and unique:

1. Linux platform adaptation: `platform-adaptation / linux-ci-gate`
2. macOS platform adaptation: `platform-adaptation / macos-ci-gate`
3. Windows platform adaptation: `platform-adaptation / windows-ci-gate`

Each declared platform gate must appear exactly once as a GitHub Actions job name under `.github/workflows/*.yml` or `.github/workflows/*.yaml`. The runner must match the declared host platform for Linux, macOS, and Windows. All checks for that platform belong inside the single corresponding platform gate; a second Linux, macOS, or Windows adaptation gate is a policy failure.

Non-platform gates that need delivery classification are declared under `ci_gate_contract.classified_gates` using `category / action` naming. For example, a VS Code marketplace publishing gate is `client / release / marketplace`: `client` identifies the product surface and `release` identifies the delivery action.

Test gates are declared under `ci_gate_contract.test_gates` and use a fixed vocabulary:

1. `test / smoke` is the fast confidence gate. It must run real smoke coverage for the repository instead of being an empty marker.
2. `test / golden-standard` is the submit-readiness gate. It may aggregate the heavier platform, delivery, and smoke jobs through `needs`, but it must represent the point where the candidate version is complete enough to submit.

Any project module that declares test gates must also define `ci_gate_contract.submit_readiness`. That text must mention both `test / smoke` and `test / golden-standard` so reviewers can see the tested-to-what-degree standard without reverse-engineering workflow steps.

Every Styio-family repository must also declare `ci_gate_contract.golden_standard_suite`. The suite contract points at the repository-local manifest, normally `docs/specs/GOLDEN-STANDARD-TEST-SUITE.md`, and may list additional required files or markers. The audit gate checks that the manifest exists and names the smoke gate, golden-standard gate, and submit readiness standard.

For the Styio programming-language repository, the golden-standard suite also includes syntax convergence evidence: `scripts/syntax-convergence-gate.py` validates `docs/design/syntax/SYNTAX-CONVERGENCE-MATRIX.json`. Each accepted syntax family must have one feature id, exactly one implementation owner, documentation evidence, and golden test cases. A syntax feature with multiple implementation declarations is not converged and cannot pass the golden-standard suite.

Every repository with a role-specific delivery surface must declare `ci_gate_contract.industry_gate_groups`. These groups use the same `category / action` naming as classified gates, but they are allowed to be covered by an existing grouped gate such as `test / golden-standard`. This prevents status-check explosion while still making the domain standard explicit. The audit gate validates three things for each industry group:

1. The group name is classified, for example `language / compiler-quality`, `package-manager / registry-safety`, or `ide / extension-quality`.
2. `covered_by` names exactly one existing workflow job, normally `test / golden-standard` or a release gate.
3. The golden-standard manifest names the group and includes every required marker for that role.

Industry groups are mapped by repository role:

1. Programming language and compiler repositories use `language / compiler-quality`: syntax convergence, parser and diagnostic regressions, IR/pipeline goldens, milestone cases, fuzz smoke, and golden cases.
2. Package-manager or registry-facing repositories use `package-manager / registry-safety`: manifest validation, dependency integrity, package archive verification, publish dry-run, provenance, credential boundaries, and registry protocol compatibility.
3. IDE and extension repositories use `ide / extension-quality`: extension-host integration, LSP wire compatibility, packaged VSIX evidence, release preflight, and marketplace readiness.
4. Desktop client repositories use `client / desktop-quality`: application tests, platform adaptation, dependency restoration, checkpoint health, and docs gates.
5. Backend service repositories use `backend / service-security` or `backend / workflow-integrity`: auth, deployment security, dependency vulnerability, runtime secret, state-machine, adapter, storage, serialization, and public workflow evidence.
6. Framework-policy repositories use `framework / policy-integrity`: module schema, self gate, report behavior, policy drift, and local workflow rendering.
7. Documentation, website, example, benchmark, development-environment, and aggregate repositories use the smallest domain group that reflects their role, such as `docs / publication-quality`, `website / release-root`, `examples / runnable-contract`, `benchmark / measurement-integrity`, `dev-env / reproducibility`, or `ecosystem / integration-quality`.

The industry references used for the current taxonomy are primary sources: GitHub Rulesets and security scanning documentation, OpenSSF Scorecard checks, SLSA build/provenance requirements, npm package provenance, Cargo package/archive verification, LLVM testing guidance, Rust compiler test guidance, VS Code extension testing/publishing documentation, and Flutter testing guidance. These references inform the required markers; they are not copied wholesale into every workflow.

Every repository must also declare `ci_gate_contract.local_gate_profile`. This is the repository-owned adaptation boundary. The organization-level framework may require that the profile exists, is covered by exactly one grouped workflow job, and is documented in a repository-local manifest, but it must not define the repository's unique gate details outside that repository. The local profile contract validates:

1. `profile_id`: a unique lowercase dash-separated profile id across the loaded project modules.
2. `manifest`: a repository-local file, normally `docs/specs/GOLDEN-STANDARD-TEST-SUITE.md`.
3. `covered_by`: the grouped workflow job that owns the local profile, normally `test / golden-standard`.
4. `required_markers`: repository-specific markers that must appear in the local manifest.

The manifest must contain `Local Gate Profile`, `repo-owned adaptation`, the exact `profile_id`, and every required marker. This keeps Styio-wide governance external and stable while keeping the concrete package-manager, language, IDE, website, benchmark, documentation, or service checks inside the repository that owns them.

## Gate Contract

`styio-audit gate` validates:

1. Module schema.
2. Required project manifest inventory lists.
3. Required `release`, `stable`, and `nightly` branch evidence from local or remote-tracking git refs for core SymPolicy repositories.
4. Upstream and downstream pull request merge-flow boundaries, including the rule that temporary branches may target only `nightly`.
5. Repository-local `styio-audit.yml` workflow conformance to the released authoritative template.
6. Classified CI gate contracts, including one and only one gate for each declared platform adaptation, smoke test, golden-standard test, and classified release gate.
7. Golden-standard suite manifests, required files, and required markers for every repository that declares the suite.
8. Industry gate groups for the repository role, including their grouped workflow coverage and manifest markers.
9. Repository-local gate profiles, including unique profile ids, local manifests, grouped workflow coverage, and repo-owned adaptation markers.
10. Repository hygiene boundaries so temporary files, caches, build outputs, logs, raw data dumps, archives, and oversized generated artifacts cannot enter pull requests.
11. Styio compiler local delivery-framework contract files and scheduler markers.
12. Resource-class state machines.
13. Target repository scope globs.
14. Styio-family Apache-2.0 license evidence and source-distribution notices.
15. Dependency commercial-risk evidence, including dependency usage boundaries and prohibited commercial authorization markers.
16. Backend operations sensitive security boundaries for authentication, privacy, password storage, keys, tokens, production secret material, deployment security, dependency vulnerability, DAST, rate limit, log redaction, SSRF, and command execution.
17. Backend operations infrastructure exposure boundaries so public service repositories cannot carry official operations material.
18. Current-worktree secret evidence for passwords, tokens, API keys, private keys, client secrets, and access keys.
19. Target defect records when present, unless `--framework-only` is used.
20. Optional dynamic module hooks.

`styio-audit pre-commit` validates staged content only:

1. Staged repository hygiene evidence, including repository-junk paths and oversized generated artifacts.
2. Redacted staged secret evidence for passwords, tokens, API keys, private keys, client secrets, and access keys.
3. Staged IPv4 and IPv6 literals using the same loopback and service-DNS allowlist as the common IP exposure policy.
4. Staged backend operations infrastructure exposure for repositories whose project id matches the backend operations policy.

Gate failure is based on audit quality. Passing application tests is not enough to override a failed audit framework check.

## Repository Hygiene Policy

The default module applies `repo_hygiene_policy` to every Styio-family repository. This is the PR-stage cleanup gate: source repositories may contain source, documentation, tests, fixtures, and explicit golden evidence, but not local runtime debris.

The gate blocks these classes by path:

1. OS and editor junk such as `.DS_Store`, `Thumbs.db`, swap files, backup files, rejected patches, and temporary files.
2. Language and tool caches such as `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.dart_tool`, `.tox`, and `.nox`.
3. Dependency and generated-output directories such as `node_modules`, `build`, `dist`, `out`, and Xcode `DerivedData`.
4. Logs, coverage, profiler, and compiler coverage outputs.
5. Raw local data stores and serialized dumps such as SQLite databases, parquet/arrow/numpy files, pickle files, dump files, and database journals.
6. Compressed archives such as zip, tar, tgz, 7z, and rar files.
7. Files larger than the configured `max_file_bytes` threshold, currently 5 MiB, unless explicitly allowed by `allowed_large_file_globs`.

The policy is intentionally central. Individual repositories should use `.gitignore` and local cleanup scripts for developer ergonomics, but PR acceptance is governed by `styio-audit gate`. If a file is legitimate source evidence, narrow allowlist it in the policy-bearing change with a reason; otherwise it stays outside Git.

## License And Commercial-Risk Policy

The default module applies source-license and commercial-risk gates to `Styio`, `Pafio`, `Vityo`, `styio-all-in-one`, `styio-ext-vsc`, `pafio`, `styio-community`, and `styio-audit`, including their accepted legacy project-id aliases.

License checks require:

1. A repository license file declaring Apache-2.0.
2. Apache-2.0 package metadata when a supported metadata file is present.
3. A source-distribution notice stating that redistributed Styio-family source or binaries must preserve Apache-2.0 license, copyright, NOTICE, modification, and patent-license notices.

Commercial-risk checks require:

1. No dependency manifest may declare commercial authorization, paid-license, subscription, membership, trial-only, or proprietary-use terms.
2. A dependency usage-boundary file must exist.
3. Every dependency discovered in supported manifests must be named in usage-boundary evidence.

This is an engineering gate, not legal advice. Apache-2.0 does not impose GPL-style copyleft inheritance, but ambiguous dependency terms should fail closed until project owners record acceptable open-source license evidence and a clear usage boundary.

## Backend Operations Sensitive-Boundary Policy

The default module treats a project as backend-operations scoped when its project module declares `audit_profile: "backend-operations"`. Current backend operations repositories are `Pafio`, `Styio-Cloud`, and `styio-community`.

For those open-source repositories, public implementation code is allowed when it is a standard, auditable protocol or algorithm implementation. Security must not depend on hiding the algorithm. The enforced boundary is instead:

1. Project manifests must document authentication/authorization boundaries.
2. Project manifests must document privacy or PII boundaries.
3. Project manifests must document password-storage boundaries, including an explicit no-production-password-storage statement when applicable.
4. Project manifests must document secret, token, key, and credential boundaries.
5. Project manifests must document that production private material is offline, in approved secret management, or otherwise not committed to GitHub.
6. Project manifests must document permission-matrix or route-authorization regression coverage.
7. Project manifests must document deployment-security coverage for TLS, CORS, CSRF, cookies, and debug exposure where applicable.
8. Project manifests must document dependency-vulnerability evidence such as SBOM, CVE, or vulnerability-scan gates.
9. Project manifests must document DAST, black-box, penetration, or security-regression coverage for deployed service surfaces.
10. Project manifests must document runtime secret management, such as Secret Manager, KMS, or key rotation.
11. Project manifests must document rate-limit, anti-replay, nonce, or idempotency boundaries for externally reachable routes.
12. Project manifests must document log-redaction and audit-log handling for sensitive request data.
13. Project manifests must document SSRF, egress allowlist, URL allowlist, or outbound-request boundaries.
14. Project manifests must document command-execution, shell-injection, or subprocess-allowlist boundaries.

The gate still hard-fails unsafe code and source artifacts: deployable secret material, production `.env` files, private keys, generated key bundles, custom cryptography, auth-bypass toggles, JWT `none` shortcuts, disabled verification, wildcard CORS, disabled CSRF, insecure cookies, weak password hashing, insecure random secret generation, plaintext password handling, command-injection surfaces, unrestricted SSRF-prone fetches, default credentials, public debug exposure, disabled rate limits, and production-key shortcuts. The gate reports the path, matched marker, and category, but it does not copy suspected secret values into findings.

## Backend Operations Infrastructure Exposure Policy

The default module applies an extra infrastructure exposure gate to backend operations repositories: `Pafio`, `Styio-Cloud`, and `styio-community`. This is intentionally stricter than the policy for surrounding language-core, documentation, extension, website, benchmark, development-environment, and example repositories.

This gate blocks production ops paths, private deployment directories, kubeconfig material, Terraform variable/state files, inventory files, real database/cache/broker/SMTP DSNs, cloud resource identifiers, and operational hosts whose names reveal admin, backend, bastion, console, database, internal, production, staging, monitoring, vault, VPN, or similar service surfaces.

Placeholder material is allowed when it is clearly marked as example, sample, template, test, fixture, fake, dummy, placeholder, or public material. Local loopback hosts and `example.*` domains are allowed for documentation and tests. Public source may still implement standard URL, database, package, or protocol syntax; the gate is aimed at committed official service coordinates and operations material, not at language features.

## Secret Scan Policy

The default module scans current worktrees for passwords, tokens, API keys, private keys, client secrets, and access keys across every `audit_profile`. It also provides the `secret-history` command for full git-history scans over all reachable commits:

```bash
python3 -m styio_audit.cli secret-history --repo /path/to/repo --project Pafio --format json
```

Secret findings are intentionally redacted. Reports include rule id, class, file path, line number, value length, fingerprint, and first/last commit for history scans, but never include the suspected secret value.

## IP Exposure Policy

The default module scans current worktrees for IPv4 and IPv6 literals. Loopback addresses are allowed for local development examples. Non-loopback IP literals are blocked unless they match an explicitly scoped service-DNS allowlist entry.

The default service allowlist only permits the GitHub Pages apex-domain A/AAAA records in DNS configuration documentation paths. Those IPs remain invalid everywhere else in source code, scripts, and generated release material.

## Report Contract

`styio-audit report` produces a versioned external-audit payload with:

1. Framework metadata.
2. Target repository metadata.
3. Loaded module summaries.
4. Summary counts and pass/fail status.
5. Full finding records.

This format is intended for downstream tooling and archiveable audit evidence. It stays independent from any target repository API or project-local wrapper.

`styio-audit report` writes JSON or plain-text output into a target path selected by the auditor. This is still external audit behavior: the target repository does not need to provide scripts or plugins.
