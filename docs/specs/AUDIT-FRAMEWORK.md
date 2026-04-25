# Audit Framework

**Purpose:** Define how `styio-audit` stays generic while supporting project-specific auditable-code modules.

**Last updated:** 2026-04-26

## Loading Model

The CLI loads modules in this order:

1. All `modules/*/module.json` entries with `module_type: "default"`.
2. All top-level `for-*/module.json` entries whose `project_ids` match `--project` or the target repository directory name.
3. Optional `checks.py` files next to loaded module descriptors.

This keeps the common framework stable while allowing each repository to evolve its own resource taxonomy, state machines, tests, and gates.

The audited repository does not provide an audit interface. `styio-audit` reads the target worktree externally and applies its own modules.

## Execution Contract

Each Styio-family repository must own a dedicated `styio-audit` GitHub Actions workflow. The workflow must run on pull requests, pushes, and manual dispatch for managed delivery branches, check out `eBioRing/styio-audit` from `stable`, execute that checkout's `bin/styio-audit` entrypoint directly against the target repository, and report the repository-local check name `styio-audit`. eBioRing upstream checks must also fetch the target repository's `stable`, `nightly`, and `ai-dev` branch evidence before running the gate. The authoritative repository-local workflow template is stored in [../templates/workflows/styio-audit-local.yml](../../templates/workflows/styio-audit-local.yml), and upstream repository-local workflows must match that template after rendering repository/project placeholders.

`styio-audit` separates self-promotion from ecosystem patrols. `.github/workflows/audit-self-essential.yml` runs on pull requests, pushes, merge queue entries, and manual dispatch for all branches. It validates module schema, unit tests, and the `styio-audit` self gate with branch-governance checks disabled, so temporary branches still receive documentation, schema, and security coverage. `.github/workflows/audit-self-complete.yml` runs on pull requests, pushes, merge queue entries, and manual dispatch for `stable` and `main`. It validates the same framework plus branch-governance checks. `audit-self-complete` is the only self-promotion status check that should be required for `styio-audit` promotion into `stable` and `main`.

`styio-audit` also runs `.github/workflows/ecosystem-audit.yml` on pushes to `main`, `stable`, `nightly`, and `ai-dev`, plus manual dispatch. That fan-out workflow checks out `eBioRing/styio-audit@stable` as the released audit-policy source, then checks out configured eBioRing target repository branches and applies that released audit framework to `styio`, `styio-spio`, `styio-view`, `styio-platform`, `styio-community`, and `styio-audit`. Ecosystem findings must be triaged separately and must not be configured as required `styio-audit` self-promotion checks.

Detailed branch roles, promotion paths, downstream submission rules, and live GitHub Ruleset expectations are maintained in [BRANCH-GOVERNANCE.md](BRANCH-GOVERNANCE.md). This framework document references that policy and keeps only the framework-facing constraints:

1. Every upstream eBioRing repository in scope must expose `stable`, `nightly`, and `ai-dev` branch evidence.
2. `styio-audit` must run `audit-self-essential` on every branch so writable branches always produce current audit evidence.
3. `styio-audit` must require `audit-self-complete` for promotion into `stable` and `main`.
4. `ecosystem-audit` must remain visible but must not block `styio-audit` self-promotion.
5. Downstream repositories must run repository-local `styio-audit` workflows for their own pull-request and protected-branch delivery.
6. Upstream eBioRing repositories must keep `.github/workflows/styio-audit.yml` identical to the authoritative template rendered from `templates/workflows/styio-audit-local.yml`, and `styio-audit gate` must fail if that file drifts.

Audit execution must record both the audit framework commit SHA and the target repository commit SHA in the workflow log. CI must not rely on a `styio-audit` binary found on `PATH`, because that can be older than the repository policy.

## GitHub Ruleset Governance

Styio delivery gates are governed through GitHub Rulesets. Maintainers must not treat legacy classic branch protection required-status-check configuration as the source of truth for audit enforcement. The full protected-branch policy lives in [BRANCH-GOVERNANCE.md](BRANCH-GOVERNANCE.md). Audit tooling and manual reviews must inspect effective rules, for example `GET /repos/{owner}/{repo}/rules/branches/{branch}`. The legacy classic endpoint `GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks` is informational only for Styio governance and can return 404 when Rulesets are correctly enforcing the gate.

## Module Contract

A project module must define:

1. `project_ids`.
2. `technology_stack`.
3. `internal_components`.
4. `open_source_components`.
5. `dependency_manifests`.
6. `resource_classes`.
7. For each resource class: owner, scope globs, copying policy, concurrency policy, nullability policy, cleanup policy, state machine, required tests, required gates, and audit risks.

The state machine must define stable state names, transitions, and invalid operations. A resource class without a state machine is not auditable.

The manifest inventory fields are blocking audit inputs. If a project module does not provide the technology stack, internal component, open-source component, and dependency manifest lists, the module cannot pass validation.

## Gate Contract

`styio-audit gate` validates:

1. Module schema.
2. Required project manifest inventory lists.
3. Required `stable`, `nightly`, and `ai-dev` branch evidence from local or remote-tracking git refs for eBioRing upstream repositories.
4. Upstream and downstream pull request merge-flow boundaries, including the rule that temporary branches may target only `ai-dev` or `nightly`.
5. Resource-class state machines.
6. Target repository scope globs.
7. Styio-family Apache-2.0 license evidence and source-distribution notices.
8. Dependency commercial-risk evidence, including dependency usage boundaries and prohibited commercial authorization markers.
9. Server-deployment sensitive security boundaries for authentication, privacy, password storage, keys, tokens, and production secret material.
10. Current-worktree secret evidence for passwords, tokens, API keys, private keys, client secrets, and access keys.
11. Target defect records when present, unless `--framework-only` is used.
12. Optional dynamic module hooks.

Gate failure is based on audit quality. Passing application tests is not enough to override a failed audit framework check.

## License And Commercial-Risk Policy

The default module applies source-license and commercial-risk gates to `styio`, `styio-nightly`, `styio-spio`, `styio-view`, `styio-platform`, and `styio-audit`.

License checks require:

1. A repository license file declaring Apache-2.0.
2. Apache-2.0 package metadata when a supported metadata file is present.
3. A source-distribution notice stating that redistributed Styio-family source or binaries must preserve Apache-2.0 license, copyright, NOTICE, modification, and patent-license notices.

Commercial-risk checks require:

1. No dependency manifest may declare commercial authorization, paid-license, subscription, membership, trial-only, or proprietary-use terms.
2. A dependency usage-boundary file must exist.
3. Every dependency discovered in supported manifests must be named in usage-boundary evidence.

This is an engineering gate, not legal advice. Apache-2.0 does not impose GPL-style copyleft inheritance, but ambiguous dependency terms should fail closed until project owners record acceptable open-source license evidence and a clear usage boundary.

## Server Sensitive-Boundary Policy

The default module treats a project as server-deployment scoped when its project manifest describes server deployment, server-side, backend, deployment, cloud, hosted, control-plane, registry, regional-node, systemd, VM deployment, or worker-control surfaces.

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

## Secret Scan Policy

The default module scans current worktrees for passwords, tokens, API keys, private keys, client secrets, and access keys. It also provides the `secret-history` command for full git-history scans over all reachable commits:

```bash
python3 -m styio_audit.cli secret-history --repo /path/to/repo --project styio-spio --format json
```

Secret findings are intentionally redacted. Reports include rule id, class, file path, line number, value length, fingerprint, and first/last commit for history scans, but never include the suspected secret value.

## Report Contract

`styio-audit report` produces a versioned external-audit payload with:

1. Framework metadata.
2. Target repository metadata.
3. Loaded module summaries.
4. Summary counts and pass/fail status.
5. Full finding records.

This format is intended for downstream tooling and archiveable audit evidence. It stays independent from any target repository API or project-local wrapper.

`styio-audit report` writes JSON or plain-text output into a target path selected by the auditor. This is still external audit behavior: the target repository does not need to provide scripts or plugins.
