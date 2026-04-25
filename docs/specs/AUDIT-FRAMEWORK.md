# Audit Framework

**Purpose:** Define how `styio-audit` stays generic while supporting project-specific auditable-code modules.

**Last updated:** 2026-04-25

## Loading Model

The CLI loads modules in this order:

1. All `modules/*/module.json` entries with `module_type: "default"`.
2. All top-level `for-*/module.json` entries whose `project_ids` match `--project` or the target repository directory name.
3. Optional `checks.py` files next to loaded module descriptors.

This keeps the common framework stable while allowing each repository to evolve its own resource taxonomy, state machines, tests, and gates.

The audited repository does not provide an audit interface. `styio-audit` reads the target worktree externally and applies its own modules.

## Execution Contract

Each Styio-family repository must own a dedicated `styio-audit` GitHub Actions workflow. The workflow must run on pull requests, pushes, and manual dispatch for every protected delivery branch, check out `eBioRing/styio-audit` from `ai-dev`, and execute that checkout's `bin/styio-audit` entrypoint directly against the target repository. eBioRing upstream checks must also fetch the target repository's `stable`, `nightly`, and `ai-dev` branch evidence before running the gate.

`styio-audit` also runs `.github/workflows/ecosystem-audit.yml` on pull requests and pushes to `main`, `stable`, `nightly`, and `ai-dev`. That fan-out workflow checks out configured eBioRing target repository branches and applies the current audit framework to `styio`, `styio-spio`, `styio-view`, `styio-platform`, `styio-community`, and `styio-audit`.

Downstream forks are outside the upstream eBioRing fan-out boundary. Each downstream repository must own a repository-local `styio-audit` workflow that runs on `pull_request`, `push`, and `workflow_dispatch`, checks out `eBioRing/styio-audit@ai-dev`, and runs the target project gate before protected-branch delivery.

Downstream repositories do not have to prove that every long-lived delivery branch exists before a pull request can merge. They must enforce version-promotion boundaries instead: arbitrary feature branches may target `ai-dev`, `ai-dev` may only merge into `nightly`, `nightly` may only merge into `stable`, and `stable` may only merge into `main`. Direct updates to downstream `main`, `stable`, and `nightly` must be blocked by GitHub Rulesets that require pull requests, because a post-update `push` workflow cannot reliably distinguish a valid pull request merge from a direct push.

Audit execution must record both the audit framework commit SHA and the target repository commit SHA in the workflow log. CI must not rely on a `styio-audit` binary found on `PATH`, because that can be older than the repository policy.

## GitHub Ruleset Governance

Styio delivery gates are governed through GitHub Rulesets. Maintainers must not treat legacy classic branch protection required-status-check configuration as the source of truth for audit enforcement.

Required governance state:

1. `ai-dev` and protected default or release branches must be covered by active GitHub Rulesets.
2. Target repositories must require the `audit` status check from the repository-local `styio-audit` workflow.
3. `styio-audit` must require every `audit-targets (...)` matrix status check from `ecosystem-audit`.
4. Required status checks must use strict mode so the merge head is up to date with the protected base branch.
5. Ruleset bypass actors must be explicitly reviewed and must not include broad maintainer bypass for normal delivery.

Audit tooling and manual reviews must inspect effective rules, for example `GET /repos/{owner}/{repo}/rules/branches/{branch}`. The legacy classic endpoint `GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks` is informational only for Styio governance and can return 404 when Rulesets are correctly enforcing the gate.

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
4. Downstream pull request merge-flow boundaries for Unka-Malloc repositories.
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
