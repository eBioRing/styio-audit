# Branch Governance

**Purpose:** Define the source-of-truth branch, promotion, and GitHub Ruleset policy for Styio-family repositories.

**Last updated:** 2026-07-04

This document is the authoritative branch-governance reference for `styio-audit`. `README.md` and `AUDIT-FRAMEWORK.md` may summarize the model, but detailed branch-flow and Ruleset policy must be maintained here.

## Scope

This policy applies to:

- `SymPolicy/styio-audit`
- SymPolicy upstream Styio-family repositories audited by `ecosystem-audit`
- downstream Styio-family repositories that adopt the same promotion model through repository-local workflows

## Branch Roles

| Branch | Role | Writable | Entry mode | Primary gate |
| --- | --- | --- | --- | --- |
| `temporary branch` | Scratch branch for new commits | Yes | Direct push | `self-audit-baseline` on push |
| `nightly` | Promotion gate | No | Pull request only | `self-promotion-gate` |
| `stable` | Release gate | No | Pull request only | `self-promotion-gate` |
| `release` | Final delivery gate | No | Pull request only | repository-local required gates |

`nightly`, `stable`, and `release` may also require review approval according to the active GitHub Ruleset. Direct updates to those branches are not part of the supported promotion flow. `styio-audit` itself keeps its historical `main` branch for framework self-promotion, but product repositories use `release` as the final protected branch.

## Upstream Promotion Flow

For SymPolicy upstream repositories, the managed promotion chain is:

`temporary branch -> nightly -> stable -> release`

Required constraints:

1. Temporary branches are the writable integration lanes.
2. AI agent and human temporary branches target `nightly` first.
3. Temporary branches must not promote directly into `stable` or `release`.
4. `nightly` must not bypass `stable` when promoting toward `release`.
5. Promotion into `nightly`, `stable`, and `release` must happen through pull requests.
6. Promotion into `nightly`, `stable`, and `release` must satisfy the repository's required protected-branch checks.

## Downstream Submission Rules

Downstream repositories are outside the upstream `ecosystem-audit` fan-out boundary, but they must follow the same promotion structure when contributing into upstream protected branches.

1. A fork-based downstream branch may contribute into upstream protected branches only through a pull request opened against the upstream repository.
2. Downstream temporary or feature branches must first target an upstream temporary branch. After that upstream temporary branch carries the candidate commit, it can PR into upstream `nightly`.
3. `Unka-Malloc` downstream `nightly` may synchronize directly into upstream `nightly`; it must not bypass upstream `nightly` by targeting `stable` or `release` directly.
4. Required status checks for an upstream protected branch must run in the upstream repository context. A downstream repository's own CI result does not satisfy upstream required checks by itself.
5. A non-fork external repository cannot promote directly into an upstream protected branch. The change must first exist on an upstream branch and then be promoted through the normal pull-request path.

## GitHub Ruleset Policy

GitHub Rulesets are the source of truth for protected-branch enforcement. Legacy classic branch-protection endpoints are not authoritative for Styio delivery governance.

Required policy shape:

1. `nightly`, `stable`, and `release` must require pull requests before merging.
2. `styio-audit` self-promotion branches must require `self-promotion-gate`; product repository `nightly`, `stable`, and `release` branches must require the repository-local `styio-audit` check.
3. `temporary branch` must remain writable so new SHAs can be created and audited before promotion.
4. `self-audit-baseline` must still run on every branch push so writable branches always produce current audit evidence.
5. `ecosystem-audit` must remain informational for `styio-audit` self-promotion and must not be configured as a required status check.
6. Ruleset bypass actors must be explicitly reviewed and must not grant broad normal-delivery bypass.
7. Upstream repositories must keep `.github/workflows/styio-audit.yml` aligned with the authoritative template in `styio-audit/templates/workflows/styio-audit-local.yml`, because protected-branch promotion depends on that local workflow actually reporting the required check.

When auditing live enforcement, inspect effective rules from:

`GET /repos/{owner}/{repo}/rules/branches/{branch}`

Do not treat `GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks` as the source of truth when Rulesets are active.

## Operational Consequences

The current model intentionally trades delivery speed for boundary clarity:

- `temporary branch -> nightly` requires a pull request instead of same-SHA direct promotion.
- Downstream temporary branches first target an upstream temporary branch, then the upstream temporary branch targets upstream `nightly`.
- `Unka-Malloc:nightly -> SymPolicy:nightly` is the supported direct downstream synchronization path for nightly work.
- `nightly -> stable` and `stable -> release` continue to require pull requests.
- A promotion pull request must produce current required status checks for the candidate commit before it can merge.

## Documentation Rule

Any change to branch flow, branch roles, promotion paths, or protected-branch Ruleset semantics must update this document first. Entry docs may then be updated to keep their summaries aligned.
