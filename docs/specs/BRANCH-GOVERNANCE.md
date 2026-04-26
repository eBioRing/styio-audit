# Branch Governance

**Purpose:** Define the source-of-truth branch, promotion, and GitHub Ruleset policy for Styio-family repositories.

**Last updated:** 2026-04-26

This document is the authoritative branch-governance reference for `styio-audit`. `README.md` and `AUDIT-FRAMEWORK.md` may summarize the model, but detailed branch-flow and Ruleset policy must be maintained here.

## Scope

This policy applies to:

- `eBioRing/styio-audit`
- eBioRing upstream Styio-family repositories audited by `ecosystem-audit`
- downstream Styio-family repositories that adopt the same promotion model through repository-local workflows

This policy does not apply to `styio-dev-env`, `styio-dev-doc`, `styio-book`,
`styio-example`, or `styio-ext-vsc`. `styio-deprecated` is no longer maintained
and is reference-only, so it is outside both branch-governance and audit
coverage expectations.

## Branch Roles

| Branch | Role | Writable | Entry mode | Primary gate |
| --- | --- | --- | --- | --- |
| `temporary branch` | Scratch branch for new commits | Yes | Direct push | `self-audit-baseline` on push |
| `ai-dev` | Writable integration branch | Yes | Direct push | `self-audit-baseline` on push |
| `nightly` | Promotion gate | No | Pull request only | `self-promotion-gate` |
| `stable` | Release gate | No | Pull request only | `self-promotion-gate` |
| `main` | Final delivery gate | No | Pull request only | `self-promotion-gate` |

`nightly`, `stable`, and `main` may also require review approval according to the active GitHub Ruleset. Direct updates to those branches are not part of the supported promotion flow.

## Upstream Promotion Flow

For eBioRing upstream repositories, the managed promotion chain is:

`temporary branch -> ai-dev -> nightly -> stable -> main`

Required constraints:

1. Temporary branches and `ai-dev` are the only writable integration lanes.
2. AI agent temporary branches are expected to target `ai-dev` first.
3. Temporary branches must not promote directly into `stable` or `main`.
4. `ai-dev` must not bypass `nightly` when promoting toward `stable`.
5. Promotion into `nightly`, `stable`, and `main` must happen through pull requests.
6. Promotion into `nightly`, `stable`, and `main` must satisfy the repository's required protected-branch checks.

## Downstream Submission Rules

Downstream repositories are outside the upstream `ecosystem-audit` fan-out boundary, but they must follow the same promotion structure when contributing into upstream protected branches.

1. A fork-based downstream branch may contribute into upstream `nightly`, `stable`, or `main` only through a pull request opened against the upstream repository.
2. Required status checks for an upstream protected branch must run in the upstream repository context. A downstream repository's own CI result does not satisfy upstream required checks by itself.
3. A non-fork external repository cannot promote directly into an upstream protected branch. The change must first exist on an upstream branch and then be promoted through the normal pull-request path.

## GitHub Ruleset Policy

GitHub Rulesets are the source of truth for protected-branch enforcement. Legacy classic branch-protection endpoints are not authoritative for Styio delivery governance.

Required policy shape:

1. `nightly`, `stable`, and `main` must require pull requests before merging.
2. `nightly`, `stable`, and `main` must require `self-promotion-gate` for `styio-audit`, and the repository-local `styio-audit` check for target repositories.
3. `temporary branch` and `ai-dev` must remain writable so new SHAs can be created and audited before promotion.
4. `self-audit-baseline` must still run on every branch push so writable branches always produce current audit evidence.
5. `ecosystem-audit` must remain informational for `styio-audit` self-promotion and must not be configured as a required status check.
6. Ruleset bypass actors must be explicitly reviewed and must not grant broad normal-delivery bypass.
7. Upstream repositories must keep `.github/workflows/styio-audit.yml` aligned with the authoritative template in `styio-audit/templates/workflows/styio-audit-local.yml`, because protected-branch promotion depends on that local workflow actually reporting the required check.

When auditing live enforcement, inspect effective rules from:

`GET /repos/{owner}/{repo}/rules/branches/{branch}`

Do not treat `GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks` as the source of truth when Rulesets are active.

## Operational Consequences

The current model intentionally trades delivery speed for boundary clarity:

- `temporary branch -> nightly` now requires a pull request instead of same-SHA direct promotion.
- `ai-dev -> nightly` now requires a pull request instead of direct promotion.
- `nightly -> stable` and `stable -> main` continue to require pull requests.
- A promotion pull request must produce current required status checks for the candidate commit before it can merge.

## Documentation Rule

Any change to branch flow, branch roles, promotion paths, or protected-branch Ruleset semantics must update this document first. Entry docs may then be updated to keep their summaries aligned.
