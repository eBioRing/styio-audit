# Branch Governance

**Purpose:** Define the source-of-truth branch, promotion, and GitHub Ruleset policy for Styio-family repositories.

**Last updated:** 2026-06-30

This document is the authoritative branch-governance reference for `styio-audit`. `README.md` and `AUDIT-FRAMEWORK.md` may summarize the model, but detailed branch-flow and Ruleset policy must be maintained here.

## Scope

This policy applies to the core product repositories:

- `SymPolicy/Styio`
- `SymPolicy/Pafio`
- `SymPolicy/Vityo`
- `SymPolicy/Styio-Cloud`
- downstream branches contributing into those upstream protected branches

`styio-audit` owns the validation policy and workflow templates for this model, but this page does not require every support repository to use `release` as its default branch.

## Branch Roles

| Branch | Role | Writable | Entry mode | Primary gate |
| --- | --- | --- | --- | --- |
| `temporary branch` | Scratch branch for new commits | Yes | Direct push | `self-audit-baseline` on push |
| `nightly` | Promotion gate | No | Pull request only | repository-local required gates |
| `stable` | Release gate | No | Pull request only | repository-local required gates |
| `release` | Final delivery gate and default branch | No | Pull request only | repository-local required gates |

`release`, `stable`, and `nightly` may also require review approval according to the active GitHub Ruleset. Direct updates to those branches are not part of the supported promotion flow. Every other branch name is treated as a temporary branch with no special semantics.

## Upstream Promotion Flow

For SymPolicy upstream repositories, the managed promotion chain is:

`temporary branch -> nightly -> stable -> release`

Required constraints:

1. Temporary branches are the only writable integration lanes.
2. Temporary branches may target `nightly` through pull requests.
3. Temporary branches must not promote directly into `stable` or `release`.
4. `nightly` must promote to `stable`, and `stable` must promote to `release`.
5. Promotion into `nightly`, `stable`, and `release` must happen through pull requests.
6. Promotion into `nightly`, `stable`, and `release` must satisfy the repository's required protected-branch checks.
7. A temporary branch should be deleted automatically after its pull request is merged.

## Downstream Submission Rules

Downstream repositories are outside the upstream `ecosystem-audit` fan-out boundary, but they must follow the same promotion structure when contributing into upstream protected branches.

1. A fork-based downstream branch may contribute into upstream `nightly`, `stable`, or `release` only through a pull request opened against the upstream repository.
2. Required status checks for an upstream protected branch must run in the upstream repository context. A downstream repository's own CI result does not satisfy upstream required checks by itself.
3. A non-fork external repository cannot promote directly into an upstream protected branch. The change must first exist on an upstream branch and then be promoted through the normal pull-request path.

## GitHub Ruleset Policy

GitHub Rulesets are the source of truth for protected-branch enforcement. Legacy classic branch-protection endpoints are not authoritative for Styio delivery governance.

Required policy shape:

1. `release`, `stable`, and `nightly` must require pull requests before merging.
2. `release`, `stable`, and `nightly` must require the repository-local `styio-audit` check and the product's grouped CI gates.
3. Temporary branches must remain writable so new SHAs can be created and audited before promotion.
4. Repositories must enable GitHub's delete-head-branch-on-merge behavior so merged temporary branches are removed automatically.
5. Branches other than `release`, `stable`, and `nightly` must be treated as temporary branches, regardless of their names.
6. `self-audit-baseline` must still run on every branch push so writable branches always produce current audit evidence.
7. `ecosystem-audit` must remain informational for `styio-audit` self-promotion and must not be configured as a required status check.
8. Ruleset bypass actors must be explicitly reviewed and must not grant broad normal-delivery bypass.
9. Upstream repositories must keep `.github/workflows/styio-audit.yml` aligned with the authoritative template in `styio-audit/templates/workflows/styio-audit-local.yml`, because protected-branch promotion depends on that local workflow actually reporting the required check.

When auditing live enforcement, inspect effective rules from:

`GET /repos/{owner}/{repo}/rules/branches/{branch}`

Do not treat `GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks` as the source of truth when Rulesets are active.

## Operational Consequences

The current model intentionally trades delivery speed for boundary clarity:

- Temporary branches now target `nightly` by pull request; there is no named integration branch between temporary work and `nightly`.
- `nightly -> stable` and `stable -> release` require pull requests.
- A promotion pull request must produce current required status checks for the candidate commit before it can merge.
- Merged temporary branches should disappear automatically; `release`, `stable`, and `nightly` are the protected exceptions.

## Documentation Rule

Any change to branch flow, branch roles, promotion paths, or protected-branch Ruleset semantics must update this document first. Entry docs may then be updated to keep their summaries aligned.
