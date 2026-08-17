# Golden Standard Test Suite

**Purpose:** Define the styio-audit framework test level that makes an audit-policy version submittable.

`test / smoke` runs the framework unit suite.

`test / golden-standard` runs the full unit suite, module schema validation, and the framework-only self gate so policy schema, target project modules, and report behavior remain aligned.

## Local Gate Profile

`styio-audit-policy-self-gate-profile` is the repository-owned adaptation for audit-policy integrity. It is maintained in this repository through module schema validation, the framework-only self gate, local workflow rendering, and policy drift checks. The organization-level audit only verifies that this local profile is present and covered by `test / golden-standard`.

Required local markers: repo-owned adaptation, module schema validation, framework-only self gate, local workflow rendering, policy drift.

## Industry Gate Group

`framework / policy-integrity` is the role-specific gate group for styio-audit itself. It keeps module schema, framework-only self checks, report behavior, policy drift detection, and local workflow rendering grouped under `test / golden-standard`.

Required evidence markers: module schema, framework-only self gate, report behavior, policy drift, local workflow.

## Submit Readiness

A styio-audit version is submittable only when `test / smoke` and `test / golden-standard` both pass.
