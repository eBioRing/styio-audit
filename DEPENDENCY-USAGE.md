# Dependency Usage Boundary

**Purpose:** Record dependency authorization boundaries for `styio-audit`.

**Last updated:** 2026-04-24

`styio-audit` has no runtime third-party dependency in `pyproject.toml`; it uses the Python standard library only.

Dependency policy:

- No dependency may require commercial authorization, paid licensing, subscription access, membership access, trial-only terms, or proprietary-use approval.
- Any future dependency must be listed here with its license evidence, source boundary, and usage boundary before it can pass audit.
- Generated reports must summarize dependency and license evidence without copying target repository source.
