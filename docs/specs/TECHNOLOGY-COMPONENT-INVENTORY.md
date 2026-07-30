# Technology And Component Inventory

**Purpose:** Record the technology stack, self-developed components, open-source components, and dependency manifest surfaces required for Styio audit coverage.

**Last updated:** 2026-04-24

This inventory is the baseline required by `modules/default/module.json`. A project module manifest must list `technology_stack`, `internal_components`, `open_source_components`, and `dependency_manifests`; otherwise `styio-audit validate-modules` and every downstream gate fail. Server-deployment modules must also document `security_boundaries` for authentication, privacy, password handling, secret/key material, production/offline material, permission matrices, deployment security, dependency vulnerability evidence, DAST/penetration regression, runtime secret management, rate-limit/anti-replay controls, log redaction, SSRF/egress controls, and command-execution boundaries before the audit gate can pass.

`styio` currently maps to the local `styio-nightly` checkout for audit evidence because `/home/unka/styio` is not present in this workspace.

## styio / styio-nightly

Technology stack:

- C++ compiler/runtime code built with CMake and CTest.
- Styio source corpus and `.styio` fixtures.
- Tree-sitter grammar and parser shadow tooling.
- Python and Bash repository gates, docs automation, fuzz and benchmark scripts.
- GitHub Actions workflow automation.
- Rust, JavaScript, TypeScript, Zig, Nix, and Bazel fixture/tooling surfaces present in the repository.

Self-developed components:

- Compiler pipeline: `StyioAST`, `StyioAnalyzer`, `StyioIR`, `StyioCodeGen`.
- Runtime and external resource layer: `StyioRuntime`, `StyioExtern`.
- IDE and LSP workspace services: `StyioIDE`, `StyioLSP`.
- Parser route and shadow comparison pipeline: `StyioParser`, tree-sitter grammar, benchmark and fuzz gates.
- Security, pipeline, fuzz, benchmark, docs, workflow, and repo hygiene automation.

Open-source or external components:

- CMake and CTest.
- LLVM toolchain integration where present.
- Tree-sitter grammar tooling.
- GitHub Actions.
- Python standard library and Bash shell tooling.
- Fixture-only Rust, JavaScript, TypeScript, Zig, Nix, and Bazel ecosystems requiring per-manifest evidence before promotion.

Dependency manifest surfaces:

- `CMakeLists.txt`, `src/CMakeLists.txt`, `tests/CMakeLists.txt`, `benchmark/CMakeLists.txt`, `tests/fuzz/CMakeLists.txt`.
- `Cargo.toml` files.
- `package.json` files.
- `.github/workflows/*.yml`.
- `.devcontainer/devcontainer.json`, `.docker/docker-compose.yaml`.

## pafio / pafio-nightly

Technology stack:

- C++ project and package CLI built with CMake and CTest.
- Python documentation, contract, hygiene, and interoperability gates.
- JSON metadata, workflow, registry-client, TOML manifest, and lockfile contract artifacts.
- GitHub Actions workflow automation.

Self-developed components:

- Pafio manifest v1, deterministic resolver, lock transaction, content-addressed cache, sync, and vendor state.
- `metadata v1` plus stable `check`, `build`, `run`, and `test` workflow envelopes.
- External system-Styio discovery and compile-plan production.
- Registry trust and read client, deterministic source pack, and publish client.
- Native, interoperability, documentation, and delivery gates.

Open-source or external components:

- CMake and CTest.
- `nlohmann/json`.
- GoogleTest.
- Python standard library and Bash shell tooling.
- GitHub Actions.

Dependency manifest surfaces:

- `CMakeLists.txt`, `src/CMakeLists.txt`.
- `.github/workflows/*.yml`.

## vityo / vityo-nightly

Technology stack:

- Flutter and Dart frontend workspace.
- Android, iOS, macOS, Linux, Windows, and web platform runners.
- CMake native runner integration for desktop platforms.
- JavaScript, HTML, and CSS prototype with Playwright screenshot tooling.
- Python and Bash repository, docs, and device/profile scripts.
- GitHub Actions workflow automation.

Self-developed components:

- Workspace document store, editor controller, selection, persistence, and shell state.
- Owner adapters for Pafio metadata/workflow, system Styio machine contracts, and Platform hosted-workspace APIs.
- Module host, module manifests, capability matrices, staged updates, and platform visibility.
- Runtime replay surfaces, hosted payload codecs, debug console summaries, and graph/lane models.
- Prototype UI and development server security harness.
- Docs, product, device, and delivery gate scripts.

Open-source or external components:

- Flutter SDK and Dart SDK.
- `cupertino_icons`.
- `shared_preferences`.
- `path_provider`.
- `flutter_test`.
- `flutter_lints`.
- `playwright-core`.
- `PkgConfig`.
- Android Gradle and platform runner toolchains.
- Apple platform runner toolchains.
- GitHub Actions.

Dependency manifest surfaces:

- `products/vityo_app/pubspec.yaml`, `products/vityo_app/pubspec.lock`.
- `products/vityo_app/linux/CMakeLists.txt`, `products/vityo_app/linux/flutter/CMakeLists.txt`.
- `products/vityo_app/windows/CMakeLists.txt`, `products/vityo_app/windows/flutter/CMakeLists.txt`.
- Android Gradle files.
- `.github/workflows/*.yml`.

## styio-platform

Technology stack:

- C++ platform service kernel built with CMake and CTest.
- Native JSON contract packages and canonical examples.
- Python contract, registry, docs, hygiene, and stress gates.
- Bash delivery and docs scripts.
- JSON and YAML control-plane artifacts.
- TypeScript and web fixture surfaces present in the repository.
- GitHub Actions workflow automation.

Self-developed components:

- `PlatformService` route dispatch, daemon self-test, identity, object-store, and job lifecycle code.
- Registry control-plane and registry v2 contract packages.
- Native contract governance, example packs, and source gates.
- Registry mirror distribution and regional node runbooks.
- Docs ownership, team runbook, repo hygiene, and delivery gate automation.
- Native and interop tests for platform service and contract compatibility.

Open-source or external components:

- CMake and CTest.
- `nlohmann_json`.
- `tomlplusplus`.
- `googletest`.
- Python standard library and Bash shell tooling.
- GitHub Actions.

Dependency manifest surfaces:

- `CMakeLists.txt`, `src/CMakeLists.txt`, `tests/CMakeLists.txt`.
- `contracts/**/*.json`.
- `.github/workflows/*.yml`.

## styio-audit

Technology stack:

- Python 3.10+ audit CLI and framework library.
- JSON module manifests.
- `unittest` framework tests.
- Markdown policy, spec, and inventory documents.
- Git CLI integration for target repository file discovery.

Self-developed components:

- `styio_audit` loader, model, check, CLI, and report modules.
- Default audit module and project-specific audit module manifests.
- Apache-2.0 license policy and source-distribution notice gate.
- Commercial-risk dependency and usage-boundary gate.
- Server-deployment sensitive security boundary gate for authentication, privacy, password handling, key/token material, permission matrices, deployment security, dependency vulnerability evidence, DAST/penetration regression, runtime secret management, rate-limit/anti-replay controls, log redaction, SSRF/egress controls, command-execution boundaries, dangerous crypto/auth patterns, and production secret artifacts.
- Manifest inventory schema gate.
- Framework test suite and command wrapper.

Open-source or external components:

- Python standard library.
- Git command-line client.
- Apache-2.0 license text.

Dependency manifest surfaces:

- `pyproject.toml`.
- `modules/default/module.json`.
- `for-styio/module.json`, `for-pafio/module.json`, `for-vityo/module.json`, `for-styio-platform/module.json`, `for-styio-audit/module.json`.

## Audit Rule

Every project module manifest must keep these four inventory lists current:

- `technology_stack`
- `internal_components`
- `open_source_components`
- `dependency_manifests`

The lists are intentionally part of the project module manifest, not only prose documentation. Missing lists are schema failures because later license, commercial-risk, ownership, and usage-boundary checks cannot be trusted without this inventory.
