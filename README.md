# Chromifer

**Compatibility-preserving reconstruction of Chromium's browser and service layers in Rust.**

Chromifer is a long-term engineering project for incrementally replacing Chromium infrastructure with memory-safe Rust components without removing browser features, weakening process isolation, or breaking web compatibility.

This repository does **not** claim to contain a Rust browser engine. The first milestone is the migration kernel: a machine-readable architecture manifest, compatibility gates, and a planner that rejects unsafe component transitions before code is replaced.

## Principles

- Preserve Chromium behavior before reducing code size.
- Migrate components, not individual source files.
- Keep Blink, V8, Skia, ANGLE, and media engines behind audited boundaries during early phases.
- Require executable compatibility gates for every migrated component.
- Concentrate C++ interoperability in small, reviewable bridge crates.
- Forbid unscoped `unsafe` Rust.

## Current state

The initial workspace provides:

- `chromifer-attestation`: creates detached Ed25519 runner signatures for evidence bundles.
- `chromifer-manifest`: parses and validates migration manifests.
- `chromifer-build`: generates Chromium `rust_static_library` targets from Cargo metadata.
- `chromifer-cabi`: validates explicit Rust C ABI contracts and generates C headers.
- `chromifer-checkout`: locks Chromium Git, gclient metadata, GN outputs, and required targets.
- `chromifer-mojo`: validates Mojom target/import contracts and generates C++ and Rust binding targets.
- `chromifer-safety`: audits Cargo workspaces against exact safe/bridge unsafe-code policies.
- `chromifer-gates`: derives direct compatibility gates and hashed inputs from build, safety, coverage, checkout, and integration provenance.
- `chromifer-gn`: imports GN JSON project graphs into reproducible manifests.
- `chromifer-integration`: builds generated Rust/C ABI packages through GN and Ninja and executes a C++ endpoint.
- `chromifer-components`: aggregates GN targets and ranks migration candidates.
- `chromifer-coverage`: binds LLVM line coverage to exact manifest source inventories.
- `chromifer-owners`: resolves Chromium OWNERS hierarchy and per-source provenance.
- `chromifer-evidence`: executes compatibility gates and verifies content-addressed evidence.
- `chromifer-planner`: computes legal next transitions and explains blocked ones.
- `chromifer-source`: scans source files for CXX, C ABI, Mojo, callback, and observer evidence.
- `chromifer`: command-line interface for import, scanning, validation, and planning.
- `examples/chromium.toml`: a small model of the intended Chromium component graph.
- `examples/gn-project.json`: a representative GN export used by tests and examples.
- `examples/multi-consumer-bridge/`: two C++ consumers selecting distinct CXX bridge subsets.

## Try it

```bash
cargo run -p chromifer -- validate examples/chromium.toml
cargo run -p chromifer -- frontier examples/chromium.toml
cargo run -p chromifer -- check-transition examples/chromium.toml network_service rust_owned
```

Import a GN target closure:

```bash
cargo run -p chromifer -- import-gn \
  examples/gn-project.json \
  /tmp/chromifer-inventory.toml \
  --baseline example \
  --root //app:browser
```

Annotate an imported manifest with source-level boundary evidence:

```bash
cargo run -p chromifer -- scan-boundaries \
  chromium-inventory.toml \
  /path/to/chromium/src \
  chromium-boundaries.toml
```

Resolve Chromium ownership:

```bash
cargo run -p chromifer -- scan-owners \
  chromium-boundaries.toml \
  /path/to/chromium/src \
  chromium-owned.toml
```

Summarize measured source coverage and use it while ranking migration candidates:

```bash
cargo run -p chromifer -- summarize-coverage \
  chromium-owned.toml \
  /path/to/chromium/src \
  llvm-cov.json \
  chromifer-coverage.json

cargo run -p chromifer -- rank-components \
  chromium-owned.toml \
  --coverage chromifer-coverage.json
```

Generate a Chromium Rust build target:

```bash
cargo run -p chromifer -- generate-gn \
  path/to/Cargo.toml \
  path/to/BUILD.gn \
  --visibility //services/example:*

# Add a C++ consumer for a CXX bridge:
cargo run -p chromifer -- generate-gn \
  path/to/Cargo.toml \
  path/to/BUILD.gn \
  --gn-package-path //services/example/rust \
  --consumer-target example_bridge_cpp \
  --consumer-source consumer/example_bridge.cc

# Or declare multiple consumers with distinct CXX bridge subsets:
cargo run -p chromifer -- generate-gn \
  path/to/Cargo.toml \
  path/to/BUILD.gn \
  --gn-package-path //services/example/rust \
  --consumer-contract path/to/consumers.json

# Generate and attach an explicit C ABI:
cargo run -p chromifer -- generate-c-abi \
  path/to/package \
  path/to/package/c-abi.json \
  path/to/package/include/api.h

cargo run -p chromifer -- generate-gn \
  path/to/package/Cargo.toml \
  path/to/package/BUILD.gn \
  --gn-package-path //services/example/rust \
  --allow-unsafe \
  --consumer-target example_c_abi \
  --consumer-source consumer/example.cc \
  --consumer-header include/api.h

# Generate C++ and Rust Mojo binding targets:
cargo run -p chromifer -- generate-mojo \
  path/to/mojom-package \
  path/to/mojom-package/mojo.json \
  path/to/mojom-package/BUILD.gn

# Audit workspace unsafe-code boundaries:
cargo run -p chromifer -- audit-unsafe \
  Cargo.toml \
  unsafe-policy.json \
  chromifer-unsafe.json

# Lock a Chromium checkout and generated GN graph:
cargo run -p chromifer -- audit-checkout \
  /path/to/chromium-workspace \
  /path/to/chromium-workspace/chromifer-checkout.json \
  /path/to/chromium-workspace/chromifer-checkout-lock.json \
  --gn /path/to/depot_tools/gn

# Build, link, and run a generated C ABI endpoint through real GN/Ninja:
cargo run -p chromifer -- run-gn-integration \
  . \
  examples/integration/gn-root \
  examples/integration/c-abi.json \
  --gn /path/to/gn

# Prepare and verify the same endpoint through Chromium's native Rust template:
examples/integration/prepare-chromium-native.sh \
  /path/to/chromium-workspace \
  --full
examples/integration/run-chromium-native.sh \
  /path/to/chromium-workspace \
  --check

# Derive and execute structured checks from committed provenance:
cargo run -p chromifer -- derive-gates \
  . \
  examples/gates/base.toml \
  examples/gates/gates.json \
  examples/gates/generated.toml

cargo run -p chromifer -- run-gates \
  examples/gates/generated.toml \
  . \
  evidence-root
```

Execute and verify compatibility evidence:

```bash
cargo run -p chromifer -- run-gates \
  chromium-owned.toml /path/to/chromium/src evidence-root \
  --module network_service

cargo run -p chromifer -- verify-evidence \
  chromium-owned.toml \
  evidence-root/evidence/<digest>.json \
  evidence-root
```

Bind evidence to an exact clean Git checkout and direct executables:

```bash
revision=$(git rev-parse HEAD)
cargo run -p chromifer -- run-gates \
  examples/gates/generated.toml . /tmp/chromifer-evidence \
  --attest-checkout \
  --expected-revision "$revision" \
  --require-clean-checkout \
  --attest-executables

cargo run -p chromifer -- verify-evidence \
  examples/gates/generated.toml \
  /tmp/chromifer-evidence/evidence/<digest>.json \
  /tmp/chromifer-evidence \
  --workdir .

# Optionally bind the exact evidence bytes to an externally trusted runner key:
cargo run -p chromifer -- sign-evidence \
  /tmp/chromifer-evidence/evidence/<digest>.json \
  /secure/runner.key \
  /tmp/chromifer-evidence/evidence/<digest>.sig.json \
  --runner-id ci/linux-x64

cargo run -p chromifer -- verify-evidence-signature \
  /tmp/chromifer-evidence/evidence/<digest>.json \
  /tmp/chromifer-evidence/evidence/<digest>.sig.json \
  /trusted/runner.pub
```

JSON output is available for automation:

```bash
cargo run -p chromifer -- frontier examples/chromium.toml --json
```

## Migration states

```text
legacy_cpp -> bridged -> rust_owned
```

A transition to `rust_owned` is legal only when:

1. the component declares compatibility gates;
2. all cross-language dependency edges use an audited boundary (`cxx`, `c_abi`, or `mojo`);
3. no callback or observer review remains unresolved;
4. no legacy dependent reaches the component through a private C++ interface.

The planner is deliberately conservative. A false block costs engineering time; a false approval can create an untestable browser fork.

GN imports follow the same rule. Cross-language edges inferred only from source extensions are written as `unclassified` until a maintainer verifies the actual CXX, C ABI, or Mojo boundary.

## Repository layout

```text
crates/
  chromifer-attestation/ Detached Ed25519 evidence signatures
  chromifer-manifest/  Manifest model and structural validation
  chromifer-build/     Cargo-to-Chromium GN bridge generation
  chromifer-cabi/      Explicit C ABI validation and header generation
  chromifer-checkout/  Chromium checkout and GN output locking
  chromifer-mojo/      Mojom target graph and Rust binding generation
  chromifer-safety/    Workspace unsafe-code policy and evidence audit
  chromifer-gates/     Provenance-to-structured-gate derivation
  chromifer-gn/        GN JSON graph importer
  chromifer-integration/ Real GN/Ninja endpoint execution
  chromifer-source/    Source boundary evidence scanner
  chromifer-owners/    Chromium OWNERS hierarchy scanner
  chromifer-components/ Target aggregation and candidate ranking
  chromifer-coverage/  LLVM source coverage ingestion and aggregation
  chromifer-evidence/  Content-addressed gate execution evidence
  chromifer-planner/   Transition safety analysis
  chromifer-cli/       Command-line frontend
docs/
  architecture.md      Target architecture and migration policy
  gn-import.md         Chromium GN export and import workflow
  source-scan.md       Source evidence and review workflow
  owners-scan.md       Chromium OWNERS hierarchy and provenance
  component-ranking.md Aggregation policy and scoring formula
  coverage.md          Measured source coverage and ranking evidence
  gate-evidence.md     Gate execution and evidence verification
  attestation.md       Git checkout and executable identity evidence
  evidence-signing.md  Detached runner signatures and key trust
  checkout-lock.md     Chromium source, gclient, and GN output lock
  gn-integration.md    Real Rust/C++ GN build, link, and endpoint run
  build-bridge.md      Cargo-to-Chromium GN generation
  c-abi.md             Explicit Rust C ABI contracts
  mojo.md              Mojo target, import, and binding contracts
  unsafe-policy.md     Safe/bridge package policy and unsafe evidence
  structured-gates.md  Direct gate derivation and hashed input contracts
  roadmap.md           Milestones and acceptance criteria
examples/
  chromium.toml        Example migration manifest
  gn-project.json      Example GN JSON project graph
  c-abi-bridge/        Generated C ABI and C++ consumer example
  multi-consumer-bridge/ Multiple C++ targets selecting CXX bridge subsets
  mojo-bridge/         Multi-target C++ and Rust Mojo binding example
  gates/               Provenance-derived gate manifest and contract
  checkout/            Relocatable checkout lock smoke fixture
  integration/         Pinned-GN endpoint integration fixture
```

## Scope

The project initially targets Chromium's browser framework, service layer, process/security orchestration, and platform adapters. Rewriting Blink or V8 is explicitly outside the first phases.

See [docs/migration-exposure.md](docs/migration-exposure.md) for production migration exposure measurement, [docs/gn-import.md](docs/gn-import.md) for graph import, [docs/source-scan.md](docs/source-scan.md) for boundary evidence, [docs/owners-scan.md](docs/owners-scan.md) for ownership, [docs/component-ranking.md](docs/component-ranking.md) for component analysis, [docs/coverage.md](docs/coverage.md) for measured source coverage, [docs/gate-evidence.md](docs/gate-evidence.md) for executable evidence, [docs/attestation.md](docs/attestation.md) for checkout and tool identity, [docs/evidence-signing.md](docs/evidence-signing.md) for detached runner signatures, [docs/checkout-lock.md](docs/checkout-lock.md) for Chromium source and GN graph locking, [docs/gn-integration.md](docs/gn-integration.md) for real GN/Ninja endpoint execution, [docs/structured-gates.md](docs/structured-gates.md) for provenance-derived direct checks, [docs/build-bridge.md](docs/build-bridge.md) for Chromium GN generation, [docs/c-abi.md](docs/c-abi.md) for explicit C ABI contracts, [docs/mojo.md](docs/mojo.md) for Mojo target contracts, [docs/unsafe-policy.md](docs/unsafe-policy.md) for workspace unsafe-code enforcement, and [docs/roadmap.md](docs/roadmap.md) for the staged plan.
