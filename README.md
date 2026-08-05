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

- `chromifer-manifest`: parses and validates migration manifests.
- `chromifer-gn`: imports GN JSON project graphs into reproducible manifests.
- `chromifer-planner`: computes legal next transitions and explains blocked ones.
- `chromifer`: command-line interface for validation and planning.
- `examples/chromium.toml`: a small model of the intended Chromium component graph.
- `examples/gn-project.json`: a representative GN export used by tests and examples.

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
3. no legacy dependent reaches the component through a private C++ interface.

The planner is deliberately conservative. A false block costs engineering time; a false approval can create an untestable browser fork.

GN imports follow the same rule. Cross-language edges inferred only from source extensions are written as `unclassified` until a maintainer verifies the actual CXX, C ABI, or Mojo boundary.

## Repository layout

```text
crates/
  chromifer-manifest/  Manifest model and structural validation
  chromifer-gn/        GN JSON graph importer
  chromifer-planner/   Transition safety analysis
  chromifer-cli/       Command-line frontend
docs/
  architecture.md      Target architecture and migration policy
  gn-import.md         Chromium GN export and import workflow
  roadmap.md           Milestones and acceptance criteria
examples/
  chromium.toml        Example migration manifest
  gn-project.json      Example GN JSON project graph
```

## Scope

The project initially targets Chromium's browser framework, service layer, process/security orchestration, and platform adapters. Rewriting Blink or V8 is explicitly outside the first phases.

See [docs/gn-import.md](docs/gn-import.md) for the inventory workflow and [docs/roadmap.md](docs/roadmap.md) for the staged plan.
