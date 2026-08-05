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
- `chromifer-planner`: computes legal next transitions and explains blocked ones.
- `chromifer`: command-line interface for validation and planning.
- `examples/chromium.toml`: a small model of the intended Chromium component graph.

## Try it

```bash
cargo run -p chromifer -- validate examples/chromium.toml
cargo run -p chromifer -- frontier examples/chromium.toml
cargo run -p chromifer -- check-transition examples/chromium.toml network_service rust_owned
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

## Repository layout

```text
crates/
  chromifer-manifest/  Manifest model and structural validation
  chromifer-planner/   Transition safety analysis
  chromifer-cli/       Command-line frontend
docs/
  architecture.md      Target architecture and migration policy
  roadmap.md           Milestones and acceptance criteria
examples/
  chromium.toml        Example migration manifest
```

## Scope

The project initially targets Chromium's browser framework, service layer, process/security orchestration, and platform adapters. Rewriting Blink or V8 is explicitly outside the first phases.

See [docs/roadmap.md](docs/roadmap.md) for the staged plan.
