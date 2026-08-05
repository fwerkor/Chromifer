# Cargo to Chromium GN bridge

`generate-gn` converts a first-party Cargo library package into Chromium's `rust_static_library` form and writes deterministic provenance beside the generated `BUILD.gn`.

```bash
cargo run -p chromifer -- generate-gn \
  path/to/Cargo.toml \
  path/to/BUILD.gn
```

The output path must be `BUILD.gn` in the selected package root. This keeps all generated source paths package-relative and prevents an apparently valid file from referring to a different checkout location.

Chromium's first-party Rust integration uses `rust_static_library`, rather than GN's generic `rust_library`, so the generated target receives Chromium's compiler configuration and mixed-language behavior. Rust files containing `#[cxx::bridge]` are listed in `cxx_bindings` so Chromium can generate the C++ side of the bridge.

## Generated files

The command writes:

```text
package-root/
  BUILD.gn
  chromifer-build.json
  Cargo.toml
  src/
```

`chromifer-build.json` records:

- package name and version;
- SHA-256 of `Cargo.toml`;
- target name, edition, and crate root;
- complete generated Rust source inventory;
- detected CXX bridge files;
- selected Cargo features;
- Cargo dependency to GN label mappings;
- additional GN-only dependencies;
- visibility and unsafe policy;
- SHA-256 of the generated `BUILD.gn`.

The provenance is deterministic and contains no timestamp or host-specific absolute source path.

## Source inventory

Chromifer starts at the Cargo library target's crate root and includes all `.rs` files beneath that source directory, excluding conventional `tests`, `examples`, `benches`, and `target` subdirectories. The crate root is always included.

Additional Rust inputs outside that directory must be explicit:

```bash
chromifer generate-gn Cargo.toml BUILD.gn \
  --extra-source generated/api.rs
```

The generator rejects absolute paths, parent traversal, and missing files.

## CXX bridges and unsafe policy

CXX bridge files are detected by the presence of `cxx::bridge` in generated source inventory:

```rust
#[cxx::bridge]
mod ffi {
    // ...
}
```

When at least one bridge is detected, the generated target contains:

```gn
cxx_bindings = [ "src/lib.rs" ]
allow_unsafe = true
```

The `cxx` Cargo dependency is not emitted as a GN dependency because Chromium's `cxx_bindings` integration adds the required CXX machinery. For pure Rust crates, unsafe remains disabled unless `--allow-unsafe` is explicit.

## Cargo dependency mapping

Cargo package names do not determine Chromium GN labels. Every active normal dependency must therefore be mapped explicitly:

```bash
chromifer generate-gn Cargo.toml BUILD.gn \
  --dep serde=//third_party/rust/serde/v1:lib \
  --public-dep protocol=//components/protocol/rust
```

`--dep` produces `deps`; `--public-dep` produces `public_deps`. A dependency may not appear in both groups. Mappings for inactive dependencies are rejected to catch stale or misspelled configuration.

Additional build-only GN dependencies that have no Cargo counterpart use:

```bash
--gn-dep //base \
--gn-public-dep //components/example/public
```

The generator deliberately rejects target-specific Cargo dependencies. Translating Cargo `cfg(...)` expressions into equivalent GN conditions without changing semantics requires a separate condition model; emitting them unconditionally would be unsafe.

## Features

Features are repeatable:

```bash
--feature json \
--feature compression
```

Cargo's `default` feature is enabled and recursively expanded unless `--no-default-features` is supplied. Chromifer resolves local feature-to-feature references and optional dependencies activated through `dep:name`. An active optional dependency must have a GN mapping like every other dependency.

Dependency feature forwarding such as `serde/derive`, and dependency declarations that disable defaults or request dependency features, are currently rejected. A GN label alone does not prove that the referenced target was built with the same feature set.

## Visibility

Visibility labels are explicit and repeatable:

```bash
--visibility //services/network:* \
--visibility //content/browser:*
```

Only `//...` and `:local` GN labels are accepted for dependencies and visibility.

## Drift checking

Generated files should be committed and checked in CI:

```bash
chromifer generate-gn Cargo.toml BUILD.gn \
  --visibility //services/example:* \
  --check
```

`--check` regenerates both files in memory and fails when either differs. Changes to Cargo metadata, Rust source inventory, CXX bridges, dependency mappings, features, unsafe policy, or the generated GN text therefore become review-visible.

`examples/rust-bridge` is checked this way by Chromifer's own CI.

## Current boundary

This stage generates a first-party Rust target. It does not yet:

- translate target-specific Cargo dependencies into GN conditions;
- preserve dependency crate feature configurations;
- generate the C++ consumer `source_set`;
- generate Mojo interfaces;
- map Cargo build scripts;
- vendor crates.io dependencies into Chromium;
- prove that generated GN builds on all Chromium platforms.

Those are subsequent M2 tasks. The current generator refuses unsupported dependency semantics rather than silently weakening them.
