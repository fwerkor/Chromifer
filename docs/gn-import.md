# Importing a Chromium GN graph

Chromifer consumes GN's JSON project export. The export contains resolved targets, source lists, toolchains, and target dependencies for one generated Chromium build configuration.

## 1. Export the graph

From a Chromium checkout:

```bash
gn gen out/Chromifer \
  --ide=json \
  --json-file-name=chromifer-project.json
```

The resulting file is normally written under the selected output directory. The relevant GN documentation is the [generic JSON IDE output](https://gn.googlesource.com/gn/+/HEAD/docs/reference.md).

Record the exact Chromium revision used for the export:

```bash
git rev-parse HEAD
```

A manifest without an exact baseline is not suitable as migration evidence.

## 2. Import a root closure

Import the browser target and its transitive default-toolchain dependencies:

```bash
cargo run -p chromifer -- import-gn \
  out/Chromifer/chromifer-project.json \
  chromium-inventory.toml \
  --baseline "$(git rev-parse HEAD)" \
  --root //chrome:chrome
```

Repeat `--root` to import more than one closure. With no root, every eligible target in the JSON export is considered.

The generated manifest records:

- the Chromium baseline;
- GN build directory and default toolchain;
- requested roots and filtering flags;
- one deterministic module ID per imported GN source target;
- each module's exact GN label and target type;
- dependency edges after meta-target contraction;
- the number of dependencies omitted by the selected policy.

## Conservative defaults

The importer deliberately avoids claiming more than GN can prove.

- Only the default toolchain is imported.
- Test-only targets are excluded.
- Targets without compilable C, C++, Objective-C, assembly, or Rust sources are treated as meta targets. Their dependencies are connected directly to the nearest source targets.
- All imported modules start as `legacy_cpp`.
- All dependency boundaries start as `cpp_internal`.
- Dependencies excluded because they use another toolchain or are test-only are printed explicitly.

These defaults produce a structural inventory, not an automatic declaration that a target is safe to migrate.

## Optional state inference

Source-extension inference can identify obvious Rust-only and mixed Rust/C++ targets:

```bash
cargo run -p chromifer -- import-gn \
  out/Chromifer/chromifer-project.json \
  chromium-inventory.toml \
  --baseline "$(git rev-parse HEAD)" \
  --root //chrome:chrome \
  --infer-state \
  --gate-command 'autoninja -C out/Chromifer browser_tests'
```

When inference is enabled:

- C/C++ only becomes `legacy_cpp`;
- Rust only becomes `rust_owned`;
- mixed C/C++ and Rust becomes `bridged`;
- Rust-to-Rust edges become `rust`;
- C++-to-C++ edges remain `cpp_internal`;
- every other edge becomes `unclassified`.

`unclassified` is intentionally unsafe for a transition to `rust_owned`. A maintainer must inspect the implementation and replace it with `cxx`, `c_abi`, `mojo`, or another justified boundary.

A compatibility gate is mandatory when inference creates a non-legacy module. The importer cannot derive a meaningful test command from the build graph alone.

## Additional switches

```text
--all-toolchains        Include host and secondary toolchain targets
--include-testonly      Include GN test-only targets
--include-meta-targets  Preserve groups/actions as modules instead of contracting them
--force                 Replace an existing output manifest
--json                  Print the import summary as JSON
```

`--all-toolchains` is useful for build-system analysis, but it can create multiple modules for the same source target compiled under different toolchains. It should not be enabled by default for migration planning.

## Current limitations

GN describes the build graph, not source-level ownership or ABI semantics. The importer therefore does not yet infer:

- CXX bridge declarations;
- Mojo interface ownership;
- callback and observer crossings;
- generated-code ownership;
- source-level unsafe operations;
- which tests exercise each target;
- higher-level component grouping across several GN targets.

Those analyses are the remaining Chromium inventory work. The initial importer establishes a reproducible target graph on which they can operate.
