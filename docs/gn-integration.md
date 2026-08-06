# Real GN endpoint integration

Chromifer can build a generated Rust/C ABI bridge through GN and Ninja and execute a C++ endpoint that crosses the generated boundary.

This stage is stronger than formatting or static syntax checks:

1. a generated package is materialized into a GN source tree;
2. GN evaluates the generated `BUILD.gn` through a dedicated root target;
3. Rust is compiled as a native static library;
4. the generated C++ consumer is compiled;
5. Ninja links a real executable containing both languages;
6. the executable calls the Rust export and its exit status is checked;
7. every temporary source overlay is removed;
8. GN and Ninja identities are rechecked after execution;
9. Rustc identity is also rechecked when the host adapter directly owns compiler invocation.

## Command

```bash
cargo run -p chromifer -- run-gn-integration \
  /path/to/Chromifer \
  /path/to/gn/source/root \
  examples/integration/c-abi.json \
  --gn /path/to/gn \
  --ninja /path/to/ninja \
  --rustc /path/to/rustc
```

The default executable names are `gn`, `ninja`, and `rustc`, resolved from `PATH` before the run. The summary records each used tool's requested name, invocation path, canonical target, SHA-256, byte count, and version. Every recorded tool file and invocation symlink is checked again after the endpoint completes.

## Integration contract

```json
{
  "schema_version": 1,
  "package_root": "examples/c-abi-bridge",
  "build_provenance": "examples/c-abi-bridge/chromifer-build.json",
  "c_abi_provenance": "examples/c-abi-bridge/include/api.h.chromifer.json",
  "destination": "examples/c-abi-bridge",
  "source_inputs": [
    ".gn",
    "BUILD.gn",
    "build/BUILD.gn",
    "build/BUILDCONFIG.gn",
    "build/toolchain/BUILD.gn"
  ],
  "endpoint_source": "consumer/main.cc",
  "endpoint_target": "c_abi_endpoint",
  "integration_target": "integration",
  "out_dir": "out/ChromiferIntegration",
  "rust_template": "host_adapter",
  "expected_exit_code": 0
}
```

The destination must match the `gn_package_path` stored in `chromifer-build.json`. This preserves generated root-relative includes and package visibility instead of rewriting the generated bridge.

`source_inputs` lists the GN checkout files whose bytes define the build environment. Structured gate derivation content-addresses every declared source input.

The integration runner also validates:

- build and C ABI provenance schema versions;
- generated `BUILD.gn` digest;
- C ABI contract, header, and Rust source digests;
- presence of a generated C++ consumer;
- endpoint source location;
- normalized, non-symlinked source and package paths;
- an output directory below `out/`;
- absence of a pre-existing overlay destination.

## Root-target isolation

GN supports a command-line root target. Chromifer generates with:

```text
gn gen <out> \
  --root-target=//examples/c-abi-bridge:integration \
  --ide=json \
  --json-file-name=project.json
```

The root `BUILD.gn` is not modified. The project graph contains only the integration group and its transitive dependencies.

The temporary package `BUILD.gn` is the generated file plus two integration-only targets:

```gn
executable("c_abi_endpoint") {
  sources = [ "consumer/main.cc" ]
  deps = [ ":c_abi_smoke" ]
}

group("integration") {
  deps = [ ":c_abi_endpoint" ]
}
```

The executable stays inside the package because the generated consumer deliberately exposes package-local visibility.

## Rust template modes

### `host_adapter`

The repository fixture does not contain Chromium's native Rust GN templates. Chromifer temporarily installs a narrow adapter under `//build/rust/`:

- an action invokes the exact resolved Rustc path;
- Rust sources are compiled with `--crate-type staticlib` and `panic=abort`;
- `allow_unsafe` is consumed from the generated target;
- safe targets receive `-F unsafe-code`;
- the static archive is propagated through a public GN config;
- Linux native libraries are supplied explicitly;
- the source root include directory is propagated to the generated C++ consumer.

The adapter exists only for the integration run and is removed afterward.

### `existing`

A full Chromium checkout already provides `//build/rust/rust_static_library.gni`. With `rust_template` set to `existing`, Chromifer requires that non-symlinked template, requires it in `source_inputs`, and does not install or modify it. Rustc identity is omitted in this mode because the existing GN toolchain, rather than Chromifer's host adapter, owns compiler selection.

The current repository CI proves the `host_adapter` path using upstream GN itself. Executing the `existing` mode against a pinned full Chromium checkout remains the next integration stage; this document does not claim that full Chromium build has already completed.

## Materialized files

Only files required by committed provenance are copied:

- generated `BUILD.gn`;
- Rust crate root and declared Rust sources;
- generated C++ consumer sources;
- required generated headers;
- C ABI contract inputs;
- the explicit endpoint source.

Cargo `target/`, arbitrary package files, and undeclared generated files are excluded.

All path components are checked for symlinks and root escape. Parents created solely for the overlay are tracked and removed in reverse order. The generated Ninja output under `out/` is retained for inspection and incremental reruns.

## Structured gate and evidence

The structured gate contract supports an `integration` check:

```json
{
  "kind": "integration",
  "id": "c-abi-gn-endpoint",
  "source_root": "examples/integration/gn-root",
  "contract": "examples/integration/c-abi.json",
  "modules": ["c_abi_bridge"],
  "targets": ["host"]
}
```

`derive-gates` reconstructs:

```text
run-gn-integration . examples/integration/gn-root examples/integration/c-abi.json
```

The resulting gate includes the integration contract, five GN source inputs, build provenance, C ABI provenance, generated `BUILD.gn`, Rust source, C++ consumer, generated header, C ABI contract, and endpoint source as hashed inputs.

The normal evidence runner executes this direct gate. It attests the outer Cargo executable, while `run-gn-integration` independently records and verifies GN and Ninja, plus Rustc when the host adapter directly invokes it.

## Pinned GN

The repository builds upstream GN at the exact revision:

```text
64cfb8344ec3e8585a89a3836716a026e2771fcb
```

Build it with:

```bash
examples/integration/build-pinned-gn.sh /tmp/chromifer-gn
export PATH="/tmp/chromifer-gn/out:$PATH"
```

The script performs a full clone because GN's generator uses the historical `initial-commit` tag to calculate its version. It checks out the exact detached revision and builds only the `gn` target.

Run the endpoint smoke:

```bash
examples/integration/run-smoke.sh
```

CI runs the standalone smoke first, then executes the same endpoint again as part of the complete structured evidence suite.

## Current verified result

With GN `2509 (64cfb8344ec3)`, Ninja `1.11.1`, and Rustc `1.88.0`, the fixture generates five GN targets, compiles the Rust archive and two C++ objects, links `c_abi_endpoint`, and exits with status 0.

The endpoint calls `ChromiferCAbiSmoke()`, which calls the Rust export `chromifer_add(20, 22)` through the generated C header and returns success only when the result is 42.

## Trust boundary

This proves that committed Chromifer generators can produce a Rust/C ABI package that survives real GN graph evaluation, Ninja compilation, native linking, and endpoint execution. It uses upstream GN and real host compilers.

It does not yet prove compatibility with every Chromium Rust template revision, Chromium's full toolchain wrappers, component builds, sanitizers, cross-compilation, or browser test infrastructure. Those require execution in pinned full Chromium checkouts and platform-specific builders.
