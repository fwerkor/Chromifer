# Structured compatibility gates

Chromifer can derive executable compatibility gates directly from committed build and boundary provenance. Generated gates use an exact program plus argument vector and declare every file whose bytes define the check. This removes shell parsing from generated checks and makes contract drift visible before a process is launched.

## Gate execution forms

Migration manifests accept exactly one of two execution forms. Declaring both forms, mixing shell commands with direct arguments, or adding unknown gate fields is rejected during parsing.

Legacy shell gates remain supported:

```toml
[[gates]]
id = "browser-tests"
command = "autoninja -C out/Default browser_tests && out/Default/browser_tests"
```

Generated gates use direct execution:

```toml
[[gates]]
id = "c-abi-current"
program = "cargo"
args = [
  "run",
  "-q",
  "-p",
  "chromifer",
  "--",
  "generate-c-abi",
  "examples/c-abi-bridge",
  "examples/c-abi-bridge/c-abi.json",
  "examples/c-abi-bridge/include/api.h",
  "--check",
]
```

Direct gates call `Command::new(program).args(args)`. Shell metacharacters, quoting characters, substitutions, and redirections are passed as literal argument bytes rather than interpreted by `sh` or `cmd`.

## Hashed inputs

A gate may declare repository-relative inputs:

```toml
[[gates.inputs]]
path = "examples/c-abi-bridge/c-abi.json"
sha256 = "...64 lowercase hexadecimal characters..."
```

Before process launch, the evidence executor reads every input from the selected work directory and compares its SHA-256 with the manifest. A missing or changed input produces `launch_failed`; the command is not started. Inputs are checked again after process completion. A command that changes an input is marked failed even when it exits with status 0.

Input paths must be normalized repository-relative paths. Absolute paths, parent traversal, malformed digests, duplicate inputs, input symlinks, and paths that resolve outside the work directory are rejected.

## Derivation contract

`derive-gates` reads a source migration manifest and a JSON contract describing which committed provenance files should become checks:

```bash
cargo run -p chromifer -- derive-gates \
  . \
  examples/gates/base.toml \
  examples/gates/gates.json \
  examples/gates/generated.toml
```

The contract has one runner and one or more checks:

```json
{
  "schema_version": 1,
  "runner": {
    "program": "cargo",
    "args": ["run", "--locked", "-q", "-p", "chromifer", "--"]
  },
  "checks": [
    {
      "kind": "c_abi",
      "id": "c-abi-current",
      "package_root": "examples/c-abi-bridge",
      "provenance": "examples/c-abi-bridge/include/api.h.chromifer.json",
      "modules": ["c_abi_bridge"],
      "targets": ["host"]
    }
  ]
}
```

Each check ID must be unique and must not already exist in the source manifest. Module references and target references are validated against the generated manifest.

## Supported provenance

Seven check kinds are currently supported.

### `rust_gn`

Reads `chromifer-build.json`, verifies its schema and all referenced files, then reconstructs the exact `generate-gn ... --check` argument vector. Inputs include:

- Cargo manifest and nearest `Cargo.lock`;
- generated `BUILD.gn`;
- bridge provenance;
- all Rust sources;
- C++ consumer sources and explicit C ABI headers.

Cargo dependency mappings, features, visibility, target name, unsafe policy, GN-only dependencies, package path, and consumer settings are reconstructed from provenance rather than copied from the gate contract.

### `c_abi`

Reads the generated C ABI provenance and reconstructs `generate-c-abi ... --check`. The contract, generated header, provenance, and every Rust source are content-addressed inputs.

### `mojo`

Reads `chromifer-mojo.json` and reconstructs `generate-mojo ... --check`. The Mojo contract, generated `BUILD.gn`, provenance, and all Mojom sources are inputs.

### `unsafe`

Reads `chromifer-unsafe.json` and reconstructs `audit-unsafe ... --check`. Inputs include the workspace manifest, lockfile, unsafe policy, audit report, every package manifest, and every inventoried Rust source.

### `checkout`

Reads a Chromium checkout contract and deterministic lock report, verifies their schema and contract digest, then reconstructs `audit-checkout ... --check`. Inputs include the contract, lock report, gclient/DEPS metadata, every locked `args.gn`, `build.ninja`, and GN project export. Raw file identities are checked against the lock when available; path-normalized metadata and the semantic project digest are revalidated by `audit-checkout` itself.

The portable derived gate does not add `--gn` because depot_tools locations are environment-specific and GN would be a subprocess of the direct gate runner. CI should run `audit-checkout --gn ... --check` separately before executing the derived gate.

### `integration`

Reads a GN endpoint integration contract and reconstructs `run-gn-integration . <source-root> <contract>`. Inputs include the contract, every declared GN checkout input, build provenance, C ABI provenance, generated `BUILD.gn`, Rust sources, generated C++ consumer, required C header, C ABI contract, and endpoint source.

The direct gate resolves GN and Ninja from the runner environment. In `host_adapter` mode it also resolves the CLI-selected Rustc; in `existing` mode the contract names a source-relative native Rustc that must be included in `source_inputs`. `run-gn-integration` records and rechecks every declared tool; the outer evidence executor independently attests the Cargo executable used to launch the gate.

### `coverage`

Reads a deterministic `chromifer-coverage.json`, verifies that its manifest digest, baseline, per-file measurements, module aggregates, and totals match the selected coverage manifest, and reconstructs `summarize-coverage ... --check`. Inputs include the coverage manifest, LLVM export, generated coverage report, and every manifest source below the configured source root. The LLVM export digest stored in the report is checked during derivation, while the direct gate regenerates the report from that export during execution.

## Generated manifest

The output is a complete migration manifest. Generated gates are sorted by ID and attached to the modules named in the contract. Every gate also includes the source manifest and gate contract as inputs, binding the result to the exact derivation request.

Use check mode in CI:

```bash
cargo run -p chromifer -- derive-gates \
  . examples/gates/base.toml examples/gates/gates.json \
  examples/gates/generated.toml \
  --check
```

Changes to provenance, source files, generated outputs, dependency locks, the source manifest, or the derivation contract require the generated manifest to be refreshed.

## Execution and evidence

The generated manifest uses the normal evidence pipeline:

```bash
cargo run -p chromifer -- run-gates \
  examples/gates/generated.toml \
  . \
  evidence-root

cargo run -p chromifer -- verify-evidence \
  examples/gates/generated.toml \
  evidence-root/evidence/<digest>.json \
  evidence-root
```

Evidence schema version 3 records the exact execution form, argument vector, input paths and digests, declared platform targets, status, timing, content-addressed stdout/stderr, and optional checkout/tool attestations. Verification compares the execution definition and input contract with the current manifest before accepting the logs.

`examples/gates` derives six real checks from this repository's Rust GN, C ABI, Mojo, unsafe, measured source coverage, and GN endpoint integration provenance. All six are executed through the same evidence runner in CI.

## Trust boundary

The derivation proves that a check command and its declared inputs correspond to committed Chromifer provenance. Checkout and executable attestations can additionally bind a run to the selected revision and tool binaries. They still do not prove that the host or initial filesystem state was trustworthy. Isolated runners, signed evidence, and transparency-backed source attestations remain separate requirements.
