# Architecture

## Objective

Chromifer incrementally replaces Chromium's browser-side infrastructure while retaining upstream behavior and mergeability. The unit of migration is a component with an explicit boundary, dependency graph, owner, and compatibility contract.

## Layer model

```text
Product
  Browser UI, extensions, settings
Browser services
  Network, storage, permissions, downloads, identity
Process and security kernel
  Navigation, site isolation, sandbox, IPC supervision
Web runtime
  Blink and V8
Graphics and media
  Skia, ANGLE, codecs, platform acceleration
```

The first three layers are primary Rust migration targets. Web runtime, graphics, and media remain upstream C++ subsystems until their interfaces are stable and measured migration value justifies replacement.

## Boundary types

- `unclassified`: imported or observed edge whose ABI has not been audited. Always blocks Rust ownership.
- `cpp_internal`: private C++ ownership or ABI assumptions. Never accepted for a Rust-owned crossing.
- `cxx`: typed bridge generated through the CXX interoperability model.
- `c_abi`: narrow C-compatible ABI with explicit ownership and error contracts.
- `mojo`: process boundary using Chromium Mojo interfaces.
- `rust`: native Rust dependency.

A boundary label is a claim that must be supported by source evidence and boundary-specific tests. GN imports initially use `unclassified` for language crossings because the build graph does not prove which ABI is used. The source scanner can attach file-and-line evidence for high-confidence CXX, C ABI, and Mojo crossings, but it never treats a textual match as proof of ownership semantics.

Callback and observer findings are separate review obligations. They describe lifetime, cancellation, reentrancy, thread-affinity, or destruction-order risks that remain even when the transport mechanism is audited. An unresolved finding blocks `rust_owned`; a reviewer must preserve the finding and mark it resolved after auditing the contract.

## Inventory provenance

Generated manifests retain the GN build directory, default toolchain, selected roots, filtering flags, state-inference policy, and omitted dependency count. Each imported module also retains its exact GN label, target type, and root-relative source list. Source evidence records the file, line, mechanism, and review status. This makes later analysis traceable to one Chromium revision and one generated build configuration.

GN groups, actions, and other targets without compilable sources are contracted by default: a source target depending on a group is connected to the nearest source targets reachable through that group. The original meta targets can be retained when build-system analysis requires them.

Source targets are then grouped into component proposals by owner and directory prefix. Internal target edges disappear inside the proposal; crossing edges retain their boundary types, evidence, unresolved reviews, and ownership changes. The proposal and ranking policy are deterministic and documented rather than inferred by a statistical model.

The owner key is refined from Chromium OWNERS files when available. Per-source primary and inherited owners are stored separately from the project's architectural owner label, including `set noparent`, per-file rules, and included owner files.

Candidate ranking uses compatibility-gate declaration coverage only as a proxy. Actual execution is recorded separately as content-addressed evidence: the exact manifest digest, execution definitions, hashed inputs, results, timings, and full output logs can be re-verified before a transition check consumes them. Optional checkout attestation binds the evidence runner's Git worktree and direct executables. A separate Chromium checkout lock binds a nested gclient workspace to an exact source revision, DEPS/gclient metadata, GN args, Ninja output, normalized project export, and required target semantics. Source coverage and signed runner identity remain separate requirements.

## Compatibility contracts

Every component leaving `legacy_cpp` must identify executable gates. Gates are commands, not prose. Legacy manifests may retain shell command strings; generated gates use a program and argument vector so shell syntax cannot alter argument boundaries. Planned gate classes include:

- Chromium unit and browser tests;
- Web Platform Tests;
- performance and memory regression budgets;
- crash, fuzzing, and sanitizer suites;
- platform build matrices;
- binary and IPC compatibility checks.

The migration planner verifies the presence and references of gates. The evidence executor verifies each declared input digest before launch, runs selected gates, preserves full content-addressed logs, and writes a content-addressed JSON bundle. Verification recomputes the bundle digest, manifest digest, execution and input definitions, result consistency, every referenced log digest, checkout before/after consistency, and executable before/after consistency before the evidence can support a transition check. Optional live verification compares the recorded final checkout and executable identities with a supplied worktree.

Build contracts do not require maintainers to duplicate generator commands in migration manifests. `derive-gates` reads committed Rust GN, C ABI, Mojo, unsafe, Chromium checkout, and endpoint integration provenance, verifies every referenced digest, reconstructs direct argument vectors, attaches the resulting gates to selected modules, and includes the source manifest and derivation contract in every gate's input set.

## Build bridge

First-party Cargo libraries are projected into Chromium's `rust_static_library` template. The bridge records Cargo manifest digest, source inventory, edition, features, CXX bridge files, dependency mappings, visibility, unsafe policy, and the generated BUILD.gn digest. Cargo dependencies never become GN dependencies by name inference: every active dependency requires an explicit GN label, while CXX's own machinery is supplied through `cxx_bindings`.

For CXX migrations, the same BUILD.gn can contain a generated C++ `source_set`. Chromifer derives each generated header from the Chromium package path and Rust bridge source, verifies that the declared consumer sources actually include every header, records file-and-line evidence, and gives the consumer a private dependency on the Rust target.

For C ABI migrations, an explicit JSON contract is authoritative for exported symbol names and signatures. Chromifer parses Rust source syntax, requires a matching public `no_mangle` `extern "C"` definition for every contract symbol, rejects uncontracted or duplicate exports, generates a deterministic C header, and records contract, source, symbol, and header digests. The generated header can be attached to the same C++ consumer model, which verifies the repository-root include path before generating GN.

The endpoint integration harness materializes only provenance-declared package files into a GN source tree and selects an integration group through GN's `--root-target`, leaving the checkout's root BUILD file untouched. Upstream GN evaluates the generated package, Ninja compiles the Rust static archive and C++ consumer, and a package-local executable calls the Rust export. Tool identities are recorded before execution and rechecked afterward; temporary source overlays and newly created parent directories are removed in reverse order.

For Mojo migrations, a multi-target JSON contract assigns every package-local `.mojom` source to one target and maps every external import to an exact GN label. Chromifer derives local `public_deps`, rejects unowned local imports and target cycles, inventories top-level declarations, reserves Chromium's generated target namespace, and emits `mojom()` targets with `generate_rust = true`. Provenance records the C++ and `_rust` labels, source digests, import lines, declarations, and resolved dependency graph; Chromium's real Mojom parser and generators remain authoritative for complete IDL and runtime validation.

Unsafe Rust is governed by a workspace-level policy rather than by the GN `allow_unsafe` switch alone. Safe packages require `forbid(unsafe_code)` at every crate root and may contain neither unsafe syntax nor local allowances. Bridge packages require `deny(unsafe_code)` and `deny(unsafe_op_in_unsafe_fn)`, an exact unsafe-source allowlist, and a used local `allow(unsafe_code)` scope for every occurrence. The audit records Cargo manifests, the lockfile, source digests, crate-root lint posture, unsafe syntax, and authorizing allowances; stale allowances, source symlinks, and `include!` injection are rejected.

Target-specific Cargo dependencies pass through a strict `cfg(...)` parser. Only OS and CPU predicates with an explicit Chromium GN equivalent, plus `all/any/not`, are translated; the original Cargo condition and canonical GN expression remain in provenance. Inexact families such as bare `unix`, arbitrary target triples, and unknown keys or values are rejected rather than linked unconditionally. Generated files support a check-only mode and are intended to be committed beside the Rust package.

## Upstream strategy

Chromifer should remain a downstream integration layer rather than a permanent full-tree fork. Rust components should be consumable from Chromium GN targets, while source patches stay small and mechanically rebaseable. Vendoring Chromium source into this repository is not planned.
