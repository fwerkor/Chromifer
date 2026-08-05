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

Candidate ranking uses compatibility-gate declaration coverage only as a proxy. Actual execution is recorded separately as content-addressed evidence: the exact manifest digest, commands, results, timings, and full output logs are hashed and can be re-verified before a transition check consumes them. Source coverage and signed runner attestations remain separate requirements.

## Compatibility contracts

Every component leaving `legacy_cpp` must identify executable gates. Gates are commands, not prose. Planned gate classes include:

- Chromium unit and browser tests;
- Web Platform Tests;
- performance and memory regression budgets;
- crash, fuzzing, and sanitizer suites;
- platform build matrices;
- binary and IPC compatibility checks.

The migration planner verifies the presence and references of gates. The evidence executor runs selected gates, preserves full content-addressed logs, and writes a content-addressed JSON bundle. Verification recomputes the bundle digest, manifest digest, gate definitions, result consistency, and every referenced log digest before the evidence can support a transition check.

## Upstream strategy

Chromifer should remain a downstream integration layer rather than a permanent full-tree fork. Rust components should be consumable from Chromium GN targets, while source patches stay small and mechanically rebaseable. Vendoring Chromium source into this repository is not planned.
