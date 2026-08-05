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

A boundary label is a claim that must eventually be supported by generated inventory data and boundary-specific tests. GN imports initially use `unclassified` for language crossings because the build graph does not prove which ABI is used.

## Inventory provenance

Generated manifests retain the GN build directory, default toolchain, selected roots, filtering flags, state-inference policy, and omitted dependency count. Each imported module also retains its exact GN label and target type. This makes later source analysis traceable to one Chromium revision and one generated build configuration.

GN groups, actions, and other targets without compilable sources are contracted by default: a source target depending on a group is connected to the nearest source targets reachable through that group. The original meta targets can be retained when build-system analysis requires them.

## Compatibility contracts

Every component leaving `legacy_cpp` must identify executable gates. Gates are commands, not prose. Planned gate classes include:

- Chromium unit and browser tests;
- Web Platform Tests;
- performance and memory regression budgets;
- crash, fuzzing, and sanitizer suites;
- platform build matrices;
- binary and IPC compatibility checks.

The migration planner verifies the presence and references of gates. A later executor will run them and attach immutable evidence to a proposed state transition.

## Upstream strategy

Chromifer should remain a downstream integration layer rather than a permanent full-tree fork. Rust components should be consumable from Chromium GN targets, while source patches stay small and mechanically rebaseable. Vendoring Chromium source into this repository is not planned.
