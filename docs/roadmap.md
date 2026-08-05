# Roadmap

## M0 — Migration kernel

Acceptance criteria:

- validated component manifests;
- cycle and unknown-reference detection;
- explicit compatibility gates;
- conservative transition planning;
- deterministic CLI and JSON output;
- CI on Linux.

## M1 — Chromium inventory

- import GN target metadata from a Chromium checkout; **implemented**
- retain exact labels, target types, source lists, toolchain policy, roots, and omitted-edge counts; **implemented**
- contract non-source GN meta targets into source-target dependency edges; **implemented**
- detect high-confidence CXX, C ABI, and Mojo edge evidence; **implemented**
- record callback and observer review obligations and enforce their resolution; **implemented**
- emit a reproducible manifest with source locations; **implemented**
- group source targets into owner-aware migration components; **implemented**
- retain component-level boundary sets, evidence, review obligations, and owner crossings; **implemented**
- rank candidate components with a documented boundary, topology, scope, and gate-coverage proxy; **implemented**
- infer Chromium `OWNERS` hierarchy beyond the manifest's current owner field; **implemented**
- execute compatibility gates and persist content-addressed results and logs; **implemented**
- verify evidence against exact manifest bytes, gate definitions, and log digests; **implemented**
- measure source coverage rather than declaration proxies;
- sign evidence with isolated runner identity and source-checkout attestation.

## M2 — Build-system bridge

- generate first-party `rust_static_library` GN targets from Cargo metadata; **implemented**
- detect CXX bridge sources and generate `cxx_bindings`; **implemented**
- require explicit Cargo dependency to GN label mappings; **implemented**
- persist deterministic build provenance and detect generated-file drift; **implemented**
- generate C++ `source_set` consumers with verified CXX include contracts; **implemented**
- support multiple consumer targets selecting different CXX bridge subsets;
- translate supported Cargo target conditions into GN conditions;
- establish C ABI and Mojo boundary templates;
- enforce that `unsafe` appears only in designated bridge crates;
- build generated bridge examples on Linux, Windows, and macOS.

Evidence execution is available before the build bridge, but current gates still depend on commands supplied by the manifest. The first M2 generator now emits first-party Rust GN targets and deterministic provenance; subsequent work will generate C++ consumer targets and build/test gate definitions from the bridge model.

## M3 — First production component

Target a self-contained browser service rather than Blink or V8. Candidate selection will be data-driven after M1. Acceptance requires:

- feature parity on all supported desktop platforms;
- upstream test parity;
- no regression outside defined performance budgets;
- rollback through a build flag during stabilization;
- a measured reduction in memory-safety exposure and maintenance complexity.

## M4 — Service migration pipeline

- reusable compatibility harness;
- automated shadow execution against the C++ implementation;
- differential state and IPC comparison;
- migration evidence recorded per Chromium revision;
- multiple Rust-owned browser services.

## M5 — Process and security kernel

Gradually migrate navigation orchestration, process supervision, and sandbox-facing policy code only after the service pipeline has demonstrated reliable parity enforcement.

## Explicitly deferred

A clean-room Blink, V8, Skia, ANGLE, or media rewrite is not part of the initial program. Those projects would each require independent research and compatibility programs.
