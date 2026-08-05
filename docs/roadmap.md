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
- retain exact labels, target types, toolchain policy, roots, and omitted-edge counts; **implemented**
- contract non-source GN meta targets into source-target dependency edges; **implemented**
- group source targets into migration components;
- identify C++ ownership and callback crossings;
- emit a reproducible manifest with source locations;
- rank candidate components by boundary complexity and test coverage.

## M2 — Build-system bridge

- build Rust static libraries through Chromium's supported Rust toolchain;
- generate GN targets from Cargo metadata;
- establish CXX, C ABI, and Mojo boundary templates;
- enforce that `unsafe` appears only in designated bridge crates;
- build on Linux, Windows, and macOS.

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
