# UKM recorder Rust pilot

This directory tracks Chromifer's first M3 production-component pilot against Chromium revision `008cdad85f0721c89b42ef4dcaabcee615482609`.

## Scope

The pilot replaces the implementation of `ukm.mojom.UkmRecorderInterface` inside `//services/metrics:metrics`. The legacy receiver is a self-owned C++ Mojo implementation with two methods: `AddEntry` and `UpdateSourceURL`. The pilot keeps Chromium's public Mojo contract and `UkmRecorderFactoryImpl` entry point stable while moving receiver dispatch into Rust and retaining a narrow C++ bridge to `ukm::UkmRecorder`.

The migration deliberately does not broaden into `components/ukm`, metrics storage, reporting, or browser-process orchestration.

## Stabilization rollback

The migrated build defines `use_rust_ukm_recorder`, defaulting to `enable_rust`. When enabled, `//services/metrics:metrics` builds the Rust receiver and its C++ bridge. When disabled, it builds the original `ukm_recorder_interface.cc/.h` implementation.

A shared `//services/metrics:ukm_recorder_interface_unittests` target is available in both configurations. The Rust configuration currently passes three tests, including the end-to-end Mojo receiver path. The C++ fallback configuration passes the same interface-contract path, and its GN dependency graph contains neither the Rust receiver nor the scoped-handle interop dependency.

## M3 acceptance work

The rollback criterion is complete for the current Linux checkout. The exact Chromium implementation patch is now stored as `chromium.patch` and bound to the pinned upstream revision by SHA-256 in `pilot.toml`. Remaining work before calling the pilot M3-complete is:

- finish and record `//components/ukm:ukm_unittests` against the Rust configuration;
- expand contract coverage for receiver lifetime/disconnect behavior and richer UKM entry payloads where needed;
- build and execute the migration on the supported desktop configurations rather than inferring portability from the Mojo contract;
- define and run an apples-to-apples performance budget for receiver creation and message forwarding;
- measure active C++/Rust implementation surface, unsafe exposure, and maintenance complexity against the legacy implementation;

`pilot.toml` is the machine-readable status record. A pending item remains explicitly pending rather than being inferred from a successful narrower test.
