# UKM recorder Rust pilot

This directory tracks Chromifer's first M3 production-component pilot against Chromium revision `008cdad85f0721c89b42ef4dcaabcee615482609`.

## Scope

The pilot migrates the `ukm.mojom.UkmRecorderFactory` dispatch path together with its `ukm.mojom.UkmRecorderInterface` child receivers inside `//services/metrics:metrics`. Chromium callers continue to use the existing `UkmRecorderFactoryImpl::Create` entry point and the public Mojom contract is unchanged.

When the Rust path is enabled, Rust owns both Mojo receiver lifetimes and dispatch. A single `SharedPtr<UkmRecorderFactoryImpl>` is used as a narrow C++ capability for access to the existing `ukm::UkmRecorder`; the capability stores a non-null `raw_ref`, checks its sequence on recorder access, and performs the small conversions needed at the Rust/C++ boundary. Client remotes are transferred into the existing `UkmRecorderClientInterfaceRegistry` rather than reimplementing that cross-thread registry in this pilot.

The migration deliberately does not broaden into `components/ukm`, metrics storage, reporting, or the client-registry state machine.

## Stabilization rollback

The migrated build defines `use_rust_ukm_recorder`, defaulting to `enable_rust`. When enabled, `//services/metrics:metrics` builds the combined Rust factory/recorder implementation. When disabled, GN selects a source-separated C++ factory plus Chromium's original `ukm_recorder_interface.cc/.h` implementation; the Rust target and scoped-handle interop dependency are absent from that implementation path.

A shared `//services/metrics:ukm_recorder_interface_unittests` target runs in both configurations. The Rust configuration passes three tests: two direct capability tests and one end-to-end Mojo contract test. The shared Mojo test covers multi-metric entries, ordered calls on one receiver, and multiple independent child receivers. The C++ rollback configuration passes the same end-to-end contract.

### Performance measurement

The Chromium patch provides `//services/metrics:ukm_recorder_interface_perf`, an in-process Mojo harness for the four workloads declared in `performance.toml`. Build separate release-like outputs for `use_rust_ukm_recorder=false` and `true`, then run the controller-side comparison runner with their exact `args.gn` files:

```bash
python3 migrations/services-metrics-ukm-recorder/measure_performance.py \
  --baseline-binary /path/to/cpp/ukm_recorder_interface_perf \
  --candidate-binary /path/to/rust/ukm_recorder_interface_perf \
  --baseline-args /path/to/cpp/args.gn \
  --candidate-args /path/to/rust/args.gn \
  --raw-output /path/to/raw-samples.json
```

The runner first rejects baseline/candidate GN args that differ outside `use_rust_ukm_recorder`, then alternates candidate/baseline order between samples, pins each invocation to one allowed CPU, rejects excessive background load or a changed CPU frequency policy, verifies the forwarded-message count, and prints the `[results]` block expected by `performance.toml`. It does not edit the manifest or declare a pass automatically; the raw evidence and reported budgets must be reviewed first.

## M3 acceptance work

The Linux rollback criterion and focused contract path are verified. `chromium.patch` is bound to the pinned upstream revision by SHA-256 and must be regenerated whenever the candidate implementation changes. Remaining work before calling the pilot M3-complete is:

- build and execute the migration on the supported desktop configurations rather than inferring portability from the Mojo contract;
- run the defined apples-to-apples performance budget for receiver creation and message forwarding;
- resolve the maintenance-complexity acceptance criterion with measured evidence rather than weakening it to fit the implementation.

`pilot.toml` is the machine-readable status record. A pending item remains explicitly pending rather than being inferred from a successful narrower test. `exposure-sources.toml` records the exact active production source inventory used by `chromifer measure-migration-exposure`. On the current combined candidate, the reproducible measurement reduces authored memory-unsafe LOC from 98 to 97, active implementation files from 4 to 3, and manual raw-pointer fields from 2 to 1. The idiomatic candidate has two authored branch points versus one in the baseline, and authored production LOC grows from 98 to 160 because of the Rust/CXX boundary, so the existing maintenance gate is intentionally not marked passed.
