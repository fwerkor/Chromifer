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
- attest exact Git revision, dirty state, recursive submodules, and Git executable identity; **implemented**
- attest direct gate executable entry paths and canonical binary hashes before and after execution; **implemented**
- lock nested Chromium source revision, gclient metadata, GN outputs, and required target semantics; **implemented**
- validate required targets against live `gn desc` output; **implemented**
- measure source coverage rather than declaration proxies; **implemented**
- bind measured source coverage, LLVM exports, and exact source files into structured gate evidence; **implemented**
- sign evidence with a detached Ed25519 runner identity and externally pinned public key; **implemented**
- isolate production signing keys and add transparency-backed source/workload attestation.

## M2 — Build-system bridge

- generate first-party `rust_static_library` GN targets from Cargo metadata; **implemented**
- detect CXX bridge sources and generate `cxx_bindings`; **implemented**
- require explicit Cargo dependency to GN label mappings; **implemented**
- persist deterministic build provenance and detect generated-file drift; **implemented**
- generate C++ `source_set` consumers with verified CXX include contracts; **implemented**
- support multiple consumer targets selecting different CXX bridge subsets;
- translate a proven Cargo `cfg` OS/architecture subset into GN conditions; **implemented**
- extend condition translation to additional exact Cargo/Chromium mappings;
- establish an explicit C ABI contract, Rust export validator, generated header, and GN consumer integration; **implemented**
- establish multi-target Mojo contracts, import resolution, C++/Rust targets, and deterministic provenance; **implemented**
- derive direct compatibility gates and hashed inputs from Rust GN, C ABI, Mojo, unsafe, checkout, and integration provenance; **implemented**
- compile, link, and execute a generated Rust/C ABI endpoint through pinned upstream GN and Ninja; **implemented**
- validate generated bindings and endpoint behavior through Chromium's native Rust template and bundled toolchain at a pinned revision; **implemented**
- exercise deterministic arithmetic, repeated-call, null-pointer, length, and bool-return C ABI behavior in both integration paths; **implemented**
- enforce safe packages, designated bridge sources, local unsafe allowances, and deterministic audit evidence; **implemented**
- build generated bridge examples on Linux, Windows, and macOS.

M2 now emits first-party Rust targets, CXX and C ABI consumers, multi-target Mojo bindings, unsafe-policy evidence, structured direct gates, executable attestations, deterministic Chromium checkout locks, a lightweight upstream-GN endpoint, and a Chromium-native endpoint using the pinned Rust template, local standard library, bundled Rustc, Clang, and Ninja. The next integration work is platform expansion and binding/runtime coverage beyond the C ABI smoke.

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
