# Scanning source boundaries

GN proves that one target depends on another, but it does not identify the ABI, generated interface, or lifetime contract used by that edge. `scan-boundaries` adds source-level evidence to an imported manifest without treating textual matches as ownership proof.

## Run the scanner

Use the Chromium checkout that produced the GN export:

```bash
cargo run -p chromifer -- scan-boundaries \
  chromium-inventory.toml \
  /path/to/chromium/src \
  chromium-boundaries.toml
```

The input manifest must contain module source lists. `import-gn` now records them as root-relative paths. The output is a normal validated manifest and can be passed directly to `frontier` or `check-transition`.

Use `--force` to replace an existing output file and `--json` for a machine-readable summary.

## Automatic boundary evidence

The scanner changes an edge only when all detected high-confidence evidence agrees on one mechanism:

- `cxx_generated_header`: C++ includes a generated `.rs.h` or `cxxbridge` header owned by the dependency;
- `cxx_bridge_include`: a Rust file containing `#[cxx::bridge]` includes a header owned by the dependency;
- `c_abi_symbol`: one side declares an `extern "C"` symbol and the dependency defines the same symbol, or the reverse;
- `mojo_generated_header`: a generated `.mojom*.h` include maps to a `.mojom` source owned by the dependency.

Each evidence item stores its kind, source file, line number, and a compact explanation. Existing `unclassified` or `cpp_internal` edges may be upgraded to `cxx`, `c_abi`, or `mojo`. An existing audited boundary is never silently replaced.

When an edge has evidence for multiple mechanisms, the scanner records a conflict and leaves the boundary unchanged. This is common for aggregation targets and must be resolved by component grouping or manual inspection.

## Callback and observer reviews

Callbacks and observers are lifetime contracts, not transport mechanisms. The scanner therefore records them as review obligations instead of assigning a boundary type.

Current patterns include Chromium callback and closure types, `std::function`, Rust closure traits, `ObserverList`, `ScopedObservation`, and common observer registration calls. A finding is attached to a dependency edge only when the containing source file references exactly one dependency from the manifest. Ambiguous findings remain at module scope.

Unresolved module or edge reviews block a transition to `rust_owned`, even when the edge already uses CXX, C ABI, or Mojo. After auditing ownership, cancellation, thread affinity, reentrancy, and destruction order, mark the finding explicitly:

```toml
[[modules.dependencies.reviews]]
kind = "callback"
file = "services/example/client.cc"
line = 42
detail = "base::OnceCallback<void(Result)> completion"
resolved = true
```

Deleting a finding without recording the review loses provenance. Marking it resolved keeps the source location and the decision visible to later reviewers.

## Missing and generated sources

Missing files do not abort a scan. They are listed in the summary because GN exports can contain generated files that are absent until the corresponding build step runs. A manifest with many missing sources should not be treated as a complete boundary inventory.

Source paths are restricted to the supplied checkout root. GN-style `//path/to/file` paths are accepted; host absolute paths and parent-directory traversal are rejected.

## Current limits

The scanner is deliberately textual and conservative. It does not yet:

- expand C/C++ macros or fully parse multiline declarations;
- prove ownership, aliasing, thread, or destruction semantics;
- determine whether a callback actually crosses the detected dependency edge when several dependencies share one source file;
- group several GN targets into one migration component;
- identify which test target exercises each boundary;
- invalidate stale evidence automatically after the source baseline changes.

Run the scanner against the exact revision stored in the manifest. Source evidence from a different Chromium revision is not valid migration proof.
