# Production migration exposure measurement

`chromifer measure-migration-exposure` measures the authored production surface of a migration against the exact upstream Git revision pinned by `pilot.toml`.

Each migration records its active source sets in `exposure-sources.toml`. Baseline files are read with `git show <pinned-revision>:<path>`; candidate files are read from the supplied Chromium working tree. Tests and generated CXX/Mojo bindings stay outside the inventory when `exposure.toml` declares them excluded.

The v1 measurement contract reports:

- **authored production LOC**: non-blank, non-comment source lines;
- **authored memory-unsafe LOC**: all active C/C++ authored LOC plus authored Rust lines covered by explicit unsafe blocks, unsafe functions/impls/traits, or unsafe foreign modules;
- **active implementation files**: the exact files listed for each configuration;
- **branch points**: deterministic structural branch counts for C/C++ and Rust;
- **manual raw-pointer fields**: `raw_ptr`/`raw_ref` or raw pointer fields in C/C++, and raw-pointer struct fields in Rust;
- **cross-language forwarding methods**: explicit reviewed method names in the source inventory, because generated bindings are excluded;
- **new public API / Mojom methods**: explicit contract-review counts. Public API parity is not inferred from fragile C++ text heuristics.

The report hashes every measured source file and a canonical stream of raw counts, forwarding-method declarations, and contract-review counts. `--check` recomputes the report and rejects drift from committed `[results]` in `exposure.toml`.

Example:

```sh
cargo run -p chromifer -- measure-migration-exposure \
  migrations/services-metrics-ukm-recorder \
  /path/to/chromium/src \
  --json
```

A measurement does not imply acceptance. `validate-migration` separately enforces the pilot's configured reduction and non-regression criteria; a candidate whose measured surface grows remains explicitly incomplete.
