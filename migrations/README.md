# Production migration evidence

Each directory under `migrations/` is a revision-pinned record for one real Chromium production migration. These records are stricter than design notes: an acceptance state is only advanced after the corresponding evidence has been executed against the pinned upstream revision.

A pilot directory contains:

- `pilot.toml` — scope, upstream identities, boundary, rollback configuration, executed verification, and aggregate M3 status;
- `parity.toml` — interface contract cases, upstream test suites, and supported-desktop matrix;
- `performance.toml` — baseline/candidate comparison protocol and regression budgets;
- `exposure.toml` — reproducible memory-safety exposure and maintenance-complexity measurements;
- the exact upstream patch and its digest once the implementation has stabilized.

Status values deliberately distinguish `pending`, `partial`, `defined_not_measured`, and verified/passed states. Defining a budget does not satisfy it, a Linux contract test does not establish desktop parity, and a rollback flag is not considered verified until the fallback configuration is actually built and its contract test executed.

Validate any pilot directory with the same fail-closed contract used by repository tests:

```bash
cargo run -p chromifer -- validate-migration migrations/services-metrics-ukm-recorder
```

The validator rejects schema/version drift, invalid upstream identities, boundary/parity method drift, incomplete rollback evidence, cross-revision performance or exposure evidence, mismatched linked statuses, empty parity suites, and attempts to mark an incomplete pilot as complete.

M3 may be marked complete only when feature parity, upstream test parity, performance, rollback, memory-safety reduction, and maintenance-complexity reduction all have recorded passing evidence at the same pinned Chromium revision.
