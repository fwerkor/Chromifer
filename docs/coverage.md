# Measured source coverage

Chromifer can ingest line coverage exported by LLVM and bind it to the exact source inventory of a migration manifest. The resulting report is deterministic, content-addressed by its inputs, and can be supplied to component ranking.

## Produce an LLVM export

Build and run the relevant Chromium tests with Clang source-based coverage enabled, merge the resulting profile data, then export JSON. Chromifer only requires the per-file line summaries, so `--summary-only` is sufficient:

```bash
llvm-cov export \
  --summary-only \
  -instr-profile merged.profdata \
  out/Coverage/unit_tests \
  > llvm-cov.json
```

Multiple instrumented objects should be passed to one `llvm-cov export` invocation. Chromifer rejects duplicate normalized file entries instead of guessing how independently exported counts should be combined.

## Generate the Chromifer report

```bash
cargo run -p chromifer -- summarize-coverage \
  chromium-owned.toml \
  /path/to/chromium/src \
  llvm-cov.json \
  chromifer-coverage.json
```

The report records:

- the exact migration-manifest SHA-256 and baseline;
- the LLVM export SHA-256 and export version;
- normalized repository-relative source paths;
- covered and coverable line counts per measured file;
- module-level measured and missing source counts;
- module and whole-manifest line coverage in basis points.

Use `--check` to regenerate the report in memory and reject committed-file drift.

## Path and input rules

Every source declared by the manifest must exist under the supplied source root. Source paths must be normalized repository-relative paths and may not traverse symlinks. Absolute filenames in the LLVM export are accepted only when they resolve below the same source root. Coverage for files that are not part of the manifest source inventory is ignored.

A manifest source absent from the LLVM export is recorded as missing. It is not silently treated as an uncovered file because the export does not provide a trustworthy executable-line denominator for that source.

The report loader validates its own line counts and duplicate paths. When `rank-components` consumes a report, Chromifer also checks the exact manifest digest and reconstructs module and total aggregates from the per-file entries, so edited aggregate summaries cannot override the measured file entries. The committed LLVM export remains the measurement input of record; `summarize-coverage --check` regenerates the report from that export and detects report/export drift.

## Ranking with measured coverage

```bash
cargo run -p chromifer -- rank-components \
  chromium-owned.toml \
  --coverage chromifer-coverage.json
```

The existing module/required-target gate matrix remains visible as `test_coverage`; it describes platform compatibility declarations. When measured source coverage is supplied, the ranking risk calculation uses measured source coverage instead of assigning the old declaration proxy a coverage-risk penalty.

For a component, Chromifer computes:

```text
measurement completeness = measured source files / manifest source files
line coverage            = covered lines / coverable lines
measured coverage score  = min(measurement completeness, line coverage)
source coverage risk     = ceil((1 - measured coverage score) * 25)
```

Files with zero coverable lines do not reduce line coverage. Missing manifest sources create an `incomplete_source_coverage` concern and make the candidate ineligible until the measurement is complete. Less than 100% line coverage increases risk but does not by itself block a component.

This keeps two different questions separate: whether required platform gates exist, and how much of the component source was actually exercised.

## Fixture

`examples/coverage/` contains a committed LLVM-export fixture and generated report. It measures three manifest sources and demonstrates both full and partial line coverage. CI verifies the report in `--check` mode and asserts that measured source risk is used by ranking.
