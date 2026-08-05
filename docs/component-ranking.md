# Component aggregation and candidate ranking

Chromium's GN graph is too fine-grained to use one build target as one migration project. `rank-components` contracts related GN targets into deterministic component proposals and ranks the non-Rust-owned components for follow-up engineering.

## Run the analysis

```bash
cargo run -p chromifer -- rank-components \
  chromium-boundaries.toml
```

Use a different directory prefix depth when the default two-segment grouping is too broad or too narrow:

```bash
cargo run -p chromifer -- rank-components \
  chromium-boundaries.toml \
  --path-depth 3
```

Machine-readable output includes every component, aggregated edge, metric, concern, and ranked candidate:

```bash
cargo run -p chromifer -- rank-components \
  chromium-boundaries.toml \
  --json > component-analysis.json
```

Each component includes a `risk` object containing every individual point contribution and the capped total, so automation does not need to reconstruct the formula from prose.

## Aggregation policy

The default policy groups modules by:

1. the inferred primary Chromium owner set, falling back to the manifest owner; and
2. the first two directory segments of the module path.

For example, targets under `services/network/core` and `services/network/public` become one `services/network` proposal when they have the same owner. Identical paths with different owners remain separate components.

The policy is intentionally mechanical:

- component IDs are deterministic;
- source files, gates, and migration-state counts are unioned;
- module dependencies inside one component are folded away;
- dependencies crossing components are aggregated by source and destination;
- every distinct boundary type, evidence count, unresolved review count, and owner crossing is retained.

This is a proposal generator, not a declaration of architectural truth. A maintainer can change `--path-depth` or later replace the proposal with an explicit component definition.

## Compatibility coverage proxy

The analysis reports a strict `module × required target` gate-coverage proxy. A pair is covered only when that module references a defined compatibility gate that includes the required target.

For a component containing two modules and three required targets, full proxy coverage is six covered pairs.

This metric proves only that executable gates are declared. It does not prove that:

- the gate was executed successfully;
- the relevant source paths are exercised;
- branch or line coverage is sufficient;
- performance and compatibility budgets pass.

Actual gate results are produced by `run-gates` and verified by `verify-evidence`; they remain separate from this declaration-based ranking score.

## Migration scopes

Directory paths receive an explicit scope priority:

| Scope | Typical paths | Risk points |
|---|---|---:|
| `browser_service` | `services/*` | 0 |
| `reusable_infrastructure` | `base`, `components/*`, `net/*`, `ui/*` | 5 |
| `process_security_kernel` | `content/*`, `chrome/*` | 15 |
| `deferred_runtime` | Blink, V8, Skia, GPU, media | 40 |
| `other` | unmatched paths | 10 |

The scope policy implements the roadmap decision to migrate a self-contained browser service before process orchestration or major runtime engines. A deferred-runtime component is never marked ready.

## Readiness score

The score is deterministic and deliberately transparent. The analysis starts with zero risk points and adds:

| Factor | Risk points |
|---|---:|
| Additional module after the first | 2 each, capped at 20 |
| Source volume | 1 per started block of 10 files, capped at 15 |
| Incident component topology | 1 per incoming/outgoing component, capped at 20 |
| `unclassified` or `cpp_internal` external boundary type | 8 each |
| Audited CXX, C ABI, or Mojo external boundary type | 2 each |
| Native Rust external boundary type | 1 each |
| All boundary points | capped at 40 |
| Unresolved callback/observer review | 10 each, capped at 40 |
| Mixed migration states inside one proposal | 20 |
| No compatibility gates | 15 |
| Missing required module-target gate pairs | proportional penalty from 0 to 25 |
| Migration scope | table above |

The total risk is capped at 100:

```text
readiness_score = 100 - risk_score
```

A component is marked `ready` only when it has source files, compatibility gates, complete required-target gate declarations, one migration-state class, no unresolved callback/observer reviews, no private or unclassified external boundary, and is outside the explicitly deferred runtime scope.

A high score is a triage result, not permission to merge a Rust replacement. The transition planner and executable compatibility gates remain authoritative.

## Candidate ordering

Non-Rust-owned components are ordered by:

1. ready components before audit-required components;
2. higher readiness score;
3. lower risk score;
4. fewer source files;
5. stable component ID.

Fully Rust-owned components remain in the component graph but are omitted from the migration candidate ranking.
