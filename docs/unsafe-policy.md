# Unsafe-code policy

Chromifer treats `unsafe` as a boundary contract, not as a package-wide permission bit. The `audit-unsafe` command inventories a Cargo workspace, validates every workspace package against an explicit policy, and writes deterministic evidence that can be committed and checked in CI.

## Command

```bash
chromifer audit-unsafe \
  Cargo.toml \
  unsafe-policy.json \
  chromifer-unsafe.json
```

Use `--check` in CI to regenerate the report in memory and fail if the committed report differs:

```bash
chromifer audit-unsafe \
  Cargo.toml \
  unsafe-policy.json \
  chromifer-unsafe.json \
  --check
```

The Cargo executable can be overridden with `--cargo`. `--force` replaces an existing report and cannot be combined with `--check`.

## Policy format

The policy must list every Cargo workspace package exactly once:

```json
{
  "schema_version": 1,
  "packages": [
    {
      "package": "safe-library",
      "mode": "safe"
    },
    {
      "package": "ffi-bridge",
      "mode": "bridge",
      "allowed_sources": ["src/ffi.rs"]
    }
  ]
}
```

Unknown packages, duplicate package entries, omitted workspace packages, duplicate allowed source paths, missing files, absolute paths, and parent traversal are rejected.

## Safe packages

Every crate root in a `safe` package must contain exactly one crate-level:

```rust
#![forbid(unsafe_code)]
```

A safe package fails when the scanner finds any unsafe occurrence or any `#[allow(unsafe_code)]`. `warn`, `allow`, `expect`, a missing lint, or multiple root declarations do not satisfy the policy.

## Bridge packages

A bridge package must contain actual unsafe syntax and must list every source file allowed to contain it. Each crate root must use:

```rust
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
```

`forbid(unsafe_code)` is accepted for a crate root with no bridge occurrence, but at least one crate root in the package must use `deny(unsafe_code)` so that local allowances can be expressed. `unsafe_op_in_unsafe_fn` must be denied in every bridge crate root.

Every unsafe occurrence must satisfy both conditions:

1. its source appears in `allowed_sources`;
2. it is inside an active, local `#[allow(unsafe_code)]` scope.

Example:

```rust
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boundary(pointer: *const u8) -> bool {
    !pointer.is_null()
}
```

A parent `forbid(unsafe_code)` cannot be reopened by a child allowance. Unused `#[allow(unsafe_code)]` directives and allowed source files that contain no unsafe occurrence are rejected as stale policy.

## Inventoried syntax

The AST scanner records file, line, column, kind, enclosing context, and the allowance that authorizes each occurrence. It covers:

- unsafe functions and methods;
- unsafe blocks;
- unsafe traits and implementations;
- explicit and legacy implicit unsafe extern blocks;
- unsafe foreign functions;
- mutable static items;
- unsafe attributes, including `no_mangle`, `export_name`, `link_section`, and `naked`;
- the same attributes nested under `cfg_attr` or `unsafe(...)`;
- `unsafe` tokens inside macro definitions and invocations.

`include!` is rejected because the injected Rust syntax is not represented by the parsed source file. Rust source symlinks are also rejected so the committed source inventory cannot silently point outside the package tree.

## Evidence

`chromifer-unsafe.json` records:

- SHA-256 of the selected workspace `Cargo.toml`;
- SHA-256 of `Cargo.lock`;
- SHA-256 of the policy;
- every workspace package manifest path and digest;
- every Rust source path and digest;
- every crate root, Cargo target, and root lint posture;
- every unsafe occurrence and its authorizing allowance;
- every `#[allow(unsafe_code)]` and whether it was used.

The report contains no timestamp or host-specific absolute source path. Changes to dependencies, package metadata, source bytes, policy, lint posture, or unsafe syntax therefore become review-visible.

## Repository examples

The Chromifer workspace is audited with every workspace package in safe mode by `unsafe-policy.json` and has no unsafe occurrence. `examples/c-abi-bridge` demonstrates a bridge package with an exact source allowlist, two local allowances, and three inventoried occurrences. Both committed reports are checked by CI.

This audit complements the C ABI and build contracts. It proves where unsafe syntax exists and how narrowly it is scoped; it does not prove pointer validity, ownership, lifetime, threading, or semantic correctness. Those properties remain the responsibility of the boundary contract and executable compatibility gates.
