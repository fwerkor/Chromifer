# Contributing

Chromifer is in its architecture-bootstrap phase. Changes should improve the migration model, boundary enforcement, Chromium integration tooling, or compatibility validation.

## Before submitting a change

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## Design rules

- Do not add an abstraction without a second concrete use or a documented boundary requirement.
- Keep interoperability code separate from pure Rust logic.
- Every migration rule needs a focused test covering both acceptance and rejection.
- Do not silently weaken validation to accommodate a manifest. Explain and model the real exception.
- Avoid generated code in commits unless its generator and reproducibility path are included.

## Commit identity

Project commits use `Cao Yuhang <caoyuhang@fwerkor.com>` unless a contributor supplies their own identity.
