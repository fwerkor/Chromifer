# Explicit C ABI contracts

Chromifer uses an explicit contract before allowing a Rust component to expose a C ABI. The contract is the reviewed source of truth for symbol names and signatures; Rust source and the generated header must match it exactly.

## Contract format

A schema version 1 contract is JSON:

```json
{
  "schema_version": 1,
  "header_guard": "NETWORK_RUST_API_H_",
  "symbols": [
    {
      "name": "network_parse",
      "return_type": "i32",
      "parameters": [
        { "name": "data", "type": "const_u8_ptr" },
        { "name": "length", "type": "usize" }
      ]
    }
  ]
}
```

`header_guard` is optional. Without it, Chromifer derives a deterministic guard from the output path.

Supported scalar types are:

```text
void  bool
 i8   u8   i16  u16  i32  u32  i64  u64
isize usize f32 f64
```

Supported pointer types are deliberately narrow:

```text
const_i8_ptr   mut_i8_ptr
const_u8_ptr   mut_u8_ptr
const_void_ptr mut_void_ptr
```

`void` is valid only as a return type. Structs, enums, references, slices, strings, callbacks, ownership-bearing pointers, and platform-dependent C typedefs are not inferred. They require a later contract extension with explicit layout and lifetime rules.

## Rust export requirements

Every contract symbol must have exactly one matching Rust definition:

```rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn network_parse(
    data: *const u8,
    length: usize,
) -> i32 {
    // Boundary validation belongs here.
    0
}
```

Rust 2024 `#[unsafe(no_mangle)]` and the older `#[no_mangle]` spelling are accepted. Chromifer requires:

- public visibility;
- `extern "C"`;
- `no_mangle`;
- the exact symbol name;
- the exact parameter names, order, and supported types;
- the exact return type;
- no generics, receiver, or variadic arguments.

`export_name` is rejected because the Rust function name must equal the contract symbol. Non-public `no_mangle` functions, non-C exported ABIs, and `cfg`/`cfg_attr`-controlled exports are also rejected. Conditional state is propagated through conventional inline and out-of-line Rust modules; conditionally compiled modules using a custom `#[path]` are refused rather than guessed.

Generation fails for a missing contract symbol, an exported symbol absent from the contract, duplicate exports, duplicate contract symbols, unsupported Rust syntax, or any signature mismatch.

## Generate and verify

```bash
cargo run -p chromifer -- generate-c-abi \
  path/to/package \
  path/to/package/c-abi.json \
  path/to/package/include/api.h
```

The command writes:

```text
include/api.h
include/api.h.chromifer.json
```

The provenance records:

- SHA-256 of the contract and generated header;
- package-relative contract and header paths;
- every scanned Rust source and its SHA-256;
- each exported symbol's source file and line;
- whether the Rust function is declared `unsafe`;
- the validated ABI signature.

Generated files should be committed. CI verifies drift without rewriting them:

```bash
cargo run -p chromifer -- generate-c-abi \
  path/to/package \
  path/to/package/c-abi.json \
  path/to/package/include/api.h \
  --check
```

## Chromium GN consumer

A generated C header can be attached to the Cargo-to-GN bridge:

```bash
cargo run -p chromifer -- generate-gn \
  path/to/package/Cargo.toml \
  path/to/package/BUILD.gn \
  --gn-package-path //services/example/rust \
  --allow-unsafe \
  --consumer-target example_c_abi \
  --consumer-source consumer/example.cc \
  --consumer-header include/api.h
```

For `include/api.h`, the C++ source must include the repository-root path:

```cpp
#include "services/example/rust/include/api.h"
```

Chromifer verifies the include and records file-and-line evidence in `chromifer-build.json`. The generated consumer receives a private dependency on the Rust target. A pure C ABI consumer does not require `cxx_bindings`.

## Current safety boundary

The generated header proves symbol and type agreement. It does not by itself prove pointer validity, ownership, aliasing, thread safety, panic containment, or error semantics. Those rules must remain narrow, be documented by the component, and be exercised by compatibility and fuzzing gates before a transition can become `rust_owned`.

See `examples/c-abi-bridge` for a complete contract, Rust exports, generated header, C++ consumer, BUILD.gn, and both provenance files.
