# data_decoder Gzipper Rust successor (WIP)

This directory tracks the M3 successor candidate that replaces Chromium's `services/data_decoder::Gzipper` implementation with Rust at upstream revision `04f9a8144d9b1701aa0b329b6000cf3299bbaf22`.

The candidate keeps the public `data_decoder.mojom.Gzipper` contract unchanged. `use_rust_data_decoder_gzipper` defaults to `enable_rust`; when enabled, the C++ `gzipper.cc/.h` implementation is excluded and the Mojo receiver is handed to a Rust implementation backed by Chromium's vendored `flate2`. When disabled, the original C++ implementation and zlib dependency are selected as a source-separated rollback.

Unlike the rejected UKM pilot, the per-message data path does not cross CXX. C++ transfers receiver ownership to Rust once; `Deflate`, `Inflate`, `Compress`, and `Uncompress` then remain on the Rust Mojo path. Large `mojo_base.mojom.BigBuffer` values are mapped through a target-local Rust typemap, including shared-memory-backed buffers.

The patch also contains the Rust Mojo infrastructure needed by this production path: nullable typemaps retain `Option<T>`, `parse_as` accepts qualified/generic Rust types, imported typemap traits are discovered, and Rust shared-buffer helpers support owned initialization and copying mapped bytes.

Current Linux checkpoint:

- Rust Mojom generator regression tests: 11/11 passed.
- `//services/data_decoder:gzipper_rust`: builds successfully.
- focused `//services/data_decoder:gzipper_unittests`: 5/5 passed, including a 128 KiB BigBuffer round trip.
- patch SHA-256: `bd81d1642295389f3764837d7c7ef2b7d4c832a61c757bfb3cfbf4d3894b4844`.

This is deliberately a WIP record and therefore has no `pilot.toml` yet. The C++ rollback configuration, broader upstream regression suite, exposure measurement, desktop portability, and performance gate still need to be executed before this successor can become the M3 production pilot.
