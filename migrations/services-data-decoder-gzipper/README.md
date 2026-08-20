# data_decoder Gzipper Rust successor (WIP)

This directory tracks the M3 successor candidate that replaces Chromium's `services/data_decoder::Gzipper` implementation with Rust at upstream revision `04f9a8144d9b1701aa0b329b6000cf3299bbaf22`.

The public `data_decoder.mojom.Gzipper` contract is unchanged. `use_rust_data_decoder_gzipper` defaults to `enable_rust`; when enabled, `gzipper.cc/.h` are excluded and the Mojo receiver is handed to a Rust implementation backed by Chromium's vendored `flate2`. When disabled, the original C++ implementation and zlib dependency are selected as a source-separated rollback.

The CXX boundary is only the one-time receiver ownership handoff. Per-message `Deflate`, `Inflate`, `Compress`, and `Uncompress` stay entirely on the Rust Mojo path. The Rust implementation consumes the generated raw `mojo_base.mojom.BigBuffer` representation directly. Inline buffers become owned `Vec<u8>` values, while shared-memory buffers are copied with volatile byte reads before compression. Outputs larger than 64 KiB are emitted as shared-memory BigBuffers. This keeps shared-memory aliasing confined to explicit Rust `unsafe` operations without requiring a custom typemap or modifications to the Rust Mojom generator.

Current Linux checkpoint:

- Rust `//services/data_decoder:gzipper_unittests`: 5/5 passed, including a 128 KiB shared-memory BigBuffer round trip.
- source-separated C++ rollback: the same 5/5 contract passes with `use_rust_data_decoder_gzipper=false`; the focused graph excludes `//services/data_decoder:gzipper_rust`, and the production source list restores `gzipper.cc/.h`.
- exact Chromium patch SHA-256: `1abd0676dce20a1250302c197e8e37d3a300d0800efc4712e1f85872ef86211f`.

The earlier custom BigBuffer typemap prototype was deliberately removed before acceptance measurement because it added unnecessary generator and generic Mojo-system changes. The current patch modifies only the Rust-enablement/build wiring, generated-base Rust availability, first-party `flate2` visibility, the focused shared contract, the service handoff, and the Rust Gzipper implementation.

The candidate is now registered as an `in_progress` M3 pilot and has a reproducible exposure measurement. Under the same strict gate used for UKM, memory-unsafe authored LOC drops from 153 to 86 and active implementation files drop from 3 to 2, so the memory-safety acceptance passes. Maintenance does not: authored production LOC grows from 153 to 203 and branch points from 6 to 29. The exposure record is therefore correctly marked `failed`, with memory-safety `passed` and maintenance-complexity `failed` separately.

This means Gzipper is useful evidence but is not currently the final M3 production migration. A full cold build of the broad `//services/data_decoder:lib` dependency graph has not been claimed as rollback evidence; only its GN source/dependency selection and the focused executable were verified. Broader upstream regression, desktop portability, and performance remain pending while a thicker successor component is evaluated.
