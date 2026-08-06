# GN endpoint integration fixture

This fixture proves that the generated C ABI package can be evaluated by upstream GN, compiled by Ninja, linked as a mixed Rust/C++ executable, and run successfully. The endpoint covers fixed arithmetic vectors, repeated calls, null and non-null pointers, zero and nonzero lengths, and C-compatible bool returns.

Build the exact GN revision used by CI:

```bash
examples/integration/build-pinned-gn.sh /tmp/chromifer-gn
export PATH="/tmp/chromifer-gn/out:$PATH"
```

Run the endpoint:

```bash
examples/integration/run-smoke.sh
```

The fixture uses `gn-root/` as a minimal GN checkout and `c-abi.json` as the integration contract. The generated package and host Rust adapter are temporary overlays. The Ninja output under `gn-root/out/ChromiferIntegration` is ignored and retained for inspection or incremental reruns.

The same endpoint is also derived as `c-abi-gn-endpoint` in `examples/gates/generated.toml` and executed by the content-addressed evidence pipeline.

## Chromium-native run

Prepare the pinned gclient workspace and native Rust toolchain:

```bash
examples/integration/prepare-chromium-native.sh \
  /path/to/chromium-workspace \
  --full
```

Build, run, and verify the committed checkout lock and report:

```bash
examples/integration/run-chromium-native.sh \
  /path/to/chromium-workspace \
  --check
```

The native workflow uses `chromium-native.json`, the committed GN arguments, and the proven source closure. `--full` expands that closure into the complete Chromium source worktree before execution; omitting it keeps the lower-disk sparse materialization. `chromium-native-checkout-lock.json` binds Chromium revision `008cdad85f0721c89b42ef4dcaabcee615482609`, native tools, GN graph, and required targets. `chromium-native-report.json` additionally records the successful endpoint and path-independent GN, Ninja, and Rustc identities.
