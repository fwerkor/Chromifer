# GN endpoint integration fixture

This fixture proves that the generated C ABI package can be evaluated by upstream GN, compiled by Ninja, linked as a mixed Rust/C++ executable, and run successfully.

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
