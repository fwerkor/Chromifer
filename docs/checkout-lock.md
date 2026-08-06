# Chromium checkout lock

A migration result must identify the Chromium source, dependency metadata, GN configuration, and target graph it was tested against. `audit-checkout` generates a deterministic lock report for a gclient-style workspace and rejects drift from that report.

## Workspace layout

The workspace root is normally the directory containing `.gclient`; the Chromium Git checkout is usually its `src/` child:

```text
chromium-workspace/
  .gclient
  .gclient_entries
  src/
    .git/
    DEPS
    out/Default/
      args.gn
      build.ninja
      project.json
```

The source directory must be the exact root of a Git checkout. GN output directories must be inside that source checkout. Output files may be ignored by Git, as Chromium's `out/` directories normally are.

## Contract

```json
{
  "schema_version": 1,
  "source_dir": "src",
  "revision": "0123456789abcdef0123456789abcdef01234567",
  "require_clean": true,
  "metadata_files": [
    {"path": "src/DEPS"},
    {"path": ".gclient"},
    {"path": ".gclient_entries", "mode": "workspace_text"}
  ],
  "gn_outputs": [
    {
      "id": "linux-release",
      "directory": "src/out/Default",
      "required_targets": [
        "//services/network:network_service",
        "//chrome/test:browser_tests"
      ],
      "expected_default_toolchain": "//build/toolchain/linux:clang_x64"
    }
  ]
}
```

`revision` is an exact 40- or 64-character lowercase Git object ID. Symbolic refs and abbreviated revisions are rejected.

`require_clean` defaults to `true`. Clean-state inspection uses porcelain v2 with all untracked files and recursive submodule state. Ignored files, including normal GN output directories, do not make the checkout dirty.

Metadata modes:

- `raw`: hash exact bytes.
- `workspace_text`: require UTF-8, normalize CRLF to LF, and replace absolute workspace/source paths with `${WORKSPACE}` and `${SOURCE}` before hashing. This is intended for generated gclient metadata such as `.gclient_entries`.

Each GN output defaults to:

```text
args_file    = args.gn
project_file = project.json
build_file   = build.ninja
```

Alternative normalized relative filenames can be declared explicitly.

## Generate and verify

Generate a GN project export first:

```bash
gn gen out/Default --ide=json --json-file-name=project.json
```

Then generate the lock:

```bash
cargo run -p chromifer -- audit-checkout \
  /path/to/chromium-workspace \
  /path/to/chromium-workspace/chromifer-checkout.json \
  /path/to/chromium-workspace/chromifer-checkout-lock.json
```

Verify a committed lock without modifying it:

```bash
cargo run -p chromifer -- audit-checkout \
  /path/to/chromium-workspace \
  /path/to/chromium-workspace/chromifer-checkout.json \
  /path/to/chromium-workspace/chromifer-checkout-lock.json \
  --check
```

The report records:

- exact source revision and clean state;
- SHA-256 and entry count for Git status;
- recursive submodule status;
- exact or path-normalized metadata file identities;
- exact `args.gn` and `build.ninja` identities;
- a canonical semantic digest of the GN project export with host paths normalized;
- GN build directory and default toolchain;
- total exported target count;
- required target type, toolchain, source count, dependency count, and `testonly` state.

The generated JSON contains no workspace-specific absolute path when the declared metadata and project export contain only paths recognized by the normalizer.

## Live GN validation

Passing an explicit GN executable checks the current generated graph in addition to the files already locked:

```bash
cargo run -p chromifer -- audit-checkout \
  /path/to/chromium-workspace \
  /path/to/chromium-workspace/chromifer-checkout.json \
  /path/to/chromium-workspace/chromifer-checkout-lock.json \
  --gn /path/to/depot_tools/gn \
  --check
```

For every output, Chromifer runs:

```text
gn args <out> --list --short --overrides-only
gn ls <out> <required-target>
gn desc <out> <required-target> --format=json
```

The live target description must match the lock's type, toolchain, source count, dependency count, and `testonly` state. A stale `project.json` therefore cannot pass merely because the same target label still exists.

The GN executable is intentionally supplied rather than discovered implicitly. The checkout lock records GN's version in the command summary, not in the portable report. Tool binary identity belongs in the evidence attestation layer.

## Structured gate

A checkout lock can become a derived compatibility gate:

```json
{
  "kind": "checkout",
  "id": "chromium-checkout-current",
  "workspace_root": "chromium-workspace",
  "contract": "chromium-workspace/chromifer-checkout.json",
  "report": "chromium-workspace/chromifer-checkout-lock.json",
  "modules": ["network_service"],
  "targets": ["linux"]
}
```

`derive-gates` reconstructs:

```text
audit-checkout chromium-workspace <contract> <report> --check
```

The gate declares the contract, lock report, metadata files, GN args, Ninja build file, and project export as hashed inputs. Path-normalized metadata and semantic project content are still revalidated by `audit-checkout`; the evidence runner additionally binds the exact bytes used by that execution.

Live `--gn` validation is kept outside the portable derived gate because the GN path is environment-specific and is launched as a subprocess. CI or the runner setup should execute `audit-checkout --gn ... --check` before running the portable gate.

## Repository fixture

The repository includes a relocatable end-to-end fixture:

```bash
examples/checkout/run-smoke.sh
```

It creates a temporary gclient-style workspace, initializes a fixed Git revision, writes a path-bearing GN project export, generates a checkout lock, performs live validation through a deterministic GN fixture, and reruns the command in `--check` mode. The smoke also verifies that the lock does not retain the temporary absolute path.

## Trust boundary

The lock proves consistency among declared source revision, workspace metadata, generated GN files, and required target semantics. It does not prove the initial source was obtained from an authentic upstream, that depot_tools or GN were trustworthy, or that the builder was isolated. Those properties require signed source provenance, trusted tool distribution, runner identity, and transparency logging.
