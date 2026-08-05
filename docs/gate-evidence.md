# Compatibility gate evidence

Chromifer can execute manifest compatibility gates and persist their results as content-addressed evidence.

```bash
cargo run -p chromifer -- run-gates \
  chromium-owned.toml \
  /path/to/chromium/src \
  /path/to/evidence \
  --module network_service
```

With no `--gate` or `--module` filters, every gate in the manifest is selected. Filters are repeatable and their union is executed in stable gate-ID order.

## Artifact layout

```text
evidence-root/
  evidence/
    <evidence-json-sha256>.json
  logs/
    <stdout-or-stderr-sha256>.log
  .tmp/
```

The evidence JSON records:

- project and exact baseline;
- SHA-256 of the exact manifest bytes;
- host OS, architecture, and shell;
- working directory and selected gate IDs;
- per-gate command and declared targets;
- start time, duration, exit code, and status;
- stdout/stderr byte counts, SHA-256, relative artifact paths, and bounded tails;
- skipped gates after fail-fast;
- overall pass status.

Full stdout and stderr are always retained in `logs/`. The JSON embeds only a configurable tail:

```bash
cargo run -p chromifer -- run-gates \
  manifest.toml checkout evidence-root \
  --max-tail-bytes 16384
```

A failed or timed-out gate still produces a complete evidence bundle. The CLI writes the evidence path before returning a nonzero exit status.

## Timeouts

The timeout is per gate:

```bash
cargo run -p chromifer -- run-gates \
  manifest.toml checkout evidence-root \
  --timeout-seconds 1800
```

The executor terminates the launched shell when the timeout expires and records `timed_out`. Commands that deliberately detach background descendants remain responsible for their own cleanup; gate commands should run foreground test processes.

## Verification

Never trust a file only because it is stored under `evidence/`. Re-verify it:

```bash
cargo run -p chromifer -- verify-evidence \
  manifest.toml \
  evidence-root/evidence/<digest>.json \
  evidence-root
```

Verification checks:

1. the evidence filename equals the SHA-256 of its exact JSON bytes;
2. schema version, project, baseline, and manifest SHA-256 match;
3. every selected gate still exists;
4. commands and declared targets have not changed;
5. executed and skipped gate sets exactly partition the selected gates;
6. overall pass status matches recorded gate statuses;
7. every referenced log path is safe and repository-relative;
8. every log's byte count and SHA-256 match its current contents.

Renaming evidence, editing JSON, changing a gate command, changing the manifest bytes, or modifying a log causes verification to fail.

## Transition checks

Structural transition checks remain available without evidence:

```bash
cargo run -p chromifer -- check-transition \
  manifest.toml network_service rust_owned
```

Supplying verified evidence adds an execution requirement:

```bash
cargo run -p chromifer -- check-transition \
  manifest.toml network_service rust_owned \
  --evidence evidence-root/evidence/<digest>.json \
  --artifact-root evidence-root
```

For a `rust_owned` transition, every compatibility gate declared by the module must appear as a verified passing gate. A valid bundle may contain failed unrelated gates; only the candidate module's declared gates are required for this check.

## Trust boundary

Content addressing detects accidental or malicious modification after generation. It does not prove that the host itself was trustworthy, that a command tested the intended behavior, or that the baseline source checkout matched the manifest beyond the recorded identifier. Signed attestations and isolated runners are later work.
