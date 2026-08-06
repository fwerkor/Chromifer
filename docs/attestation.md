# Checkout and executable attestation

Compatibility results are useful only when their source checkout and tools are identifiable. `run-gates` can bind an evidence bundle to the Git worktree and direct executables used for the run.

## Run with attestations

```bash
revision=$(git rev-parse HEAD)

cargo run -p chromifer -- run-gates \
  examples/gates/generated.toml \
  . \
  /tmp/chromifer-evidence \
  --attest-checkout \
  --expected-revision "$revision" \
  --require-clean-checkout \
  --attest-executables
```

The checkout working directory must be the Git top-level directory. Evidence output should be outside that checkout; otherwise creating evidence files changes the worktree during the run and the attestation fails.

## Checkout snapshot

Checkout attestation resolves the `git` entry found through `PATH`, records both its invocation path and canonical target, and hashes the canonical executable before and after the run. It then records a Git snapshot before and after all selected gates:

- canonical checkout root;
- exact `HEAD` revision;
- symbolic branch when attached, or no branch when detached;
- dirty state;
- SHA-256 of `git status --porcelain=v2 -z --untracked-files=all --ignore-submodules=none`;
- number of status entries;
- SHA-256 and readable lines from `git submodule status --recursive`.

`--expected-revision` requires an exact revision match. `--require-clean-checkout` blocks every gate when the initial snapshot is dirty. Both options require `--attest-checkout`.

A checkout may be dirty when clean enforcement is omitted, but its complete dirty-state fingerprint must remain unchanged throughout execution. Any revision, tracked file, untracked file, index, branch, or submodule change makes the overall evidence fail even when every command exits successfully.

## Direct executable identity

`--attest-executables` applies to structured direct gates:

```toml
[[gates]]
id = "bridge-current"
program = "cargo"
args = ["run", "--locked", "-p", "chromifer", "--", "generate-gn", "..."]
```

For each direct gate, Chromifer:

1. resolves the program through the current `PATH` or from its explicit path;
2. records the absolute invocation path;
3. resolves the canonical executable target;
4. hashes the canonical target before execution;
5. launches the invocation path with the declared argument vector;
6. confirms the invocation path still resolves to the same target;
7. hashes the target again after execution.

Keeping invocation and canonical paths separate is required for multicall tools. For example, a `cargo` entry may point at a rustup dispatcher whose behavior depends on the invoked filename. Chromifer hashes the real dispatcher while still invoking the `cargo` entry.

If the entry is retargeted, deleted, or modified during execution, the gate fails. Shell gates remain supported for legacy manifests, but commands launched from inside a shell cannot be individually attested; generated contracts use direct gates.

## Live verification

Normal verification checks the content-addressed evidence and its internal attestation consistency. Supplying a worktree also compares the recorded final state with the current machine:

```bash
cargo run -p chromifer -- verify-evidence \
  examples/gates/generated.toml \
  /tmp/chromifer-evidence/evidence/<digest>.json \
  /tmp/chromifer-evidence \
  --workdir .
```

Live verification re-hashes the recorded Git executable and every direct gate executable, confirms each invocation path still points to the recorded canonical target, and captures a new Git snapshot. The command fails when the current checkout or any executable differs.

Historical evidence can still be verified without `--workdir`. In that mode, log hashes, manifest bytes, gate definitions, checkout before/after consistency, and executable before/after consistency are checked, but the current host is not compared. The verification summary reports whether live attestation was performed.

## Trust boundary

These attestations prove deterministic identity relationships inside one evidence bundle and allow later comparison with a live machine. They do not prove that the operating system, Git process, filesystem, runner identity, or initial checkout was trustworthy. Cryptographic signing, isolated builders, transparency logs, and hardware-backed runner identity remain separate work.
