# Signed evidence attestations

Chromifer can attach a deterministic Ed25519 signature to an existing content-addressed evidence bundle without modifying the evidence JSON itself. The signature is detached so evidence digests and log references remain stable.

## Trust model

Two checks are intentionally separate:

1. `verify-evidence` proves that the evidence bundle, gate definitions, hashed inputs, logs, checkout attestation, and executable attestations are internally valid and match the selected manifest.
2. `verify-evidence-signature` proves that the exact evidence file bytes were signed by the holder of an Ed25519 private key corresponding to an externally trusted public key.

A valid signature does not make a failing or malformed evidence bundle valid. Consumers should perform both checks.

The attestation embeds the runner identifier and public key for auditability, but verification still requires a separate trusted public-key file. Trusting the key copied from the attestation itself would only prove self-consistency, not runner identity.

## Key format

Chromifer uses a narrow key format rather than accepting ambiguous PEM variants:

- private key: exactly 32 bytes encoded as 64 lowercase hexadecimal characters, with an optional final newline;
- public key: exactly 32 bytes encoded the same way;
- Unix private-key files must not be readable or writable by group or other users (`0600`, `0400`, or stricter permissions are accepted).

Private-key text and decoded seed bytes are zeroized after constructing the signing key. Private keys should live in the runner's secret store or protected filesystem and must not be committed to the repository.

Derive a public key that can be distributed through a trusted channel:

```bash
cargo run -p chromifer -- derive-attestation-public-key \
  /secure/runner.key \
  runner.pub
```

Use `--check` to verify that an existing public-key file still corresponds to the private key without rewriting it.

## Sign evidence

First execute and validate the normal evidence pipeline. Then create the detached signature:

```bash
cargo run -p chromifer -- sign-evidence \
  evidence-root/evidence/<digest>.json \
  /secure/runner.key \
  evidence-root/evidence/<digest>.sig.json \
  --runner-id ci/linux-x64
```

`runner_id` is part of the signed payload. It accepts 1–128 ASCII characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `:`, `@`, `/`, and `-`.

The signed payload is domain-separated and contains:

- runner ID;
- SHA-256 of the exact evidence file bytes;
- Ed25519 public key;
- SHA-256 of that public key.

Ed25519 signing is deterministic, so `sign-evidence --check` can regenerate the expected attestation in memory and detect drift.

## Verify a trusted runner signature

```bash
cargo run -p chromifer -- verify-evidence-signature \
  evidence-root/evidence/<digest>.json \
  evidence-root/evidence/<digest>.sig.json \
  /trusted/runner.pub
```

Verification rejects:

- any evidence-byte change;
- runner-ID or attestation-field modification;
- malformed or non-canonical hexadecimal data;
- an attestation signed by a different key;
- a public-key digest mismatch;
- an invalid Ed25519 signature.

The verifier uses strict Ed25519 verification.

## CI and isolated runners

Repository CI generates an ephemeral signing key only for a functional smoke test, signs the freshly produced structured evidence, and verifies it against a separately derived public-key file. No private test key is committed.

Production runner identity requires stronger key custody: provision a long-lived or workload-bound private key only inside an isolated runner, publish/pin the corresponding public key through a separately trusted channel, and rotate it under an explicit policy. Chromifer provides the cryptographic envelope and external-key verification; it does not yet provide a transparency log, hardware-backed key service, or remote workload identity protocol.
