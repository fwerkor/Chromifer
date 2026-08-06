# Checkout lock fixture

`run-smoke.sh` creates a temporary gclient-style workspace and exercises `audit-checkout` end to end.

The fixture intentionally generates its Git revision and absolute GN `root_path` at runtime. A committed checkout lock cannot describe the Chromifer repository itself because adding that lock would change the revision it claims to pin.

Run:

```bash
examples/checkout/run-smoke.sh
```

The smoke validates deterministic Git state, `DEPS`, gclient metadata, GN args, Ninja output, project export normalization, required targets, live GN target descriptions, drift checking, and removal of temporary absolute paths from the report. It then derives a structured `checkout` gate, executes it with executable attestation, and verifies the resulting content-addressed evidence.
