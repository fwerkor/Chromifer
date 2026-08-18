#!/usr/bin/env python3

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RUNNER = ROOT / "measure_performance.py"
SOURCE_MANIFEST = ROOT / "performance.toml"


class MeasurePerformanceEndToEndTest(unittest.TestCase):
    def test_alternates_pairs_and_aggregates_raw_samples(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_source = root / "fake.py"
            fake_source.write_text(
                """#!/usr/bin/env python3
import pathlib
import sys
candidate = pathlib.Path(sys.argv[0]).name.startswith("candidate")
case = next(a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--case="))
messages = int(next(a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--messages=")))
ns = 105.0 if candidate else 100.0
rss_warm = 1_000_000
rss_sample = 1_100_000 if candidate else 1_090_000
print(
    f"case={case} ns_per_message={ns} rss_after_warmup={rss_warm} "
    f"rss_after_sample={rss_sample} forwarded_messages={messages} "
    f"last_source_id={messages}"
)
"""
            )
            fake_source.chmod(0o755)
            baseline = root / "baseline-perf"
            candidate = root / "candidate-perf"
            baseline.write_bytes(fake_source.read_bytes())
            candidate.write_bytes(fake_source.read_bytes())
            baseline.chmod(0o755)
            candidate.chmod(0o755)

            baseline_args = root / "baseline.args"
            candidate_args = root / "candidate.args"
            baseline_args.write_text("use_rust_ukm_recorder = false\n")
            candidate_args.write_text("use_rust_ukm_recorder = true\n")

            manifest = root / "performance.toml"
            manifest.write_text(
                SOURCE_MANIFEST.read_text()
                .replace("samples = 15", "samples = 3")
                .replace("minimum_completed_samples = 15", "minimum_completed_samples = 3")
                .replace("warmup_messages = 10000", "warmup_messages = 10")
                .replace("messages_per_sample = 200000", "messages_per_sample = 20")
            )
            raw = root / "raw.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--baseline-binary",
                    str(baseline),
                    "--candidate-binary",
                    str(candidate),
                    "--baseline-args",
                    str(baseline_args),
                    "--candidate-args",
                    str(candidate_args),
                    "--raw-output",
                    str(raw),
                    "--manifest",
                    str(manifest),
                    "--max-load-per-cpu",
                    "100",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )

            self.assertIn("completed_samples = 3", completed.stdout)
            self.assertEqual(completed.stdout.count("median_regression_percent = 5.000000"), 4)
            self.assertEqual(completed.stdout.count("p95_regression_percent = 5.000000"), 4)
            self.assertIn("steady_state_rss_regression_bytes = 10000", completed.stdout)

            evidence = json.loads(raw.read_text())
            self.assertEqual(len(evidence["samples"]), 3 * 4 * 2)
            for index in range(3):
                pair = [
                    sample["configuration"]
                    for sample in evidence["samples"]
                    if sample["index"] == index
                    and sample["case"] == "add_entry_single_metric"
                ]
                expected = (
                    ["baseline", "candidate"]
                    if index % 2 == 0
                    else ["candidate", "baseline"]
                )
                self.assertEqual(pair, expected)
            self.assertGreater(evidence["effective_cpu_capacity"], 0)
            self.assertEqual(evidence["workload"]["samples"], 3)
            self.assertEqual(len(evidence["artifacts"]["baseline_binary_sha256"]), 64)
            self.assertEqual(len(evidence["artifacts"]["candidate_binary_sha256"]), 64)

    def test_rejects_non_migration_gn_arg_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_binary = root / "baseline"
            candidate_binary = root / "candidate"
            baseline_binary.write_bytes(b"baseline")
            candidate_binary.write_bytes(b"candidate")
            baseline_args = root / "baseline.args"
            candidate_args = root / "candidate.args"
            baseline_args.write_text(
                "enable_rust = true\nuse_rust_ukm_recorder = false\n"
            )
            candidate_args.write_text(
                "enable_rust = true\nis_official_build = true\n"
                "use_rust_ukm_recorder = true\n"
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--baseline-binary",
                    str(baseline_binary),
                    "--candidate-binary",
                    str(candidate_binary),
                    "--baseline-args",
                    str(baseline_args),
                    "--candidate-args",
                    str(candidate_args),
                    "--raw-output",
                    str(root / "raw.json"),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "GN args differ outside the migration flag", completed.stderr
            )


if __name__ == "__main__":
    unittest.main()
