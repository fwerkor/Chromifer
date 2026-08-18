#!/usr/bin/env python3
"""Run the revision-pinned UKM baseline/candidate performance comparison.

The Chromium harness emits one key=value record per invocation. This runner
alternates baseline/candidate order for every sample, pins both sides of a pair
to the same CPU, records raw samples plus artifact hashes, and prints the
aggregate TOML result block expected by performance.toml.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Sample:
    index: int
    case: str
    configuration: str
    order: int
    ns_per_message: float
    rss_after_warmup: int
    rss_after_sample: int
    forwarded_messages: int
    last_source_id: int


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def comparable_gn_args(path: Path, migration_arg: str) -> list[str]:
    """Return non-migration GN assignments in fail-closed source order."""
    comparable: list[str] = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        name, separator, _ = line.partition("=")
        if separator and name.strip() == migration_arg:
            continue
        comparable.append(line)
    return comparable


def require_identical_non_migration_args(
    baseline: Path, candidate: Path, migration_arg: str
) -> None:
    baseline_args = comparable_gn_args(baseline, migration_arg)
    candidate_args = comparable_gn_args(candidate, migration_arg)
    if baseline_args != candidate_args:
        raise SystemExit(
            "baseline/candidate GN args differ outside the migration flag:\n"
            + json.dumps(
                {"baseline": baseline_args, "candidate": candidate_args}, indent=2
            )
        )


def percentile(values: list[float], p: float) -> float:
    if not values:
        raise ValueError("cannot compute a percentile of an empty sample")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * p
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def regression_percent(baseline: float, candidate: float) -> float:
    if baseline <= 0:
        raise ValueError(f"baseline must be positive, got {baseline}")
    return (candidate / baseline - 1.0) * 100.0


def parse_record(stdout: str) -> dict[str, str]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError(f"expected one harness output line, got {len(lines)}: {lines!r}")
    record: dict[str, str] = {}
    for token in lines[0].split():
        key, sep, value = token.partition("=")
        if not sep or not key or not value:
            raise ValueError(f"malformed harness token: {token!r}")
        record[key] = value
    return record


def cpu_policy(cpu: int) -> dict[str, str | int | None]:
    root = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
    result: dict[str, str | int | None] = {"cpu": cpu}
    for name in (
        "scaling_governor",
        "scaling_driver",
        "scaling_min_freq",
        "scaling_max_freq",
        "cpuinfo_min_freq",
        "cpuinfo_max_freq",
    ):
        path = root / name
        result[name] = path.read_text().strip() if path.exists() else None
    return result


def effective_cpu_capacity() -> float:
    affinity = (
        float(max(1, len(os.sched_getaffinity(0))))
        if hasattr(os, "sched_getaffinity")
        else float(max(1, os.cpu_count() or 1))
    )

    quota_capacity: float | None = None
    cpu_max = Path("/sys/fs/cgroup/cpu.max")
    if cpu_max.exists():
        quota, period = cpu_max.read_text().split()
        if quota != "max":
            quota_capacity = int(quota) / int(period)
    else:
        quota_path = Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
        period_path = Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
        if quota_path.exists() and period_path.exists():
            quota = int(quota_path.read_text())
            period = int(period_path.read_text())
            if quota > 0 and period > 0:
                quota_capacity = quota / period

    if quota_capacity is None:
        return affinity
    return max(0.01, min(affinity, quota_capacity))


def load_per_cpu() -> float:
    return os.getloadavg()[0] / effective_cpu_capacity()


def require_valid_background_load(max_load_per_cpu: float) -> float:
    current = load_per_cpu()
    if current > max_load_per_cpu:
        raise SystemExit(
            f"background load too high for a valid comparison: "
            f"load/cpu={current:.3f} > {max_load_per_cpu:.3f}"
        )
    return current


def run_harness(
    binary: Path,
    case: str,
    warmup: int,
    messages: int,
    cpu: int,
) -> dict[str, str]:
    command = [
        str(binary),
        f"--case={case}",
        f"--warmup={warmup}",
        f"--messages={messages}",
    ]

    def pin_cpu() -> None:
        if hasattr(os, "sched_setaffinity"):
            os.sched_setaffinity(0, {cpu})

    completed = subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=pin_cpu if sys.platform.startswith("linux") else None,
    )
    return parse_record(completed.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-binary", type=Path, required=True)
    parser.add_argument("--candidate-binary", type=Path, required=True)
    parser.add_argument("--baseline-args", type=Path, required=True)
    parser.add_argument("--candidate-args", type=Path, required=True)
    parser.add_argument("--raw-output", type=Path, required=True)
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--max-load-per-cpu", type=float, default=0.5)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).with_name("performance.toml"),
    )
    args = parser.parse_args()

    with args.manifest.open("rb") as f:
        manifest = tomllib.load(f)
    comparison = manifest["comparison"]
    workload = manifest["workload"]
    validity = manifest["validity"]

    if comparison["require_identical_non_migration_gn_args"]:
        require_identical_non_migration_args(
            args.baseline_args, args.candidate_args, "use_rust_ukm_recorder"
        )

    if validity["reject_if_cpu_migration_or_frequency_policy_differs"] and not hasattr(
        os, "sched_setaffinity"
    ):
        raise SystemExit(
            "this performance protocol requires CPU affinity support on the measurement host"
        )

    available_cpus = (
        sorted(os.sched_getaffinity(0))
        if hasattr(os, "sched_getaffinity")
        else list(range(max(1, os.cpu_count() or 1)))
    )
    cpu = args.cpu if args.cpu is not None else available_cpus[0]
    if cpu not in available_cpus:
        raise SystemExit(
            f"requested CPU {cpu} is outside the process affinity: {available_cpus}"
        )

    artifacts = {
        "baseline_binary_sha256": sha256(args.baseline_binary),
        "candidate_binary_sha256": sha256(args.candidate_binary),
        "baseline_gn_args_sha256": sha256(args.baseline_args),
        "candidate_gn_args_sha256": sha256(args.candidate_args),
    }

    if validity["reject_if_background_load_invalidates_pairing"]:
        require_valid_background_load(args.max_load_per_cpu)

    policy_before = cpu_policy(cpu)
    samples: list[Sample] = []
    binaries = {
        "baseline": args.baseline_binary,
        "candidate": args.candidate_binary,
    }
    sample_count = int(workload["samples"])
    warmup = int(workload["warmup_messages"])
    messages = int(workload["messages_per_sample"])

    for index in range(sample_count):
        order = ("baseline", "candidate") if index % 2 == 0 else ("candidate", "baseline")
        for case in workload["cases"]:
            if validity["reject_if_background_load_invalidates_pairing"]:
                require_valid_background_load(args.max_load_per_cpu)
            for order_index, configuration in enumerate(order):
                record = run_harness(
                    binaries[configuration], case, warmup, messages, cpu
                )
                if record.get("case") != case:
                    raise RuntimeError(f"harness returned wrong case: {record}")
                forwarded = int(record["forwarded_messages"])
                if forwarded != messages:
                    raise RuntimeError(
                        f"forwarding mismatch for {configuration}/{case}: {forwarded}"
                    )
                samples.append(
                    Sample(
                        index=index,
                        case=case,
                        configuration=configuration,
                        order=order_index,
                        ns_per_message=float(record["ns_per_message"]),
                        rss_after_warmup=int(record["rss_after_warmup"]),
                        rss_after_sample=int(record["rss_after_sample"]),
                        forwarded_messages=forwarded,
                        last_source_id=int(record["last_source_id"]),
                    )
                )

    if validity["reject_if_background_load_invalidates_pairing"]:
        require_valid_background_load(args.max_load_per_cpu)
    policy_after = cpu_policy(cpu)
    if validity["reject_if_cpu_migration_or_frequency_policy_differs"] and policy_before != policy_after:
        raise SystemExit(
            "CPU frequency policy changed during measurement:\n"
            + json.dumps({"before": policy_before, "after": policy_after}, indent=2)
        )

    case_results: list[dict[str, float | str]] = []
    for case in workload["cases"]:
        baseline = [
            s.ns_per_message
            for s in samples
            if s.case == case and s.configuration == "baseline"
        ]
        candidate = [
            s.ns_per_message
            for s in samples
            if s.case == case and s.configuration == "candidate"
        ]
        case_results.append(
            {
                "id": case,
                "median_regression_percent": regression_percent(
                    statistics.median(baseline), statistics.median(candidate)
                ),
                "p95_regression_percent": regression_percent(
                    percentile(baseline, 0.95), percentile(candidate, 0.95)
                ),
            }
        )

    # Compare workload-induced steady-state growth after each warmup. Taking the
    # median keeps page-fault noise from a single fresh process from dominating
    # the single manifest-level RSS result.
    baseline_rss_growth = [
        s.rss_after_sample - s.rss_after_warmup
        for s in samples
        if s.configuration == "baseline"
    ]
    candidate_rss_growth = [
        s.rss_after_sample - s.rss_after_warmup
        for s in samples
        if s.configuration == "candidate"
    ]
    rss_regression = round(
        statistics.median(candidate_rss_growth) - statistics.median(baseline_rss_growth)
    )

    raw = {
        "schema_version": 1,
        "generated_unix_ns": time.time_ns(),
        "host": platform.node(),
        "platform": platform.platform(),
        "cpu_policy_before": policy_before,
        "cpu_policy_after": policy_after,
        "effective_cpu_capacity": effective_cpu_capacity(),
        "load_per_cpu_after": load_per_cpu(),
        "artifacts": artifacts,
        "workload": workload,
        "samples": [asdict(s) for s in samples],
    }
    args.raw_output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(raw, indent=2, sort_keys=True) + "\n").encode()
    args.raw_output.write_bytes(encoded)
    raw_sha = hashlib.sha256(encoded).hexdigest()

    print("[results]")
    print(f"completed_samples = {sample_count}")
    print(f"steady_state_rss_regression_bytes = {rss_regression}")
    print(f'baseline_binary_sha256 = "{artifacts["baseline_binary_sha256"]}"')
    print(f'candidate_binary_sha256 = "{artifacts["candidate_binary_sha256"]}"')
    print(f'baseline_gn_args_sha256 = "{artifacts["baseline_gn_args_sha256"]}"')
    print(f'candidate_gn_args_sha256 = "{artifacts["candidate_gn_args_sha256"]}"')
    print(f'raw_samples_sha256 = "{raw_sha}"')
    for result in case_results:
        print("\n[[results.cases]]")
        print(f'id = "{result["id"]}"')
        print(
            f'median_regression_percent = {result["median_regression_percent"]:.6f}'
        )
        print(f'p95_regression_percent = {result["p95_regression_percent"]:.6f}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
