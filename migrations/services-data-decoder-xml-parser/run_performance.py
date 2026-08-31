#!/usr/bin/env python3
"""Run paired XmlParser candidate/fallback performance samples."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import statistics
import subprocess
import time

CASES = ("small_xml", "attributes_namespaces", "mixed_text_cdata", "large_xml")
SAMPLES = 15
MAX_PRE_BUSY = 0.20
MIN_CHILD_CPU_RATIO = 0.85
MAX_RUN_ATTEMPTS = 5


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized_args_sha256(path: Path) -> str:
    lines = [
        stripped
        for line in path.read_text().splitlines()
        if (stripped := line.strip())
        and not stripped.startswith("use_rust_data_decoder_xml_parser =")
    ]
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


def cpu_policy(cpu: int) -> dict[str, str]:
    root = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
    result: dict[str, str] = {}
    for name in (
        "scaling_governor",
        "scaling_driver",
        "energy_performance_preference",
        "scaling_min_freq",
        "scaling_max_freq",
    ):
        path = root / name
        if path.is_file():
            result[name] = path.read_text().strip()
    return result


def thread_siblings(cpu: int) -> list[int]:
    text = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list").read_text().strip()
    cpus: list[int] = []
    for token in text.split(","):
        if "-" in token:
            lo, hi = map(int, token.split("-"))
            cpus.extend(range(lo, hi + 1))
        else:
            cpus.append(int(token))
    return cpus


def read_cpu_ticks(cpus: set[int]) -> dict[int, tuple[int, int]]:
    result: dict[int, tuple[int, int]] = {}
    with open("/proc/stat", encoding="utf-8") as stream:
        for line in stream:
            fields = line.split()
            if not fields or not fields[0].startswith("cpu") or fields[0] == "cpu":
                continue
            cpu = int(fields[0][3:])
            if cpu not in cpus:
                continue
            values = list(map(int, fields[1:]))
            idle = values[3] + values[4]
            result[cpu] = (idle, sum(values))
    return result


def sample_busy(cpus: list[int], seconds: float = 0.20) -> dict[int, float]:
    selected = set(cpus)
    before = read_cpu_ticks(selected)
    time.sleep(seconds)
    after = read_cpu_ticks(selected)
    busy: dict[int, float] = {}
    for cpu in cpus:
        idle_delta = after[cpu][0] - before[cpu][0]
        total_delta = after[cpu][1] - before[cpu][1]
        busy[cpu] = 1.0 - idle_delta / total_delta if total_delta else 1.0
    return busy


def percentile(values: list[int], fraction: float) -> float:
    ordered = sorted(values)
    rank = fraction * (len(ordered) - 1)
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return float(ordered[lo])
    weight = rank - lo
    return ordered[lo] * (1.0 - weight) + ordered[hi] * weight


def run_one(binary: Path, case: str, cpu: int, siblings: list[int]) -> dict:
    rejected_attempts = 0
    last_cpu_ratio = 0.0
    for run_attempt in range(MAX_RUN_ATTEMPTS):
        for _ in range(20):
            pre_busy = sample_busy(siblings)
            if max(pre_busy.values()) <= MAX_PRE_BUSY:
                break
        else:
            raise RuntimeError(f"physical core stayed busy before {binary.name}/{case}: {pre_busy}")

        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        start = time.monotonic()
        completed = subprocess.run(
            ["taskset", "-c", str(cpu), str(binary), f"--case={case}"],
            check=True,
            capture_output=True,
            text=True,
        )
        wall_s = time.monotonic() - start
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        child_cpu_s = (after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime)
        cpu_ratio = child_cpu_s / wall_s if wall_s else 1.0
        last_cpu_ratio = cpu_ratio
        if cpu_ratio < MIN_CHILD_CPU_RATIO:
            rejected_attempts += 1
            continue

        payload = json.loads(completed.stdout)
        if payload["messages"] != 1000 or payload["warmup_messages"] != 100:
            raise RuntimeError(f"unexpected workload counters: {payload}")
        payload["wall_s"] = wall_s
        payload["child_cpu_s"] = child_cpu_s
        payload["child_cpu_ratio"] = cpu_ratio
        payload["pre_busy"] = {str(k): v for k, v in pre_busy.items()}
        payload["rejected_attempts"] = rejected_attempts
        return payload

    raise RuntimeError(
        f"background contention repeatedly invalidated {binary.name}/{case}: "
        f"attempts={MAX_RUN_ATTEMPTS}, last_child_cpu_ratio={last_cpu_ratio:.3f}"
    )


def regression_percent(candidate: float, baseline: float) -> float:
    return (candidate / baseline - 1.0) * 100.0


def summarize(raw_samples: list[dict]) -> dict:
    summary: dict[str, dict] = {}
    for case in CASES:
        by_config: dict[str, dict] = {}
        for config in ("fallback", "candidate"):
            matching = [
                run
                for sample in raw_samples
                for run in sample["runs"]
                if run["config"] == config and run["case"] == case
            ]
            latencies = [value for run in matching for value in run["latencies_ns"]]
            rss = [run["rss_bytes"] for run in matching]
            by_config[config] = {
                "completed_samples": len(matching),
                "latency_median_ns": statistics.median(latencies),
                "latency_p95_ns": percentile(latencies, 0.95),
                "rss_median_bytes": statistics.median(rss),
                "rss_max_bytes": max(rss),
            }
        baseline = by_config["fallback"]
        candidate = by_config["candidate"]
        summary[case] = {
            **by_config,
            "median_regression_percent": regression_percent(
                candidate["latency_median_ns"], baseline["latency_median_ns"]
            ),
            "p95_regression_percent": regression_percent(
                candidate["latency_p95_ns"], baseline["latency_p95_ns"]
            ),
            "rss_median_regression_bytes": int(
                candidate["rss_median_bytes"] - baseline["rss_median_bytes"]
            ),
        }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--fallback", type=Path, required=True)
    parser.add_argument("--candidate-args", type=Path, required=True)
    parser.add_argument("--fallback-args", type=Path, required=True)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    allowed = os.sched_getaffinity(0)
    if args.cpu not in allowed:
        raise RuntimeError(f"CPU {args.cpu} is not in process affinity {sorted(allowed)}")
    siblings = thread_siblings(args.cpu)
    candidate_args_hash = normalized_args_sha256(args.candidate_args)
    fallback_args_hash = normalized_args_sha256(args.fallback_args)
    if candidate_args_hash != fallback_args_hash:
        raise RuntimeError("non-migration GN args differ")

    initial_policy = cpu_policy(args.cpu)
    raw_samples: list[dict] = []
    for sample_index in range(SAMPLES):
        order = ("candidate", "fallback") if sample_index % 2 == 0 else ("fallback", "candidate")
        sample = {"sample": sample_index + 1, "order": list(order), "runs": []}
        for config in order:
            binary = args.candidate if config == "candidate" else args.fallback
            for case in CASES:
                run = run_one(binary, case, args.cpu, siblings)
                run["config"] = config
                sample["runs"].append(run)
        raw_samples.append(sample)

    final_policy = cpu_policy(args.cpu)
    if initial_policy != final_policy:
        raise RuntimeError(f"CPU frequency policy changed: {initial_policy} -> {final_policy}")

    summary = summarize(raw_samples)
    passed = all(
        metrics["candidate"]["completed_samples"] >= SAMPLES
        and metrics["fallback"]["completed_samples"] >= SAMPLES
        and metrics["median_regression_percent"] <= 5.0
        and metrics["p95_regression_percent"] <= 10.0
        and metrics["rss_median_regression_bytes"] <= 1_048_576
        for metrics in summary.values()
    )
    evidence = {
        "schema_version": 1,
        "status": "passed" if passed else "failed",
        "machine": os.uname().nodename,
        "cpu": args.cpu,
        "thread_siblings": siblings,
        "cpu_policy": initial_policy,
        "validity": {
            "max_pre_busy": MAX_PRE_BUSY,
            "min_child_cpu_ratio": MIN_CHILD_CPU_RATIO,
            "max_run_attempts": MAX_RUN_ATTEMPTS,
            "alternating_sample_order": True,
            "same_machine": True,
            "non_migration_gn_args_sha256": candidate_args_hash,
        },
        "artifacts": {
            "candidate_binary_sha256": sha256(args.candidate),
            "fallback_binary_sha256": sha256(args.fallback),
            "candidate_args_sha256": sha256(args.candidate_args),
            "fallback_args_sha256": sha256(args.fallback_args),
        },
        "workload": {
            "warmup_messages": 100,
            "messages_per_sample": 1000,
            "samples": SAMPLES,
            "cases": list(CASES),
            "in_process_mojo": True,
        },
        "budgets": {
            "median_regression_percent_max": 5.0,
            "p95_regression_percent_max": 10.0,
            "steady_state_rss_regression_bytes_max": 1_048_576,
        },
        "summary": summary,
        "raw_samples": raw_samples,
    }
    args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({"status": evidence["status"], "summary": summary}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
