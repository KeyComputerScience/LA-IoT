# SPDX-License-Identifier: Apache-2.0
"""Explicit external-baseline adapter runner; never substitutes mock algorithms.

Run only through `python -m laiot.baselines PLAN --output DIRECTORY`.
Reference implementations supply their own instrumented result JSON.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import random
import subprocess
import time
from typing import Any


METRICS = ("rmse", "nll", "wire_bytes_per_scheduled_round",
           "latency_ms_per_completed_round", "energy_mj_per_scheduled_round")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def validate_result(value: Any, expected: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"pairing", "scope", "metrics", "counts", "evidence"}:
        raise ValueError("Baseline result must declare pairing, scope, metrics, counts and evidence")
    if value["pairing"] != expected:
        raise ValueError("Baseline input/topology/scenario/seed differs from the paired request")
    if value["evidence"] not in {"device_measurement", "network_simulation", "local_fusion_profile"}:
        raise ValueError("Use an explicit evidence type; no synthetic fallback is supported")
    if not isinstance(value["scope"], dict) or set(value["scope"]) != set(METRICS):
        raise ValueError("Declare the evaluation boundary for every metric")
    if any(not isinstance(s, str) or not s.strip() for s in value["scope"].values()):
        raise ValueError("Metric scopes must be nonempty descriptions")
    counts = value["counts"]
    if not isinstance(counts, dict) or set(counts) != {"scheduled_rounds", "completed_rounds", "estimates"}:
        raise ValueError("Declare scheduled/completed rounds and estimate count")
    if any(type(v) is not int or v < 0 for v in counts.values()):
        raise ValueError("Counts must be nonnegative integers")
    if counts["scheduled_rounds"] < 1 or counts["completed_rounds"] > counts["scheduled_rounds"]:
        raise ValueError("Invalid round counts")
    metrics = value["metrics"]
    if not isinstance(metrics, dict) or set(metrics) != set(METRICS):
        raise ValueError("Supply all metric fields; use null for unavailable measurements")
    for name, number in metrics.items():
        if number is None:
            continue
        if isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(number):
            raise ValueError("Metric must be finite or null")
        if name != "nll" and number < 0:
            raise ValueError("This metric cannot be negative")
    if counts["completed_rounds"] == 0 and metrics["latency_ms_per_completed_round"] is not None:
        raise ValueError("No completed-round latency exists without a completed round")
    if counts["estimates"] == 0 and any(metrics[n] is not None for n in ("rmse", "nll")):
        raise ValueError("Accuracy metrics require completed estimates")
    return value


def run_plan(plan_path: Path, output: Path) -> None:
    plan_path = Path(plan_path).resolve()
    plan = json.loads(plan_path.read_bytes())
    if not isinstance(plan, dict) or set(plan) != {"workload", "topology", "scenario", "seeds", "implementations"}:
        raise ValueError("Unexpected baseline-plan fields")
    workload = (plan_path.parent / plan["workload"]).resolve()
    topology = (plan_path.parent / plan["topology"]).resolve()
    seeds = plan["seeds"]
    if (not isinstance(seeds, list) or not seeds or len(set(seeds)) != len(seeds)
            or any(type(s) is not int or s < 0 for s in seeds)):
        raise ValueError("Provide distinct nonnegative run seeds")
    implementations = plan["implementations"]
    if not isinstance(implementations, list) or not implementations:
        raise ValueError("Provide actual baseline adapters")
    names = set()
    for spec in implementations:
        if not isinstance(spec, dict) or set(spec) != {"method", "revision", "repository", "command", "timeout_s"}:
            raise ValueError("Invalid implementation descriptor")
        for field in ("method", "revision", "repository"):
            if not isinstance(spec[field], str) or not spec[field].strip():
                raise ValueError("Record the method, implementation revision and source")
        if spec["method"] in names:
            raise ValueError("Repeated baseline name")
        names.add(spec["method"])
        if not isinstance(spec["command"], list) or not spec["command"] or any(not isinstance(s, str) for s in spec["command"]):
            raise ValueError("Use an executable argument list, never a shell command")
        if type(spec["timeout_s"]) is not int or spec["timeout_s"] < 1:
            raise ValueError("Positive timeout_s required")
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    workload_hash, topology_hash = digest(workload), digest(topology)
    scenario_hash = hashlib.sha256(canonical(plan["scenario"])).hexdigest()
    records = []
    scopes: dict[int, tuple[dict[str, str], str]] = {}
    for seed in seeds:
        order = list(implementations)
        random.Random(seed).shuffle(order)  # Experiment order only, not crypto.
        for index, spec in enumerate(order):
            directory = output / f"seed-{seed}-adapter-{index}"
            directory.mkdir()
            expected = {"seed": seed, "workload_sha256": workload_hash,
                        "topology_sha256": topology_hash, "scenario_sha256": scenario_hash}
            request = {"pairing": expected, "workload": str(workload),
                       "topology": str(topology), "scenario": plan["scenario"]}
            request_path, result_path = directory / "request.json", directory / "result.json"
            request_path.write_bytes(canonical(request))
            substitutions = {"{request}": str(request_path), "{result}": str(result_path)}
            command = [substitutions.get(item, item) for item in spec["command"]]
            record = {"method": spec["method"], "revision": spec["revision"],
                      "repository": spec["repository"], "pairing": expected,
                      "status": "failed", "result": None}
            started = time.perf_counter_ns()
            try:
                subprocess.run(command, cwd=plan_path.parent, check=True,
                               timeout=spec["timeout_s"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, shell=False)
                if not result_path.is_file() or result_path.stat().st_size > 1_048_576:
                    raise ValueError("Missing or oversized adapter result")
                result = validate_result(json.loads(result_path.read_bytes()), expected)
                scope_key = (result["scope"], result["evidence"])
                if seed in scopes and scopes[seed] != scope_key:
                    raise ValueError("Paired implementations use different metric boundaries or evidence types")
                scopes[seed] = scope_key
                record.update(status="recorded", result=result,
                              result_sha256=digest(result_path))
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                record["failure_type"] = type(error).__name__
            record["adapter_wall_ms"] = (time.perf_counter_ns() - started) / 1_000_000
            # Launch wall time is orchestration information, not application latency.
            records.append(record)
    for seed in seeds:
        pair = [record for record in records if record["pairing"]["seed"] == seed]
        complete = len(pair) == len(implementations) and all(r["status"] == "recorded" for r in pair)
        for record in pair:
            record["pair_complete"] = complete
    (output / "paired_baselines.json").write_bytes(canonical({
        "plan_sha256": digest(plan_path), "records": records,
        "note": "No algorithm or unavailable metric is replaced by a synthetic value."}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run_plan(args.plan, args.output)


if __name__ == "__main__":
    main()
