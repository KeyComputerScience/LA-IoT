# SPDX-License-Identifier: Apache-2.0
"""Summarize recorded experiments and draw PNG/PDF figures without invented data.

Generated as source only and not executed. Network intervals use independent
runs as bootstrap units. All rounds enter completion and decision time; only
complete rounds enter JCT and conditional latency. Measured and modeled energy stay
separate. Empty inputs create a missing-data report, not numerical plots.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import random
import statistics


def read_csv(path: Path | None, fields: tuple[str, ...]) -> list[dict]:
    if path is None:
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not set(fields).issubset(reader.fieldnames or []):
            raise ValueError(f"Missing columns in {path}: {fields}")
        return list(reader)


def number(value: str, label: str, minimum: float = 0) -> float:
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise ValueError(f"Invalid {label}")
    return result


def optional_number(value, label: str) -> float | None:
    """Absent instrumentation stays missing, never a favorable zero cost."""
    return None if value is None or value == "" else number(value, label)


COST_COLUMNS = (
    "n_wire_bytes", "source_copy_bytes", "provisional_aggregate_bytes",
    "control_bytes", "result_bytes", "controller_reencrypt_ms", "verification_ms",
    "controller_recovery_ms", "controller_reconstruction_ms", "aggregation_processing_ms",
    "bottleneck_wire_bytes", "bottleneck_load_pct", "e2e_latency_ms", "host_peak_rss_bytes",
)


def write_csv(path: Path, fields: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def interval(values: list[float], repetitions: int, seed: int) -> dict:
    mean = statistics.mean(values)
    if len(values) < 2:
        return {"mean": mean, "lower95": None, "upper95": None, "n_units": len(values)}
    rng = random.Random(seed)
    samples = sorted(statistics.mean(rng.choices(values, k=len(values)))
                     for _ in range(repetitions))
    return {"mean": mean, "lower95": samples[int(.025 * (repetitions - 1))],
            "upper95": samples[int(.975 * (repetitions - 1))], "n_units": len(values)}


def energy_profile(path: Path | None, mode: str) -> dict:
    if path is None:
        raise ValueError("Energy input requires an explicit energy profile")
    profile = json.loads(path.read_text(encoding="utf-8"))
    if (profile.get("mode") != mode or profile.get("disjoint_components") is not True
            or not profile.get("calibration_artifact_sha256")
            or not profile.get("clock_domain") or not profile.get("calibration_artifact")):
        raise ValueError("Declare energy mode, disjoint components, clock, and calibration artifact")
    calibration = path.parent / profile["calibration_artifact"]
    if hashlib.sha256(calibration.read_bytes()).hexdigest() != profile["calibration_artifact_sha256"]:
        raise ValueError("Calibration artifact hash does not match")
    components = profile.get("components", {})
    scopes = [item.get("physical_scope_id") or item.get("scope_id") for item in components.values()]
    if not components or not all(scopes) or len(scopes) != len(set(scopes)):
        raise ValueError("Energy scopes must be nonempty and nonoverlapping")
    return profile


def validate_energy_windows(rounds: list[dict], power: list[dict], states: list[dict], profile: dict) -> None:
    windows = {}
    for row in rounds:
        if row["clock_domain"] != profile["clock_domain"]:
            raise ValueError("Round clocks must match the explicitly aligned energy clock")
        key = (row["run_id"], row["scheme"])
        start, stop = number(row["release_s"], "release"), number(row["decision_s"], "decision")
        old = windows.get(key, (start, stop))
        windows[key] = (min(start, old[0]), max(stop, old[1]))
    traced = defaultdict(list)
    for row in power:
        if row["clock_domain"] != profile["clock_domain"]:
            raise ValueError("Align power timestamps and document that mapping before analysis")
        traced[(row["run_id"], row["scheme"], row["component"])].append(number(row["time_s"], "power time"))
    for (run_id, scheme, _), times in traced.items():
        expected = windows.get((run_id, scheme))
        if expected is None or abs(times[0] - expected[0]) > 1e-6 or abs(times[-1] - expected[1]) > 1e-6:
            raise ValueError("Power trace must include exact full-schedule boundary samples")
    durations = defaultdict(float)
    for row in states:
        durations[(row["run_id"], row["scheme"], row["component"])] += number(row["duration_s"], "state duration")
    for (run_id, scheme, _), duration in durations.items():
        expected = windows.get((run_id, scheme))
        if expected is None or abs(duration - (expected[1] - expected[0])) > 1e-6:
            raise ValueError("State accounting must cover the entire scheduled-round window")


def measured_energy(rows: list[dict], profile: dict) -> dict:
    """Trapezoid-integrate actual power samples: W * s * 1000 = mJ."""
    traces = defaultdict(list)
    for row in rows:
        component = row["component"]
        if component not in profile["components"]:
            raise ValueError("Unknown measured-power component")
        traces[(row["run_id"], row["scheme"], component)].append(
            (number(row["time_s"], "time"), number(row["power_w"], "power")))
    totals, windows, observed = defaultdict(float), {}, defaultdict(set)
    for (run_id, scheme, component), points in traces.items():
        # Do not sort or repair logs: nonmonotonic clocks must be investigated.
        if len(points) < 2 or any(b[0] <= a[0] for a, b in zip(points, points[1:])):
            raise ValueError("Power samples need strictly increasing timestamps")
        key = (run_id, scheme)
        window = (points[0][0], points[-1][0])
        if key in windows and any(abs(a - b) > 1e-6 for a, b in zip(window, windows[key])):
            raise ValueError("Energy components must cover the same measurement window")
        windows[key] = window
        observed[key].add(component)
        totals[key] += 1000 * sum((b[0] - a[0]) * (a[1] + b[1]) / 2
                                 for a, b in zip(points, points[1:]))
    if any(items != set(profile["components"]) for items in observed.values()):
        raise ValueError("Missing measured component in a run")
    return dict(totals)


def modeled_energy(rows: list[dict], profile: dict) -> dict:
    """Use calibrated, exclusive states within each disjoint component only."""
    totals, durations, seen, observed = defaultdict(float), defaultdict(float), set(), defaultdict(set)
    for row in rows:
        run_id, scheme, component, state = (row[k] for k in ("run_id", "scheme", "component", "state"))
        item = profile["components"].get(component)
        key = (run_id, scheme, component, state)
        if not item or state not in item.get("exclusive_states", []) or key in seen:
            raise ValueError("Unknown or repeated modeled state")
        seen.add(key)
        duration = number(row["duration_s"], "state duration")
        power = number(row["power_mw"], "state power")
        totals[(run_id, scheme)] += duration * power
        durations[(run_id, scheme, component)] += duration
        observed[(run_id, scheme, component)].add(state)
    by_run = defaultdict(list)
    for (run_id, scheme, component), duration in durations.items():
        if observed[(run_id, scheme, component)] != set(profile["components"][component]["exclusive_states"]):
            raise ValueError("Missing modeled state; record zero durations explicitly")
        by_run[(run_id, scheme)].append(duration)
    for key, values in by_run.items():
        if len(values) != len(profile["components"]) or max(values) - min(values) > 1e-6:
            raise ValueError("Modeled components must cover the same run duration")
    return dict(totals)


def summarize_rounds(rows: list[dict], energies: dict, repetitions: int, seed: int) -> list[dict]:
    runs, seen, run_scenarios = defaultdict(list), set(), {}
    run_seeds, independent_seeds = {}, {}
    for row in rows:
        run_id, scheme, scenario = (row[k] for k in ("run_id", "scheme", "scenario_id"))
        key = (run_id, scheme, row["round_id"])
        if key in seen or row["status"] not in {"complete", "timeout", "rejected", "incomplete"}:
            raise ValueError("Duplicate round or unknown round status")
        seen.add(key)
        run_key = (run_id, scheme)
        if run_key in run_scenarios and run_scenarios[run_key] != scenario:
            raise ValueError("One run ID cannot pool scenarios")
        run_scenarios[run_key] = scenario
        workload_seed = int(row["seed"])
        if workload_seed < 0 or (run_key in run_seeds and run_seeds[run_key] != workload_seed):
            raise ValueError("One run must retain one nonnegative workload seed")
        run_seeds[run_key] = workload_seed
        seed_key = (scenario, scheme, workload_seed)
        if seed_key in independent_seeds and independent_seeds[seed_key] != run_id:
            raise ValueError("Repeated same-seed sessions are not independent topology/workload runs")
        independent_seeds[seed_key] = run_id
        expected, accepted = int(row["n_expected"]), int(row["n_accepted"])
        if expected < 1 or not 0 <= accepted <= expected:
            raise ValueError("Invalid participant counts")
        if row["status"] == "complete" and accepted != expected:
            raise ValueError("Complete rounds must include all expected participants")
        row["_jct"] = optional_number(row["jct_ms"], "round-decision duration")
        if row["_jct"] is not None:
            elapsed_ms = 1000 * (number(row["decision_s"], "decision") - number(row["release_s"], "release"))
            if elapsed_ms < 0 or abs(elapsed_ms - row["_jct"]) > max(.001, abs(elapsed_ms) * 1e-6):
                raise ValueError("JCT does not match recorded release/decision timestamps")
        row["_latency"] = (optional_number(row["latency_ms"], "conditional latency")
                           if row["status"] == "complete" else None)
        for metric in COST_COLUMNS:
            row["_cost_" + metric] = optional_number(row.get(metric), metric)
        runs[(scenario, scheme, run_id)].append(row)
    unknown_energy = set(energies) - set(run_scenarios)
    if unknown_energy:
        raise ValueError("Energy inputs do not match recorded runs")
    if energies and set(energies) != set(run_scenarios):
        raise ValueError("An energy analysis requires the complete declared set of runs")
    groups = defaultdict(list)
    for (scenario, scheme, run_id), values in runs.items():
        if all(row["_jct"] is not None for row in values):
            groups[(scenario, scheme, "all_round_decision_ms")].append(statistics.mean(row["_jct"] for row in values))
        complete = [row for row in values if row["status"] == "complete"]
        if complete and all(row["_jct"] is not None for row in complete):
            groups[(scenario, scheme, "completed_jct_ms")].append(statistics.mean(row["_jct"] for row in complete))
        groups[(scenario, scheme, "completion_pct")].append(
            100 * sum(row["status"] == "complete" for row in values) / len(values))
        latency = [row["_latency"] for row in values if row["_latency"] is not None]
        if latency and len(latency) == len(complete):
            groups[(scenario, scheme, "latency_ms")].append(statistics.mean(latency))
        for metric in COST_COLUMNS:
            # End-to-end acceptance latency is conditional on completed rounds.
            selected = complete if metric == "e2e_latency_ms" else values
            observed = [row["_cost_" + metric] for row in selected]
            if observed and all(item is not None for item in observed):
                aggregate = max(observed) if metric == "host_peak_rss_bytes" else statistics.mean(observed)
                groups[(scenario, scheme, metric)].append(aggregate)
        if (run_id, scheme) in energies:
            groups[(scenario, scheme, "energy_mj_per_scheduled_round")].append(
                energies[(run_id, scheme)] / len(values))
    result = []
    for index, ((scenario, scheme, metric), values) in enumerate(sorted(groups.items())):
        result.append(dict(scenario_id=scenario, scheme=scheme, metric=metric,
                           **interval(values, repetitions, seed + index)))
    return result


def plotting():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib import font_manager
    # Fail clearly rather than silently substituting a different font.
    font_manager.findfont("Times New Roman", fallback_to_default=False)
    plt.rcParams.update({"font.family": "Times New Roman", "font.size": 11,
                         "figure.facecolor": "white", "axes.facecolor": "white",
                         "text.color": "black", "axes.labelcolor": "black",
                         "pdf.fonttype": 42, "ps.fonttype": 42})
    return plt


def bars(axis, rows: list[dict], label: str) -> None:
    if not rows:
        axis.text(.5, .5, "No recorded data", ha="center", va="center", transform=axis.transAxes)
        axis.set_xticks([])
        axis.set_ylabel(label)
        return
    labels = [row.get("scheme", row.get("algorithm")) for row in rows]
    for index, row in enumerate(rows):
        color = "#b22222" if labels[index] == "LA-IoT" else "white"
        axis.bar(index, row["mean"], color=color, edgecolor="black", width=.65)
        if row["lower95"] is not None:
            midpoint = (row["lower95"] + row["upper95"]) / 2
            axis.errorbar(index, midpoint,
                          yerr=(row["upper95"] - row["lower95"]) / 2,
                          color="black", capsize=3, fmt="none")
    axis.set_xticks(range(len(labels)), labels, rotation=25, ha="right")
    axis.set_ylabel(label)
    axis.set_ylim(bottom=0)
    axis.spines[["top", "right"]].set_visible(False)
    axis.grid(axis="y", color="0.85", linewidth=.5)
    axis.set_axisbelow(True)


def save_figure(figure, base: Path, plt) -> None:
    figure.tight_layout()
    figure.savefig(base.with_suffix(".png"), dpi=300, bbox_inches="tight", facecolor="white")
    figure.savefig(base.with_suffix(".pdf"), bbox_inches="tight", facecolor="white")
    plt.close(figure)


def network_figures(summary: list[dict], output: Path, energy_kind: str) -> None:
    if not summary:
        return
    plt = plotting()
    metrics = (("completed_jct_ms", "JCT of complete rounds (ms)"),
               ("energy_mj_per_scheduled_round", f"Energy (mJ / scheduled round; {energy_kind})"),
               ("completion_pct", "Complete rounds (%)"),
               ("latency_ms", "Recorded latency in complete rounds (ms)"))
    for index, scenario in enumerate(sorted({row["scenario_id"] for row in summary})):
        figure, axes = plt.subplots(2, 2, figsize=(10, 6.5))
        for axis, (metric, label) in zip(axes.flat, metrics):
            selected = [row for row in summary if row["scenario_id"] == scenario and row["metric"] == metric]
            bars(axis, selected, label)
        figure.suptitle(f"Scenario: {scenario}; intervals across independent runs", fontsize=12)
        save_figure(figure, output / f"network_{energy_kind}_{index:02d}", plt)
        cost_metrics = (("source_copy_bytes", "Original-report traffic (bytes / round)"),
                        ("provisional_aggregate_bytes", "Relay partial traffic (bytes / round)"),
                        ("controller_reconstruction_ms", "Controller reconstruction (ms / round)"),
                        ("bottleneck_load_pct", "Identified bottleneck load (%)"))
        if any(row["scenario_id"] == scenario and row["metric"] in {item[0] for item in cost_metrics} for row in summary):
            figure, axes = plt.subplots(1, 4, figsize=(15, 4))
            for axis, (metric, label) in zip(axes.flat, cost_metrics):
                bars(axis, [row for row in summary if row["scenario_id"] == scenario and row["metric"] == metric], label)
            figure.suptitle(f"Scenario: {scenario}; separate traffic and reconstruction scopes", fontsize=12)
            save_figure(figure, output / f"accounting_{index:02d}", plt)


def benchmark_summary(rows: list[dict], repetitions: int, seed: int) -> list[dict]:
    metrics = ("keygen_ms", "encaps_ms", "decaps_ms", "kdf_sender_ms", "kdf_receiver_ms",
               "aead_encrypt_ms", "aead_decrypt_ms",
               "source_mac_ms", "source_verify_ms", "protected_body_bytes",
               "actual_micro_envelope_bytes", "worker_peak_rss_bytes")
    groups = defaultdict(list)
    seen, memory_workers, input_sizes = set(), set(), set()
    for row in rows:
        if row["status"] != "ok":
            continue
        key = (row["run_id"], row["algorithm"], row["trial"])
        if key in seen:
            raise ValueError("Repeated benchmark trial")
        seen.add(key)
        input_sizes.add((int(row["plaintext_bytes"]), int(row["aad_bytes"])))
        if len(input_sizes) > 1:
            raise ValueError("Do not pool benchmarks with different logical input sizes")
        for metric in metrics:
            if metric == "worker_peak_rss_bytes":
                worker = (row["run_id"], row["algorithm"])
                if worker in memory_workers:
                    continue
                memory_workers.add(worker)
            groups[(row["algorithm"], metric)].append(number(row[metric], metric))
    result = []
    for index, ((algorithm, metric), values) in enumerate(sorted(groups.items())):
        stats = interval(values, repetitions, seed + index)
        if metric in {"protected_body_bytes", "actual_micro_envelope_bytes", "worker_peak_rss_bytes"}:
            stats["lower95"] = stats["upper95"] = None
        result.append(dict(algorithm=algorithm, metric=metric, **stats))
    return result


def benchmark_figure(summary: list[dict], output: Path) -> None:
    if not summary:
        return
    plt = plotting()
    figure, axes = plt.subplots(2, 2, figsize=(11, 7))
    for axis, metric, label in zip(axes.flat,
            ("keygen_ms", "encaps_ms", "decaps_ms", "actual_micro_envelope_bytes"),
            ("Key generation (ms)", "Encapsulation (ms)", "Decapsulation (ms)", "Micro-envelope (bytes)")):
        bars(axis, [row for row in summary if row["metric"] == metric], label)
    figure.suptitle("KEM microbenchmarks; timing intervals across trials, not deployments", fontsize=12)
    save_figure(figure, output / "crypto_microbenchmark", plt)


def comparison_rows(summary: list[dict]) -> list[dict]:
    lookup = {(row["scenario_id"], row["scheme"], row["metric"]): row for row in summary}
    comparisons = []
    for row in summary:
        if row["scheme"] == "LA-IoT":
            continue
        la = lookup.get((row["scenario_id"], "LA-IoT", row["metric"]))
        if la is None:
            continue
        completion = row["metric"] == "completion_pct"
        comparisons.append({"scenario_id": row["scenario_id"], "baseline": row["scheme"],
            "metric": row["metric"], "la_mean": la["mean"], "baseline_mean": row["mean"],
            "relative_reduction_pct": 100 * (row["mean"] - la["mean"]) / row["mean"]
                if not completion and row["mean"] else "",
            "completion_difference_percentage_points": la["mean"] - row["mean"] if completion else "",
            "n_la_runs": la["n_units"], "n_baseline_runs": row["n_units"]})
    return comparisons


def latex_escape(value: str) -> str:
    replacements = {"\\": r"\textbackslash{}", "{": r"\{", "}": r"\}",
                    "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#",
                    "_": r"\_", "^": r"\textasciicircum{}", "~": r"\textasciitilde{}"}
    return "".join(replacements.get(character, character) for character in value)


def results_paragraph(summary: list[dict], micro: list[dict], output: Path, energy_kind: str) -> None:
    """Produce an English manuscript fragment only from actual observations."""
    if not summary and not micro:
        return
    paragraphs = ["% Generated from recorded input files; see analysis_manifest.json."]
    labels = {"completed_jct_ms": "completed-round JCT (ms)",
              "all_round_decision_ms": "all-round decision time (ms)",
              "completion_pct": r"completion rate (\%)",
              "latency_ms": "recorded completed-round latency (ms)",
              "energy_mj_per_scheduled_round": "energy per scheduled round (mJ)"}
    labels.update({"n_wire_bytes": "all-hop wire traffic (bytes/round)",
        "source_copy_bytes": "original-report wire traffic (bytes/round)",
        "provisional_aggregate_bytes": "relay-partial wire traffic (bytes/round)",
        "control_bytes": "control wire traffic (bytes/round)",
        "result_bytes": "result wire traffic (bytes/round)",
        "verification_ms": "controller verification (ms/round)",
        "controller_recovery_ms": "controller recovery (ms/round)",
        "controller_reencrypt_ms": "controller re-encryption (ms/round)",
        "controller_reconstruction_ms": "controller reconstruction (ms/round)",
        "aggregation_processing_ms": "recorded aggregation processing (ms/round)",
        "bottleneck_wire_bytes": "identified bottleneck wire traffic (bytes/round)",
        "bottleneck_load_pct": r"identified bottleneck load (\%)",
        "e2e_latency_ms": "release-to-recipient acceptance latency (ms)",
        "host_peak_rss_bytes": "peak host process memory (bytes)"})
    for scenario in sorted({row["scenario_id"] for row in summary}):
        clauses = []
        for row in summary:
            if row["scenario_id"] != scenario:
                continue
            uncertainty = (f"95\\% interval {row['lower95']:.4g}--{row['upper95']:.4g}"
                           if row["lower95"] is not None else "interval unavailable from one run")
            clauses.append(f"{latex_escape(row['scheme'])}: mean {labels[row['metric']]} "
                           f"{row['mean']:.4g} ({uncertainty}; {row['n_units']} runs)")
        paragraphs.append(f"For scenario \\texttt{{{latex_escape(scenario)}}}, " + "; ".join(clauses) + ".")
    if summary:
        paragraphs.append("Completed-round JCT and report latency are conditional on successful rounds. "
                          "Completion includes all scheduled rounds. All-round decision time also includes "
                          f"timeouts and rejections. The energy source for this analysis is {energy_kind}; "
                          "measured and modeled energy are analyzed separately.")
    if micro:
        values = [f"{latex_escape(row['algorithm'])}: {row['mean']:.4g} ms"
                  for row in micro if row["metric"] == "encaps_ms"]
        paragraphs.append("The observed mean KEM encapsulation times are " + "; ".join(values) + ". "
                          "These component timings describe the executing host and do not measure the full "
                          "LA-IoT protocol or demonstrate deployment within 32 KB of RAM.")
    (output / "results_analysis_generated.tex").write_text("\n\n".join(paragraphs) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=Path)
    parser.add_argument("--power", type=Path)
    parser.add_argument("--energest", type=Path)
    parser.add_argument("--energy-profile", type=Path)
    parser.add_argument("--benchmark", type=Path)
    parser.add_argument("--security", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bootstrap", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20261012)
    args = parser.parse_args()
    if args.bootstrap < 100 or (args.power and args.energest):
        parser.error("Use at least 100 bootstrap draws and one energy source per analysis")
    rounds = read_csv(args.rounds, ("run_id", "scheme", "scenario_id", "seed", "round_id", "status",
                                  "release_s", "decision_s", "clock_domain", "jct_ms", "latency_ms", "n_expected", "n_accepted"))
    power = read_csv(args.power, ("run_id", "scheme", "component", "time_s", "power_w", "clock_domain"))
    energest = read_csv(args.energest, ("run_id", "scheme", "component", "state", "duration_s", "power_mw"))
    benchmark = read_csv(args.benchmark, ("run_id", "algorithm", "trial", "status"))
    security = read_csv(args.security, ("run_id", "scheme", "scenario_id", "attack", "attempted",
                                       "detected", "accepted_modified", "legitimate", "false_rejected"))
    energies, energy_kind = {}, "unavailable"
    if power:
        energy_kind = "measured"
        profile = energy_profile(args.energy_profile, energy_kind)
        validate_energy_windows(rounds, power, [], profile)
        energies = measured_energy(power, profile)
    if energest:
        energy_kind = "modeled"
        profile = energy_profile(args.energy_profile, energy_kind)
        validate_energy_windows(rounds, [], energest, profile)
        energies = modeled_energy(energest, profile)
    summary = summarize_rounds(rounds, energies, args.bootstrap, args.seed)
    micro = benchmark_summary(benchmark, args.bootstrap, args.seed)
    args.output.mkdir(parents=True, exist_ok=False)
    fields = ("scenario_id", "scheme", "metric", "mean", "lower95", "upper95", "n_units")
    write_csv(args.output / "network_summary.csv", fields, summary)
    write_csv(args.output / "benchmark_summary.csv",
              ("algorithm", "metric", "mean", "lower95", "upper95", "n_units"), micro)
    write_csv(args.output / "baseline_comparisons.csv",
              ("scenario_id", "baseline", "metric", "la_mean", "baseline_mean",
               "relative_reduction_pct", "completion_difference_percentage_points",
               "n_la_runs", "n_baseline_runs"), comparison_rows(summary))
    results_paragraph(summary, micro, args.output, energy_kind)
    security_output = []
    for row in security:
        counts = {key: int(row[key]) for key in ("attempted", "detected", "accepted_modified", "legitimate", "false_rejected")}
        if (min(counts.values()) < 0 or counts["detected"] > counts["attempted"]
                or counts["accepted_modified"] > counts["attempted"]
                or counts["detected"] + counts["accepted_modified"] > counts["attempted"]
                or counts["false_rejected"] > counts["legitimate"]):
            raise ValueError("Invalid security event counts")
        security_output.append({**row,
            "detection_pct": 100 * counts["detected"] / counts["attempted"] if counts["attempted"] else "",
            "accepted_modified_pct": 100 * counts["accepted_modified"] / counts["attempted"] if counts["attempted"] else "",
            "false_rejection_pct": 100 * counts["false_rejected"] / counts["legitimate"] if counts["legitimate"] else ""})
    if security:
        write_csv(args.output / "security_report.csv", tuple(security_output[0]), security_output)
    missing = []
    if not rounds:
        missing.append("No scheduled-round records: network result figures not generated.")
    if not energies:
        missing.append("No calibrated energy records: energy panel contains no numerical values.")
    if not micro:
        missing.append("No successful KEM trials: crypto result figure not generated.")
    if not security:
        missing.append("No attack-event counts: security rates not calculated.")
    hashes = {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in (args.rounds, args.power, args.energest, args.energy_profile,
                           args.benchmark, args.security, Path(__file__)) if path is not None}
    report = {"input_sha256": hashes, "bootstrap_seed": args.seed,
              "bootstrap_repetitions": args.bootstrap, "energy_kind": energy_kind,
              "missing": missing, "ind_cca_proved_by_experiment": False,
              "latency_condition": "recorded latency; complete rounds only; see input clock/scope metadata",
              "jct_condition": "release to recorded terminal delivery decision; receipt confirmation may follow receiver acceptance",
              "all_round_decision_condition": "release to confirmed delivery or timeout/rejection; all scheduled rounds",
              "cost_columns": COST_COLUMNS,
              "missing_cost_policy": "no zero fill; a per-run metric needs all eligible round values",
              "figures": "generated only for available observations"}
    (args.output / "analysis_manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    network_figures(summary, args.output, energy_kind)
    benchmark_figure(micro, args.output)


if __name__ == "__main__":
    main()

