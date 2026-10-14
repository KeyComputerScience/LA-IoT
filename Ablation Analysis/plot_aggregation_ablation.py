#!/usr/bin/env python3
"""Analyze paired aggregation ablations from recorded run summaries.

This source does not contain experimental results or illustrative performance
values. Run it explicitly after collecting JSON Lines records. Each record
describes one independent run, one source count, and one variant. Its schema is
documented by REQUIRED_FIELDS below. A pair_id identifies four matched runs;
replicate IDs must remain unique when configurations are combined in one file.

Squared errors and fusion timings describe successfully completed rounds only.
Their denominator must therefore exclude unfinished rounds. Energy and traffic
describe every scheduled round, including failures. The script includes failed
runs in completion, energy, and traffic summaries. It never substitutes zeros
for absent measurements. Run-level bootstrap intervals treat independent runs,
rather than reports within a run, as the experimental sampling units.

Dependencies: numpy, matplotlib. Python 3.11 or newer is recommended.
Example invocation (paths only; no example performance data):
    python plot_aggregation_ablation.py runs.jsonl --output analysis

No processing, file generation, or network activity occurs on import.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


VARIANTS = ("full", "equal_weights", "no_prior", "relay_off")
LABELS = {
    "full": "LA-IoT",
    "equal_weights": "Equal weights",
    "no_prior": "No prior",
    "relay_off": "Relay off",
}
EVIDENCE_TYPES = {
    "local_fusion_profile",
    "device_measurement",
    "network_simulation",
    "link_model",
}
REQUIRED_FIELDS = {
    "run_id", "pair_id", "variant", "nodes", "seed", "sensitive_fraction",
    "evidence", "workload_hash", "topology_hash", "environment_hash",
    "network_profile", "prior_case",
    "scheduled_rounds", "completed_rounds", "squared_error_sum",
    "estimate_count", "exact_match",
}
OPTIONAL_METRICS = (
    "fusion_ms_per_completed_round",
    "energy_mj_per_scheduled_round",
    "traffic_kib_per_scheduled_round",
)
PANEL_METRICS = (
    ("rmse", "RMSE", "Reading units"),
    ("fusion_ms_per_completed_round", "Fusion time", "ms / completed round"),
    ("traffic_kib_per_scheduled_round", "Traffic", "KiB / scheduled round"),
    ("energy_mj_per_scheduled_round", "Energy", "mJ / scheduled round"),
)
ALL_METRICS = tuple(item[0] for item in PANEL_METRICS) + ("completion_pct",)
PAIR_SETTINGS = (
    "seed", "nodes", "sensitive_fraction", "evidence", "workload_hash",
    "topology_hash", "environment_hash", "scheduled_rounds",
    "network_profile", "prior_case",
)


@dataclass(frozen=True)
class Run:
    line: int
    values: dict[str, Any]

    @property
    def group(self) -> tuple[str, str, float, str, str]:
        v = self.values
        return (
            v["evidence"], v["environment_hash"], v["sensitive_fraction"],
            v["network_profile"], v["prior_case"],
        )

    def metric(self, name: str) -> float | None:
        v = self.values
        if name == "completion_pct":
            return 100.0 * v["completed_rounds"] / v["scheduled_rounds"]
        if name == "rmse":
            if v["completed_rounds"] == 0 or v["estimate_count"] == 0:
                return None
            return math.sqrt(v["squared_error_sum"] / v["estimate_count"])
        if name == "fusion_ms_per_completed_round" and v["completed_rounds"] == 0:
            return None
        value = v.get(name)
        return None if value is None else float(value)


def require_integer(value: Any, field: str, line: int, minimum: int = 0) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"Line {line}: {field} must be an integer >= {minimum}")


def require_number(value: Any, field: str, line: int, minimum: float = 0.0) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < minimum
    ):
        raise ValueError(f"Line {line}: {field} must be finite and >= {minimum}")


def reject_constant(value: str) -> None:
    raise ValueError(f"JSON contains non-finite constant {value}")


def reject_duplicate_keys(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def load_records(path: Path) -> list[Run]:
    records: list[Run] = []
    seen_runs: set[str] = set()
    seen_variants: set[tuple[str, str]] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_number, text in enumerate(handle, 1):
            if not text.strip():
                continue
            try:
                v = json.loads(
                    text, parse_constant=reject_constant,
                    object_pairs_hook=reject_duplicate_keys,
                )
            except (ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"Line {line_number}: {exc}") from exc
            if not isinstance(v, dict):
                raise ValueError(f"Line {line_number}: expected a JSON object")
            missing = REQUIRED_FIELDS.difference(v)
            if missing:
                raise ValueError(f"Line {line_number}: missing {sorted(missing)}")
            for field in (
                "run_id", "pair_id", "variant", "evidence", "workload_hash",
                "topology_hash", "environment_hash",
                "network_profile", "prior_case",
            ):
                if not isinstance(v[field], str) or not v[field].strip():
                    raise ValueError(f"Line {line_number}: {field} must be nonempty text")
            for field in ("workload_hash", "topology_hash", "environment_hash"):
                if re.fullmatch(r"[0-9a-fA-F]{64}", v[field]) is None:
                    raise ValueError(f"Line {line_number}: {field} must contain 64 hexadecimal characters")
                v[field] = v[field].lower()
            if v["variant"] not in VARIANTS:
                raise ValueError(f"Line {line_number}: unknown variant {v['variant']!r}")
            if v["evidence"] not in EVIDENCE_TYPES:
                raise ValueError(f"Line {line_number}: unknown evidence {v['evidence']!r}")
            require_integer(v["nodes"], "nodes", line_number, 1)
            require_integer(v["seed"], "seed", line_number)
            require_integer(v["scheduled_rounds"], "scheduled_rounds", line_number, 1)
            require_integer(v["completed_rounds"], "completed_rounds", line_number)
            require_integer(v["estimate_count"], "estimate_count", line_number)
            require_number(v["sensitive_fraction"], "sensitive_fraction", line_number)
            require_number(v["squared_error_sum"], "squared_error_sum", line_number)
            if v["sensitive_fraction"] > 1:
                raise ValueError(f"Line {line_number}: sensitive_fraction must be <= 1")
            if v["completed_rounds"] > v["scheduled_rounds"]:
                raise ValueError(f"Line {line_number}: completed rounds exceed scheduled rounds")
            if not isinstance(v["exact_match"], bool) and v["exact_match"] is not None:
                raise ValueError(f"Line {line_number}: exact_match must be a Boolean or null")
            if v["completed_rounds"] > 0 and v["exact_match"] is None:
                raise ValueError(f"Line {line_number}: exact_match is required for completed rounds")
            if v["completed_rounds"] == 0 and (
                v["estimate_count"] != 0 or v["squared_error_sum"] != 0
            ):
                raise ValueError(
                    f"Line {line_number}: no completed rounds requires zero estimates and zero error sum"
                )
            if v["completed_rounds"] > 0 and v["estimate_count"] == 0:
                raise ValueError(f"Line {line_number}: completed rounds require a positive estimate_count")
            if v["estimate_count"] == 0 and v["squared_error_sum"] != 0:
                raise ValueError(f"Line {line_number}: nonzero error sum with zero estimates")
            for field in OPTIONAL_METRICS:
                if v.get(field) is not None:
                    require_number(v[field], field, line_number)
            if v["completed_rounds"] == 0 and v.get("fusion_ms_per_completed_round") is not None:
                raise ValueError(
                    f"Line {line_number}: fusion time must be null when no round completed"
                )
            if v["run_id"] in seen_runs:
                raise ValueError(f"Line {line_number}: duplicate run_id {v['run_id']!r}")
            key = (v["pair_id"], v["variant"])
            if key in seen_variants:
                raise ValueError(f"Line {line_number}: duplicate pair/variant {key!r}")
            seen_runs.add(v["run_id"])
            seen_variants.add(key)
            records.append(Run(line_number, v))
    if not records:
        raise ValueError("Input contains no run records")
    return records


def select_complete_pairs(
    records: list[Run],
) -> tuple[dict[str, dict[str, Run]], list[dict[str, Any]]]:
    pairs: dict[str, dict[str, Run]] = defaultdict(dict)
    for record in records:
        pairs[record.values["pair_id"]][record.values["variant"]] = record
    coverage: list[dict[str, Any]] = []
    accepted: dict[str, dict[str, Run]] = {}
    for pair_id, variants in sorted(pairs.items()):
        first = next(iter(variants.values()))
        for variant, record in variants.items():
            mismatches = [
                field for field in PAIR_SETTINGS
                if record.values[field] != first.values[field]
            ]
            if mismatches:
                raise ValueError(
                    f"Pair {pair_id!r}, variant {variant!r}: unmatched settings "
                    f"{', '.join(mismatches)}"
                )
        missing = [variant for variant in VARIANTS if variant not in variants]
        complete = not missing
        if complete:
            accepted[pair_id] = variants
        for variant in VARIANTS:
            record = variants.get(variant)
            coverage.append({
                "pair_id": pair_id,
                "variant": variant,
                "run_id": "" if record is None else record.values["run_id"],
                "nodes": first.values["nodes"],
                "seed": first.values["seed"],
                "evidence": first.values["evidence"],
                "environment_hash": first.values["environment_hash"],
                "topology_hash": first.values["topology_hash"],
                "sensitive_fraction": first.values["sensitive_fraction"],
                "network_profile": first.values["network_profile"],
                "prior_case": first.values["prior_case"],
                "record_present": record is not None,
                "pair_used": complete,
                "missing_variants": ";".join(missing),
                "completed_rounds": "" if record is None else record.values["completed_rounds"],
                "exact_match": "" if record is None else record.values["exact_match"],
            })
    return accepted, coverage


def group_identifier(group: tuple[str, str, float, str, str]) -> str:
    encoded = json.dumps(group, separators=(",", ":"), ensure_ascii=True).encode()
    return f"{group[0]}_{hashlib.sha256(encoded).hexdigest()[:12]}"


def stable_seed(seed: int, context: str) -> int:
    value = hashlib.sha256(f"{seed}:{context}".encode("utf-8")).digest()
    return int.from_bytes(value[:8], "big")


def summarize(
    values: list[float], *, seed: int, resamples: int, context: str,
) -> dict[str, Any]:
    import numpy as np

    if not values:
        return {"n": 0, "mean": None, "ci_low": None, "ci_high": None}
    data = np.asarray(values, dtype=float)
    if not np.all(np.isfinite(data)):
        raise ValueError(f"Non-finite calculated metric in {context}")
    result = {"n": len(values), "mean": float(data.mean()), "ci_low": None, "ci_high": None}
    if len(values) < 2:
        return result
    rng = np.random.default_rng(stable_seed(seed, context))
    means = np.empty(resamples, dtype=float)
    batch_size = max(1, min(512, 1_000_000 // len(values)))
    for start in range(0, resamples, batch_size):
        count = min(batch_size, resamples - start)
        indices = rng.integers(0, len(data), size=(count, len(data)))
        means[start:start + count] = data[indices].mean(axis=1)
    result["ci_low"], result["ci_high"] = (
        float(value) for value in np.quantile(means, [0.025, 0.975])
    )
    return result


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)


def build_summaries(
    pairs: dict[str, dict[str, Run]], *, seed: int, resamples: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    buckets: dict[tuple[Any, ...], list[Run]] = defaultdict(list)
    effect_buckets: dict[tuple[Any, ...], list[float]] = defaultdict(list)
    pair_counts: dict[tuple[Any, ...], int] = defaultdict(int)
    quality: list[dict[str, Any]] = []
    for pair_id, variants in pairs.items():
        full = variants["full"]
        group = full.group
        nodes = full.values["nodes"]
        for variant, record in variants.items():
            buckets[(group, nodes, variant)].append(record)
            quality.append({
                "group_id": group_identifier(group), "pair_id": pair_id,
                "run_id": record.values["run_id"], "variant": variant,
                "nodes": nodes, "exact_match": record.values["exact_match"],
                "prior_case": group[4],
                "scheduled_rounds": record.values["scheduled_rounds"],
                "completed_rounds": record.values["completed_rounds"],
                "estimate_count": record.values["estimate_count"],
            })
            if variant == "full":
                continue
            for metric in ALL_METRICS:
                key = (group, nodes, variant, metric)
                pair_counts[key] += 1
                a, b = record.metric(metric), full.metric(metric)
                if a is not None and b is not None:
                    effect_buckets[key].append(a - b)

    summaries: list[dict[str, Any]] = []
    for (group, nodes, variant), runs in sorted(buckets.items()):
        for metric in ALL_METRICS:
            values = [value for run in runs if (value := run.metric(metric)) is not None]
            summary = summarize(
                values, seed=seed, resamples=resamples,
                context=f"summary:{group}:{nodes}:{variant}:{metric}",
            )
            summaries.append({
                "group_id": group_identifier(group), "evidence": group[0],
                "environment_hash": group[1], "sensitive_fraction": group[2],
                "network_profile": group[3], "prior_case": group[4], "nodes": nodes,
                "variant": variant, "metric": metric,
                "available_runs": summary.pop("n"), "paired_runs": len(runs),
                **summary,
            })
    effects: list[dict[str, Any]] = []
    for (group, nodes, variant, metric), total in sorted(pair_counts.items()):
        values = effect_buckets[(group, nodes, variant, metric)]
        summary = summarize(
            values, seed=seed, resamples=resamples,
            context=f"effect:{group}:{nodes}:{variant}:{metric}",
        )
        effects.append({
            "group_id": group_identifier(group), "nodes": nodes,
            "prior_case": group[4],
            "variant": variant, "reference": "full", "metric": metric,
            "difference": "variant_minus_full",
            "available_pairs": summary.pop("n"), "complete_pairs": total,
            **summary,
        })
    return summaries, effects, quality


def configure_font(font_file: Path | None) -> str:
    import matplotlib as mpl
    from matplotlib import font_manager

    if font_file is not None:
        font_manager.fontManager.addfont(str(font_file))
        family = font_manager.FontProperties(fname=str(font_file)).get_name()
        if family.casefold() != "times new roman":
            raise ValueError("--font-file must contain Times New Roman")
    else:
        font_manager.findfont("Times New Roman", fallback_to_default=False)
    mpl.rcParams.update({
        "font.family": "Times New Roman", "font.size": 11,
        "axes.labelsize": 11, "axes.titlesize": 12,
        "axes.edgecolor": "black", "axes.labelcolor": "black",
        "text.color": "black", "xtick.color": "black", "ytick.color": "black",
        "figure.facecolor": "white", "axes.facecolor": "white",
        "savefig.facecolor": "white", "pdf.fonttype": 42,
        "ps.fonttype": 42, "axes.unicode_minus": False,
    })
    return font_manager.findfont("Times New Roman", fallback_to_default=False)


def draw_series(ax: Any, rows: list[dict[str, Any]], metric: str) -> bool:
    import numpy as np

    styles = {
        "full": ("#b22222", "o", "-"),
        "equal_weights": ("black", "s", "--"),
        "no_prior": ("#4a4a4a", "^", "-."),
        "relay_off": ("#7a7a7a", "D", ":"),
    }
    any_data = False
    nodes = sorted({row["nodes"] for row in rows})
    for variant in VARIANTS:
        selected = {
            row["nodes"]: row for row in rows
            if row["variant"] == variant and row["metric"] == metric
        }
        means = [
            np.nan if selected[n]["mean"] is None else selected[n]["mean"]
            for n in nodes
        ]
        if not any(math.isfinite(value) for value in means):
            continue
        any_data = True
        color, marker, line = styles[variant]
        ax.plot(
            nodes, means, color=color, marker=marker, linestyle=line,
            linewidth=1.65, markersize=5.2, label=LABELS[variant],
        )
        lows = [
            np.nan if selected[n]["ci_low"] is None else selected[n]["ci_low"]
            for n in nodes
        ]
        highs = [
            np.nan if selected[n]["ci_high"] is None else selected[n]["ci_high"]
            for n in nodes
        ]
        ax.fill_between(nodes, lows, highs, color=color, alpha=0.10, linewidth=0)
    ax.set_xlabel("Number of nodes")
    ax.grid(axis="y", color="#d8d8d8", linewidth=0.6, linestyle=":")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    if len(nodes) <= 7:
        ax.set_xticks(nodes)
    ax.tick_params(axis="x", labelrotation=30 if len(nodes) > 4 else 0)
    ax.ticklabel_format(axis="y", style="plain", useOffset=False)
    if not any_data:
        ax.text(0.5, 0.5, "Not recorded", transform=ax.transAxes, ha="center", va="center")
        ax.set_yticks([])
    return any_data


def external_legend(fig: Any, axes: Iterable[Any]) -> None:
    lookup: dict[str, Any] = {}
    for ax in axes:
        handles, labels = ax.get_legend_handles_labels()
        lookup.update(zip(labels, handles))
    ordered = [LABELS[variant] for variant in VARIANTS if LABELS[variant] in lookup]
    if ordered:
        fig.legend(
            [lookup[label] for label in ordered], ordered,
            loc="upper center", bbox_to_anchor=(0.5, 0.94),
            ncol=len(ordered), frameon=False,
        )


def create_figures(
    summaries: list[dict[str, Any]], output: Path, *, dpi: int,
) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    files: list[str] = []
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in summaries:
        groups[row["group_id"]].append(row)
    for group_id, rows in sorted(groups.items()):
        first = rows[0]
        title = (
            f"Evidence: {first['evidence']}; "
            f"sensitive fraction = {first['sensitive_fraction']:g}; "
            f"prior = {first['prior_case']}"
        )
        available_panels = [
            spec for spec in PANEL_METRICS
            if any(row["metric"] == spec[0] and row["mean"] is not None for row in rows)
        ]
        if not available_panels:
            available_panels = list(PANEL_METRICS[:2])
        fig, axes = plt.subplots(
            1, len(available_panels), figsize=(4.1 * len(available_panels), 4.2), squeeze=False,
        )
        axes = axes[0]
        fig.suptitle(title, y=0.995, fontsize=12)
        for index, (ax, (metric, heading, unit)) in enumerate(zip(axes, available_panels)):
            draw_series(ax, rows, metric)
            ax.set_title(f"({chr(97 + index)}) {heading}", pad=9)
            ax.set_ylabel(unit)
        external_legend(fig, axes)
        fig.tight_layout(rect=(0, 0, 1, 0.83), w_pad=1.9)
        for extension in ("png", "pdf"):
            name = f"{group_id}_aggregation_ablation.{extension}"
            fig.savefig(output / name, dpi=dpi, bbox_inches="tight")
            files.append(name)
        plt.close(fig)

        fig, ax = plt.subplots(figsize=(6.1, 4.2))
        fig.suptitle(title, y=0.995, fontsize=12)
        draw_series(ax, rows, "completion_pct")
        ax.set_ylabel("Completed rounds (%)")
        ax.set_ylim(-1, 101)
        external_legend(fig, [ax])
        fig.tight_layout(rect=(0, 0, 1, 0.82))
        for extension in ("png", "pdf"):
            name = f"{group_id}_completion.{extension}"
            fig.savefig(output / name, dpi=dpi, bbox_inches="tight")
            files.append(name)
        plt.close(fig)
    return files


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON Lines summaries from independent runs")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bootstrap-samples", type=int, default=10_000)
    parser.add_argument("--bootstrap-seed", type=int, default=20261013)
    parser.add_argument("--dpi", type=int, default=300)
    parser.add_argument("--font-file", type=Path, help="Optional Times New Roman font file")
    args = parser.parse_args()
    if args.bootstrap_samples < 1000:
        parser.error("--bootstrap-samples must be >= 1000")
    if args.bootstrap_seed < 0 or args.dpi < 72:
        parser.error("bootstrap seed must be nonnegative and dpi must be >= 72")

    records = load_records(args.input)
    pairs, coverage = select_complete_pairs(records)
    summaries, effects, quality = build_summaries(
        pairs, seed=args.bootstrap_seed, resamples=args.bootstrap_samples,
    )
    args.output.mkdir(parents=True, exist_ok=False)
    write_csv(args.output / "coverage.csv", coverage, list(coverage[0]))
    write_csv(args.output / "summary.csv", summaries, [
        "group_id", "evidence", "environment_hash",
        "sensitive_fraction", "network_profile", "prior_case", "nodes", "variant", "metric",
        "available_runs", "paired_runs", "mean", "ci_low", "ci_high",
    ])
    write_csv(args.output / "paired_effects.csv", effects, [
        "group_id", "nodes", "prior_case", "variant", "reference", "metric", "difference",
        "available_pairs", "complete_pairs", "mean", "ci_low", "ci_high",
    ])
    write_csv(args.output / "correctness.csv", quality, [
        "group_id", "pair_id", "run_id", "variant", "nodes", "exact_match", "prior_case",
        "scheduled_rounds", "completed_rounds", "estimate_count",
    ])
    font_path = configure_font(args.font_file) if summaries else None
    figures = create_figures(summaries, args.output, dpi=args.dpi) if summaries else []
    import numpy as np
    import matplotlib
    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "input": str(args.input.resolve()), "input_sha256": sha256_file(args.input),
        "analysis_source": str(Path(__file__).resolve()),
        "analysis_sha256": sha256_file(Path(__file__)),
        "numpy_version": np.__version__, "matplotlib_version": matplotlib.__version__,
        "font_file": font_path,
        "run_records": len(records), "complete_pairs": len(pairs),
        "excluded_incomplete_pairs": len({r.values['pair_id'] for r in records}) - len(pairs),
        "exact_match_false_in_used_runs": sum(row["exact_match"] is False for row in quality),
        "exact_match_unobserved_in_used_runs": sum(row["exact_match"] is None for row in quality),
        "grouping_fields": ["evidence", "environment_hash", "sensitive_fraction", "network_profile", "prior_case"],
        "prior_cases": sorted({record.values["prior_case"] for record in records}),
        "topology_rule": "topology_hash is matched within a pair; each seed or source count may have its own topology",
        "bootstrap": {
            "method": "independent-run percentile bootstrap; paired differences resampled by pair",
            "confidence_level": 0.95, "resamples": args.bootstrap_samples,
            "resampling_seed": args.bootstrap_seed,
            "minimum_runs_for_interval": 2,
        },
        "metric_definitions": {
            "rmse": "sqrt(squared_error_sum / estimate_count), completed-round estimates only",
            "completion_pct": "100 * completed_rounds / scheduled_rounds; all used runs",
            "fusion_ms_per_completed_round": "logged completed-round fusion time; no failed-round denominator",
            "traffic_kib_per_scheduled_round": "all logged traffic divided by scheduled rounds; 1 KiB = 1024 bytes",
            "energy_mj_per_scheduled_round": "all logged energy divided by scheduled rounds",
            "summary": "arithmetic mean of independent run summaries, not pooled report observations",
            "paired_effect": "variant minus LA-IoT for pairs with both metric values available",
        },
        "missing_metrics": "null or absent input values remain missing; no zero substitution",
        "correctness": "exact_match is exported without excluding mismatching runs",
        "figure_files": figures,
    }
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, allow_nan=False) + "\n", encoding="utf-8",
    )
    print(f"Analyzed {len(records)} records; used {len(pairs)} complete matched pairs.")
    print(f"Saved results to {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

