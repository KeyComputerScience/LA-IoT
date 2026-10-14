# SPDX-License-Identifier: Apache-2.0
"""Reduce actual metadata logs into end-to-end accounting tables.

No measurements are invented. Uninstrumented metrics remain null/empty. This
standard-library module performs no crypto, networking or work on import.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .events import TRAFFIC_CLASSES, from_csv_row, parse_event, validate_event

ROUND_FIELDS = (
    "run_id", "scheme", "scenario_id", "seed", "round_id", "status",
    "release_s", "decision_s", "recipient_accept_s", "clock_domain", "jct_ms", "latency_ms",
    "n_expected", "n_accepted", "n_verified", "e2e_latency_ms",
    "n_wire_bytes", "source_copy_bytes", "provisional_aggregate_bytes",
    "control_bytes", "result_bytes", "controller_reencrypt_ms",
    "verification_ms", "controller_recovery_ms", "controller_reconstruction_ms",
    "bottleneck_link_id", "bottleneck_wire_bytes", "bottleneck_load_pct",
    "bottleneck_load_basis", "traffic_scope", "processing_scope", "timing_note",
)
STAGE_EVENTS = {
    "CONTROLLER_VERIFY": "verification_ms", "RECOVERY": "controller_recovery_ms",
    "BFV_REENCRYPT": "controller_reencrypt_ms", "REENCRYPT": "controller_reencrypt_ms",
    "RECONSTRUCTION": "controller_reconstruction_ms",
}


def _finite(value: Any, name: str, minimum: float = 0) -> float:
    if isinstance(value, bool):
        raise ValueError(f"Invalid {name}")
    number = float(value)
    if not math.isfinite(number) or number < minimum:
        raise ValueError(f"Invalid {name}")
    return number


@dataclass(frozen=True)
class ClockMapping:
    """Explicit affine clock mapping supported by an independently saved artifact."""
    domain: str
    common_domain: str
    offset_us: float
    scale: float
    error_bound_us: float
    artifact_sha256: str

    def __post_init__(self) -> None:
        if not self.domain or not self.common_domain:
            raise ValueError("Clock domains must be named")
        if not math.isfinite(self.offset_us) or not math.isfinite(self.scale) or self.scale <= 0:
            raise ValueError("Invalid affine clock mapping")
        _finite(self.error_bound_us, "clock error bound")
        if (len(self.artifact_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.artifact_sha256)):
            raise ValueError("Clock mapping requires its evidence SHA-256")

    def seconds(self, time_us: int) -> float:
        return (self.scale * time_us + self.offset_us) / 1_000_000


def mapped_seconds(event: Mapping[str, Any], common_domain: str,
                   mappings: Mapping[str, ClockMapping]) -> float | None:
    domain = event["clock_domain"]
    if domain == common_domain:
        return event["time_us"] / 1_000_000
    mapping = mappings.get(domain)
    if mapping is None:
        return None
    if mapping.domain != domain or mapping.common_domain != common_domain:
        raise ValueError("Clock mapping target differs from the accounting clock")
    return mapping.seconds(event["time_us"])


def load_clock_mappings(path: Path | None, common_domain: str) -> dict[str, ClockMapping]:
    if path is None:
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    if document["common_domain"] != common_domain:
        raise ValueError("Clock mapping and accounting domains differ")
    result = {}
    for item in document["mappings"]:
        artifact = (path.parent / item["artifact"]).resolve()
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if digest != item["artifact_sha256"]:
            raise ValueError("Clock-mapping artifact hash mismatch")
        mapping = ClockMapping(item["domain"], common_domain, float(item["offset_us"]),
            float(item["scale"]), float(item["error_bound_us"]), digest)
        if mapping.domain in result:
            raise ValueError("Duplicate clock mapping")
        result[mapping.domain] = mapping
    return result


def read_events(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as handle:
            return [from_csv_row(row) for row in csv.DictReader(handle)]
    records = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                item = parse_event(line)
                if item is not None:
                    records.append(item)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
    return records


def reduce_events(events: Iterable[Mapping[str, Any]], *, common_clock_domain: str,
                  clock_mappings: Mapping[str, ClockMapping] | None = None,
                  traffic_trace_complete: bool = False, bottleneck_link_id: str | None = None,
                  link_capacity_bps: float | None = None,
                  expected_participants: Mapping[tuple[str, str], Sequence[str]] | None = None,
                  default_scheme: str = "LA-IoT", default_scenario: str = "unspecified") -> list[dict[str, Any]]:
    """Keep verified source counts, completed rounds and link costs distinct.

    traffic_trace_complete means the caller has saved and identified every
    transmitted frame on every included hop, including ACK/control traffic.
    Without that explicit assertion, n_wire_bytes and traffic class totals stay
    unknown; individual observed bottleneck frames are likewise not called a
    complete link-load measurement. Application-level SEND never enters sums.
    """
    if not common_clock_domain:
        raise ValueError("An explicit accounting clock is required")
    mappings = {} if clock_mappings is None else clock_mappings
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    identities, stable_events = set(), {}
    for raw in events:
        event = validate_event(raw)
        if "event_id" in event:
            stable_key = (event["run_id"], event["event_id"])
            previous = stable_events.get(stable_key)
            if previous is not None:
                if previous != event:
                    raise ValueError("A stable event ID has conflicting recorded content")
                continue
            stable_events[stable_key] = event
        if "event_index" in event:
            identity = (event["run_id"], event["clock_domain"], event["node_id"], event["event_index"])
            if identity in identities:
                raise ValueError("Duplicated event log record")
            identities.add(identity)
        groups[(event["run_id"], event["round_id"])].append(event)
    output = []
    for (run_id, round_id), records in sorted(groups.items()):
        releases = [item for item in records if item["event"] == "ROUND_RELEASE"]
        if not releases:
            raise ValueError(f"No scheduled ROUND_RELEASE for {run_id}/{round_id}")
        if len(releases) != 1:
            raise ValueError("Record one authoritative release per scheduled round")
        release = releases[0]
        seeds = {item["seed"] for item in records}
        if len(seeds) != 1:
            raise ValueError("A round must retain one workload seed")
        supplied = (expected_participants or {}).get((run_id, round_id))
        roster = tuple(sorted(supplied if supplied is not None else release.get("participants", ())))
        if not roster or len(set(roster)) != len(roster):
            raise ValueError("Provide the scheduled participant roster")
        if "n_expected" in release and release["n_expected"] != len(roster):
            raise ValueError("Release participant count differs from its roster")
        if "participants" in release and tuple(release["participants"]) != roster:
            raise ValueError("Release roster differs from the configured schedule")
        verified = {item.get("source_id", item["node_id"]) for item in records
                    if item["event"] == "REPORT_ACCEPT"}
        if not verified.issubset(roster):
            raise ValueError("An unexpected source was counted as a verified participant")
        accepted = [item for item in records if item["event"] == "RESULT_ACCEPT"]
        confirmed = [item for item in records if item["event"] == "ROUND_COMPLETE"]
        failures = [item for item in records if item["event"] in {"ROUND_TIMEOUT", "ROUND_REJECTED"}]
        if len(accepted) > 1 or len(confirmed) > 1 or len(failures) > 1 or ((accepted or confirmed) and failures):
            raise ValueError("A round has conflicting or repeated terminal decisions")
        if accepted or confirmed:
            terminal = confirmed[0] if confirmed else accepted[0]
            if (verified != set(roster)
                    or any(tuple(item.get("participants", ())) != roster for item in accepted + confirmed)):
                raise ValueError("A completed round needs the full verified and accepted roster")
            status = "complete"
        elif failures:
            terminal = failures[0]
            status = "timeout" if terminal["event"] == "ROUND_TIMEOUT" else "rejected"
        else:
            terminal, status = None, "incomplete"
        start = mapped_seconds(release, common_clock_domain, mappings)
        stop = mapped_seconds(terminal, common_clock_domain, mappings) if terminal else None
        accept_time = mapped_seconds(accepted[0], common_clock_domain, mappings) if accepted else None
        if start is not None and stop is not None and stop < start:
            raise ValueError("A terminal event precedes the scheduled release")
        if start is not None and accept_time is not None and accept_time < start:
            raise ValueError("Recipient acceptance precedes the scheduled release")
        elapsed_ms = 1000 * (stop - start) if start is not None and stop is not None else None
        latency = (1000 * (accept_time - start)
                   if status == "complete" and start is not None and accept_time is not None else None)
        row = {field: None for field in ROUND_FIELDS}
        row.update(run_id=run_id, round_id=round_id, seed=next(iter(seeds)), status=status,
            scheme=release.get("scheme", default_scheme), scenario_id=release.get("scenario_id", default_scenario),
            release_s=start, decision_s=stop, recipient_accept_s=accept_time, clock_domain=common_clock_domain,
            jct_ms=elapsed_ms, latency_ms=latency, e2e_latency_ms=latency,
            n_expected=len(roster), n_accepted=len(verified), n_verified=len(verified),
            traffic_scope="complete_all_hop_trace" if traffic_trace_complete else "not_fully_instrumented",
            processing_scope="recorded_host_stage_durations",
            timing_note="mapped_common_clock" if elapsed_ms is not None else "missing_terminal_or_clock_mapping")
        for event_type, metric in STAGE_EVENTS.items():
            items = [item for item in records if item["event"] == event_type]
            if items:
                if any("duration_ms" not in item for item in items):
                    raise ValueError("A recorded controller stage needs its measured duration_ms")
                previous = row[metric]
                row[metric] = sum(item["duration_ms"] for item in items) + (previous if previous is not None else 0)
        transmissions = [item for item in records if item["event"] == "SEND" and item.get("scope") == "link"]
        frame_ids = set()
        for frame in transmissions:
            identity = (frame["link_id"], frame["sender"], frame["frame_id"], frame["attempt"])
            if identity in frame_ids:
                raise ValueError("A physical frame transmission was counted twice")
            frame_ids.add(identity)
        if traffic_trace_complete:
            traffic = {kind: sum(item["wire_bytes"] for item in transmissions if item["traffic_class"] == kind)
                       for kind in TRAFFIC_CLASSES}
            row.update(n_wire_bytes=sum(traffic.values()), source_copy_bytes=traffic["originals"],
                provisional_aggregate_bytes=traffic["partials"], control_bytes=traffic["control"],
                result_bytes=traffic["results"])
            if bottleneck_link_id:
                selected = [item for item in transmissions if item["link_id"] == bottleneck_link_id]
                wire_bytes = sum(item["wire_bytes"] for item in selected)
                row.update(bottleneck_link_id=bottleneck_link_id, bottleneck_wire_bytes=wire_bytes)
                window_s = (stop - start) if start is not None and stop is not None else None
                if window_s is not None and window_s > 0:
                    frame_times = [mapped_seconds(item, common_clock_domain, mappings) for item in selected]
                    aligned = all(value is not None for value in frame_times)
                    if aligned and any(value < start or value > stop for value in frame_times):
                        raise ValueError("Bottleneck frames extend outside the declared round-load window")
                    if aligned and selected and all("airtime_s" in item for item in selected):
                        row["bottleneck_load_pct"] = 100 * sum(item["airtime_s"] for item in selected) / window_s
                        row["bottleneck_load_basis"] = "recorded_frame_airtime_over_round_window"
                    elif aligned and link_capacity_bps is not None:
                        capacity = _finite(link_capacity_bps, "link capacity", minimum=1e-30)
                        row["bottleneck_load_pct"] = 100 * wire_bytes * 8 / (capacity * window_s)
                        row["bottleneck_load_basis"] = "wire_bits_over_capacity_and_round_window"
        output.append(row)
    return output


def integrate_measured_power(samples: Iterable[Mapping[str, Any]], *, physical_scope_ids: Sequence[str],
                             clock_domain: str, start_s: float, end_s: float) -> dict[str, Any]:
    """Trapezoid-integrate a full physical-board window exactly once (W s -> mJ).

    Each physical scope denotes one nonoverlapping board/supply measurement.
    Processes sharing a Pi use the same physical scope and one trace, never
    separate duplicate board traces. Samples must include exact boundaries.
    This function does not infer CPU/radio energy from software activity.
    """
    scopes = tuple(physical_scope_ids)
    if not scopes or len(set(scopes)) != len(scopes):
        raise ValueError("Declare unique nonoverlapping physical energy scopes")
    start, stop = _finite(start_s, "window start"), _finite(end_s, "window end")
    if stop <= start:
        raise ValueError("Energy window must have positive duration")
    traces: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for row in samples:
        scope = row["physical_scope_id"]
        if scope not in scopes or row["clock_domain"] != clock_domain:
            raise ValueError("Unknown physical scope or unaligned power clock")
        traces[scope].append((_finite(row["time_s"], "power time"), _finite(row["power_w"], "power")))
    if set(traces) != set(scopes):
        raise ValueError("Missing physical-board power trace")
    by_scope = {}
    for scope, points in traces.items():
        if (len(points) < 2 or any(b[0] <= a[0] for a, b in zip(points, points[1:]))
                or abs(points[0][0] - start) > 1e-6 or abs(points[-1][0] - stop) > 1e-6):
            raise ValueError("Power trace needs increasing samples and exact full-window boundaries")
        by_scope[scope] = 1000 * sum((b[0] - a[0]) * (a[1] + b[1]) / 2 for a, b in zip(points, points[1:]))
    return {"mode": "measured", "physical_scope_energy_mj": by_scope,
            "total_energy_mj": sum(by_scope.values()), "start_s": start, "end_s": stop,
            "clock_domain": clock_domain, "idle_subtracted": False}


def write_rounds(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ROUND_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    domain = config["common_clock_domain"]
    mapping_path = (args.config.parent / config["clock_mappings"]) if config.get("clock_mappings") else None
    mappings = load_clock_mappings(mapping_path, domain)
    rosters = {(item["run_id"], item["round_id"]): item["participants"] for item in config.get("rounds", [])}
    rows = reduce_events(read_events(args.events), common_clock_domain=domain, clock_mappings=mappings,
        traffic_trace_complete=config.get("traffic_trace_complete") is True,
        bottleneck_link_id=config.get("bottleneck_link_id"), link_capacity_bps=config.get("link_capacity_bps"),
        expected_participants=rosters, default_scheme=config.get("scheme", "LA-IoT"),
        default_scenario=config.get("scenario_id", "unspecified"))
    write_rounds(args.output, rows)
    metadata = {"events_sha256": hashlib.sha256(args.events.read_bytes()).hexdigest(),
        "configuration_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
        "reducer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "round_count": len(rows), "complete_round_count": sum(row["status"] == "complete" for row in rows),
        "common_clock_domain": domain, "clock_mapping_domains": sorted(mappings),
        "clock_mappings_sha256": hashlib.sha256(mapping_path.read_bytes()).hexdigest() if mapping_path else None,
        "clock_mapping_evidence": {name: {"artifact_sha256": item.artifact_sha256,
            "error_bound_us": item.error_bound_us, "offset_us": item.offset_us, "scale": item.scale}
            for name, item in mappings.items()},
        "unmeasured_values": "empty CSV fields; never zero-filled",
        "wire_accounting": "link SEND tx only; traffic classes mutually exclusive",
        "energy": "use integrate_measured_power or the separate calibrated analysis input",
        "executed_network": "recorded instrumentation scope; not inferred from this reduction"}
    with args.output.with_suffix(args.output.suffix + ".manifest.json").open("x", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
