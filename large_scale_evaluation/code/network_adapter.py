# SPDX-License-Identifier: Apache-2.0
"""Normalize actual Contiki/host JSON log lines and verify recorded artifacts.

This adapter does not implement radio drivers, RPL, CoAP, clock synchronization,
cryptographic firmware, or Cooja execution. Firmware/host instrumentation must
emit the documented prefix and fields. Never derive one-way latency from
different clock domains without an independently recorded clock mapping.
Generated as source only; not executed or tested.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys

from laiot.events import EVENTS, FIELDS, PREFIX, REQUIRED, parse_event


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1_048_576), b""):
            result.update(chunk)
    return result.hexdigest()


def integer(value, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"Expected nonnegative integer: {name}")
    return value


def normalize(logs: list[Path], output: Path) -> dict:
    rows, ignored, last_time, stable_events = [], 0, {}, {}
    repeated = 0
    for path in logs:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                try:
                    event = parse_event(line)
                    if event is None:
                        ignored += 1
                        continue
                    if "event_id" in event:
                        stable_key = (event["run_id"], event["event_id"])
                        if stable_key in stable_events:
                            if stable_events[stable_key] != event:
                                raise ValueError("Stable event ID has conflicting log content")
                            repeated += 1
                            continue
                        stable_events[stable_key] = dict(event)
                    key = (str(path.resolve()), event["run_id"], event["node_id"], event["clock_domain"])
                    if event["time_us"] < last_time.get(key, 0):
                        raise ValueError("Clock moved backwards; use a new domain after reset")
                    last_time[key] = event["time_us"]
                    row = dict(event)
                    if "participants" in row:
                        row["participants"] = json.dumps(row["participants"], separators=(",", ":"))
                    rows.append(row)
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"{path}:{line_number}: {exc}") from exc
    with output.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return {"input_logs": [{"path": str(path.resolve()), "sha256": sha256(path)} for path in logs],
            "output_sha256": sha256(output), "events": len(rows), "ignored_lines": ignored,
            "duplicate_durable_event_lines": repeated,
            "source_sha256": sha256(Path(__file__)),
            "warning": "No clock alignment, report authenticity, or firmware execution inferred."}


ENERGEST_PREFIX = "LAIOT_ENERGEST "
ENERGEST_FIELDS = ("run_id", "seed", "node_id", "clock_domain", "start_time_s",
                  "end_time_s", "state", "delta_ticks", "ticks_per_second", "duration_s")
ENERGEST_STATES = ("cpu", "lpm", "deep", "tx", "listen")


def normalize_energest(logs: list[Path], output: Path, metadata_path: Path | None = None) -> dict:
    """Convert cumulative Energest ticks to state durations, never to energy.

    New firmware prints JSON with its own clock and ENERGEST_SECOND. Older
    key=value lines need a metadata snapshots entry for each path/line with
    independently recorded time_us, run_id, seed, clock_domain and tick rate.
    Missing timestamps are not inferred from CPU counters or the print period.
    """
    indexed = {}
    if metadata_path is not None:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        for entry in metadata["snapshots"]:
            key = (str((metadata_path.parent / entry["log"]).resolve()), int(entry["line"]))
            if key in indexed:
                raise ValueError("Duplicate legacy Energest snapshot metadata")
            indexed[key] = entry
    previous, rows, snapshots, used = {}, [], 0, set()
    for path in logs:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                offset = line.find(ENERGEST_PREFIX)
                if offset < 0:
                    continue
                raw = line[offset + len(ENERGEST_PREFIX):].strip()
                if raw.startswith("{"):
                    item = json.loads(raw)
                else:
                    old = dict(re.findall(r"([a-z_]+)=([^\s]+)", raw))
                    lookup = (str(path.resolve()), line_number)
                    if lookup not in indexed:
                        raise ValueError(f"{path}:{line_number}: legacy ticks require explicit timestamp/rate metadata")
                    entry = indexed[lookup]
                    used.add(lookup)
                    if str(entry["node_id"]) != str(old.get("node")):
                        raise ValueError("Legacy snapshot metadata names a different node")
                    item = {key: entry[key] for key in ("run_id", "seed", "node_id", "clock_domain", "time_us", "ticks_per_second")}
                    item.update({state: int(old[state]) for state in ENERGEST_STATES})
                required = {"run_id", "seed", "node_id", "clock_domain", "time_us", "ticks_per_second", *ENERGEST_STATES}
                if not isinstance(item, dict) or not required.issubset(item):
                    raise ValueError("Incomplete Energest snapshot")
                for field in ("seed", "time_us", "ticks_per_second", *ENERGEST_STATES):
                    integer(item[field], field)
                if item["ticks_per_second"] == 0:
                    raise ValueError("ENERGEST_SECOND must be positive")
                for field in ("run_id", "node_id", "clock_domain"):
                    if not isinstance(item[field], str) or not item[field].strip():
                        raise ValueError("Energest identity and clock fields must be strings")
                key = (item["run_id"], item["node_id"], item["clock_domain"])
                old = previous.get(key)
                if old is not None:
                    if item["time_us"] <= old["time_us"] or item["ticks_per_second"] != old["ticks_per_second"] or item["seed"] != old["seed"]:
                        raise ValueError("Energest time/rate changed; split reset clocks into new domains")
                    for state in ENERGEST_STATES:
                        delta = item[state] - old[state]
                        if delta < 0:
                            raise ValueError("Energest counter reset/wrapped; start a new clock domain")
                        rows.append({"run_id": item["run_id"], "seed": item["seed"], "node_id": item["node_id"],
                            "clock_domain": item["clock_domain"], "start_time_s": old["time_us"] / 1e6,
                            "end_time_s": item["time_us"] / 1e6, "state": state, "delta_ticks": delta,
                            "ticks_per_second": item["ticks_per_second"], "duration_s": delta / item["ticks_per_second"]})
                previous[key] = item
                snapshots += 1
    if set(indexed) != used:
        raise ValueError("Unused legacy snapshot entries; check paths and line numbers")
    with output.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ENERGEST_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return {"input_logs": [{"path": str(path.resolve()), "sha256": sha256(path)} for path in logs],
        "metadata_sha256": sha256(metadata_path) if metadata_path else None,
        "snapshots": snapshots, "state_intervals": len(rows), "output_sha256": sha256(output),
        "energy_computed": False, "conversion": "adjacent cumulative delta / recorded ENERGEST_SECOND",
        "state_overlap": "CPU and radio may overlap; supply a calibrated disjoint power model separately"}


def artifact_path(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f"Artifact outside root or missing: {relative}")
    return path


def verify(manifest: Path, root: Path) -> dict:
    value = json.loads(manifest.read_text(encoding="utf-8"))
    artifacts = value.get("artifacts", [])
    if not artifacts:
        raise ValueError("Manifest contains no artifacts")
    checked = []
    for item in artifacts:
        path = artifact_path(root, item["path"])
        actual = sha256(path)
        if actual != item["sha256"]:
            raise ValueError(f"Hash mismatch: {item['path']}")
        checked.append(item["path"])
    return {"status": "hashes_match", "checked": checked,
            "note": "Hash agreement alone does not prove experiment execution or authenticity."}


def capture(root: Path, files: list[str]) -> dict:
    try:
        commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"],
                                         stderr=subprocess.DEVNULL, text=True, timeout=10).strip()
    except (OSError, subprocess.SubprocessError):
        commit = None
    return {"status": "artifact_inventory_only", "python": sys.version,
            "platform": platform.platform(), "git_commit": commit,
            "artifacts": [{"path": item, "sha256": sha256(artifact_path(root, item))} for item in files],
            "contiki_commit": None, "cooja_commit": None, "firmware_target": None,
            "firmware_elf": None, "linker_map": None, "radio_driver": None,
            "peak_stack_bytes": None, "peak_heap_bytes": None, "static_ram_bytes": None,
            "clock_mapping_artifact": None,
            "note": "Fill null fields from actual build and execution evidence."}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    normalize_parser = commands.add_parser("normalize")
    normalize_parser.add_argument("--logs", nargs="+", type=Path, required=True)
    normalize_parser.add_argument("--output", type=Path, required=True)
    energest_parser = commands.add_parser("normalize-energest")
    energest_parser.add_argument("--logs", nargs="+", type=Path, required=True)
    energest_parser.add_argument("--metadata", type=Path)
    energest_parser.add_argument("--output", type=Path, required=True)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.add_argument("--root", type=Path, required=True)
    capture_parser = commands.add_parser("inventory")
    capture_parser.add_argument("--root", type=Path, required=True)
    capture_parser.add_argument("--files", nargs="+", required=True)
    args = parser.parse_args()
    if args.command in {"normalize", "normalize-energest"}:
        result = (normalize(args.logs, args.output) if args.command == "normalize"
                  else normalize_energest(args.logs, args.output, args.metadata))
        metadata = args.output.with_suffix(args.output.suffix + ".manifest.json")
        with metadata.open("x", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")
    elif args.command == "verify":
        result = verify(args.manifest, args.root)
    else:
        result = capture(args.root, args.files)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

