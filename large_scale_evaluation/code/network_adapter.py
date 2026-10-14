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
import subprocess
import sys

PREFIX = "LAIOT_EVENT "
EVENTS = {"SEND", "RECV", "VERIFY_OK", "VERIFY_FAIL", "AGGREGATE",
          "REENCRYPT", "ROUND_RELEASE", "ROUND_COMPLETE", "ROUND_TIMEOUT",
          "ROUND_REJECTED", "DROP", "COAP_BLOCK", "RADIO_FRAGMENT"}
FIELDS = ("run_id", "seed", "node_id", "round_id", "sequence", "event",
          "time_us", "clock_domain", "alpha", "beta", "wire_bytes",
          "report_bytes", "block_id", "fragment_id", "report_hash", "detail")
REQUIRED = {"run_id", "seed", "node_id", "round_id", "sequence", "event", "time_us", "clock_domain"}


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


def parse_event(line: str) -> dict | None:
    position = line.find(PREFIX)
    if position < 0:
        return None
    value = json.loads(line[position + len(PREFIX):])
    if not isinstance(value, dict) or not REQUIRED.issubset(value) or set(value) - set(FIELDS):
        raise ValueError("Unknown or missing event fields")
    if value["event"] not in EVENTS:
        raise ValueError("Unknown event type")
    for key in ("run_id", "node_id", "round_id", "clock_domain"):
        if not isinstance(value[key], str) or not value[key].strip():
            raise ValueError(f"Missing string field: {key}")
    for key in ("seed", "sequence", "time_us"):
        integer(value[key], key)
    for key in ("wire_bytes", "report_bytes", "block_id", "fragment_id"):
        if key in value:
            integer(value[key], key)
    if "alpha" in value or "beta" in value:
        if (type(value.get("alpha")) is not int or type(value.get("beta")) is not int
                or value["alpha"] not in (0, 1) or value["beta"] != value["alpha"]):
            raise ValueError("Use alpha=beta=1 or alpha=beta=0")
    if value.get("report_hash"):
        digest = value["report_hash"]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Invalid SHA-256 report hash")
    if "detail" in value and not isinstance(value["detail"], str):
        raise ValueError("Detail must be a text string")
    return value


def normalize(logs: list[Path], output: Path) -> dict:
    rows, ignored, last_time = [], 0, {}
    for path in logs:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                try:
                    event = parse_event(line)
                    if event is None:
                        ignored += 1
                        continue
                    key = (str(path.resolve()), event["run_id"], event["node_id"], event["clock_domain"])
                    if event["time_us"] < last_time.get(key, 0):
                        raise ValueError("Clock moved backwards; use a new domain after reset")
                    last_time[key] = event["time_us"]
                    rows.append(event)
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"{path}:{line_number}: {exc}") from exc
    with output.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return {"input_logs": [{"path": str(path.resolve()), "sha256": sha256(path)} for path in logs],
            "output_sha256": sha256(output), "events": len(rows), "ignored_lines": ignored,
            "source_sha256": sha256(Path(__file__)),
            "warning": "No clock alignment, report authenticity, or firmware execution inferred."}


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
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.add_argument("--root", type=Path, required=True)
    capture_parser = commands.add_parser("inventory")
    capture_parser.add_argument("--root", type=Path, required=True)
    capture_parser.add_argument("--files", nargs="+", required=True)
    args = parser.parse_args()
    if args.command == "normalize":
        result = normalize(args.logs, args.output)
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

