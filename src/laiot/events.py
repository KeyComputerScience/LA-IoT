# SPDX-License-Identifier: Apache-2.0
"""Metadata-only experiment events; importing this module opens no files.

A process chooses its own explicit clock domain. Equal domain names must mean
an actually shared clock, never merely the same machine type or role. Link
transmissions are emitted only by a real link/driver/trace adapter; application
SEND events contain report_bytes and do not claim radio-wire measurements.
"""
from __future__ import annotations

import json
import math
import secrets
import sqlite3
import sys
import threading
import time
from typing import Any, Mapping, TextIO

PREFIX = "LAIOT_EVENT "
EVENTS = frozenset({
    "SEND", "RECV", "VERIFY_OK", "VERIFY_FAIL", "AGGREGATE", "REENCRYPT",
    "ROUND_RELEASE", "ROUND_COMPLETE", "ROUND_TIMEOUT", "ROUND_REJECTED",
    "DROP", "COAP_BLOCK", "RADIO_FRAGMENT", "CONTROLLER_VERIFY", "RECOVERY",
    "BFV_REENCRYPT", "RECONSTRUCTION", "RESULT_ACCEPT", "RELAY_PARTIAL",
    "REPORT_ACCEPT", "RESULT_SEND", "ORIGINAL_FORWARD", "DELIVERY_RETRY",
})
REQUIRED = frozenset({"run_id", "seed", "node_id", "round_id", "sequence",
                      "event", "time_us", "clock_domain"})
INTEGER_FIELDS = frozenset({"seed", "sequence", "time_us", "event_index",
    "wire_bytes", "report_bytes", "block_id", "fragment_id", "attempt",
    "n_expected", "n_verified", "n_accepted", "process_id"})
FLOAT_FIELDS = frozenset({"duration_ms", "airtime_s"})
STRING_FIELDS = frozenset({"run_id", "node_id", "round_id", "clock_domain",
    "scheme", "scenario_id", "scope", "physical_scope_id", "source_id",
    "link_id", "sender", "receiver", "direction", "traffic_class", "frame_id",
    "stage", "status", "report_hash", "detail", "event_id"})
FIELDS = (
    "run_id", "seed", "node_id", "round_id", "sequence", "event", "time_us",
    "clock_domain", "alpha", "beta", "wire_bytes", "report_bytes", "block_id",
    "fragment_id", "report_hash", "detail", "event_index", "process_id",
    "scheme", "scenario_id", "scope", "physical_scope_id", "source_id",
    "link_id", "sender", "receiver", "direction", "traffic_class", "attempt",
    "frame_id", "airtime_s", "duration_ms", "stage", "status", "n_expected",
    "n_verified", "n_accepted", "participants", "event_id",
)
TRAFFIC_CLASSES = frozenset({"originals", "partials", "control", "results"})


def validate_event(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate old event fields plus the extended accounting schema.

    Unknown keys are rejected, preventing accidental readings, ciphertexts or
    secret-key objects from entering a metadata logger. detail is a short public
    diagnostic code; callers must never put readings, credentials or keys there.
    """
    if not isinstance(value, Mapping) or not REQUIRED.issubset(value):
        raise ValueError("Missing event fields")
    if set(value) - set(FIELDS):
        raise ValueError("Unknown event fields; log metadata only")
    result = dict(value)
    if result["event"] not in EVENTS:
        raise ValueError("Unknown event type")
    for key in INTEGER_FIELDS & result.keys():
        if type(result[key]) is not int or result[key] < 0:
            raise ValueError(f"Expected nonnegative integer: {key}")
    for key in FLOAT_FIELDS & result.keys():
        item = result[key]
        if isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(item) or item < 0:
            raise ValueError(f"Expected finite nonnegative number: {key}")
    for key in STRING_FIELDS & result.keys():
        item = result[key]
        if not isinstance(item, str) or not item.strip() or len(item.encode("utf-8")) > 512:
            raise ValueError(f"Expected bounded nonempty public string: {key}")
    if "alpha" in result or "beta" in result:
        if (type(result.get("alpha")) is not int or type(result.get("beta")) is not int
                or result["alpha"] not in (0, 1) or result["beta"] != result["alpha"]):
            raise ValueError("Use alpha=beta=0 or alpha=beta=1")
    if "report_hash" in result:
        digest = result["report_hash"]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Invalid SHA-256 report hash")
    if "participants" in result:
        members = result["participants"]
        if (not isinstance(members, (list, tuple)) or not members
                or any(not isinstance(item, str) or not item.strip() or len(item.encode("utf-8")) > 128 for item in members)
                or len(set(members)) != len(members)):
            raise ValueError("Expected unique public participant identifiers")
        result["participants"] = sorted(members)
    if "traffic_class" in result and result["traffic_class"] not in TRAFFIC_CLASSES:
        raise ValueError("Unknown mutually exclusive traffic class")
    if "scope" in result and result["scope"] not in {"host", "application", "link", "simulation"}:
        raise ValueError("Unknown event measurement scope")
    if "direction" in result and result["direction"] not in {"tx", "rx"}:
        raise ValueError("Use direction=tx or direction=rx")
    if result.get("scope") == "link" and result["event"] == "SEND":
        needed = {"wire_bytes", "link_id", "sender", "receiver", "direction", "traffic_class", "attempt", "frame_id"}
        if not needed.issubset(result) or result["direction"] != "tx":
            raise ValueError("A link SEND requires an identified actual frame transmission")
    return result


def parse_event(line: str) -> dict[str, Any] | None:
    """Allow a firmware/Cooja timestamp prefix before the JSON event marker."""
    offset = line.find(PREFIX)
    if offset < 0:
        return None
    return validate_event(json.loads(line[offset + len(PREFIX):]))


def from_csv_row(row: Mapping[str, str]) -> dict[str, Any]:
    """Decode a normalized CSV row without filling missing measurements with zero."""
    value: dict[str, Any] = {key: item for key, item in row.items() if item not in (None, "")}
    for key in (INTEGER_FIELDS | {"alpha", "beta"}) & value.keys():
        value[key] = int(value[key])
    for key in FLOAT_FIELDS & value.keys():
        value[key] = float(value[key])
    if "participants" in value:
        value["participants"] = json.loads(value["participants"])
    return validate_event(value)


class EventLogger:
    """Emit one JSON record per explicit call; default clock is process monotonic.

    sink is a text stream (sys.stdout by default). Services may choose stderr to
    keep their command-result JSON separate. No plaintext or key fields exist.
    Use a new domain after a process/device clock reset; cross-host mapping is
    recorded separately before end-to-end subtraction.
    """
    def __init__(self, *, run_id: str, seed: int, clock_domain: str,
                 sink: TextIO | None = None) -> None:
        self.run_id, self.seed, self.clock_domain = run_id, seed, clock_domain
        self.sink = sys.stdout if sink is None else sink
        self._lock = threading.Lock()
        self._index = 0
        validate_event({"run_id": run_id, "seed": seed, "clock_domain": clock_domain,
                        "node_id": "configuration", "round_id": "configuration",
                        "sequence": 0, "time_us": 0, "event": "ROUND_RELEASE"})

    def emit(self, event: str, *, node_id: str, round_id: str, sequence: int = 0,
             **fields: Any) -> dict[str, Any]:
        with self._lock:
            record = self._prepare_locked(event, node_id, round_id, sequence, fields)
            self._publish_locked(record)
            return record

    def _prepare_locked(self, event: str, node_id: str, round_id: str,
                        sequence: int, fields: Mapping[str, Any]) -> dict[str, Any]:
        supplied = dict(fields)
        timestamp = supplied.pop("time_us", time.monotonic_ns() // 1000)
        if set(supplied) & {"run_id", "seed", "clock_domain", "event_index", "event"}:
            raise ValueError("Event identity is owned by the logger")
        record = validate_event({"run_id": self.run_id, "seed": self.seed,
            "clock_domain": self.clock_domain, "node_id": node_id,
            "round_id": round_id, "sequence": sequence, "event": event,
            "time_us": timestamp, "event_index": self._index,
            "scope": supplied.pop("scope", "host"), **supplied})
        self._index += 1
        return record

    def prepare(self, event: str, *, node_id: str, round_id: str, sequence: int = 0,
                **fields: Any) -> dict[str, Any]:
        """Reserve original identity/time without writing; used inside a DB transaction."""
        with self._lock:
            return self._prepare_locked(event, node_id, round_id, sequence, fields)

    def _publish_locked(self, record: Mapping[str, Any]) -> None:
        encoded = json.dumps(dict(record), sort_keys=True, separators=(",", ":"), allow_nan=False)
        self.sink.write(PREFIX + encoded + "\n")
        self.sink.flush()

    def publish_record(self, record: Mapping[str, Any]) -> None:
        """Publish a saved record unchanged, including its original clock domain."""
        checked = validate_event(record)
        if checked["run_id"] != self.run_id or checked["seed"] != self.seed:
            raise ValueError("Saved event belongs to a different run")
        with self._lock:
            self._publish_locked(checked)


class EventOutbox:
    """Transactional metadata outbox using a caller-owned SQLite connection.

    append belongs in the SAME transaction as the recorded protocol state
    change. After commit, flush_pending writes before marking publication.
    A crash after sink write may duplicate a line; stable event_id permits
    exact deduplication. The original occurrence timestamp survives restart.
    stdout/stderr flush is not a substitute for durable external log capture.
    """
    def __init__(self, logger: EventLogger) -> None:
        self.logger = logger

    @staticmethod
    def initialize(connection: sqlite3.Connection) -> None:
        connection.execute("""CREATE TABLE IF NOT EXISTS laiot_event_outbox (
            event_id TEXT PRIMARY KEY, record BLOB NOT NULL,
            published INTEGER NOT NULL DEFAULT 0)""")

    def append(self, connection: sqlite3.Connection, event: str, *, node_id: str,
               round_id: str, sequence: int = 0, event_id: str | None = None,
               **fields: Any) -> str:
        if not connection.in_transaction:
            raise ValueError("Append the event inside the protocol state transaction")
        identifier = secrets.token_hex(16) if event_id is None else event_id
        previous = connection.execute("SELECT record FROM laiot_event_outbox WHERE event_id=?", (identifier,)).fetchone()
        if previous is not None:
            saved = json.loads(previous[0])
            wanted = {"event": event, "node_id": node_id, "round_id": round_id, "sequence": sequence}
            extra = dict(fields)
            if "participants" in extra:
                extra["participants"] = sorted(extra["participants"])
            if (any(saved[key] != value for key, value in wanted.items())
                    or saved["run_id"] != self.logger.run_id or saved["seed"] != self.logger.seed
                    or any(saved.get(key) != value for key, value in extra.items())):
                raise ValueError("A stable event ID cannot describe a different transition")
            return identifier
        record = self.logger.prepare(event, node_id=node_id, round_id=round_id,
                                     sequence=sequence, event_id=identifier, **fields)
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        connection.execute("INSERT INTO laiot_event_outbox(event_id,record) VALUES(?,?)", (identifier, encoded))
        return identifier

    def flush_pending(self, connection: sqlite3.Connection) -> int:
        if connection.in_transaction:
            raise ValueError("Publish metadata only after the protocol transaction commits")
        rows = connection.execute("SELECT event_id,record FROM laiot_event_outbox WHERE published=0 ORDER BY rowid").fetchall()
        for identifier, encoded in rows:
            self.logger.publish_record(json.loads(encoded))
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute("UPDATE laiot_event_outbox SET published=1 WHERE event_id=?", (identifier,))
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return len(rows)
