# SPDX-License-Identifier: Apache-2.0
"""Meaningful accounting cases. Authored only; not executed during delivery."""
import io
import json
import sqlite3
import unittest

from laiot.events import EventLogger, EventOutbox, from_csv_row, parse_event, validate_event
from laiot.end_to_end import ClockMapping, integrate_measured_power, reduce_events


def event(kind, time_us=0, node="controller", domain="shared", **extra):
    return {"run_id": "run-1", "seed": 7, "node_id": node, "round_id": "r1",
            "sequence": 0, "event": kind, "time_us": time_us,
            "clock_domain": domain, **extra}


def completed(roster=("s1", "s2")):
    return [event("ROUND_RELEASE", participants=roster, n_expected=len(roster)),
            *[event("REPORT_ACCEPT", 100, node=node) for node in roster],
            event("RESULT_ACCEPT", 1_000_000, node="recipient", participants=roster)]


def frame(link, identifier, traffic, size, attempt=0):
    return event("SEND", 500_000, node="driver", scope="link", link_id=link,
        sender="a", receiver="b", direction="tx", traffic_class=traffic,
        attempt=attempt, frame_id=identifier, wire_bytes=size)


class EventSchemaTests(unittest.TestCase):
    def test_logger_outputs_only_explicit_metadata_and_supports_stderr_like_sink(self):
        sink = io.StringIO()
        logger = EventLogger(run_id="run-1", seed=7, clock_domain="host/boot-1", sink=sink)
        record = logger.emit("ROUND_RELEASE", node_id="c", round_id="r1", time_us=12,
                             participants=("s2", "s1"))
        self.assertEqual(parse_event(sink.getvalue()), record)
        self.assertEqual(record["participants"], ["s1", "s2"])
        with self.assertRaises(ValueError):
            logger.emit("SEND", node_id="c", round_id="r1", plaintext="123")

    def test_legacy_event_and_csv_round_trip_retain_missing_fields(self):
        old = event("SEND", report_bytes=18)
        self.assertNotIn("scope", validate_event(old))
        row = {key: str(value) for key, value in old.items()}
        row["wire_bytes"] = ""
        restored = from_csv_row(row)
        self.assertNotIn("wire_bytes", restored)
        self.assertEqual(restored["report_bytes"], 18)

    def test_link_frame_needs_identity_and_traffic_class(self):
        with self.assertRaises(ValueError):
            validate_event(event("SEND", scope="link", wire_bytes=100))
        with self.assertRaises(ValueError):
            validate_event(frame("l1", "f1", "unknown", 100))


class EndToEndTests(unittest.TestCase):
    def test_complete_round_has_recipient_acceptance_latency(self):
        row = reduce_events(completed(), common_clock_domain="shared")[0]
        self.assertEqual(row["status"], "complete")
        self.assertEqual(row["n_verified"], 2)
        self.assertEqual(row["e2e_latency_ms"], 1000)
        self.assertIsNone(row["n_wire_bytes"])
        self.assertIsNone(row["verification_ms"])

    def test_twelve_verified_sources_do_not_complete_twenty_source_round(self):
        roster = tuple(f"s{i}" for i in range(20))
        events = [event("ROUND_RELEASE", participants=roster),
                  *[event("REPORT_ACCEPT", 100, node=node) for node in roster[:12]],
                  event("ROUND_TIMEOUT", 2_000_000)]
        row = reduce_events(events, common_clock_domain="shared")[0]
        self.assertEqual((row["n_expected"], row["n_verified"], row["status"]), (20, 12, "timeout"))
        self.assertIsNone(row["latency_ms"])
        self.assertEqual(row["jct_ms"], 2000)

    def test_false_completion_and_unexpected_source_are_rejected(self):
        events = completed()
        events.pop(1)
        with self.assertRaises(ValueError):
            reduce_events(events, common_clock_domain="shared")
        with self.assertRaises(ValueError):
            reduce_events(completed() + [event("REPORT_ACCEPT", 10, node="outsider")], common_clock_domain="shared")

    def test_cross_process_clock_subtraction_requires_mapping(self):
        events = completed()
        events[-1]["clock_domain"] = "recipient/boot-1"
        events[-1]["time_us"] = 3_000_000
        row = reduce_events(events, common_clock_domain="shared")[0]
        self.assertEqual(row["status"], "complete")
        self.assertIsNone(row["e2e_latency_ms"])
        mapping = ClockMapping("recipient/boot-1", "shared", -2_000_000, 1, 10, "a" * 64)
        row = reduce_events(events, common_clock_domain="shared",
                            clock_mappings={mapping.domain: mapping})[0]
        self.assertEqual(row["e2e_latency_ms"], 1000)

    def test_authenticated_receipt_jct_is_separate_from_recipient_clock(self):
        events = completed()
        events[-1]["clock_domain"] = "recipient/boot-1"
        events.append(event("ROUND_COMPLETE", 1_100_000, participants=("s1", "s2")))
        row = reduce_events(events, common_clock_domain="shared")[0]
        self.assertAlmostEqual(row["jct_ms"], 1100)
        self.assertIsNone(row["e2e_latency_ms"])

    def test_all_hops_and_bottleneck_use_separate_frame_sums(self):
        events = completed() + [frame("hop1", "original1", "originals", 100),
            frame("bottleneck", "original2", "originals", 100),
            frame("bottleneck", "partial1", "partials", 20),
            frame("bottleneck", "ack1", "control", 10),
            frame("result-link", "result1", "results", 30)]
        # Application SEND and receiver trace must not duplicate actual TX bytes.
        events += [event("SEND", scope="host", report_bytes=100),
                   event("RECV", scope="link", wire_bytes=100, direction="rx")]
        row = reduce_events(events, common_clock_domain="shared", traffic_trace_complete=True,
                            bottleneck_link_id="bottleneck", link_capacity_bps=8000)[0]
        self.assertEqual(row["n_wire_bytes"], 260)
        self.assertEqual(row["source_copy_bytes"], 200)
        self.assertEqual(row["provisional_aggregate_bytes"], 20)
        self.assertEqual(row["control_bytes"], 10)
        self.assertEqual(row["result_bytes"], 30)
        self.assertEqual(row["bottleneck_wire_bytes"], 130)
        self.assertAlmostEqual(row["bottleneck_load_pct"], 13)

    def test_retransmission_counted_once_per_attempt_duplicate_trace_rejected(self):
        first = frame("hop1", "frame1", "originals", 100)
        retry = frame("hop1", "frame1", "originals", 100, attempt=1)
        row = reduce_events(completed() + [first, retry], common_clock_domain="shared",
                            traffic_trace_complete=True)[0]
        self.assertEqual(row["source_copy_bytes"], 200)
        with self.assertRaises(ValueError):
            reduce_events(completed() + [first, dict(first)], common_clock_domain="shared",
                          traffic_trace_complete=True)

    def test_stage_durations_are_separate_missing_stays_missing(self):
        rows = completed() + [event("CONTROLLER_VERIFY", duration_ms=2),
                              event("RECOVERY", duration_ms=3),
                              event("BFV_REENCRYPT", duration_ms=0)]
        row = reduce_events(rows, common_clock_domain="shared")[0]
        self.assertEqual(row["verification_ms"], 2)
        self.assertEqual(row["controller_recovery_ms"], 3)
        self.assertEqual(row["controller_reencrypt_ms"], 0)
        self.assertIsNone(row["controller_reconstruction_ms"])

    def test_uninstrumented_frames_are_not_a_full_traffic_total(self):
        row = reduce_events(completed() + [frame("hop1", "f1", "originals", 100)],
                            common_clock_domain="shared", traffic_trace_complete=False)[0]
        self.assertIsNone(row["n_wire_bytes"])
        self.assertIsNone(row["bottleneck_load_pct"])

    def test_link_load_needs_the_link_clock_aligned_to_its_window(self):
        transmission = frame("bottleneck", "f1", "originals", 100)
        transmission["clock_domain"] = "radio/boot-1"
        row = reduce_events(completed() + [transmission], common_clock_domain="shared",
                            traffic_trace_complete=True, bottleneck_link_id="bottleneck",
                            link_capacity_bps=8000)[0]
        self.assertEqual(row["bottleneck_wire_bytes"], 100)
        self.assertIsNone(row["bottleneck_load_pct"])


class EnergyTests(unittest.TestCase):
    def test_each_physical_board_once_and_units_are_mj(self):
        samples = [{"physical_scope_id": scope, "clock_domain": "meter", "time_s": time_s,
                    "power_w": power} for scope, power in (("pi-1", 2), ("nano-1", 3)) for time_s in (0, 1)]
        result = integrate_measured_power(samples, physical_scope_ids=("pi-1", "nano-1"),
                                         clock_domain="meter", start_s=0, end_s=1)
        self.assertEqual(result["total_energy_mj"], 5000)
        with self.assertRaises(ValueError):
            integrate_measured_power(samples, physical_scope_ids=("pi-1", "pi-1"),
                                     clock_domain="meter", start_s=0, end_s=1)

    def test_duplicate_samples_and_missing_board_are_rejected(self):
        point = {"physical_scope_id": "pi-1", "clock_domain": "meter", "time_s": 0, "power_w": 2}
        with self.assertRaises(ValueError):
            integrate_measured_power([point, point], physical_scope_ids=("pi-1",),
                                     clock_domain="meter", start_s=0, end_s=1)
        with self.assertRaises(ValueError):
            integrate_measured_power([point], physical_scope_ids=("pi-1", "nano-1"),
                                     clock_domain="meter", start_s=0, end_s=1)


class DurableEventTests(unittest.TestCase):
    def test_rollback_does_not_publish_a_state_transition(self):
        connection = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(connection.close)
        sink = io.StringIO()
        outbox = EventOutbox(EventLogger(run_id="run-1", seed=7, clock_domain="boot-1", sink=sink))
        outbox.initialize(connection)
        connection.execute("BEGIN IMMEDIATE")
        outbox.append(connection, "ROUND_RELEASE", node_id="controller", round_id="r1", event_id="release-r1")
        connection.execute("ROLLBACK")
        self.assertEqual(outbox.flush_pending(connection), 0)
        self.assertEqual(sink.getvalue(), "")

    def test_failed_sink_replays_original_timestamp_and_clock_after_restart(self):
        class FailedSink(io.StringIO):
            def flush(self):
                raise OSError("simulated capture failure")

        connection = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(connection.close)
        original = EventOutbox(EventLogger(run_id="run-1", seed=7, clock_domain="boot-1", sink=FailedSink()))
        original.initialize(connection)
        connection.execute("BEGIN IMMEDIATE")
        original.append(connection, "ROUND_RELEASE", node_id="controller", round_id="r1",
                        event_id="release-r1", time_us=123, participants=("s1", "s2"))
        connection.execute("COMMIT")
        with self.assertRaises(OSError):
            original.flush_pending(connection)
        record = json.loads(connection.execute("SELECT record FROM laiot_event_outbox").fetchone()[0])
        self.assertEqual(connection.execute("SELECT published FROM laiot_event_outbox").fetchone()[0], 0)
        sink = io.StringIO()
        restored = EventOutbox(EventLogger(run_id="run-1", seed=7, clock_domain="boot-2", sink=sink))
        self.assertEqual(restored.flush_pending(connection), 1)
        self.assertEqual(parse_event(sink.getvalue()), record)
        self.assertEqual(record["clock_domain"], "boot-1")
        self.assertEqual(record["time_us"], 123)

    def test_identical_durable_replay_deduplicates_but_conflict_fails(self):
        records = completed()
        records[0]["event_id"] = "release-r1"
        row = reduce_events(records + [dict(records[0])], common_clock_domain="shared")[0]
        self.assertEqual(row["status"], "complete")
        with self.assertRaises(ValueError):
            reduce_events(records + [{**records[0], "time_us": 10}], common_clock_domain="shared")


if __name__ == "__main__":
    unittest.main()
