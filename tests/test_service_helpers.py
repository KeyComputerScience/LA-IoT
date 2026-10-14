# SPDX-License-Identifier: Apache-2.0
"""Service helper and state invariants. Authored but not executed."""

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from laiot import authenticated_bayesian_fusion as fusion
from laiot import la_iot_cca as protocol
from laiot.config import RoleConfig, atomic_private_write, encode_json, private_bytes, trusted_round
from laiot.sensor_input import parse_readings
from laiot.services import (PARTIAL_MAGIC, _RelayStore, parse_partial, receipt_uri,
                            seal_delivery_receipt, verify_delivery_receipt)


class SensorInputTests(unittest.TestCase):
    def test_only_readings_can_be_supplied_by_sensor(self):
        self.assertEqual(parse_readings(b'{"readings":[-1,0,1,2]}', maximum=100), (-1, 0, 1, 2))
        for encoded in (b'{"readings":[true,0,1,2]}', b'{"readings":[0,1,2]}',
                        b'{"readings":[0,1,2,101]}',
                        b'{"readings":[0,1,2,3],"precision":100}',
                        b'{"readings":[0,1,2,3],"readings":[1,2,3,4]}'):
            with self.subTest(encoded=encoded), self.assertRaises((ValueError, TypeError)):
                parse_readings(encoded, maximum=100)


class ReceiptTests(unittest.TestCase):
    def test_receipt_binds_result_schedule_and_key(self):
        scheduled = fusion.TrustedRound(protocol.ProtocolConfig(), "round-1", "controller-1",
                                        "a" * 64, "b" * 64, ("source-1",), 2)
        key = fusion.Credential("result-1", b"k" * 32)
        result = b"an authenticated result supplied by the protocol"
        receipt = seal_delivery_receipt(result, scheduled, key)
        verify_delivery_receipt(receipt, result, scheduled, key)
        for selected_result, selected_round, selected_key in (
                (result + b"changed", scheduled, key),
                (result, replace(scheduled, round_id="round-2"), key),
                (result, scheduled, fusion.Credential("result-1", b"q" * 32))):
            with self.assertRaises(ValueError):
                verify_delivery_receipt(receipt, selected_result, selected_round, selected_key)
        self.assertEqual(receipt_uri("coap://[::1]:5685/laiot/reports"),
                         "coap://[::1]:5685/laiot/receipts")


class ProvisionedFileTests(unittest.TestCase):
    def test_no_overwrite_and_private_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credential"
            atomic_private_write(path, b"private test material")
            self.assertEqual(private_bytes(path), b"private test material")
            with self.assertRaises(FileExistsError):
                atomic_private_write(path, b"replacement")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                private_bytes(path)

    def test_round_hash_also_binds_the_encoding_configuration(self):
        cfg = protocol.ProtocolConfig(max_nodes=1)
        value = {"round_id": "round-1", "controller_id": "controller-1",
                 "policies": {"source-1": {"alpha": 1, "precision": 1, "sequence": 1}},
                 "trusted_round": {"spec_id": "a" * 64, "context_id": "b" * 64,
                                   "config_id": "f" * 64, "participants": ["source-1"], "total_precision": 2}}
        with self.assertRaises(ValueError):
            trusted_round(RoleConfig(Path("operator/config.json"), value, cfg))


class RelayCandidateTests(unittest.TestCase):
    def test_partial_cannot_change_round_or_claim_unscheduled_inputs(self):
        value = {"version": 1, "relay": "regional-1", "round": "round-1", "context_id": "c" * 64,
                 "input_hashes": {"source-1": "d" * 64}, "stats": "cHJvdmlzaW9uYWw="}
        encoded = PARTIAL_MAGIC + encode_json(value)
        parse_partial(encoded, round_id="round-1", context_id="c" * 64, participant_ids={"source-1"})
        with self.assertRaises(ValueError):
            parse_partial(encoded, round_id="round-2", context_id="c" * 64, participant_ids={"source-1"})
        with self.assertRaises(ValueError):
            parse_partial(encoded, round_id="round-1", context_id="c" * 64, participant_ids={"different-source"})

    def test_rejected_unauthenticated_candidate_does_not_lock_out_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            atomic_private_write(root / "bfv.public", b"public context fixture; no BFV operation")
            cfg = protocol.ProtocolConfig(max_nodes=1)
            value = {"role": "relay", "round_id": "round-1", "relay_id": "relay-1",
                     "participants": ["source-1"], "bfv_public": "bfv.public", "database": "relay.sqlite",
                     "policies": {"source-1": {"alpha": 1, "precision": 1, "sequence": 1}}}
            role = RoleConfig(root / "config.json", value, cfg)
            store = _RelayStore(role)
            try:
                header = {"node": "source-1", "round": "round-1", "seq": 1, "alpha": 1, "beta": 1,
                          "context_id": protocol.bfv_context_id(b"public context fixture; no BFV operation")}
                first = protocol.Packet(header, b"invalid candidate", bytes(32)).to_bytes()
                second = protocol.Packet(header, b"different candidate", b"q" * 32).to_bytes()
                store.accept(first)
                store.accept(second)
                pending = store.pending()
                self.assertEqual(len(pending), 2)
                first_row = next(row for row in pending if row[2] == first)
                store.reject_candidate(first_row[0], first_row[1])
                self.assertEqual([row[2] for row in store.pending()], [second])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
