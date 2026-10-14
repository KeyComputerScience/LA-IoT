# SPDX-License-Identifier: Apache-2.0
"""Explicit crypto integration checks; never executed during source delivery.

Set LAIOT_RUN_CRYPTO=1 when manually running unittest to enable key generation.
"""
from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
import os
from pathlib import Path
import secrets
import tempfile
import unittest

from laiot import authenticated_bayesian_fusion as fusion
from laiot import la_iot_cca as protocol


@unittest.skipUnless(os.environ.get("LAIOT_RUN_CRYPTO") == "1",
                     "Explicit opt-in is required for crypto integration")
class MixedPathIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = protocol.ProtocolConfig(max_nodes=4, max_precision=4,
                                          prior_mean=3, prior_precision=2)
        cls.bfv_public, cls.bfv_secret = fusion.generate_bfv_contexts(cls.cfg)
        cls.mlkem_public, cls.mlkem_private = fusion.generate_mlkem_keys()
        cls.policies = {f"s-{i}": fusion.NodePolicy(i % 2, i + 1) for i in range(4)}
        cls.keys = {node: fusion.Credential(node + "-key", secrets.token_bytes(32))
                    for node in cls.policies}
        cls.result_key = fusion.Credential("result-key", secrets.token_bytes(32))
        cls.values = {node: (i - 2, i + 1, -i, 5) for i, node in enumerate(cls.policies)}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.controller_store = fusion.PersistentStore(self.root / "controller.sqlite")
        self.receiver_store = fusion.PersistentStore(self.root / "receiver.sqlite")
        self.processor = self.make_controller()
        self.reports = {node: fusion.protect_report(
            self.values[node], config=self.cfg, node_id=node, round_id="r-1",
            sequence=1, policy=policy, source_key=self.keys[node],
            bfv_public_context=self.bfv_public, mlkem_public_key=self.mlkem_public)
            for node, policy in self.policies.items()}

    def tearDown(self):
        self.controller_store.close()
        self.receiver_store.close()
        self.temp.cleanup()

    def make_controller(self):
        return fusion.AuthenticatedBayesianFusion(
            store=self.controller_store, config=self.cfg, round_id="r-1",
            policies=self.policies, source_keys=self.keys,
            expected_sequences={node: 1 for node in self.policies},
            bfv_public_context=self.bfv_public, mlkem_private_key=self.mlkem_private,
            mlkem_public_key=self.mlkem_public, controller_id="control",
            result_key=self.result_key)

    def finish(self):
        for report in self.reports.values():
            self.processor.accept(report)
        return self.processor.finish()

    def recover(self, result, **kwargs):
        return fusion.recover_fusion(
            result, trusted_round=self.processor.trusted_round,
            receiver_store=self.receiver_store, bfv_secret_context=self.bfv_secret,
            result_key=self.result_key, **kwargs)

    def test_mixed_paths_match_independent_integer_reference(self):
        posterior = self.recover(self.finish())
        denominator = self.cfg.prior_precision + sum(p.precision for p in self.policies.values())
        expected = tuple(Fraction(
            self.cfg.prior_precision * self.cfg.prior_mean
            + sum(self.policies[node].precision * self.values[node][slot] for node in self.policies),
            denominator) for slot in range(self.cfg.slots))
        self.assertEqual(posterior.means, expected)
        self.assertEqual(posterior.variance, Fraction(1, denominator))
        self.assertEqual(posterior.participants, tuple(sorted(self.policies)))

    def test_invalid_inner_payload_does_not_consume_sequence(self):
        node = "s-1"  # Sensitive path.
        packet = protocol.Packet.from_bytes(self.reports[node])
        header = dict(packet.metadata)
        raw = bytearray(protocol._decompress(header["codec"], packet.body, header["raw_len"]))
        raw[-1] ^= 1
        header["codec"], body = protocol.adaptive_compress(bytes(raw))
        header["raw_len"] = len(raw)
        changed = protocol.Packet(header, body,
            protocol._source_tag(self.keys[node].secret, header, body)).to_bytes()
        with self.assertRaises(protocol.PacketRejected):
            self.processor.accept(changed)
        self.assertTrue(self.processor.accept(self.reports[node]))

    def test_wrong_source_mac_and_configuration_are_rejected(self):
        node = "s-1"
        packet = protocol.Packet.from_bytes(self.reports[node])
        bad = replace(packet, source_mac=bytes(len(packet.source_mac)))
        with self.assertRaises(protocol.PacketRejected):
            self.processor.accept(bad.to_bytes())
        header = dict(packet.metadata)
        header["config_id"] = "0" * 64
        bad = protocol.Packet(header, packet.body,
            protocol._source_tag(self.keys[node].secret, header, packet.body))
        with self.assertRaises(protocol.PacketRejected):
            self.processor.accept(bad.to_bytes())
        self.assertTrue(self.processor.accept(self.reports[node]))

    def test_missing_source_does_not_finalize(self):
        self.processor.accept(self.reports["s-0"])
        with self.assertRaises(fusion.IncompleteRound):
            self.processor.finish()

    def test_duplicate_and_restart_keep_one_contribution_and_same_result(self):
        report = self.reports["s-0"]
        self.assertTrue(self.processor.accept(report))
        self.assertFalse(self.processor.accept(report))
        result = self.finish()
        self.assertEqual(self.processor.finish(), result)
        self.controller_store.close()
        self.controller_store = fusion.PersistentStore(self.root / "controller.sqlite")
        self.processor = self.make_controller()
        self.assertEqual(self.processor.finish(), result)

    def test_changed_provisional_sum_cannot_replace_originals(self):
        plain = [report for node, report in self.reports.items() if not self.policies[node].alpha]
        batch = fusion.provisional_fusion(plain, config=self.cfg,
            bfv_public_context=self.bfv_public, round_id="r-1")
        changed = replace(batch, provisional_stats=b"untrusted provisional bytes")
        self.processor.accept_relay(changed)
        posterior = self.recover(self.finish())
        denominator = self.cfg.prior_precision + sum(p.precision for p in self.policies.values())
        expected = tuple(Fraction(
            self.cfg.prior_precision * self.cfg.prior_mean
            + sum(self.policies[node].precision * self.values[node][slot] for node in self.policies),
            denominator) for slot in range(self.cfg.slots))
        self.assertEqual(posterior.means, expected)
        self.assertEqual(posterior.total_precision, denominator)

    def test_observer_failure_does_not_count_rejected_direct_receive(self):
        def fail_after_add(stage, duration_ms, **fields):
            if stage == "RECONSTRUCTION":
                raise OSError("Audit sink unavailable")

        controller = protocol.TrustedController(
            self.cfg, "r-1", self.policies,
            {node: key.secret for node, key in self.keys.items()}, self.bfv_public,
            self.mlkem_private, protocol.lattice_key_id(self.mlkem_public),
            observer=fail_after_add)
        with self.assertRaises(protocol.PacketRejected):
            controller.receive(self.reports["s-0"])
        controller._observer = None
        controller.receive(self.reports["s-0"])
        self.assertEqual(controller._seen, {"s-0"})

    def test_receipt_failure_rolls_back_delivery_record(self):
        result = self.finish()
        self.receiver_store.connection.execute("CREATE TABLE receipt_test(value TEXT)")

        def fail_receipt(connection, posterior):
            connection.execute("INSERT INTO receipt_test VALUES('should roll back')")
            raise RuntimeError("Receipt storage failed")

        with self.assertRaises(RuntimeError):
            self.recover(result, on_accept=fail_receipt)
        self.assertEqual(self.receiver_store.connection.execute(
            "SELECT COUNT(*) FROM delivered_results").fetchone()[0], 0)
        self.assertEqual(self.receiver_store.connection.execute(
            "SELECT COUNT(*) FROM receipt_test").fetchone()[0], 0)
        self.assertEqual(self.recover(result).total_precision, 12)
        with self.assertRaises(fusion.SecurityError):
            self.recover(result)

    def test_watermark_unit_recovers_exact_encoded_bytes(self):
        node = "s-1"
        header = protocol.Packet.from_bytes(self.reports[node]).metadata
        raw = protocol.core._pack_readings(self.values[node], self.cfg)
        frame = protocol.watermark_compress(raw, self.keys[node].secret, header)
        self.assertEqual(protocol.watermark_restore(frame, self.keys[node].secret, header), raw)


class ConfigurationBounds(unittest.TestCase):
    def test_heterogeneous_large_profile_uses_sufficient_plaintext_range(self):
        with self.assertRaises(ValueError):
            protocol.ProtocolConfig(max_nodes=5000, max_precision=4)
        cfg = protocol.ProtocolConfig(max_nodes=5000, max_precision=4, plain_modulus=7340033)
        self.assertLess(2 * cfg.max_numerator_abs, cfg.plain_modulus)

    def test_calibration_scales_change_authenticated_configuration(self):
        self.assertNotEqual(protocol.ProtocolConfig().config_id,
                            protocol.ProtocolConfig(reading_scale=10).config_id)
        self.assertNotEqual(protocol.ProtocolConfig().config_id,
                            protocol.ProtocolConfig(calibration_sha256="ab" * 32).config_id)


if __name__ == "__main__":
    unittest.main()
