# SPDX-License-Identifier: Apache-2.0
"""Source-only unit tests; not executed during delivery."""

from fractions import Fraction
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import tempfile
import sys
import unittest

from laiot.calibration import (CalibratedSensor, CommonScale, exact,
                               load_calibration, restore_posterior, round_up_ties)
from laiot.fusion_metrics import FusionMetrics, gaussian_nll


class CalibrationTests(unittest.TestCase):
    def test_affine_conversion_applies_gain_squared_to_variance(self):
        sensor = CalibratedSensor("fahrenheit", Fraction(5, 9), Fraction(-160, 9),
                                  Fraction(81, 25))
        scale = CommonScale("degree_C", 10, 4)
        self.assertEqual(sensor.common_value(68), Fraction(20))
        self.assertEqual(sensor.common_variance, Fraction(1))
        self.assertEqual(sensor.encode_reading(68, scale), 200)
        self.assertEqual(sensor.encode_precision(scale), 4)

    def test_restore_preserves_common_precision_scale_in_variance(self):
        scale = CommonScale("degree_C", 10, 4)
        mean, variance = restore_posterior(Fraction(4200, 21), Fraction(1, 21), scale)
        self.assertEqual(mean, Fraction(20))
        self.assertEqual(variance, Fraction(4, 21))
        self.assertNotEqual(variance, Fraction(1, 21 * 100))

    def test_rounding_is_explicit_for_signed_half_ties(self):
        self.assertEqual(round_up_ties(Fraction(1, 2)), 1)
        self.assertEqual(round_up_ties(Fraction(-1, 2)), 0)
        self.assertEqual(round_up_ties(Fraction(-3, 2)), -1)

    def test_unrepresentable_precision_and_nonpositive_variance_reject(self):
        scale = CommonScale("unit")
        for value in (0, -1, "100"):
            with self.subTest(variance=value), self.assertRaises(ValueError):
                scale.encode_precision(value)
        with self.assertRaises(TypeError):
            exact(0.1)
        with self.assertRaises(ValueError):
            CommonScale("unit", True, 1)

    def test_loaded_artifact_hash_matches_original_bytes(self):
        path = Path(__file__).resolve().parents[1] / "examples" / "calibration.json"
        profile = load_calibration(path)
        self.assertEqual(profile.source_sha256, hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(profile.sensors["sensor-a"].encode_precision(profile.scale), 16)
        self.assertEqual(profile.encoded_prior_mean, 200)
        self.assertEqual(profile.encoded_prior_precision, 1)
        self.assertIn("not a measured", profile.provenance)

    def test_duplicate_sensor_identity_rejects(self):
        path = Path(__file__).resolve().parents[1] / "examples" / "calibration.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["sensors"].append(document["sensors"][0])
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "duplicate.json"
            artifact.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_calibration(artifact)


class FusionMetricTests(unittest.TestCase):
    def test_standard_normal_nll_at_mean(self):
        self.assertAlmostEqual(gaussian_nll(0, 0, 1), .5 * math.log(2 * math.pi))

    def test_nll_can_be_negative(self):
        result = gaussian_nll(0, 0, Fraction(1, 100))
        self.assertLess(result, 0)
        self.assertAlmostEqual(result, .5 * math.log(2 * math.pi / 100))

    def test_accumulation_retains_separate_sample_counts(self):
        metrics = FusionMetrics()
        metrics.add(2, 0, 1)
        metrics.add(0, 0, 1)
        output = metrics.as_dict()
        self.assertEqual(output["estimate_count"], 2)
        self.assertEqual(output["nll_count"], 2)
        self.assertEqual(output["squared_error_sum"], 4)
        self.assertAlmostEqual(output["rmse"], math.sqrt(2))
        self.assertAlmostEqual(output["nll"], .5 * math.log(2 * math.pi) + 1)

    def test_empty_metrics_remain_unavailable(self):
        output = FusionMetrics().as_dict()
        self.assertIsNone(output["rmse"])
        self.assertIsNone(output["nll"])
        self.assertEqual(output["nll_count"], 0)

    def test_invalid_score_does_not_add_a_sample(self):
        metrics = FusionMetrics()
        for variance in (0, -1, math.nan, math.inf):
            with self.subTest(variance=variance), self.assertRaises(ValueError):
                metrics.add(0, 0, variance)
        self.assertEqual(metrics.estimate_count, 0)
        self.assertEqual(metrics.nll_count, 0)


class AblationDefinitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        source = root / "Ablation Analysis" / "aggregation_ablation.py"
        spec = importlib.util.spec_from_file_location("laiot_ablation_test_definition", source)
        cls.runner = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.runner
        spec.loader.exec_module(cls.runner)
        cls.workload = json.loads((root / "examples" / "workloads.json").read_text())["runs"][0]

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop("laiot_ablation_test_definition", None)

    def test_uniform_protection_preserves_statistical_inputs(self):
        variants = {value.name: value for value in self.runner.VARIANTS}
        self.assertTrue(variants["uniform_pqc"].uniform_pqc)
        self.assertEqual(self.runner.exact_statistics(self.workload, variants["full"]),
                         self.runner.exact_statistics(self.workload, variants["uniform_pqc"]))
        self.assertEqual([s["alpha"] for s in self.workload["sources"]], [1, 0])

    def test_equal_weight_fixture_retains_total_precision(self):
        variants = {value.name: value for value in self.runner.VARIANTS}
        weighted = self.runner.exact_statistics(self.workload, variants["full"])
        equal = self.runner.exact_statistics(self.workload, variants["equal_weights"])
        self.assertEqual(weighted[-1], equal[-1])
        self.assertNotEqual(weighted[:-1], equal[:-1])

    def test_workload_binds_the_supplied_calibration_bytes(self):
        path = Path(__file__).resolve().parents[1] / "examples" / "calibration.json"
        self.assertEqual(self.workload["calibration_sha256"],
                         hashlib.sha256(path.read_bytes()).hexdigest())

    def test_no_prior_changes_only_prior_statistics(self):
        variants = {value.name: value for value in self.runner.VARIANTS}
        with_prior = self.runner.exact_statistics(self.workload, variants["full"])
        without_prior = self.runner.exact_statistics(self.workload, variants["no_prior"])
        self.assertEqual(with_prior[-1] - without_prior[-1], self.workload["prior_precision"])
        expected_delta = self.workload["prior_mean"] * self.workload["prior_precision"]
        self.assertEqual([a - b for a, b in zip(with_prior[:-1], without_prior[:-1])],
                         [expected_delta] * 4)


if __name__ == "__main__":
    unittest.main()
