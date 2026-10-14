# SPDX-License-Identifier: Apache-2.0
"""Scalar Gaussian posterior scores; no crypto, execution, or data generation.

NLL evaluates a known latent reference quantity under N(mean, variance).
For a future noisy reading, use its predictive variance, including that
reading's measurement variance. NLL uses natural logarithms and may be negative.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any


def _finite(value: Any, name: str) -> float:
    if isinstance(value, (bool, str, bytes)):
        raise TypeError(f"{name} must be numeric")
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(f"Invalid {name}") from error
    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")
    return result


def gaussian_nll(truth: Any, mean: Any, variance: Any) -> float:
    """-log N(truth; mean, variance), in nats per scalar observation."""
    truth, mean, variance = (_finite(truth, "truth"), _finite(mean, "mean"),
                             _finite(variance, "variance"))
    if variance <= 0:
        raise ValueError("Gaussian variance must be positive")
    standardized_error = (truth - mean) / math.sqrt(variance)
    result = .5 * (math.log(2 * math.pi) + math.log(variance)
                   + standardized_error * standardized_error)
    if not math.isfinite(result):
        raise ArithmeticError("NLL exceeds the finite reporting range")
    return result


@dataclass
class FusionMetrics:
    squared_error_sum: float = 0.0
    estimate_count: int = 0
    nll_sum: float = 0.0
    nll_count: int = 0

    def add(self, truth: Any, mean: Any, variance: Any) -> None:
        truth_value, mean_value = _finite(truth, "truth"), _finite(mean, "mean")
        score = gaussian_nll(truth, mean, variance)
        error = truth_value - mean_value
        squared = error * error
        if not math.isfinite(squared):
            raise ArithmeticError("Squared error exceeds the finite reporting range")
        error_sum = math.fsum((self.squared_error_sum, squared))
        score_sum = math.fsum((self.nll_sum, score))
        if not math.isfinite(error_sum) or not math.isfinite(score_sum):
            raise ArithmeticError("Accumulated score exceeds the reporting range")
        self.squared_error_sum, self.nll_sum = error_sum, score_sum
        self.estimate_count += 1
        self.nll_count += 1

    def as_dict(self) -> dict[str, float | int | None]:
        return {"squared_error_sum": self.squared_error_sum,
                "estimate_count": self.estimate_count, "nll_sum": self.nll_sum,
                "nll_count": self.nll_count,
                "rmse": math.sqrt(self.squared_error_sum / self.estimate_count)
                if self.estimate_count else None,
                "nll": self.nll_sum / self.nll_count if self.nll_count else None}
