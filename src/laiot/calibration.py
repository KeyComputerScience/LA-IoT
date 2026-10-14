# SPDX-License-Identifier: Apache-2.0
"""Common-unit encoding for independent Gaussian sensor observations.

Calibration values use integers or fraction/decimal strings, never binary
floats. This module does no I/O until load_calibration is explicitly called.
The returned hash and scales belong in the authenticated round configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


def exact(value: Any, name: str = "value") -> Fraction:
    if isinstance(value, Fraction):
        return value
    if type(value) is int or isinstance(value, str):
        try:
            return Fraction(value)
        except (ValueError, ZeroDivisionError) as error:
            raise ValueError(f"Invalid exact {name}") from error
    raise TypeError(f"{name} must be an integer or an exact fraction/decimal string")


def round_up_ties(value: Fraction) -> int:
    """Nearest integer, with exact half ties toward positive infinity."""
    value = exact(value)
    return (2 * value.numerator + value.denominator) // (2 * value.denominator)


@dataclass(frozen=True)
class CommonScale:
    unit: str
    reading_scale: int = 1
    precision_scale: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.unit, str) or not self.unit.strip():
            raise ValueError("Specify the common physical unit")
        for name in ("reading_scale", "precision_scale"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"{name} must be a positive integer")

    def encode_value(self, value: Any) -> int:
        return round_up_ties(self.reading_scale * exact(value))

    def encode_precision(self, variance: Any) -> int:
        variance = exact(variance, "variance")
        if variance <= 0:
            raise ValueError("Measurement variance must be positive")
        result = round_up_ties(self.precision_scale / variance)
        if result < 1:
            raise ValueError("Increase precision_scale to represent this variance")
        return result

    def descriptor(self) -> dict[str, Any]:
        return {"unit": self.unit, "reading_scale": self.reading_scale,
                "precision_scale": self.precision_scale,
                "rounding": "nearest-ties-toward-positive-infinity"}


@dataclass(frozen=True)
class CalibratedSensor:
    node_id: str
    gain: Fraction
    offset: Fraction
    variance: Fraction

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or not self.node_id.strip():
            raise ValueError("Specify a sensor identity")
        for name in ("gain", "offset", "variance"):
            object.__setattr__(self, name, exact(getattr(self, name), name))
        if self.gain == 0 or self.variance <= 0:
            raise ValueError("Gain must be nonzero and variance must be positive")

    @property
    def common_variance(self) -> Fraction:
        return self.gain * self.gain * self.variance

    def common_value(self, reading: Any) -> Fraction:
        return self.gain * exact(reading, "reading") + self.offset

    def encode_reading(self, reading: Any, scale: CommonScale) -> int:
        return scale.encode_value(self.common_value(reading))

    def encode_precision(self, scale: CommonScale) -> int:
        return scale.encode_precision(self.common_variance)


@dataclass(frozen=True)
class CalibrationProfile:
    scale: CommonScale
    sensors: Mapping[str, CalibratedSensor]
    prior_mean: Fraction
    prior_variance: Fraction
    provenance: str
    source_sha256: str

    @property
    def encoded_prior_mean(self) -> int:
        return self.scale.encode_value(self.prior_mean)

    @property
    def encoded_prior_precision(self) -> int:
        return self.scale.encode_precision(self.prior_variance)

    def descriptor(self) -> dict[str, Any]:
        return {**self.scale.descriptor(), "calibration_sha256": self.source_sha256,
                "calibration_provenance": self.provenance}


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate calibration field {key!r}")
        result[key] = value
    return result


def load_calibration(path: str | Path) -> CalibrationProfile:
    """Read a calibration artifact and retain its exact original byte hash.

    Gains convert each source's raw units to the common unit. Variance is in
    that source's raw units squared; the conversion multiplies it by gain^2.
    Prior mean and variance are already in the common unit and unit squared.
    Calibration/precision quantization is separate from exact BFV arithmetic.
    """
    payload = Path(path).read_bytes()
    document = json.loads(payload, object_pairs_hook=_unique_fields)
    fields = {"schema_version", "unit", "reading_scale", "precision_scale",
              "prior_mean", "prior_variance", "provenance", "sensors"}
    if not isinstance(document, dict) or set(document) != fields:
        raise ValueError(f"Calibration fields must be {sorted(fields)}")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ValueError("Unsupported calibration schema")
    scale = CommonScale(document["unit"], document["reading_scale"], document["precision_scale"])
    provenance = document["provenance"]
    if not isinstance(provenance, str) or not provenance.strip():
        raise ValueError("Record the calibration/variance provenance")
    source_rows = document["sensors"]
    if not isinstance(source_rows, list) or not source_rows:
        raise ValueError("Provide at least one calibrated sensor")
    sensors: dict[str, CalibratedSensor] = {}
    for row in source_rows:
        if not isinstance(row, dict) or set(row) != {"node_id", "gain", "offset", "variance"}:
            raise ValueError("Invalid calibrated sensor fields")
        sensor = CalibratedSensor(**row)
        if sensor.node_id in sensors:
            raise ValueError("Duplicate sensor identity")
        sensor.encode_precision(scale)
        sensors[sensor.node_id] = sensor
    mean = exact(document["prior_mean"], "prior_mean")
    variance = exact(document["prior_variance"], "prior_variance")
    scale.encode_precision(variance)
    return CalibrationProfile(scale, MappingProxyType(sensors), mean, variance,
                              provenance, hashlib.sha256(payload).hexdigest())


def restore_posterior(
    encoded_mean: Any, inverse_integer_precision: Any, scale: CommonScale,
) -> tuple[Fraction, Fraction]:
    """Restore physical mean and variance from U/W and 1/W.

    Readings are X=round(S*x), and integer weights are w=round(P/sigma^2).
    Thus the restored mean is (U/W)/S and variance is P/W. The latter is
    not 1/W divided by S^2. These are exact for the represented model;
    encoding quantization is reported separately from encryption error.
    """
    mean = exact(encoded_mean, "encoded_mean")
    variance = exact(inverse_integer_precision, "inverse_integer_precision")
    if variance <= 0:
        raise ValueError("Posterior inverse integer precision must be positive")
    return mean / scale.reading_scale, variance * scale.precision_scale
