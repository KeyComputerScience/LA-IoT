# SPDX-License-Identifier: Apache-2.0
"""Explicit local Pico-to-Pi input adapters, without firmware or driver claims."""

from __future__ import annotations

import json
from typing import BinaryIO, TextIO

from .config import integer, unique_object


MAX_INPUT_BYTES = 4096


def parse_readings(encoded: bytes | str, *, maximum: int) -> tuple[int, int, int, int]:
    """Accept one JSON line: {"readings":[x1,x2,x3,x4]} in configured units.

    The local operator's source configuration supplies identity, sequence,
    sensitivity and precision; sensor input cannot override these fields.
    """
    if isinstance(encoded, str):
        encoded = encoded.encode("utf-8")
    if not isinstance(encoded, bytes) or not 0 < len(encoded) <= MAX_INPUT_BYTES:
        raise ValueError("Invalid sensor input length")
    value = json.loads(encoded, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or set(value) != {"readings"}:
        raise ValueError("Sensor input must contain only readings")
    values = value["readings"]
    if not isinstance(values, list) or len(values) != 4:
        raise ValueError("Exactly four integer readings are required")
    return tuple(integer(item, "reading", -maximum, maximum) for item in values)


def read_stream(stream: BinaryIO | TextIO, *, maximum: int) -> tuple[int, int, int, int]:
    line = stream.readline(MAX_INPUT_BYTES + 1)
    return parse_readings(line, maximum=maximum)


def read_uart(port: str, *, baudrate: int, timeout_s: float,
              maximum: int) -> tuple[int, int, int, int]:
    """Read one line from an already provisioned local serial device.

    Opening a UART is explicit. pyserial is an optional dependency. Physical
    trust, device ownership and the Pico reading firmware are deployment inputs.
    """
    if not isinstance(port, str) or not port:
        raise ValueError("Missing UART device")
    integer(baudrate, "baudrate", 1, 4_000_000)
    if not isinstance(timeout_s, (int, float)) or not 0 < timeout_s < float("inf"):
        raise ValueError("Invalid UART timeout")
    import serial

    with serial.Serial(port, baudrate=baudrate, timeout=timeout_s) as connection:
        return read_stream(connection, maximum=maximum)
