# SPDX-License-Identifier: Apache-2.0
"""Compatibility entry point; implementation moved to laiot.la_iot_ring_lwe."""
from pathlib import Path
import sys

try:
    from laiot import la_iot_ring_lwe as _implementation
except ModuleNotFoundError as error:
    if error.name != "laiot":
        raise
    sys.path.insert(0, str((Path(__file__).resolve().parent / "../../../src").resolve()))
    from laiot import la_iot_ring_lwe as _implementation

sys.modules[__name__] = _implementation
