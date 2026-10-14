# SPDX-License-Identifier: Apache-2.0
"""Compatibility entry point; implementation moved to laiot.security_mechanism_workflow."""
from pathlib import Path
import sys

try:
    from laiot import security_mechanism_workflow as _implementation
except ModuleNotFoundError as error:
    if error.name != "laiot":
        raise
    sys.path.insert(0, str((Path(__file__).resolve().parent / "../../../src").resolve()))
    from laiot import security_mechanism_workflow as _implementation

sys.modules[__name__] = _implementation
