# SPDX-License-Identifier: Apache-2.0
"""Run the CLI only when explicitly invoked as python -m laiot."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
