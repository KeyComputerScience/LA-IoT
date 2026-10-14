# SPDX-License-Identifier: Apache-2.0
"""Explicit LA-IoT host-role commands. Importing does not execute a command."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict
import json
import os
from pathlib import Path
import secrets
import socket
import sys


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="LA-IoT provisioned host services")
    commands = root.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("provision", help="Explicitly generate private role material")
    setup.add_argument("--plan", type=Path, required=True)
    setup.add_argument("--output", type=Path, required=True)
    for command in ("start-controller", "start-relay", "start-recipient"):
        service = commands.add_parser(command, help="Run one provisioned role until interrupted")
        service.add_argument("--config", type=Path, required=True)
        if command == "start-relay":
            service.add_argument("--disable-partials", action="store_true",
                                 help="Relay-off ablation: retain every original but omit provisional BFV work")
    source = commands.add_parser("source", help="Protect and send one frozen source report")
    source.add_argument("--config", type=Path, required=True)
    inputs = source.add_mutually_exclusive_group()
    inputs.add_argument("--readings", type=int, nargs=4)
    inputs.add_argument("--input", type=Path, help="One JSON line; default is standard input")
    inputs.add_argument("--uart", help="A trusted local serial-device path")
    source.add_argument("--baudrate", type=int, default=115200)
    source.add_argument("--input-timeout", type=float, default=10.0)
    source.add_argument("--calibration", type=Path,
                        help="Convert raw integers using the exact provisioned calibration artifact")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    # State, journals, receipts and generated keys inherit owner-only access.
    # This is a command action, not an import side effect.
    os.umask(0o077)
    from .config import integer, load_role, provision

    if args.command == "provision":
        paths = provision(args.plan, args.output)
        print(json.dumps({"status": "provisioned", "output": str(args.output.resolve()),
                          "files_written": len(paths)}))
        return 0
    role_name = "source" if args.command == "source" else args.command.removeprefix("start-")
    role = load_role(args.config, role_name)
    from .events import EventLogger
    from . import services

    logger = EventLogger(run_id=role.value["run_id"], seed=role.value["seed"],
                         clock_domain=f"{socket.gethostname()}/process-{secrets.token_hex(8)}", sink=sys.stderr)
    if args.command == "source":
        from .sensor_input import read_stream, read_uart

        input_maximum = (1 << 31) - 1 if args.calibration is not None else role.protocol.max_abs_reading
        if args.readings is not None:
            readings = tuple(integer(value, "reading", -input_maximum, input_maximum) for value in args.readings)
        elif args.uart is not None:
            readings = read_uart(args.uart, baudrate=args.baudrate, timeout_s=args.input_timeout,
                                 maximum=input_maximum)
        elif args.input is not None:
            with args.input.open("rb") as handle:
                readings = read_stream(handle, maximum=input_maximum)
        else:
            readings = read_stream(sys.stdin.buffer, maximum=input_maximum)
        if args.calibration is not None:
            from .calibration import load_calibration

            profile = load_calibration(args.calibration)
            sensor = profile.sensors.get(role.value["node_id"])
            if (sensor is None or profile.source_sha256 != role.protocol.calibration_sha256
                    or profile.scale.unit != role.protocol.unit
                    or profile.scale.reading_scale != role.protocol.reading_scale
                    or profile.scale.precision_scale != role.protocol.precision_scale
                    or profile.encoded_prior_mean != role.protocol.prior_mean
                    or profile.encoded_prior_precision != role.protocol.prior_precision
                    or sensor.encode_precision(profile.scale) != role.value["policies"][role.value["node_id"]]["precision"]):
                raise ValueError("Calibration artifact differs from trusted source provisioning")
            readings = tuple(integer(sensor.encode_reading(value, profile.scale), "encoded reading",
                                     -role.protocol.max_abs_reading, role.protocol.max_abs_reading) for value in readings)
        receipt = asyncio.run(services.send_source(role, readings, logger))
        print(json.dumps({"status": "transport_acknowledged", **asdict(receipt)}))
        return 0
    target = {"controller": services.run_controller,
              "relay": services.run_relay, "recipient": services.run_recipient}[role_name]
    try:
        if role_name == "relay":
            asyncio.run(target(role, logger, enable_partials=not args.disable_partials))
        else:
            asyncio.run(target(role, logger))
    except KeyboardInterrupt:
        return 130
    return 0
