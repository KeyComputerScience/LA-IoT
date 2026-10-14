# SPDX-License-Identifier: Apache-2.0
# Packaged implementation; migrated from IoT Application on 2026-10-14.
"""Explicit Pi/Nano application wiring. Generated source; never executed.

The calling application provisions keys and schedules before invoking these
functions. Start the controller after its IPv6 route/border router is ready.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .coap_transport import (
    ControllerEndpoint, ReportSender, TransferReceipt, TransportLimits,
    create_controller_endpoint, create_source_context,
)
from .joint_watermarking_iot import (
    AuthenticatedBayesianFusion, ControllerWorker, Credential, NodePolicy,
    PersistentStore, ProtocolConfig, SourceOutbox,
)


@dataclass(frozen=True)
class ControllerSettings:
    config: ProtocolConfig
    round_id: str
    controller_id: str
    policies: Mapping[str, NodePolicy]
    source_keys: Mapping[str, Credential]
    expected_sequences: Mapping[str, int]
    bfv_public_context: bytes
    mlkem_public_key: bytes
    mlkem_private_seed: bytes
    result_key: Credential


@dataclass
class RunningController:
    worker: ControllerWorker
    endpoint: ControllerEndpoint

    async def finish(self) -> bytes:
        """Return the authenticated encrypted result after all scheduled reports."""
        return await self.worker.finish()

    async def close(self) -> None:
        # Stop network admission before closing the crypto/database worker.
        try:
            await self.endpoint.close()
        finally:
            await self.worker.close()


async def start_controller(
    settings: ControllerSettings, *, database_path: str | Path,
    bind: tuple[str, int] = ("::", 5683),
    limits: TransportLimits | None = None,
) -> RunningController:
    """Explicitly create the verified inbox and CoAP endpoint.

    Raw ML-KEM private seed bytes are provisioned secrets (64 bytes), not read
    from incoming messages. The BFV context here contains the public key only.
    Store each live round in the durable controller database across restarts.
    """
    # Freeze registry contents before handing them to the worker thread.
    policies = dict(settings.policies)
    source_keys = dict(settings.source_keys)
    expected_sequences = dict(settings.expected_sequences)

    def factory() -> AuthenticatedBayesianFusion:
        store = PersistentStore(database_path)
        try:
            return AuthenticatedBayesianFusion(
                store=store, config=settings.config, round_id=settings.round_id,
                policies=policies, source_keys=source_keys,
                expected_sequences=expected_sequences,
                bfv_public_context=settings.bfv_public_context,
                mlkem_private_key=settings.mlkem_private_seed,
                mlkem_public_key=settings.mlkem_public_key,
                controller_id=settings.controller_id,
                result_key=settings.result_key,
            )
        except BaseException:
            store.connection.close()
            raise

    worker = await ControllerWorker.create(factory)
    try:
        endpoint = await create_controller_endpoint(
            worker.accept_report, bind=bind, limits=limits,
        )
        return RunningController(worker, endpoint)
    except BaseException:
        await worker.close()
        raise


async def send_readings(
    readings: Sequence[int], *, outbox_path: str | Path,
    controller_uri: str, config: ProtocolConfig, node_id: str,
    round_id: str, sequence: int, policy: NodePolicy,
    source_key: Credential, bfv_public_context: bytes,
    mlkem_public_key: bytes, limits: TransportLimits | None = None,
) -> TransferReceipt:
    """Protect four readings in the trusted Pi process and transmit their bytes.

    A Pico application's local input adapter supplies readings. A retry of the
    same (node, round, sequence) transmits the already saved encrypted report.
    Crypto/outbox work is kept off the CoAP event loop and owns its database.
    """
    values = tuple(readings)

    def prepare() -> bytes:
        outbox = SourceOutbox(outbox_path)
        try:
            return outbox.prepare(
                values, config=config, node_id=node_id, round_id=round_id,
                sequence=sequence, policy=policy, source_key=source_key,
                bfv_public_context=bfv_public_context,
                mlkem_public_key=mlkem_public_key,
            )
        finally:
            outbox.close()

    protected = await asyncio.to_thread(prepare)
    context = await create_source_context()
    try:
        sender = ReportSender(context, controller_uri, limits=limits)
        return await sender.send_report(protected)
    finally:
        await context.shutdown()


# No automatic setup, event loop, network listener, or demonstration run.

