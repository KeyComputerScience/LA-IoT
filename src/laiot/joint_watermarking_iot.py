# SPDX-License-Identifier: Apache-2.0
# Packaged implementation; migrated from IoT Application on 2026-10-14.
"""LA-IoT joint compression/watermarking and verified CoAP admission.

Generated source only. Do not run examples automatically. The supported
sensitive path is ML-KEM-768 -> HKDF-SHA-256 -> AES-256-GCM; the bundled
compatibility module's older custom lattice encryption is never invoked.

The Pi source process and its Pico form one trusted terminal. Routing and
802.15.4 adaptation are provided by the configured network/border router.
Keep every supporting module from this directory beside this file.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import hmac
from pathlib import Path
import sqlite3
from typing import Callable, Sequence

from . import authenticated_bayesian_fusion as fusion_api
from . import la_iot_cca as protocol

ProtocolConfig = fusion_api.ProtocolConfig
NodePolicy = fusion_api.NodePolicy
Credential = fusion_api.Credential
PersistentStore = fusion_api.PersistentStore
AuthenticatedBayesianFusion = fusion_api.AuthenticatedBayesianFusion
generate_mlkem_keys = fusion_api.generate_mlkem_keys
generate_bfv_contexts = fusion_api.generate_bfv_contexts
recover_fusion = fusion_api.recover_fusion
watermark_compress = protocol.watermark_compress
watermark_restore = protocol.watermark_restore


class SourceOutbox:
    """Persist the first protected report before transport; retry its exact bytes.

    Instantiate and use on one source worker thread. The trusted scheduler
    assigns a new sequence to each new reading report. Reusing an existing
    (node, round, sequence) requests retransmission of its frozen report.
    No original readings or private keys are written to this database.
    """

    def __init__(self, path: str | Path) -> None:
        if not str(path).strip() or str(path) == ":memory:":
            raise ValueError("Use a persistent source outbox path")
        self._db = sqlite3.connect(str(path), isolation_level=None, timeout=30)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS source_outbox (
                node TEXT NOT NULL, round_id TEXT NOT NULL,
                sequence INTEGER NOT NULL, descriptor TEXT NOT NULL,
                packet BLOB NOT NULL,
                PRIMARY KEY (node, round_id, sequence)
            )
        """)

    def prepare(
        self, readings: Sequence[int], *, config: ProtocolConfig,
        node_id: str, round_id: str, sequence: int, policy: NodePolicy,
        source_key: Credential, bfv_public_context: bytes,
        mlkem_public_key: bytes,
    ) -> bytes:
        """Return an existing report or commit a freshly protected report.

        Fresh reports use independent ML-KEM encapsulation and independent
        watermark/GCM nonces. Retried reports preserve ciphertext and sequence.
        The descriptor binds the trusted configuration and key identifiers.
        """
        protocol._identifier(node_id, "node")
        protocol._identifier(round_id, "round")
        protocol.core._require_int(sequence, "sequence", 0, (1 << 63) - 1)
        if not isinstance(source_key, Credential):
            raise TypeError("Expected a provisioned Credential")
        descriptor = hashlib.sha256(protocol.core._canonical_json({
            "protocol": protocol.VERSION, "suite": protocol.SUITE,
            "config": asdict(config), "policy": asdict(policy),
            "key_id": source_key.key_id, "key_binding": source_key.binding,
            "bfv_context": protocol.bfv_context_id(bfv_public_context),
            "mlkem_key": protocol.lattice_key_id(mlkem_public_key),
        })).hexdigest()
        self._db.execute("BEGIN IMMEDIATE")
        try:
            previous = self._db.execute(
                "SELECT descriptor,packet FROM source_outbox "
                "WHERE node=? AND round_id=? AND sequence=?",
                (node_id, round_id, sequence),
            ).fetchone()
            if previous is not None:
                if previous[0] != descriptor:
                    raise ValueError("An outbox entry cannot change its configuration")
                packet = previous[1]
            else:
                packet = fusion_api.protect_report(
                    readings, config=config, node_id=node_id, round_id=round_id,
                    sequence=sequence, policy=policy, source_key=source_key,
                    bfv_public_context=bfv_public_context,
                    mlkem_public_key=mlkem_public_key,
                )
                self._db.execute(
                    "INSERT INTO source_outbox VALUES(?,?,?,?,?)",
                    (node_id, round_id, sequence, descriptor, packet),
                )
            self._db.execute("COMMIT")
            return packet
        except BaseException:
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self._db.close()


class VerifiedReportInbox:
    """Fully verify a report before its persistent admission.

    Private helpers intentionally match the fixed supporting modules bundled
    here. Validation releases no plaintext over the CoAP response. Finalization
    reconstructs statistics from the saved originals using the existing BFV
    workflow. Pre-admission verification is included in processing costs.
    """

    def __init__(self, fusion: AuthenticatedBayesianFusion) -> None:
        self.fusion = fusion

    def accept_report(self, encoded: bytes) -> bool:
        """True: newly stored verified report; False: identical stored retry.

        The returned Boolean is admission status, not a Bayesian result.
        All validation failures expose one rejection class and message.
        """
        return self.fusion.accept(encoded)

    def finish(self) -> bytes:
        """Verify saved originals, restore/re-encrypt sensitive statistics,
        add the prior once, and authenticate the final encrypted result.
        """
        return self.fusion.finish()

    def close(self) -> None:
        self.fusion._round.store.connection.close()


class ControllerWorker:
    """One crypto/database worker; CoAP handling stays on its asyncio loop.

    Create the fusion object and its PersistentStore inside the supplied
    factory, not beforehand: SQLite connections stay on their owner thread.
    """

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="laiot-controller",
        )
        self._inbox: VerifiedReportInbox | None = None
        self._closed = False

    @classmethod
    async def create(
        cls, factory: Callable[[], AuthenticatedBayesianFusion],
    ) -> ControllerWorker:
        worker = cls()
        try:
            worker._inbox = await asyncio.get_running_loop().run_in_executor(
                worker._executor, lambda: VerifiedReportInbox(factory()),
            )
            return worker
        except BaseException:
            worker._executor.shutdown(wait=False, cancel_futures=True)
            raise

    def _ready(self) -> VerifiedReportInbox:
        if self._closed or self._inbox is None:
            raise RuntimeError("Controller worker is not active")
        return self._inbox

    async def accept_report(self, encoded: bytes) -> bool:
        inbox = self._ready()
        return await asyncio.get_running_loop().run_in_executor(
            self._executor, inbox.accept_report, encoded,
        )

    async def trusted_round(self):
        """Return the immutable trusted schedule from the database worker."""
        inbox = self._ready()
        return await asyncio.get_running_loop().run_in_executor(
            self._executor, lambda: inbox.fusion.trusted_round,
        )

    async def finish(self) -> bytes:
        inbox = self._ready()
        return await asyncio.get_running_loop().run_in_executor(
            self._executor, inbox.finish,
        )

    async def close(self) -> None:
        if self._closed:
            return
        inbox = self._ready()
        self._closed = True
        try:
            await asyncio.get_running_loop().run_in_executor(
                self._executor, inbox.close,
            )
        finally:
            self._executor.shutdown(wait=False, cancel_futures=True)


# No __main__ block. Nothing generates keys, opens a database, or connects to
# a network until the application explicitly calls the corresponding API.

