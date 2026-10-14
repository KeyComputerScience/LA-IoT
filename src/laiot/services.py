# SPDX-License-Identifier: Apache-2.0
"""Explicit host services for source -> relay -> controller -> recipient.

Original source reports are authoritative. Provisional relay ciphertexts use a
separate, bounded envelope and never enter controller reconstruction. All role
state is persistent; importing this module starts no service or cryptography.
"""

from __future__ import annotations

import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from . import authenticated_bayesian_fusion as fusion
from . import la_iot_cca as protocol
from .coap_transport import ReportRejected, ReportSender, TransportLimits, create_controller_endpoint, create_source_context
from .config import (RoleConfig, atomic_private_write, encode_json, integer,
                     load_credential, policies, read_json, report_uri, trusted_round, unique_object)
from .joint_watermarking_iot import SourceOutbox, VerifiedReportInbox
from .events import EventOutbox


PARTIAL_MAGIC = b"LA-IoT/relay-partial/v1\x00"
RECEIPT_DOMAIN = b"LA-IoT/service/recipient-receipt/v1\x00"
RECEIPT_KEY_DOMAIN = b"LA-IoT/service/recipient-receipt-key/v1\x00"
MAX_PARTIAL_BYTES = protocol.MAX_PACKET_BYTES
MAX_RECEIPT_BYTES = 8192


def _emit(logger: Any, event: str, role: RoleConfig, *, node_id: str | None = None,
          sequence: int = 0, **fields: Any) -> None:
    if logger is not None:
        logger.emit(event, node_id=node_id or role.value.get("node_id", role.value.get("relay_id", role.role)),
                    round_id=role.round_id, sequence=sequence, **fields)


def transport_limits(role: RoleConfig) -> TransportLimits:
    values = role.value.get("transport", {})
    if not isinstance(values, dict):
        raise ValueError("Invalid transport configuration")
    return TransportLimits(**values)


def _schedule_fields(role: RoleConfig) -> dict[str, Any]:
    return {"participants": tuple(sorted(role.value["policies"])),
            "n_expected": len(role.value["policies"]), "scheme": "LA-IoT",
            "scenario_id": role.value["run_id"], "scope": "host"}


def _digest(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def _hex_digest(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("Invalid digest")
    return value


def partial_envelope(batch: Any, relay_id: str) -> bytes:
    """Separate provisional statistics from independently forwarded originals."""
    reports = [protocol.Packet.from_bytes(item) for item in batch.originals]
    hashes = {packet.metadata["node"]: _digest(encoded)
              for packet, encoded in zip(reports, batch.originals)}
    payload = {"version": 1, "relay": relay_id, "round": batch.round_id,
               "context_id": batch.context_id, "input_hashes": hashes,
               "stats": base64.b64encode(batch.provisional_stats).decode("ascii")}
    encoded = PARTIAL_MAGIC + encode_json(payload)
    if len(encoded) > MAX_PARTIAL_BYTES:
        raise ValueError("Provisional envelope exceeds its limit")
    return encoded


def parse_partial(encoded: bytes, *, round_id: str, context_id: str,
                  participant_ids: set[str]) -> dict[str, Any]:
    if (not isinstance(encoded, bytes) or not encoded.startswith(PARTIAL_MAGIC)
            or not len(PARTIAL_MAGIC) < len(encoded) <= MAX_PARTIAL_BYTES):
        raise ValueError("Invalid provisional envelope")
    value = json.loads(encoded[len(PARTIAL_MAGIC):], object_pairs_hook=unique_object)
    if (not isinstance(value, dict) or set(value) != {"version", "relay", "round", "context_id", "input_hashes", "stats"}
            or type(value["version"]) is not int or value["version"] != 1
            or value["round"] != round_id or value["context_id"] != context_id):
        raise ValueError("Provisional envelope context mismatch")
    protocol._identifier(value["relay"], "relay_id")
    hashes = value["input_hashes"]
    if not isinstance(hashes, dict) or not hashes or set(hashes) - participant_ids:
        raise ValueError("Invalid provisional participant list")
    for node, digest in hashes.items():
        protocol._identifier(node, "source")
        _hex_digest(digest)
    if not isinstance(value["stats"], str):
        raise ValueError("Invalid provisional statistics")
    raw = base64.b64decode(value["stats"], validate=True)
    if not 0 < len(raw) <= protocol.MAX_RAW_BYTES:
        raise ValueError("Invalid provisional statistics length")
    if encoded != PARTIAL_MAGIC + encode_json(value):
        raise ValueError("Noncanonical provisional envelope")
    # Deliberately no BFV parsing or acceptance of these statistics.
    return value


def seal_delivery_receipt(result: bytes, scheduled: fusion.TrustedRound,
                          key: fusion.Credential) -> bytes:
    payload = {"version": 1, "controller": scheduled.controller_id,
               "round": scheduled.round_id, "spec_id": scheduled.spec_id,
               "context_id": scheduled.context_id, "config_id": scheduled.config.config_id, "key_id": key.key_id,
               "result_sha256": _digest(result)}
    purpose_key = hmac.new(key.secret, RECEIPT_KEY_DOMAIN, hashlib.sha256).digest()
    tag = hmac.new(purpose_key, RECEIPT_DOMAIN + encode_json(payload), hashlib.sha256).hexdigest()
    return encode_json({"payload": payload, "mac": tag})


def verify_delivery_receipt(encoded: bytes, result: bytes, scheduled: fusion.TrustedRound,
                            key: fusion.Credential) -> None:
    if not isinstance(encoded, bytes) or not 0 < len(encoded) <= MAX_RECEIPT_BYTES:
        raise ValueError("Invalid recipient receipt")
    expected = seal_delivery_receipt(result, scheduled, key)
    if not hmac.compare_digest(encoded, expected):
        raise ValueError("Recipient receipt authentication failed")


def receipt_uri(uri: str) -> str:
    parsed = urlsplit(report_uri(uri))
    return urlunsplit((parsed.scheme, parsed.netloc, "/laiot/receipts", "", ""))


class _OneWorker:
    """Instantiate, use and close a role's SQLite/crypto state on one thread."""

    def __init__(self, name: str) -> None:
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix=name)
        self.host: Any = None

    async def create(self, factory: Callable[[], Any]) -> None:
        try:
            self.host = await asyncio.get_running_loop().run_in_executor(self.pool, factory)
        except BaseException:
            self.pool.shutdown(wait=False, cancel_futures=True)
            raise

    async def call(self, method: str, *args: Any) -> Any:
        if self.host is None:
            raise RuntimeError("Role worker is not active")
        operation = getattr(self.host, method)
        return await asyncio.get_running_loop().run_in_executor(self.pool, operation, *args)

    async def close(self) -> None:
        try:
            if self.host is not None:
                await self.call("close")
                self.host = None
        finally:
            self.pool.shutdown(wait=False, cancel_futures=True)


class _ControllerHost:
    def __init__(self, role: RoleConfig, logger: Any) -> None:
        self.role, self.logger = role, logger
        self.store = fusion.PersistentStore(role.file("database"))
        try:
            self.events = EventOutbox(logger) if logger is not None else None
            EventOutbox.initialize(self.store.connection)
            if self.events is not None:
                self.events.flush_pending(self.store.connection)
            source_values = read_json(role.file("source_credentials"), private=True)
            if set(source_values) != set(role.value["policies"]):
                raise ValueError("Controller credentials differ from the schedule")
            source_keys = {}
            for node, value in source_values.items():
                if not isinstance(value, dict) or set(value) != {"key_id", "secret_b64"}:
                    raise ValueError("Invalid source credential")
                source_keys[node] = fusion.Credential(value["key_id"], base64.b64decode(value["secret_b64"], validate=True))
            self.result_key = load_credential(role.file("result_credential"))
            self.fusion = fusion.AuthenticatedBayesianFusion(
                store=self.store, config=role.protocol, round_id=role.round_id,
                policies=policies(role.value), source_keys=source_keys,
                expected_sequences={node: item["sequence"] for node, item in role.value["policies"].items()},
                bfv_public_context=role.public_bytes("bfv_public"),
                mlkem_private_key=role.public_bytes("mlkem_seed"),
                mlkem_public_key=role.public_bytes("mlkem_public"),
                controller_id=role.value["controller_id"], result_key=self.result_key,
                observer=lambda stage, duration_ms, **fields: _emit(
                    logger, stage, role, node_id=fields["node_id"] or role.value["controller_id"],
                    scope="host", duration_ms=duration_ms),
                on_admit=self._on_admit)
            self.scheduled = trusted_round(role)
            if self.fusion.trusted_round != self.scheduled:
                raise ValueError("Controller registration differs from trusted provisioning")
            self.inbox = VerifiedReportInbox(self.fusion)
            self.store.connection.executescript("""
                CREATE TABLE IF NOT EXISTS service_round_state (
                    round_id TEXT PRIMARY KEY, release_wall REAL NOT NULL,
                    deadline_wall REAL NOT NULL, status TEXT NOT NULL,
                    delivery_confirmed INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS service_partials (
                    round_id TEXT NOT NULL, relay_id TEXT NOT NULL,
                    digest TEXT NOT NULL, envelope BLOB NOT NULL,
                    PRIMARY KEY(round_id, relay_id));
            """)
            now = time.time()
            with self.store.transaction() as connection:
                inserted = connection.execute("INSERT OR IGNORE INTO service_round_state VALUES(?,?,?,'open',0)",
                                              (role.round_id, now, now + integer(role.value["deadline_s"], "deadline_s", 1))).rowcount
                if inserted and self.events is not None:
                    self.events.append(connection, "ROUND_RELEASE", node_id=role.value["controller_id"],
                                       round_id=role.round_id, **_schedule_fields(role))
            if self.events is not None:
                self.events.flush_pending(self.store.connection)
        except BaseException:
            self.store.close()
            raise

    def status(self) -> tuple[str, bool]:
        row = self.store.connection.execute(
            "SELECT status,delivery_confirmed FROM service_round_state WHERE round_id=?", (self.role.round_id,)).fetchone()
        return row[0], bool(row[1])

    def _on_admit(self, connection: sqlite3.Connection, node: str, packet: Any) -> None:
        if self.events is None:
            return
        verified = connection.execute("SELECT node_id FROM reports WHERE round_id=? ORDER BY node_id",
                                      (self.role.round_id,)).fetchall()
        encoded = packet.to_bytes()
        self.events.append(connection, "REPORT_ACCEPT", node_id=self.role.value["controller_id"],
                           source_id=node, round_id=self.role.round_id, sequence=packet.metadata["seq"],
                           scope="host", alpha=packet.metadata["alpha"], beta=packet.metadata["beta"],
                           n_verified=len(verified), participants=tuple(row[0] for row in verified),
                           traffic_class="originals", report_bytes=len(encoded), report_hash=_digest(encoded))

    def accept(self, encoded: bytes) -> bool:
        if encoded.startswith(PARTIAL_MAGIC):
            value = parse_partial(encoded, round_id=self.role.round_id,
                                  context_id=self.scheduled.context_id,
                                  participant_ids=set(self.scheduled.participants))
            allowed_relays = self.role.value.get("relay_ids", [])
            if value["relay"] not in allowed_relays:
                raise ValueError("Unscheduled provisional relay")
            with self.store.transaction() as connection:
                old = connection.execute("SELECT digest,envelope FROM service_partials WHERE round_id=? AND relay_id=?",
                                         (self.role.round_id, value["relay"])).fetchone()
                if old is not None:
                    if old != (_digest(encoded), encoded):
                        raise ValueError("Conflicting provisional relay envelope")
                    return False
                connection.execute("INSERT INTO service_partials VALUES(?,?,?,?)",
                                   (self.role.round_id, value["relay"], _digest(encoded), encoded))
            _emit(self.logger, "RELAY_PARTIAL", self.role, node_id=value["relay"],
                  scope="host", traffic_class="partials", report_bytes=len(encoded))
            return True
        state, _ = self.status()
        deadline = self.store.connection.execute("SELECT deadline_wall FROM service_round_state WHERE round_id=?",
                                                 (self.role.round_id,)).fetchone()[0]
        if state == "timeout" or (state == "open" and time.time() >= deadline):
            raise ValueError("Round deadline reached")
        started = time.perf_counter_ns()
        try:
            fresh = self.inbox.accept_report(encoded)
        except Exception:
            _emit(self.logger, "VERIFY_FAIL", self.role, scope="host", report_bytes=len(encoded))
            raise
        packet = protocol.Packet.from_bytes(encoded)
        if self.events is not None:
            self.events.flush_pending(self.store.connection)
        if not fresh:
            _emit(self.logger, "DELIVERY_RETRY", self.role,
                  node_id=packet.metadata["node"], sequence=packet.metadata["seq"],
                  scope="host", alpha=packet.metadata["alpha"], beta=packet.metadata["beta"],
                  traffic_class="originals", report_bytes=len(encoded), report_hash=_digest(encoded),
                  duration_ms=(time.perf_counter_ns() - started) / 1_000_000)
        return fresh

    def result(self) -> bytes | None:
        state, _ = self.status()
        if state == "timeout":
            return None
        try:
            encoded = self.fusion.finish()
        except fusion.IncompleteRound:
            deadline = self.store.connection.execute("SELECT deadline_wall FROM service_round_state WHERE round_id=?",
                                                     (self.role.round_id,)).fetchone()[0]
            if time.time() >= deadline:
                with self.store.transaction() as connection:
                    changed = connection.execute("UPDATE service_round_state SET status='timeout' WHERE round_id=? AND status='open'",
                                                 (self.role.round_id,)).rowcount
                    if changed and self.events is not None:
                        self.events.append(connection, "ROUND_TIMEOUT", node_id=self.role.value["controller_id"],
                                           round_id=self.role.round_id, **_schedule_fields(self.role))
                if self.events is not None:
                    self.events.flush_pending(self.store.connection)
            return None
        with self.store.transaction() as connection:
            connection.execute("UPDATE service_round_state SET status='complete' WHERE round_id=?", (self.role.round_id,))
        return encoded

    def confirm(self, receipt: bytes, result: bytes) -> None:
        verify_delivery_receipt(receipt, result, self.scheduled, self.result_key)
        with self.store.transaction() as connection:
            old = connection.execute("SELECT delivery_confirmed FROM service_round_state WHERE round_id=?", (self.role.round_id,)).fetchone()[0]
            connection.execute("UPDATE service_round_state SET delivery_confirmed=1 WHERE round_id=?", (self.role.round_id,))
            if not old and self.events is not None:
                self.events.append(connection, "ROUND_COMPLETE", node_id=self.role.value["controller_id"],
                                   round_id=self.role.round_id, n_verified=len(self.scheduled.participants),
                                   **_schedule_fields(self.role))
        if self.events is not None:
            self.events.flush_pending(self.store.connection)

    def close(self) -> None:
        self.store.close()


def posterior_json(posterior: Any, role: RoleConfig) -> bytes:
    """Store exact encoded and physical fractions with explicit scale metadata."""
    from .calibration import CommonScale, restore_posterior

    def fraction(value: Any) -> dict[str, int]:
        return {"numerator": value.numerator, "denominator": value.denominator}

    scale = CommonScale(role.protocol.unit, role.protocol.reading_scale, role.protocol.precision_scale)
    restored = [restore_posterior(mean, posterior.variance, scale) for mean in posterior.means]
    return encode_json({"round": role.round_id, "controller": role.value["controller_id"],
                        "participants": list(posterior.participants),
                        "encoded_means": [fraction(value) for value in posterior.means],
                        "encoded_variance": fraction(posterior.variance),
                        "physical_means": [fraction(mean) for mean, _ in restored],
                        "physical_variance": fraction(restored[0][1]),
                        "total_precision": posterior.total_precision,
                        "reading_scale": role.protocol.reading_scale,
                        "precision_scale": role.protocol.precision_scale,
                        "unit": role.protocol.unit}) + b"\n"


class _RecipientHost:
    def __init__(self, role: RoleConfig, logger: Any) -> None:
        self.role, self.logger = role, logger
        self.store = fusion.PersistentStore(role.file("database"))
        try:
            self.events = EventOutbox(logger) if logger is not None else None
            EventOutbox.initialize(self.store.connection)
            if self.events is not None:
                self.events.flush_pending(self.store.connection)
            self.scheduled = trusted_round(role)
            self.key = load_credential(role.file("result_credential"))
            self.secret_context = protocol._tenseal().context_from(role.public_bytes("bfv_secret"))
            if not self.secret_context.is_private():
                raise ValueError("Recipient requires the private BFV context")
            self.store.connection.execute("""
                CREATE TABLE IF NOT EXISTS service_delivery_receipts (
                    controller TEXT NOT NULL, round_id TEXT NOT NULL, spec_id TEXT NOT NULL,
                    result_hash TEXT NOT NULL, receipt BLOB NOT NULL, posterior BLOB NOT NULL,
                    PRIMARY KEY(controller,round_id))
            """)
        except BaseException:
            self.store.close()
            raise

    def accept(self, encoded: bytes) -> bool:
        started = time.perf_counter_ns()
        if self.events is not None:
            self.events.flush_pending(self.store.connection)
        previous = self.store.connection.execute(
            "SELECT spec_id,result_hash FROM service_delivery_receipts WHERE controller=? AND round_id=?",
            (self.scheduled.controller_id, self.scheduled.round_id)).fetchone()
        if previous is not None:
            if previous != (self.scheduled.spec_id, _digest(encoded)):
                raise ValueError("Conflicting recipient result retry")
            with self.store.transaction() as connection:
                self.store.require_live(connection, "controller:" + self.scheduled.controller_id, self.key.key_id)
            _emit(self.logger, "DELIVERY_RETRY", self.role, scope="host", traffic_class="results")
            return False

        def save_receipt(connection: sqlite3.Connection, posterior: Any) -> None:
            # This runs in the same transaction as delivered_results. A crash
            # cannot commit an accepted result without its cached receipt/output.
            connection.execute("INSERT INTO service_delivery_receipts VALUES(?,?,?,?,?,?)",
                               (self.scheduled.controller_id, self.scheduled.round_id,
                                self.scheduled.spec_id, _digest(encoded),
                                seal_delivery_receipt(encoded, self.scheduled, self.key),
                                posterior_json(posterior, self.role)))
            if self.events is not None:
                self.events.append(connection, "RESULT_ACCEPT", node_id="recipient", round_id=self.role.round_id,
                                   participants=self.scheduled.participants, n_verified=len(self.scheduled.participants),
                                   scope="host", report_bytes=len(encoded), traffic_class="results",
                                   report_hash=_digest(encoded), duration_ms=(time.perf_counter_ns() - started) / 1_000_000)

        fusion.recover_fusion(encoded, trusted_round=self.scheduled,
                             receiver_store=self.store, bfv_secret_context=self.secret_context,
                             result_key=self.key, on_accept=save_receipt)
        if self.events is not None:
            self.events.flush_pending(self.store.connection)
        return True

    def receipt(self) -> bytes | None:
        row = self.store.connection.execute("SELECT receipt FROM service_delivery_receipts WHERE controller=? AND round_id=?",
                                            (self.scheduled.controller_id, self.scheduled.round_id)).fetchone()
        return row[0] if row is not None else None

    def export(self) -> None:
        row = self.store.connection.execute("SELECT posterior FROM service_delivery_receipts WHERE controller=? AND round_id=?",
                                            (self.scheduled.controller_id, self.scheduled.round_id)).fetchone()
        if row is not None:
            target = self.role.file("posterior_output")
            if not target.exists() or target.read_bytes() != row[0]:
                atomic_private_write(target, row[0], replace=True)

    def close(self) -> None:
        self.store.close()


async def run_recipient(role: RoleConfig, logger: Any) -> None:
    import aiocoap
    from aiocoap import resource

    worker = _OneWorker("laiot-recipient")
    await worker.create(lambda: _RecipientHost(role, logger))

    class ReceiptResource(resource.Resource):
        async def render_get(self, request: Any) -> Any:
            if request.opt.uri_query:
                return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=b"Rejected.")
            receipt = await worker.call("receipt")
            if receipt is None:
                return aiocoap.Message(code=aiocoap.NOT_FOUND, payload=b"Pending.")
            return aiocoap.Message(code=aiocoap.CONTENT, payload=receipt, content_format=42)

    endpoint = None
    try:
        endpoint = await create_controller_endpoint(
            lambda encoded: worker.call("accept", encoded), bind=role.bind(), limits=transport_limits(role),
            extra_resources={("laiot", "receipts"): ReceiptResource()})
        while True:
            await worker.call("export")
            await asyncio.sleep(1)
    finally:
        if endpoint is not None:
            await endpoint.close()
        await worker.close()


async def _confirmed_delivery(context: Any, role: RoleConfig, result: bytes) -> bytes:
    import aiocoap

    target = report_uri(role.value["recipient_uri"])
    await ReportSender(context, target, limits=transport_limits(role)).send_report(result)
    request = aiocoap.Message(code=aiocoap.GET, mtype=aiocoap.CON, uri=receipt_uri(target))
    response = await asyncio.wait_for(context.request(request).response, timeout=30)
    if response.code != aiocoap.CONTENT or len(response.payload) > MAX_RECEIPT_BYTES:
        raise ValueError("Recipient has not confirmed result acceptance")
    return response.payload


async def run_controller(role: RoleConfig, logger: Any) -> None:
    worker = _OneWorker("laiot-controller-service")
    await worker.create(lambda: _ControllerHost(role, logger))
    endpoint = None
    context = None
    try:
        endpoint = await create_controller_endpoint(lambda encoded: worker.call("accept", encoded),
                                                     bind=role.bind(), limits=transport_limits(role))
        context = await create_source_context()
        while True:
            state, confirmed = await worker.call("status")
            result = None if confirmed or state == "timeout" else await worker.call("result")
            if result is not None:
                try:
                    _emit(logger, "RESULT_SEND", role, scope="application", traffic_class="results", report_bytes=len(result))
                    receipt = await _confirmed_delivery(context, role, result)
                    await worker.call("confirm", receipt, result)
                except Exception:
                    # Persisted final ciphertext is retried unchanged. No fresh
                    # posterior is computed on an identical recipient retry.
                    _emit(logger, "DELIVERY_RETRY", role, scope="host", traffic_class="results")
            await asyncio.sleep(1)
    finally:
        if endpoint is not None:
            await endpoint.close()
        if context is not None:
            await context.shutdown()
        await worker.close()


class _RelayStore:
    def __init__(self, role: RoleConfig) -> None:
        self.role = role
        self.roster = set(role.value["participants"])
        if not self.roster or self.roster - set(role.value["policies"]):
            raise ValueError("Invalid relay roster")
        self.context_bytes = role.public_bytes("bfv_public")
        self.context_id = protocol.bfv_context_id(self.context_bytes)
        self.maximum = integer(role.value.get("max_cache_bytes", 64 * 1024 * 1024), "max_cache_bytes", 1)
        self.db = sqlite3.connect(str(role.file("database")), isolation_level=None, timeout=30)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS relay_reports (
                round_id TEXT NOT NULL, node_id TEXT NOT NULL, digest TEXT NOT NULL,
                packet BLOB NOT NULL, forwarded INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(round_id,node_id,digest));
            CREATE TABLE IF NOT EXISTS relay_partial (
                round_id TEXT PRIMARY KEY, packet BLOB NOT NULL, delivered INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS relay_started (
                round_id TEXT PRIMARY KEY, wall REAL NOT NULL);
        """)
        self.db.execute("INSERT OR IGNORE INTO relay_started VALUES(?,?)", (role.round_id, time.time()))

    def accept(self, encoded: bytes) -> bool:
        # The relay has no source keys. These checks select a public schedule;
        # only the controller's successful MAC/inner checks establish validity.
        packet = protocol.Packet.from_bytes(encoded)
        header = packet.metadata
        node = header.get("node")
        if node not in self.roster:
            raise ValueError("Report outside relay group")
        policy = self.role.value["policies"][node]
        if (packet.to_bytes() != encoded or header.get("round") != self.role.round_id
                or header.get("context_id") != self.context_id or header.get("seq") != policy["sequence"]
                or header.get("alpha") != policy["alpha"] or header.get("beta") != policy["alpha"]):
            raise ValueError("Relay report differs from public schedule")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            digest = _digest(encoded)
            previous = self.db.execute("SELECT digest,packet FROM relay_reports WHERE round_id=? AND node_id=? AND digest=?",
                                       (self.role.round_id, node, digest)).fetchone()
            if previous is not None:
                if previous != (digest, encoded):
                    raise ValueError("Conflicting relay source retry")
                self.db.execute("COMMIT")
                return False
            sent = self.db.execute("SELECT 1 FROM relay_reports WHERE round_id=? AND node_id=? AND forwarded=1",
                                   (self.role.round_id, node)).fetchone()
            if sent is not None:
                raise ValueError("Source already forwarded with different report bytes")
            candidates = self.db.execute("SELECT COUNT(*) FROM relay_reports WHERE round_id=? AND node_id=?",
                                         (self.role.round_id, node)).fetchone()[0]
            if candidates >= 4:
                raise ValueError("Relay source candidate queue is full")
            size = self.db.execute("SELECT COALESCE(SUM(LENGTH(packet)),0) FROM relay_reports").fetchone()[0]
            partial_size = self.db.execute("SELECT COALESCE(SUM(LENGTH(packet)),0) FROM relay_partial").fetchone()[0]
            if size + partial_size + len(encoded) > self.maximum:
                raise ValueError("Relay ciphertext cache is full")
            self.db.execute("INSERT INTO relay_reports VALUES(?,?,?,?,0)", (self.role.round_id, node, _digest(encoded), encoded))
            self.db.execute("COMMIT")
            return True
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def pending(self) -> list[tuple[str, str, bytes]]:
        return self.db.execute("SELECT node_id,digest,packet FROM relay_reports WHERE round_id=? AND forwarded=0 ORDER BY node_id,rowid",
                               (self.role.round_id,)).fetchall()

    def mark_forwarded(self, node: str, digest: str) -> None:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute("UPDATE relay_reports SET forwarded=1 WHERE round_id=? AND node_id=? AND digest=?",
                            (self.role.round_id, node, digest))
            self.db.execute("DELETE FROM relay_reports WHERE round_id=? AND node_id=? AND digest<>?",
                            (self.role.round_id, node, digest))
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def reject_candidate(self, node: str, digest: str) -> None:
        self.db.execute("DELETE FROM relay_reports WHERE round_id=? AND node_id=? AND digest=? AND forwarded=0",
                        (self.role.round_id, node, digest))

    def batch_candidates(self) -> list[bytes] | None:
        if self.db.execute("SELECT 1 FROM relay_partial WHERE round_id=?", (self.role.round_id,)).fetchone():
            return None
        rows = self.db.execute("SELECT node_id,packet FROM relay_reports WHERE round_id=? AND forwarded=1 ORDER BY node_id", (self.role.round_id,)).fetchall()
        started = self.db.execute("SELECT wall FROM relay_started WHERE round_id=?", (self.role.round_id,)).fetchone()[0]
        timeout = integer(self.role.value.get("partial_deadline_s", 30), "partial_deadline_s", 1)
        if set(node for node, _ in rows) != self.roster and time.time() < started + timeout:
            return None
        return [encoded for node, encoded in rows if self.role.value["policies"][node]["alpha"] == 0]

    def save_partial(self, encoded: bytes) -> None:
        size = self.db.execute("SELECT COALESCE(SUM(LENGTH(packet)),0) FROM relay_reports").fetchone()[0]
        if size + len(encoded) > self.maximum:
            raise ValueError("Relay ciphertext cache is full")
        self.db.execute("INSERT OR IGNORE INTO relay_partial VALUES(?,?,0)", (self.role.round_id, encoded))

    def pending_partial(self) -> bytes | None:
        row = self.db.execute("SELECT packet FROM relay_partial WHERE round_id=? AND delivered=0", (self.role.round_id,)).fetchone()
        return row[0] if row else None

    def mark_partial(self) -> None:
        self.db.execute("UPDATE relay_partial SET delivered=1 WHERE round_id=?", (self.role.round_id,))

    def close(self) -> None:
        self.db.close()


async def run_relay(role: RoleConfig, logger: Any, *, enable_partials: bool = True) -> None:
    store = _RelayStore(role)  # This connection stays on the event-loop thread.
    endpoint = None
    context = None
    partial_failed = not enable_partials
    try:
        async def accept(encoded: bytes) -> bool:
            fresh = store.accept(encoded)
            _emit(logger, "RECV", role, scope="application", traffic_class="originals", report_bytes=len(encoded))
            return fresh

        endpoint = await create_controller_endpoint(accept, bind=role.bind(), limits=transport_limits(role))
        context = await create_source_context()
        sender = ReportSender(context, report_uri(role.value["controller_uri"]), limits=transport_limits(role))
        while True:
            for node, digest, encoded in store.pending():
                try:
                    await sender.send_report(encoded)
                    store.mark_forwarded(node, digest)
                    _emit(logger, "ORIGINAL_FORWARD", role, scope="application", source_id=node,
                          traffic_class="originals", report_bytes=len(encoded), report_hash=_digest(encoded))
                except ReportRejected:
                    # Rejected unauthenticated candidates release their slot.
                    # Other candidates for the same source remain available.
                    store.reject_candidate(node, digest)
                    _emit(logger, "VERIFY_FAIL", role, scope="host", source_id=node,
                          traffic_class="originals", detail="upstream rejected relay candidate")
                except Exception:
                    _emit(logger, "DELIVERY_RETRY", role, scope="host", source_id=node, traffic_class="originals")
            candidates = None if partial_failed else store.batch_candidates()
            if candidates:
                try:
                    started = time.perf_counter_ns()
                    batch = await asyncio.to_thread(fusion.provisional_fusion, candidates,
                                                   config=role.protocol, bfv_public_context=store.context_bytes,
                                                   round_id=role.round_id)
                    encoded = partial_envelope(batch, role.value["relay_id"])
                    store.save_partial(encoded)
                    _emit(logger, "RELAY_PARTIAL", role, scope="host", traffic_class="partials",
                          report_bytes=len(encoded), duration_ms=(time.perf_counter_ns() - started) / 1_000_000)
                except Exception:
                    # Unverified relay input must not block original delivery.
                    partial_failed = True
                    _emit(logger, "VERIFY_FAIL", role, scope="host", traffic_class="partials")
            encoded = store.pending_partial() if enable_partials else None
            if encoded is not None:
                try:
                    await sender.send_report(encoded)
                    store.mark_partial()
                    _emit(logger, "SEND", role, scope="application", traffic_class="partials", report_bytes=len(encoded))
                except Exception:
                    _emit(logger, "DELIVERY_RETRY", role, scope="host", traffic_class="partials")
            await asyncio.sleep(0.1)
    finally:
        if endpoint is not None:
            await endpoint.close()
        if context is not None:
            await context.shutdown()
        store.close()


async def send_source(role: RoleConfig, readings: tuple[int, ...], logger: Any) -> Any:
    node = role.value["node_id"]
    item = role.value["policies"].get(node)
    if item is None:
        raise ValueError("Source is outside its provisioned schedule")
    credential = load_credential(role.file("source_credential"))
    public_bfv, public_mlkem = role.public_bytes("bfv_public"), role.public_bytes("mlkem_public")

    def prepare() -> bytes:
        outbox = SourceOutbox(role.file("outbox"))
        try:
            return outbox.prepare(readings, config=role.protocol, node_id=node, round_id=role.round_id,
                                  sequence=item["sequence"], policy=fusion.NodePolicy(item["alpha"], item["precision"]),
                                  source_key=credential, bfv_public_context=public_bfv, mlkem_public_key=public_mlkem)
        finally:
            outbox.close()

    started = time.perf_counter_ns()
    encoded = await asyncio.to_thread(prepare)
    _emit(logger, "SEND", role, sequence=item["sequence"], scope="application", alpha=item["alpha"], beta=item["alpha"],
          traffic_class="originals", report_bytes=len(encoded), report_hash=_digest(encoded),
          duration_ms=(time.perf_counter_ns() - started) / 1_000_000)
    context = await create_source_context()
    try:
        return await ReportSender(context, report_uri(role.value["upstream_uri"]),
                                  limits=transport_limits(role)).send_report(encoded)
    finally:
        await context.shutdown()
