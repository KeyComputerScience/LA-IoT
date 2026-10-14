# SPDX-License-Identifier: Apache-2.0
# Packaged implementation; migrated from IoT Application on 2026-10-14.
"""Bounded CoAP transport for already protected LA-IoT report bytes.

The source and controller run on Linux Pi/Nano hosts. An already configured
Contiki-NG border router provides the IPv6 route into the RPL/6LoWPAN network.
This module transports bytes; it does not configure routing or implement BFV.

API basis: aiocoap's documented Context, Message, Resource, and Block1 options.
The only network entry points are create_source_context() and
create_controller_endpoint(). Importing this module does not open a socket.

Reports use CON POST /laiot/reports and explicit RFC 7959 Block1 transfers.
The server disables automatic assembly and applies its own limits before
retaining each block. The application callback verifies and persistently
registers a complete protected report. True means a new contribution; False
means an identical, already registered retry. It must raise on rejection.

CoAP block counts are not IEEE 802.15.4 frame counts. Obtain link fragments,
ACKs, retransmissions, and per-hop frame sizes from the network logs.

Source only: this file was generated without execution, imports, or tests.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Mapping
from urllib.parse import urlsplit

import aiocoap
from aiocoap import resource


REPORT_PATH = ("laiot", "reports")
OCTET_STREAM = 42
_TRANSFER_ID = re.compile(r"[0-9a-f]{32}\Z")
_REJECTED = b"Rejected."
_ACCEPTED = b"Accepted."

AcceptReport = Callable[[bytes], bool | Awaitable[bool]]


class TransportError(RuntimeError):
    """The CoAP transfer did not finish with the expected acknowledgments."""


class ReportRejected(TransportError):
    """The endpoint returned its uniform report-rejection response."""


def _positive_integer(value: int, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _block_exponent(block_size: int) -> int:
    if type(block_size) is not int or block_size not in (
        16, 32, 64, 128, 256, 512, 1024
    ):
        raise ValueError("block_size must be a power of two from 16 to 1024")
    return block_size.bit_length() - 5


def _check_transfer_id(transfer_id: str) -> str:
    if not isinstance(transfer_id, str) or not _TRANSFER_ID.fullmatch(transfer_id):
        raise ValueError("transfer_id must contain exactly 32 lowercase hex digits")
    return transfer_id


def new_transfer_id() -> str:
    """Create a transport identifier; it is separate from the protected nonce."""
    return secrets.token_hex(16)


@dataclass(frozen=True)
class TransportLimits:
    max_report_bytes: int = 4 * 1024 * 1024
    max_transfers: int = 128
    max_cached_payload_bytes: int = 16 * 1024 * 1024
    block_size: int = 64
    idle_timeout_s: float = 180.0
    transfer_lifetime_s: float = 1800.0
    completed_retry_window_s: float = 60.0

    def __post_init__(self) -> None:
        _positive_integer(self.max_report_bytes, "max_report_bytes")
        _positive_integer(self.max_transfers, "max_transfers")
        _positive_integer(self.max_cached_payload_bytes, "max_cached_payload_bytes")
        _block_exponent(self.block_size)
        if self.max_cached_payload_bytes < self.max_report_bytes:
            raise ValueError("the cache must be able to hold one maximum-size report")
        for name in (
            "idle_timeout_s", "transfer_lifetime_s", "completed_retry_window_s"
        ):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or not 0 < value < float("inf"):
                raise ValueError(f"{name} must be positive and finite")


@dataclass(frozen=True)
class TransferReceipt:
    """A CoAP delivery acknowledgment, distinct from the final authenticated result."""

    transfer_id: str
    report_bytes: int
    report_sha256: str
    block_count: int
    elapsed_s: float


@dataclass
class _Transfer:
    size_exponent: int
    declared_size: int
    created_at: float
    touched_at: float
    finished: asyncio.Future
    payload: bytearray = field(default_factory=bytearray)
    next_block: int = 0
    final_block: int | None = None
    processing: bool = False
    completed_at: float | None = None


class BoundedReportResource(resource.Resource):
    """Receive fixed-size Block1 reports with bounded retained payload memory.

    max_cached_payload_bytes counts retained report bytes, including recently
    completed reports kept for exact retries. Object/UDP overhead is separate.
    At most one extra max_report_bytes copy is made for the serialized callback.
    The callback lock also permits a single SQLite connection to be used on
    its owning event-loop thread. A synchronous callback runs on that thread;
    an asynchronous callback can yield while doing its application work.
    """

    def __init__(
        self,
        accept_report: AcceptReport,
        *,
        limits: TransportLimits | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        super().__init__()
        if not callable(accept_report):
            raise TypeError("accept_report must be callable")
        self.limits = limits or TransportLimits()
        self._accept_report = accept_report
        self._logger = logger or logging.getLogger("laiot.coap")
        self._transfers: dict[tuple[str, str], _Transfer] = {}
        self._cached_bytes = 0
        self._state_lock = asyncio.Lock()
        self._callback_lock = asyncio.Lock()

    async def needs_blockwise_assembly(self, request) -> bool:
        # Automatic library assembly would allocate before our resource limits.
        return False

    @staticmethod
    def _reject():
        return aiocoap.Message(code=aiocoap.BAD_REQUEST, payload=_REJECTED)

    @staticmethod
    def _reply(number: int, more: bool, exponent: int):
        response = aiocoap.Message(
            code=aiocoap.CONTINUE if more else aiocoap.CHANGED,
            payload=b"" if more else _ACCEPTED,
        )
        response.opt.block1 = (number, more, exponent)
        return response

    def _discard_locked(self, key: tuple[str, str]) -> None:
        entry = self._transfers.pop(key, None)
        if entry is not None:
            self._cached_bytes -= len(entry.payload)
            entry.payload.clear()
            if not entry.finished.done():
                entry.finished.set_result(False)

    def _expire_locked(self, now: float) -> None:
        for key, entry in tuple(self._transfers.items()):
            if entry.processing:
                continue
            if entry.completed_at is not None:
                expired = now - entry.completed_at >= self.limits.completed_retry_window_s
            else:
                expired = (
                    now - entry.touched_at >= self.limits.idle_timeout_s
                    or now - entry.created_at >= self.limits.transfer_lifetime_s
                )
            if expired:
                self._discard_locked(key)

    def _make_room_locked(self, extra_bytes: int, *, new_transfer: bool) -> bool:
        # Completed retry copies are expendable; active reports are preserved.
        # This lets a long source sweep reuse the bounded cache immediately.
        def fits() -> bool:
            return (
                self._cached_bytes + extra_bytes <= self.limits.max_cached_payload_bytes
                and (
                    not new_transfer
                    or len(self._transfers) < self.limits.max_transfers
                )
            )

        if fits():
            return True
        completed = sorted(
            (
                (entry.completed_at, key)
                for key, entry in self._transfers.items()
                if entry.completed_at is not None and not entry.processing
            )
        )
        for _, key in completed:
            self._discard_locked(key)
            if fits():
                return True
        return False

    async def expire_transfers(self) -> None:
        async with self._state_lock:
            self._expire_locked(time.monotonic())

    async def cleanup_loop(self) -> None:
        interval = min(5.0, self.limits.idle_timeout_s / 2)
        while True:
            await asyncio.sleep(interval)
            await self.expire_transfers()

    async def discard_all(self) -> None:
        async with self._state_lock:
            for key in tuple(self._transfers):
                self._discard_locked(key)

    def _parse(self, request):
        if request.mtype != aiocoap.CON or request.opt.content_format != OCTET_STREAM:
            raise ValueError("invalid request profile")
        queries = tuple(request.opt.uri_query)
        if len(queries) != 1 or not queries[0].startswith("tid="):
            raise ValueError("invalid transfer query")
        transfer_id = _check_transfer_id(queries[0][4:])
        if request.remote is None or request.remote.is_multicast_locally:
            raise ValueError("unicast endpoint required")
        peer = request.remote.hostinfo
        if not isinstance(peer, str) or not peer or len(peer) > 512:
            raise ValueError("invalid peer")
        block = request.opt.block1
        if block is None:
            raise ValueError("Block1 required")
        number, more, exponent = block
        if type(number) is not int or not 0 <= number < (1 << 20):
            raise ValueError("invalid block number")
        if exponent != _block_exponent(self.limits.block_size):
            raise ValueError("unexpected block size")
        if more not in (False, True, 0, 1):
            raise ValueError("invalid more flag")
        chunk = request.payload
        if not isinstance(chunk, bytes) or not 0 < len(chunk) <= self.limits.block_size:
            raise ValueError("invalid block length")
        if more and len(chunk) != self.limits.block_size:
            raise ValueError("short non-final block")
        declared_size = request.opt.size1
        if (
            type(declared_size) is not int
            or not 0 < declared_size <= self.limits.max_report_bytes
        ):
            raise ValueError("invalid Size1")
        end = number * self.limits.block_size + len(chunk)
        if end > declared_size or (bool(more) != (end < declared_size)):
            raise ValueError("inconsistent report length")
        return (peer, transfer_id), number, bool(more), exponent, declared_size, chunk

    async def _finish(self, key: tuple[str, str], entry: _Transfer) -> bool:
        accepted = False
        try:
            async with self._callback_lock:
                # One callback at a time: no concurrent use of a replay database.
                protected_report = bytes(entry.payload)
                result = self._accept_report(protected_report)
                if inspect.isawaitable(result):
                    result = await result
                if type(result) is not bool:
                    raise TypeError("accept_report must return bool or raise")
                # Both new registration and an identical retry are successful.
                accepted = True
                self._logger.info(
                    "accepted_report bytes=%d sha256=%s",
                    len(protected_report),
                    hashlib.sha256(protected_report).hexdigest(),
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never disclose a crypto, decoding, key, or replay failure detail.
            accepted = False
        finally:
            async with self._state_lock:
                entry.processing = False
                if accepted:
                    entry.completed_at = time.monotonic()
                    if not entry.finished.done():
                        entry.finished.set_result(True)
                else:
                    self._discard_locked(key)
        return accepted

    async def render_post(self, request):
        try:
            key, number, more, exponent, declared_size, chunk = self._parse(request)
        except Exception:
            return self._reject()

        finish_here = False
        wait_for_finish = None
        async with self._state_lock:
            now = time.monotonic()
            self._expire_locked(now)
            entry = self._transfers.get(key)
            if entry is None:
                if number != 0 or not self._make_room_locked(
                    len(chunk), new_transfer=True
                ):
                    return self._reject()
                entry = _Transfer(
                    exponent, declared_size, now, now,
                    asyncio.get_running_loop().create_future(),
                )
                self._transfers[key] = entry
            if entry.size_exponent != exponent or entry.declared_size != declared_size:
                return self._reject()

            if number < entry.next_block:
                start = number * self.limits.block_size
                end = min(start + self.limits.block_size, len(entry.payload))
                expected_more = number != entry.final_block
                if entry.payload[start:end] != chunk or more != expected_more:
                    return self._reject()
                entry.touched_at = now
                if more:
                    return self._reply(number, True, exponent)
                wait_for_finish = entry.finished
            else:
                if number != entry.next_block or entry.final_block is not None:
                    return self._reject()
                if not self._make_room_locked(len(chunk), new_transfer=False):
                    return self._reject()
                entry.payload.extend(chunk)
                self._cached_bytes += len(chunk)
                entry.next_block += 1
                entry.touched_at = now
                if more:
                    return self._reply(number, True, exponent)
                entry.final_block = number
                entry.processing = True
                finish_here = True

        if finish_here:
            accepted = await self._finish(key, entry)
        else:
            # A concurrent identical final-block retry waits for the same check.
            accepted = await asyncio.shield(wait_for_finish)
        return self._reply(number, False, exponent) if accepted else self._reject()


@dataclass
class ControllerEndpoint:
    context: object
    reports: BoundedReportResource
    cleanup_task: asyncio.Task

    async def close(self) -> None:
        self.cleanup_task.cancel()
        await asyncio.gather(self.cleanup_task, return_exceptions=True)
        await self.context.shutdown()
        await self.reports.discard_all()


async def create_controller_endpoint(
    accept_report: AcceptReport,
    *,
    bind: tuple[str, int] = ("::", 5683),
    limits: TransportLimits | None = None,
    logger: logging.Logger | None = None,
    extra_resources: Mapping[tuple[str, ...], resource.Resource] | None = None,
) -> ControllerEndpoint:
    """Explicitly open the IPv6/UDP report endpoint on a Pi or Nano host."""
    reports = BoundedReportResource(accept_report, limits=limits, logger=logger)
    site = resource.Site()
    site.add_resource(REPORT_PATH, reports)
    for path, additional in (extra_resources or {}).items():
        if (not isinstance(path, tuple) or not path or path == REPORT_PATH
                or any(not isinstance(part, str) or not part or "/" in part for part in path)
                or not isinstance(additional, resource.Resource)):
            raise ValueError("Invalid additional CoAP resource")
        site.add_resource(path, additional)
    context = await aiocoap.Context.create_server_context(
        site, bind=bind, transports=["udp6"]
    )
    cleanup_task = asyncio.create_task(reports.cleanup_loop())
    return ControllerEndpoint(context, reports, cleanup_task)


async def create_source_context():
    """Explicitly open one context; retain it across all blocks and retries."""
    return await aiocoap.Context.create_client_context(transports=["udp6"])


class ReportSender:
    """Send exactly the protected bytes supplied by the source-encryption code."""

    def __init__(
        self,
        context,
        controller_uri: str,
        *,
        limits: TransportLimits | None = None,
        exchange_timeout_s: float = 120.0,
        max_attempts: int = 2,
        logger: logging.Logger | None = None,
    ) -> None:
        parsed = urlsplit(controller_uri)
        if (
            parsed.scheme != "coap" or not parsed.hostname
            or parsed.path != "/laiot/reports"
            or parsed.query or parsed.fragment
            or parsed.username is not None or parsed.password is not None
        ):
            raise ValueError("use coap://host[:port]/laiot/reports without a query")
        if not isinstance(exchange_timeout_s, (int, float)) or not (
            0 < exchange_timeout_s < float("inf")
        ):
            raise ValueError("exchange_timeout_s must be positive and finite")
        _positive_integer(max_attempts, "max_attempts")
        self.context = context
        self.controller_uri = controller_uri
        self.limits = limits or TransportLimits()
        self.exchange_timeout_s = exchange_timeout_s
        self.max_attempts = max_attempts
        self._logger = logger or logging.getLogger("laiot.coap")

    async def send_report(
        self, protected_report: bytes, *, transfer_id: str | None = None
    ) -> TransferReceipt:
        """Send/retry the same bytes; return a transport receipt, not a fusion result.

        Use a caller-retained transfer_id to resume an application retry from
        block zero. Context-owned CON retransmission handles each block. Any
        whole-report retry below retains the same context, identifier, and bytes.
        """
        if not isinstance(protected_report, bytes) or not (
            0 < len(protected_report) <= self.limits.max_report_bytes
        ):
            raise ValueError("protected_report must be nonempty bytes within the limit")
        transfer_id = _check_transfer_id(transfer_id or new_transfer_id())
        exponent = _block_exponent(self.limits.block_size)
        block_count = (
            len(protected_report) + self.limits.block_size - 1
        ) // self.limits.block_size
        uri = f"{self.controller_uri}?tid={transfer_id}"
        started = time.monotonic()

        for attempt in range(self.max_attempts):
            try:
                for number in range(block_count):
                    start = number * self.limits.block_size
                    chunk = protected_report[start:start + self.limits.block_size]
                    more = number + 1 < block_count
                    message = aiocoap.Message(
                        code=aiocoap.POST, mtype=aiocoap.CON, uri=uri, payload=chunk
                    )
                    message.opt.content_format = OCTET_STREAM
                    message.opt.size1 = len(protected_report)
                    message.opt.block1 = (number, more, exponent)
                    exchange = self.context.request(message, handle_blockwise=False)
                    response = await asyncio.wait_for(
                        exchange.response, timeout=self.exchange_timeout_s
                    )
                    if response.code == aiocoap.BAD_REQUEST:
                        raise ReportRejected("report rejected")
                    expected_code = aiocoap.CONTINUE if more else aiocoap.CHANGED
                    if response.code != expected_code or response.opt.block1 is None:
                        raise TransportError("unexpected CoAP acknowledgment")
                    ack = response.opt.block1
                    if (
                        ack.block_number != number
                        or ack.size_exponent != exponent
                        or bool(ack.more) != more
                        or response.payload != (b"" if more else _ACCEPTED)
                    ):
                        raise TransportError("inconsistent Block1 acknowledgment")
                break
            except (ReportRejected, TransportError):
                raise
            except Exception:
                if attempt + 1 == self.max_attempts:
                    raise TransportError("CoAP transfer failed") from None

        digest = hashlib.sha256(protected_report).hexdigest()
        self._logger.info(
            "sent_report bytes=%d sha256=%s", len(protected_report), digest
        )
        return TransferReceipt(
            transfer_id, len(protected_report), digest,
            block_count, time.monotonic() - started,
        )

