"""LA-IoT source authentication, persistent replay control, and trusted recomputation.

Generated without running, importing, compiling, or testing this code.
Python 3.10+. Keep la_iot_cca.py, la_iot_bayesian.py and la_iot_ring_lwe.py
beside this file. The sensitive path uses cryptography>=47 and the BFV path
uses TenSEAL. The former custom lattice encryption is not used.
No installation, key generation, database creation, or example runs on import.

Processing:
1. Use la_iot_cca.DeviceClient to create authenticated version-4 source packets.
2. A relay may call relay_partial for non-sensitive BFV reports. It forwards
   the unchanged source packets as well as its provisional partial ciphertext.
3. ControllerRound.submit authenticates and persistently records original
   packets. It never substitutes a relay MAC for the device source MAC.
4. ControllerRound.finalize reconstructs the authoritative BFV result from
   complete original reports and adds the prior once. Unverified relay
   partial ciphertexts never enter this authoritative calculation.
5. ResultReceiver authenticates the final result, checks the expected round
   and roster, and invokes the existing authorized BFV decryptor.

Original-report forwarding and full controller recomputation are deliberate
costs of this verification method. MACs authenticate a credential and message;
they do not certify physical measurements, prevent packet suppression, or
provide output privacy against an authorized recipient's inference.

The SQLite files hold ciphertexts, identifiers and replay state, not keys.
They belong to the trusted controller/recipient state. Preserve them across
restarts and do not roll them back. Create separate store instances for
separate threads/processes; admission and closure use SQLite transactions.
Keys and round schedules are provisioned by the trusted application, not
learned from incoming packets. Revocation must be distributed to the relevant
controller/recipient stores through that same trusted provisioning process.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import hmac
import importlib
import json
from pathlib import Path
import secrets
import sqlite3
from types import MappingProxyType
from typing import Any, Iterator, Mapping, Sequence


RESULT_DOMAIN = b"LA-IoT/security/v1/controller-result\x00"
SPEC_DOMAIN = b"LA-IoT/security/v1/round-spec\x00"
PACKET_DOMAIN = b"LA-IoT/security/v1/source-packet\x00"
KEY_ID_DOMAIN = b"LA-IoT/security/v1/key-binding\x00"
MAX_RESULT_BYTES = 16 * 1024 * 1024
RESULT_FIELDS = frozenset({
    "version", "controller", "key_id", "round", "spec_id", "context_id",
    "participants", "expected_total_precision", "input_hashes", "nonce", "stats",
})


class SecurityError(ValueError):
    """Authentication, replay, membership, or round-state verification failed."""


class IncompleteRound(SecurityError):
    """At least one scheduled participant has not supplied an original report."""


def _protocol() -> Any:
    return importlib.import_module("la_iot_cca")


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _identifier(value: Any, name: str) -> str:
    return _protocol()._identifier(value, name)


def _integer(value: Any, name: str) -> int:
    if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
        raise SecurityError(f"Invalid {name}")
    return value


def _hex(value: Any, byte_count: int, name: str) -> str:
    if (not isinstance(value, str) or len(value) != byte_count * 2
            or any(ch not in "0123456789abcdef" for ch in value)):
        raise SecurityError(f"Invalid {name}")
    return value


def _packet(value: Any) -> Any:
    protocol = _protocol()
    result = protocol.Packet.from_bytes(value) if isinstance(value, bytes) else value
    if not isinstance(result, protocol.Packet):
        raise TypeError("Expected a source Packet or its serialized bytes")
    if isinstance(value, bytes) and value != result.to_bytes():
        raise SecurityError("Source packet serialization must be canonical")
    return result


def _packet_hash(encoded: bytes) -> str:
    return hashlib.sha256(PACKET_DOMAIN + encoded).hexdigest()


def _validate_bfv_parameters(context: Any, config: Any) -> None:
    """Check actual BFV encoding parameters before relying on integer bounds.

    TenSEAL exposes these through its SEALContext wrapper. The batching
    qualifier implies an odd plaintext modulus (1 modulo twice the degree).
    For an odd modulus t, plain_upper_half_threshold is exactly (t + 1) // 2;
    checking both therefore identifies t without a separate Modulus binding.
    API reference: OpenMined/TenSEAL, enc_context.py and sealapi_context.cpp.
    """
    try:
        native = context.seal_context().data
        if not native.parameters_set():
            raise SecurityError("Invalid BFV encryption parameters")
        data = native.first_context_data()
        parameters = data.parms()
        if (parameters.scheme() != _protocol()._tenseal().SCHEME_TYPE.BFV.value
                or parameters.poly_modulus_degree() != config.poly_modulus_degree
                or not data.qualifiers().using_batching
                or data.plain_upper_half_threshold() != (config.plain_modulus + 1) // 2):
            raise SecurityError("BFV parameters differ from the configured integer bounds")
    except (AttributeError, TypeError) as exc:
        raise SecurityError("Cannot inspect BFV parameters with this TenSEAL API") from exc


@dataclass(frozen=True)
class Credential:
    """A provisioned key identifier and secret; key rotation creates a new pair."""

    key_id: str
    secret: bytes

    def __post_init__(self) -> None:
        _identifier(self.key_id, "key_id")
        if not isinstance(self.secret, bytes) or len(self.secret) < 32:
            raise ValueError("Use a provisioned random secret of at least 32 bytes")

    @property
    def binding(self) -> str:
        return hashlib.sha256(KEY_ID_DOMAIN + self.secret).hexdigest()


class PersistentStore:
    """Create a persistent replay/round database only when explicitly instantiated."""

    def __init__(self, path: str | Path) -> None:
        if not str(path).strip() or str(path) == ":memory:":
            raise ValueError("Replay state requires a persistent database path")
        self.connection = sqlite3.connect(str(path), timeout=30, isolation_level=None)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = FULL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS rounds (
                round_id TEXT PRIMARY KEY,
                spec_id TEXT NOT NULL,
                descriptor BLOB NOT NULL,
                closed INTEGER NOT NULL DEFAULT 0,
                result BLOB
            );
            CREATE TABLE IF NOT EXISTS reports (
                round_id TEXT NOT NULL REFERENCES rounds(round_id),
                node_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                packet_hash TEXT NOT NULL,
                packet BLOB NOT NULL,
                PRIMARY KEY (round_id, node_id)
            );
            CREATE TABLE IF NOT EXISTS used_sequences (
                node_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                PRIMARY KEY (node_id, key_id, seq)
            );
            CREATE TABLE IF NOT EXISTS revoked_keys (
                subject TEXT NOT NULL,
                key_id TEXT NOT NULL,
                PRIMARY KEY (subject, key_id)
            );
            CREATE TABLE IF NOT EXISTS delivered_results (
                controller TEXT NOT NULL,
                round_id TEXT NOT NULL,
                spec_id TEXT NOT NULL,
                result_hash TEXT NOT NULL,
                PRIMARY KEY (controller, round_id)
            );
        """)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    @staticmethod
    def require_live(connection: sqlite3.Connection, subject: str, key_id: str) -> None:
        if connection.execute(
                "SELECT 1 FROM revoked_keys WHERE subject=? AND key_id=?",
                (subject, key_id)).fetchone():
            raise SecurityError("The credential has been revoked")

    def revoke(self, subject: str, key_id: str) -> None:
        """Trusted operator API; subjects are 'device:<id>' or 'controller:<id>'."""
        if not isinstance(subject, str):
            raise TypeError("Expected a device or controller subject")
        kind, separator, entity = subject.partition(":")
        if separator != ":" or kind not in {"device", "controller"}:
            raise ValueError("Subject must be 'device:<id>' or 'controller:<id>'")
        _identifier(entity, "subject identifier")
        _identifier(key_id, "key_id")
        with self.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO revoked_keys(subject,key_id) VALUES(?,?)",
                (subject, key_id))

    def close(self) -> None:
        self.connection.close()


@dataclass(frozen=True)
class RelayBatch:
    """Provisional relay output plus the original source packets for verification."""

    round_id: str
    context_id: str
    originals: tuple[bytes, ...]
    provisional_stats: bytes


def relay_partial(reports: Sequence[Any], config: Any,
                  bfv_public_context: bytes, round_id: str) -> RelayBatch:
    """Add non-sensitive BFV ciphertexts; never add a prior at a relay.

    This function has no device source-MAC keys and makes no source-authenticity
    claim. Hop protection, if used by the transport, has separate hop keys.
    The controller must receive and authenticate the unchanged original packets.
    """
    protocol = _protocol()
    round_id = _identifier(round_id, "round_id")
    if not 0 < len(reports) <= config.max_nodes:
        raise ValueError("Invalid relay batch size")
    context_id = protocol.bfv_context_id(bfv_public_context)
    context = protocol._public_context(bfv_public_context)
    _validate_bfv_parameters(context, config)
    ts = protocol._tenseal()
    originals: list[bytes] = []
    nodes: set[str] = set()
    aggregate: Any | None = None
    for value in reports:
        packet = _packet(value)
        header = packet.metadata
        if (set(header) != protocol.HEADER_KEYS
                or type(header["version"]) is not int or header["version"] != protocol.VERSION
                or header["round"] != round_id
                or header["context_id"] != context_id
                or type(header["alpha"]) is not int or header["alpha"] != 0
                or type(header["beta"]) is not int or header["beta"] != 0
                or type(header["slots"]) is not int or header["slots"] != config.slots):
            raise SecurityError("Invalid non-sensitive relay report")
        node = _identifier(header["node"], "node")
        if node in nodes:
            raise SecurityError("Repeated source in a relay batch")
        raw = protocol._decompress(header["codec"], packet.body, header["raw_len"])
        vector = ts.bfv_vector_from(context, raw)
        if vector.size() != config.slots + 1:
            raise SecurityError("Invalid BFV statistics length")
        aggregate = vector if aggregate is None else aggregate + vector
        originals.append(packet.to_bytes())
        nodes.add(node)
    return RelayBatch(round_id, context_id, tuple(originals), aggregate.serialize())


def _seal_result(payload: Mapping[str, Any], key: Credential) -> bytes:
    tag = hmac.new(key.secret, RESULT_DOMAIN + _json(dict(payload)), hashlib.sha256).hexdigest()
    encoded = _json({"payload": dict(payload), "mac": tag})
    if len(encoded) > MAX_RESULT_BYTES:
        raise SecurityError("Result envelope exceeds its size limit")
    return encoded


def _open_result(encoded: bytes, key: Credential) -> dict[str, Any]:
    if not isinstance(encoded, bytes) or not 0 < len(encoded) <= MAX_RESULT_BYTES:
        raise SecurityError("Invalid result envelope size")
    envelope = json.loads(encoded.decode("ascii"),
                          object_pairs_hook=_protocol()._no_duplicate_pairs)
    if (not isinstance(envelope, dict) or set(envelope) != {"payload", "mac"}
            or not isinstance(envelope["payload"], dict)):
        raise SecurityError("Invalid result envelope")
    payload = envelope["payload"]
    received = _hex(envelope["mac"], 32, "result MAC")
    expected = hmac.new(key.secret, RESULT_DOMAIN + _json(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(received, expected):
        raise SecurityError("Controller result authentication failed")
    if (set(payload) != RESULT_FIELDS or type(payload["version"]) is not int
            or payload["version"] != 1 or payload["key_id"] != key.key_id):
        raise SecurityError("Unexpected result fields or key identifier")
    for field in ("controller", "round"):
        _identifier(payload[field], field)
    for field in ("spec_id", "context_id"):
        _hex(payload[field], 32, field)
    _hex(payload["nonce"], 16, "result nonce")
    _integer(payload["expected_total_precision"], "expected_total_precision")
    participants = payload["participants"]
    hashes = payload["input_hashes"]
    if (not isinstance(participants, list) or not participants
            or any(not isinstance(node, str) for node in participants)
            or participants != sorted(set(participants))
            or not isinstance(hashes, dict) or set(hashes) != set(participants)
            or not isinstance(payload["stats"], str)):
        raise SecurityError("Invalid result participant list or input manifest")
    for node in participants:
        _identifier(node, "participant")
        _hex(hashes[node], 32, "input hash")
    return payload


class ControllerRound:
    """One provisioned round; all original source reports are required.

    finalize does not trust or consume RelayBatch.provisional_stats. Repeated
    finalization returns the identical committed envelope, including after a
    restart. Source admission, sequence use, and closure are transactional.
    """

    def __init__(self, store: PersistentStore, config: Any, round_id: str,
                 policies: Mapping[str, Any], credentials: Mapping[str, Credential],
                 expected_sequences: Mapping[str, int], bfv_public_context: bytes,
                 lattice_secret_key: Any, expected_lattice_key_id: str,
                 controller_id: str, result_key: Credential) -> None:
        self.store, self.config = store, config
        self.round_id = _identifier(round_id, "round_id")
        self.controller_id = _identifier(controller_id, "controller_id")
        self.result_key = result_key
        self.policies = MappingProxyType(dict(policies))
        self.credentials = MappingProxyType(dict(credentials))
        self.expected_sequences = MappingProxyType(dict(expected_sequences))
        self.participants = tuple(sorted(self.policies))
        if (not self.participants or set(self.credentials) != set(self.policies)
                or set(self.expected_sequences) != set(self.policies)):
            raise ValueError("Policies, credentials, and sequence schedule must match")
        if not isinstance(result_key, Credential):
            raise TypeError("Expected a provisioned result Credential")
        for node in self.participants:
            _identifier(node, "node")
            if not isinstance(self.credentials[node], Credential):
                raise TypeError("Expected provisioned device Credentials")
            _integer(self.expected_sequences[node], "expected sequence")
        source_secrets = {credential.secret for credential in self.credentials.values()}
        if len(source_secrets) != len(self.credentials):
            raise ValueError("Provision an independent source secret for each device")
        if result_key.secret in source_secrets:
            raise ValueError("The result secret must be separate from device secrets")
        self._public_context = bfv_public_context
        self._lattice_secret_key = lattice_secret_key
        self._lattice_key_id = expected_lattice_key_id
        self._validator = self._fresh_controller()
        _validate_bfv_parameters(self._validator._bfv_context, config)
        self.context_id = self._validator.context_id
        descriptor = _json({
            "version": 1, "round": self.round_id, "controller": self.controller_id,
            "protocol_version": _protocol().VERSION, "security_suite": _protocol().SUITE,
            "config": asdict(config), "context_id": self.context_id,
            "lattice_key_id": expected_lattice_key_id,
            "result_key_id": result_key.key_id, "result_key_binding": result_key.binding,
            "nodes": {node: {"alpha": self.policies[node].alpha,
                             "beta": self.policies[node].beta,
                             "precision": self.policies[node].precision,
                             "seq": self.expected_sequences[node],
                             "key_id": self.credentials[node].key_id,
                             "key_binding": self.credentials[node].binding}
                      for node in self.participants},
        })
        self.spec_id = hashlib.sha256(SPEC_DOMAIN + descriptor).hexdigest()
        with store.transaction() as connection:
            previous = connection.execute(
                "SELECT spec_id,descriptor FROM rounds WHERE round_id=?",
                (self.round_id,)).fetchone()
            if previous is None:
                connection.execute(
                    "INSERT INTO rounds(round_id,spec_id,descriptor) VALUES(?,?,?)",
                    (self.round_id, self.spec_id, descriptor))
            elif previous != (self.spec_id, descriptor):
                raise SecurityError("A round identifier cannot be reused with another schedule")

    def _fresh_controller(self) -> Any:
        return _protocol().TrustedController(
            self.config, self.round_id, self.policies,
            {node: credential.secret for node, credential in self.credentials.items()},
            self._public_context, self._lattice_secret_key, self._lattice_key_id)

    def submit(self, value: Any) -> bool:
        """Authenticate and record a source packet; True means newly recorded.

        An identical retry returns False and is never counted twice. Full
        ciphertext/watermark parsing is repeated by the trusted controller at
        finalization; malformed authenticated payloads cannot produce a result.
        """
        try:
            return self._submit(value)
        except (ValueError, TypeError, KeyError, OverflowError):
            raise _protocol().PacketRejected() from None

    def _submit(self, value: Any) -> bool:
        """Internal admission; packet rejection details are not returned to peers."""
        packet = _packet(value)
        node, _ = self._validator._validate_header(packet.metadata)
        credential = self.credentials[node]
        expected_mac = _protocol()._source_tag(credential.secret, packet.metadata, packet.body)
        if not hmac.compare_digest(packet.source_mac, expected_mac):
            raise SecurityError("Source authentication failed")
        sequence = packet.metadata["seq"]
        if sequence != self.expected_sequences[node]:
            raise SecurityError("Report sequence differs from the trusted round schedule")
        encoded = packet.to_bytes()
        digest = _packet_hash(encoded)
        with self.store.transaction() as connection:
            PersistentStore.require_live(connection, "device:" + node, credential.key_id)
            row = connection.execute(
                "SELECT spec_id,closed FROM rounds WHERE round_id=?",
                (self.round_id,)).fetchone()
            if row is None or row[0] != self.spec_id:
                raise SecurityError("Round registration mismatch")
            previous = connection.execute(
                "SELECT packet_hash,packet FROM reports WHERE round_id=? AND node_id=?",
                (self.round_id, node)).fetchone()
            if previous is not None:
                if previous == (digest, encoded):
                    return False
                raise SecurityError("Conflicting second report from the same participant")
            if row[1]:
                raise SecurityError("The round is already closed")
            try:
                connection.execute(
                    "INSERT INTO used_sequences(node_id,key_id,seq) VALUES(?,?,?)",
                    (node, credential.key_id, sequence))
            except sqlite3.IntegrityError as exc:
                raise SecurityError("This device sequence has already been used") from exc
            connection.execute(
                "INSERT INTO reports VALUES(?,?,?,?,?,?)",
                (self.round_id, node, credential.key_id, sequence, digest, encoded))
        return True

    def submit_batch(self, batch: RelayBatch) -> int:
        """Only original reports affect the ledger; the relay sum is provisional."""
        if (not isinstance(batch, RelayBatch) or batch.round_id != self.round_id
                or batch.context_id != self.context_id
                or not 0 < len(batch.originals) <= self.config.max_nodes):
            raise SecurityError("Relay batch context or size mismatch")
        return sum(self.submit(packet) for packet in batch.originals)

    def finalize(self) -> bytes:
        with self.store.transaction() as connection:
            PersistentStore.require_live(
                connection, "controller:" + self.controller_id, self.result_key.key_id)
            row = connection.execute(
                "SELECT spec_id,closed,result FROM rounds WHERE round_id=?",
                (self.round_id,)).fetchone()
            if row is None or row[0] != self.spec_id:
                raise SecurityError("Round registration mismatch")
            if row[1]:
                if not isinstance(row[2], bytes):
                    raise SecurityError("Closed round has no committed result")
                cached = _open_result(row[2], self.result_key)
                if (cached["round"] != self.round_id or cached["spec_id"] != self.spec_id
                        or cached["controller"] != self.controller_id):
                    raise SecurityError("Committed result binding mismatch")
                return row[2]
            rows = connection.execute(
                "SELECT node_id,packet_hash,packet FROM reports WHERE round_id=? ORDER BY node_id",
                (self.round_id,)).fetchall()
            by_node = {node: (digest, packet) for node, digest, packet in rows}
            if set(by_node) != set(self.participants):
                missing = sorted(set(self.participants) - set(by_node))
                raise IncompleteRound("Missing original reports: " + ", ".join(missing))
            controller = self._fresh_controller()
            for node in self.participants:
                PersistentStore.require_live(
                    connection, "device:" + node, self.credentials[node].key_id)
                digest, packet = by_node[node]
                if not hmac.compare_digest(digest, _packet_hash(packet)):
                    raise SecurityError("Stored source packet hash mismatch")
                controller.receive(packet)
            encrypted = controller.finalize(require_all=True)
            payload = {
                "version": 1, "controller": self.controller_id,
                "key_id": self.result_key.key_id, "round": self.round_id,
                "spec_id": self.spec_id, "context_id": self.context_id,
                "participants": list(encrypted.participants),
                "expected_total_precision": encrypted.expected_total_precision,
                "input_hashes": {node: by_node[node][0] for node in self.participants},
                "nonce": secrets.token_hex(16),
                "stats": base64.b64encode(encrypted.serialized_stats).decode("ascii"),
            }
            output = _seal_result(payload, self.result_key)
            connection.execute(
                "UPDATE rounds SET closed=1,result=? WHERE round_id=?",
                (output, self.round_id))
        return output


class ResultReceiver:
    """The authorized BFV secret-key holder, separate from the controller."""

    def __init__(self, store: PersistentStore, config: Any, bfv_secret_context: Any,
                 expected_context_id: str, controller_id: str,
                 result_key: Credential) -> None:
        self.store, self.config = store, config
        self.controller_id = _identifier(controller_id, "controller_id")
        if not isinstance(result_key, Credential):
            raise TypeError("Expected a provisioned result Credential")
        self.result_key = result_key
        self.context_id = _hex(expected_context_id, 32, "context_id")
        _validate_bfv_parameters(bfv_secret_context, config)
        self._decryptor = _protocol().AuthorizedDecryptor(
            config, bfv_secret_context, self.context_id)

    def receive(self, encoded: bytes, expected_round_id: str,
                expected_spec_id: str, expected_participants: Sequence[str],
                expected_total_precision: int | None = None) -> Any:
        """Authenticate, reject stale delivery, and recover exact Fraction results.

        Expected round, descriptor hash, and roster come from trusted scheduling,
        not from the received envelope. No database delivery record is committed
        if authentication, ciphertext parsing, or decryption fails.
        """
        expected_round_id = _identifier(expected_round_id, "expected round")
        expected_spec_id = _hex(expected_spec_id, 32, "expected spec_id")
        roster = tuple(sorted(expected_participants))
        if (not roster or len(roster) > self.config.max_nodes
                or len(set(roster)) != len(roster)):
            raise SecurityError("Invalid expected participant list")
        for node in roster:
            _identifier(node, "expected participant")
        payload = _open_result(encoded, self.result_key)
        if expected_total_precision is not None:
            _integer(expected_total_precision, "expected total precision")
            if expected_total_precision < 1:
                raise SecurityError("Expected total precision must be positive")
            if payload["expected_total_precision"] != expected_total_precision:
                raise SecurityError("Result precision differs from the trusted schedule")
        if (payload["controller"] != self.controller_id
                or payload["round"] != expected_round_id
                or payload["spec_id"] != expected_spec_id
                or payload["context_id"] != self.context_id
                or tuple(payload["participants"]) != roster):
            raise SecurityError("Result does not match the trusted round schedule")
        raw = base64.b64decode(payload["stats"], validate=True)
        if not 0 < len(raw) <= _protocol().MAX_RAW_BYTES:
            raise SecurityError("Invalid serialized BFV result length")
        encrypted = _protocol().EncryptedPosterior(
            payload["round"], payload["context_id"], raw, roster,
            payload["expected_total_precision"])
        with self.store.transaction() as connection:
            PersistentStore.require_live(
                connection, "controller:" + self.controller_id, self.result_key.key_id)
            if connection.execute(
                    "SELECT 1 FROM delivered_results WHERE controller=? AND round_id=?",
                    (self.controller_id, expected_round_id)).fetchone():
                raise SecurityError("This round result has already been delivered")
            posterior = self._decryptor.decrypt_posterior(encrypted)
            connection.execute(
                "INSERT INTO delivered_results VALUES(?,?,?,?)",
                (self.controller_id, expected_round_id, expected_spec_id,
                 hashlib.sha256(encoded).hexdigest()))
        return posterior


# Intentionally no executable example, __main__ block, or automatic setup.
