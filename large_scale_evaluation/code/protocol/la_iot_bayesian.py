"""LA-IoT protocol with precision-weighted Bayesian aggregation.

Python 3.10+. This file was generated and reviewed without running Python,
importing it, or executing an example or test. Nothing runs automatically.
TenSEAL must already be installed before a BFV operation is explicitly called;
this module does not install dependencies. Keep la_iot_ring_lwe.py beside it.

For each of four measurement slots, the statistical model is a common unknown
mean, independent Gaussian observations with calibrated integer precision
tau_i, and a Gaussian prior with integer mean mu_0 and precision tau_0. BFV
adds the sufficient statistics [tau_i*x_i[0], ..., tau_i*x_i[3], tau_i]. The
authorized decryptor obtains the exact rational posterior means and variance
using Fraction.

Sensitive reports (alpha=beta=1) use a unified watermark-and-compression
unit: losslessly compress the reading bytes, retain their lengths and codec,
pad the storage area to the original length, and authenticate the full unit
using a fresh 16-byte random nonce and a 16-byte HMAC-SHA256 tag.
Ring-LWE encrypts this unit. A trusted controller decrypts it, verifies its
authentication, removes its padding, and decompresses the original readings
before re-encrypting their statistics under the common BFV public key.
Non-sensitive reports (alpha=beta=0) already contain BFV statistics. Both
paths use adaptive, lossless byte compression and a per-device source MAC.

The combined unit is a removable authenticated byte frame. TenSEAL BFV operates in
leveled mode, using addition of integer statistics without bootstrapping.
The configured bounds prevent plaintext modular wraparound. Ring-LWE uses
the parameters and coefficient compression defined in the companion module.
Inputs follow the calibrated precisions and reading ranges in ProtocolConfig;
sensor-side measurement and encoding, and controller-side aggregation, are
trusted. The final result reaches the authorized decryptor through an
authenticated application channel. Replay state is in memory and must be
persisted when operation continues across process restarts.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import hmac
import json
import secrets
import struct
from types import MappingProxyType
from typing import Any, Mapping, Sequence
import zlib

import la_iot_ring_lwe as lattice


VERSION = 2
MAX_RAW_BYTES = 2 * 1024 * 1024
MAX_PACKET_BYTES = 4 * 1024 * 1024
MARKER_MAGIC = b"LACW"
MARKER_PREFIX_BYTES = 13
MARKER_NONCE_BYTES = 16
MARKER_TAG_BYTES = 16
TAG_BYTES = 32
SOURCE_DOMAIN = b"LA-IoT/BAYES/v1/source\x00"
MARKER_DOMAIN = b"LA-IoT/BAYES/v1/marker\x00"
KEY_DOMAIN = b"LA-IoT/BAYES/v1/key/"

HEADER_KEYS = frozenset({
    "version", "node", "round", "seq", "alpha", "beta", "slots",
    "precision", "context_id", "lattice_key_id", "frame_len", "codec",
    "raw_len",
})
MARKER_BINDING_KEYS = (
    "version", "node", "round", "seq", "alpha", "beta", "slots",
    "precision", "context_id", "lattice_key_id", "frame_len",
)


def _tenseal() -> Any:
    """Load the optional dependency only when a BFV API is called."""
    try:
        import tenseal
    except ImportError as exc:
        raise ImportError("BFV operations require an existing TenSEAL installation") from exc
    return tenseal


def _require_int(value: Any, name: str, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f"{name} must be an integer in [{lower}, {upper}]")
    return value


def _identifier(value: Any, name: str) -> str:
    if (not isinstance(value, str) or not value or value.strip() != value
            or len(value.encode("utf-8")) > 128):
        raise ValueError(f"{name} must be a nonempty identifier of at most 128 UTF-8 bytes")
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _psk(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) < 32:
        raise ValueError("Each device PSK must contain at least 32 bytes")
    return value


def _purpose_key(psk: bytes, purpose: bytes) -> bytes:
    """Separate source-MAC and marker-MAC keys with a keyed PRF."""
    return hmac.new(_psk(psk), KEY_DOMAIN + purpose, hashlib.sha256).digest()


def _source_tag(psk: bytes, header: Mapping[str, Any], body: bytes) -> bytes:
    encoded = _canonical_json(dict(header))
    content = (SOURCE_DOMAIN + len(encoded).to_bytes(4, "big") + encoded
               + len(body).to_bytes(8, "big") + body)
    return hmac.new(_purpose_key(psk, b"source"), content, hashlib.sha256).digest()


def _marker_binding(header: Mapping[str, Any]) -> bytes:
    return _canonical_json({key: header[key] for key in MARKER_BINDING_KEYS})


def _embed_marker(payload: bytes, psk: bytes, header: Mapping[str, Any]) -> bytes:
    """Create one compressed unit authenticated by nonce-bound RandomMAC."""
    codec, stored = adaptive_compress(payload)
    codec_id = 0 if codec == "identity" else 1
    nonce = secrets.token_bytes(MARKER_NONCE_BYTES)
    storage = stored + bytes(len(payload) - len(stored))
    prefix = (MARKER_MAGIC + bytes([codec_id]) + len(payload).to_bytes(4, "big")
              + len(stored).to_bytes(4, "big") + nonce + storage)
    binding = _marker_binding(header)
    tag = hmac.new(_purpose_key(psk, b"marker"),
                   MARKER_DOMAIN + len(binding).to_bytes(4, "big") + binding + prefix,
                   hashlib.sha256).digest()[:MARKER_TAG_BYTES]
    return prefix + tag


def _remove_marker(frame: bytes, psk: bytes, header: Mapping[str, Any]) -> bytes:
    """Authenticate the complete unit, then restore its original reading bytes."""
    if len(frame) < MARKER_PREFIX_BYTES + MARKER_NONCE_BYTES + MARKER_TAG_BYTES:
        raise ValueError("Invalid marker frame")
    prefix, received_tag = frame[:-MARKER_TAG_BYTES], frame[-MARKER_TAG_BYTES:]
    binding = _marker_binding(header)
    expected = hmac.new(_purpose_key(psk, b"marker"),
                        MARKER_DOMAIN + len(binding).to_bytes(4, "big") + binding + prefix,
                        hashlib.sha256).digest()[:MARKER_TAG_BYTES]
    if not hmac.compare_digest(received_tag, expected):
        raise ValueError("Marker authentication failed")
    if prefix[:4] != MARKER_MAGIC:
        raise ValueError("Invalid watermark-compression identifier")
    codec_id = prefix[4]
    raw_len = int.from_bytes(prefix[5:9], "big")
    stored_len = int.from_bytes(prefix[9:13], "big")
    _require_int(raw_len, "watermark raw_len", 1, MAX_RAW_BYTES)
    storage_start = MARKER_PREFIX_BYTES + MARKER_NONCE_BYTES
    if len(prefix) != storage_start + raw_len:
        raise ValueError("Invalid watermark-compression frame length")
    _require_int(stored_len, "watermark stored_len", 1, raw_len)
    storage = prefix[storage_start:]
    if any(storage[stored_len:]):
        raise ValueError("Nonzero watermark-compression storage padding")
    if codec_id not in (0, 1):
        raise ValueError("Unsupported watermark-compression codec")
    codec = "identity" if codec_id == 0 else "zlib"
    return _decompress(codec, storage[:stored_len], raw_len)


def adaptive_compress(raw: bytes) -> tuple[str, bytes]:
    """Lossless serialization compression; keep raw bytes if zlib is larger."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_RAW_BYTES:
        raise ValueError("Serialized ciphertext length is out of bounds")
    compressed = zlib.compress(raw, level=6)
    if len(compressed) < len(raw):
        return "zlib", compressed
    return "identity", raw


def _decompress(codec: str, body: bytes, raw_len: int) -> bytes:
    _require_int(raw_len, "raw_len", 1, MAX_RAW_BYTES)
    if codec == "identity":
        if len(body) != raw_len:
            raise ValueError("Identity payload length mismatch")
        return body
    if codec != "zlib" or not 0 < len(body) < raw_len:
        raise ValueError("Invalid adaptive-compression payload")
    decoder = zlib.decompressobj()
    # The cap is checked before deserialization or allocation of an FHE object.
    raw = decoder.decompress(body, raw_len + 1)
    if (len(raw) != raw_len or not decoder.eof or decoder.unconsumed_tail
            or decoder.unused_data):
        raise ValueError("Invalid or oversized zlib stream")
    return raw


@dataclass(frozen=True)
class ProtocolConfig:
    slots: int = 4
    plain_modulus: int = 1032193
    poly_modulus_degree: int = 8192
    max_nodes: int = 5000
    max_abs_reading: int = 100
    max_precision: int = 1
    prior_mean: int = 0
    prior_precision: int = 1

    def __post_init__(self) -> None:
        if (type(self.slots) is not int or self.slots != 4
                or type(self.plain_modulus) is not int or self.plain_modulus != 1032193
                or type(self.poly_modulus_degree) is not int or self.poly_modulus_degree != 8192):
            raise ValueError("This reference profile fixes slots=4, t=1032193 and degree=8192")
        _require_int(self.max_nodes, "max_nodes", 1, 5000)
        _require_int(self.max_abs_reading, "max_abs_reading", 0, (1 << 31) - 1)
        _require_int(self.max_precision, "max_precision", 1, self.plain_modulus - 1)
        _require_int(self.prior_precision, "prior_precision", 1, self.plain_modulus - 1)
        if type(self.prior_mean) is not int:
            raise ValueError("prior_mean must be an integer")
        if 2 * self.max_numerator_abs >= self.plain_modulus:
            raise ValueError("Weighted numerator could wrap in the BFV plaintext modulus")
        if 2 * self.max_total_precision >= self.plain_modulus:
            raise ValueError("Total precision could wrap in the signed BFV plaintext range")

    @property
    def max_numerator_abs(self) -> int:
        return (self.prior_precision * abs(self.prior_mean)
                + self.max_nodes * self.max_precision * self.max_abs_reading)

    @property
    def max_total_precision(self) -> int:
        return self.prior_precision + self.max_nodes * self.max_precision

    @property
    def sensitive_payload_bytes(self) -> int:
        return 2 + 4 * self.slots

    @property
    def sensitive_frame_bytes(self) -> int:
        return (MARKER_PREFIX_BYTES + MARKER_NONCE_BYTES
                + self.sensitive_payload_bytes + MARKER_TAG_BYTES)


@dataclass(frozen=True)
class NodePolicy:
    alpha: int
    precision: int = 1

    def __post_init__(self) -> None:
        _require_int(self.alpha, "alpha", 0, 1)
        if type(self.precision) is not int or self.precision < 1:
            raise ValueError("precision must be a positive calibrated integer")

    @property
    def beta(self) -> int:
        """beta=1 enables the sensitive-path marker; beta=0 disables it."""
        return self.alpha


def _validate_policy(policy: NodePolicy, config: ProtocolConfig) -> None:
    if not isinstance(policy, NodePolicy):
        raise TypeError("Expected NodePolicy")
    if policy.precision > config.max_precision:
        raise ValueError("Policy precision exceeds the configured bound")


def bfv_context_id(public_context_bytes: bytes) -> str:
    if not isinstance(public_context_bytes, bytes) or not public_context_bytes:
        raise ValueError("Expected serialized BFV public context")
    return hashlib.sha256(b"LA-IoT/BAYES/v1/BFV-context\x00" + public_context_bytes).hexdigest()


def lattice_key_id(public_key: lattice.PublicKey) -> str:
    p = public_key.params
    encoded = _canonical_json({
        "n": p.n, "q": p.q, "eta": p.eta, "d_u": p.d_u, "d_v": p.d_v,
        "a": list(public_key.a), "b": list(public_key.b),
    })
    return hashlib.sha256(b"LA-IoT/BAYES/v1/lattice-key\x00" + encoded).hexdigest()


def generate_bfv_contexts(config: ProtocolConfig | None = None) -> tuple[bytes, Any]:
    """Explicit setup: return public bytes and a separate secret context.

    Give the first value to devices and controller. Keep the second value
    exclusively with AuthorizedDecryptor. All devices and the controller
    use these same public bytes and ProtocolConfig.
    """
    cfg = ProtocolConfig() if config is None else config
    ts = _tenseal()
    secret_context = ts.context(ts.SCHEME_TYPE.BFV,
                                poly_modulus_degree=cfg.poly_modulus_degree,
                                plain_modulus=cfg.plain_modulus)
    public_bytes = secret_context.serialize(
        save_public_key=True, save_secret_key=False,
        save_galois_keys=False, save_relin_keys=False,
    )
    return public_bytes, secret_context


def _public_context(serialized: bytes) -> Any:
    context = _tenseal().context_from(serialized)
    if context.is_private():
        raise ValueError("A device/controller context must not contain the BFV secret key")
    return context


def _readings(values: Sequence[int], config: ProtocolConfig) -> tuple[int, ...]:
    readings = tuple(values)
    if len(readings) != config.slots:
        raise ValueError("A report must contain exactly four readings")
    for value in readings:
        _require_int(value, "reading", -config.max_abs_reading, config.max_abs_reading)
    return readings


def _pack_readings(readings: tuple[int, ...], config: ProtocolConfig) -> bytes:
    return struct.pack(">H" + "i" * config.slots, config.slots, *readings)


def _unpack_readings(payload: bytes, config: ProtocolConfig) -> tuple[int, ...]:
    if len(payload) != config.sensitive_payload_bytes:
        raise ValueError("Sensitive reading payload length mismatch")
    unpacked = struct.unpack(">H" + "i" * config.slots, payload)
    if unpacked[0] != config.slots:
        raise ValueError("Sensitive slot count mismatch")
    return _readings(unpacked[1:], config)


def _statistics(readings: Sequence[int], precision: int) -> list[int]:
    return [precision * value for value in readings] + [precision]


@dataclass(frozen=True)
class Packet:
    metadata: Mapping[str, Any]
    body: bytes
    source_mac: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, Mapping):
            raise TypeError("Packet metadata must be a mapping")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        if not isinstance(self.body, bytes) or not 0 < len(self.body) <= MAX_RAW_BYTES:
            raise ValueError("Packet body length is out of bounds")
        if not isinstance(self.source_mac, bytes) or len(self.source_mac) != TAG_BYTES:
            raise ValueError("Invalid source-MAC length")

    def to_bytes(self) -> bytes:
        encoded = _canonical_json({
            "metadata": dict(self.metadata),
            "body": base64.b64encode(self.body).decode("ascii"),
            "source_mac": base64.b64encode(self.source_mac).decode("ascii"),
        })
        if len(encoded) > MAX_PACKET_BYTES:
            raise ValueError("Serialized packet is too large")
        return encoded

    @classmethod
    def from_bytes(cls, encoded: bytes) -> Packet:
        if not isinstance(encoded, bytes) or not 0 < len(encoded) <= MAX_PACKET_BYTES:
            raise ValueError("Serialized packet length is out of bounds")
        value = json.loads(encoded.decode("utf-8"), object_pairs_hook=_no_duplicate_pairs)
        if (not isinstance(value, dict)
                or set(value) != {"metadata", "body", "source_mac"}
                or not isinstance(value["metadata"], dict)
                or not isinstance(value["body"], str)
                or not isinstance(value["source_mac"], str)):
            raise ValueError("Invalid packet structure")
        return cls(value["metadata"], base64.b64decode(value["body"], validate=True),
                   base64.b64decode(value["source_mac"], validate=True))


class DeviceClient:
    def __init__(self, config: ProtocolConfig, node_id: str, policy: NodePolicy,
                 psk: bytes, bfv_public_context: bytes,
                 lattice_public_key: lattice.PublicKey) -> None:
        self.config = config
        self.node_id = _identifier(node_id, "node_id")
        _validate_policy(policy, config)
        self.policy = policy
        self._psk = _psk(psk)
        self.context_id = bfv_context_id(bfv_public_context)
        # Sensitive devices only bind the target BFV context fingerprint;
        # their encryption path does not load or operate the BFV backend.
        self._bfv_context = (_public_context(bfv_public_context)
                             if policy.alpha == 0 else None)
        self._lattice_public_key = lattice_public_key
        self.lattice_key_id = lattice_key_id(lattice_public_key)
        if config.sensitive_frame_bytes * 8 > lattice_public_key.params.n:
            raise ValueError("Sensitive marker frame exceeds one Ring-LWE message")

    def make_report(self, readings: Sequence[int], round_id: str, seq: int) -> Packet:
        values = _readings(readings, self.config)
        round_id = _identifier(round_id, "round_id")
        _require_int(seq, "seq", 0, (1 << 63) - 1)
        sensitive = self.policy.alpha == 1
        header: dict[str, Any] = {
            "version": VERSION, "node": self.node_id, "round": round_id,
            "seq": seq, "alpha": self.policy.alpha, "beta": self.policy.beta,
            "slots": self.config.slots, "precision": self.policy.precision,
            "context_id": self.context_id,
            "lattice_key_id": self.lattice_key_id if sensitive else "",
            "frame_len": self.config.sensitive_frame_bytes if sensitive else 0,
        }
        if sensitive:
            payload = _pack_readings(values, self.config)
            frame = _embed_marker(payload, self._psk, header)
            message = lattice.bytes_to_message(frame, self._lattice_public_key.params)
            raw = lattice.encrypt(self._lattice_public_key, message).to_bytes()
        else:
            stats = _statistics(values, self.policy.precision)
            raw = _tenseal().bfv_vector(self._bfv_context, stats).serialize()
        codec, body = adaptive_compress(raw)
        header.update(codec=codec, raw_len=len(raw))
        return Packet(header, body, _source_tag(self._psk, header, body))


@dataclass(frozen=True)
class EncryptedPosterior:
    round_id: str
    context_id: str
    serialized_stats: bytes
    participants: tuple[str, ...]
    expected_total_precision: int


@dataclass(frozen=True)
class Posterior:
    means: tuple[Fraction, ...]
    variance: Fraction
    total_precision: int
    participants: tuple[str, ...]


class TrustedController:
    """One round, sequential receive calls, and one report per authorized node.

    Sensitive plaintexts are intentionally visible here. No BFV secret key is
    accepted. Call receive sequentially; this reference is not a concurrent
    network server. Persist accepted node/round state before acknowledging
    network delivery in a deployment.
    """

    def __init__(self, config: ProtocolConfig, round_id: str,
                 policies: Mapping[str, NodePolicy], psks: Mapping[str, bytes],
                 bfv_public_context: bytes, lattice_secret_key: lattice.SecretKey,
                 expected_lattice_key_id: str) -> None:
        self.config = config
        self.round_id = _identifier(round_id, "round_id")
        self._policies = dict(policies)
        if not self._policies or len(self._policies) > config.max_nodes:
            raise ValueError("Authorized-node count is out of bounds")
        if set(psks) != set(self._policies):
            raise ValueError("PSK registry must exactly match the policy registry")
        self._psks = {node: _psk(value) for node, value in psks.items()}
        for node, policy in self._policies.items():
            _identifier(node, "node_id")
            _validate_policy(policy, config)
        self._bfv_context = _public_context(bfv_public_context)
        self.context_id = bfv_context_id(bfv_public_context)
        self._lattice_secret_key = lattice_secret_key
        if (not isinstance(expected_lattice_key_id, str)
                or len(expected_lattice_key_id) != 64
                or any(ch not in "0123456789abcdef" for ch in expected_lattice_key_id)):
            raise ValueError("Expected a trusted Ring-LWE public-key fingerprint")
        self._lattice_key_id = expected_lattice_key_id
        if config.sensitive_frame_bytes * 8 > lattice_secret_key.params.n:
            raise ValueError("Sensitive marker frame exceeds one Ring-LWE message")
        self._seen: set[str] = set()
        self._aggregate: Any | None = None
        self._accepted_precision = 0
        self._finalized = False

    def _validate_header(self, header: Mapping[str, Any]) -> tuple[str, NodePolicy]:
        if set(header) != HEADER_KEYS:
            raise ValueError("Unexpected or missing metadata fields")
        _require_int(header["version"], "version", VERSION, VERSION)
        node = _identifier(header["node"], "node_id")
        if node not in self._policies:
            raise ValueError("Unauthorized node")
        policy = self._policies[node]
        if header["round"] != self.round_id:
            raise ValueError("Report belongs to a different round")
        _require_int(header["seq"], "seq", 0, (1 << 63) - 1)
        _require_int(header["alpha"], "alpha", policy.alpha, policy.alpha)
        _require_int(header["beta"], "beta", policy.beta, policy.beta)
        _require_int(header["slots"], "slots", self.config.slots, self.config.slots)
        _require_int(header["precision"], "precision", policy.precision, policy.precision)
        if header["context_id"] != self.context_id:
            raise ValueError("BFV context mismatch")
        expected_key = self._lattice_key_id if policy.alpha else ""
        if header["lattice_key_id"] != expected_key:
            raise ValueError("Ring-LWE key fingerprint mismatch")
        expected_frame_len = self.config.sensitive_frame_bytes if policy.alpha else 0
        _require_int(header["frame_len"], "frame_len", expected_frame_len, expected_frame_len)
        if header["codec"] not in ("identity", "zlib"):
            raise ValueError("Unsupported compression codec")
        _require_int(header["raw_len"], "raw_len", 1, MAX_RAW_BYTES)
        return node, policy

    def receive(self, packet: Packet | bytes) -> None:
        if self._finalized:
            raise ValueError("This round has already been finalized")
        if isinstance(packet, bytes):
            packet = Packet.from_bytes(packet)
        if not isinstance(packet, Packet):
            raise TypeError("Expected Packet or serialized packet bytes")
        node, policy = self._validate_header(packet.metadata)
        expected_mac = _source_tag(self._psks[node], packet.metadata, packet.body)
        if not hmac.compare_digest(packet.source_mac, expected_mac):
            raise ValueError("Source authentication failed")
        if node in self._seen:
            raise ValueError("A node may contribute only once in this round")
        if len(self._seen) >= self.config.max_nodes:
            raise ValueError("Round is full")
        raw = _decompress(packet.metadata["codec"], packet.body, packet.metadata["raw_len"])
        ts = _tenseal()
        if policy.alpha:
            ciphertext = lattice.Ciphertext.from_bytes(self._lattice_secret_key.params, raw)
            padded = lattice.message_to_bytes(lattice.decrypt(self._lattice_secret_key, ciphertext))
            frame_len = packet.metadata["frame_len"]
            if any(padded[frame_len:]):
                raise ValueError("Nonzero Ring-LWE message padding")
            payload = _remove_marker(padded[:frame_len], self._psks[node], packet.metadata)
            values = _unpack_readings(payload, self.config)
            contribution = ts.bfv_vector(self._bfv_context, _statistics(values, policy.precision))
        else:
            contribution = ts.bfv_vector_from(self._bfv_context, raw)
        if contribution.size() != self.config.slots + 1:
            raise ValueError("BFV sufficient-statistics length mismatch")
        # Complete parsing, verification and BFV addition before accepting.
        candidate = contribution if self._aggregate is None else self._aggregate + contribution
        self._aggregate = candidate
        self._accepted_precision += policy.precision
        self._seen.add(node)

    def finalize(self, require_all: bool = True) -> EncryptedPosterior:
        """Add the prior once. Partial rounds require an explicit opt-in."""
        if self._finalized:
            raise ValueError("This round has already been finalized")
        if type(require_all) is not bool:
            raise TypeError("require_all must be bool")
        if require_all and self._seen != set(self._policies):
            raise ValueError("Missing reports; use require_all=False to accept a partial round")
        prior = ([self.config.prior_precision * self.config.prior_mean] * self.config.slots
                 + [self.config.prior_precision])
        encrypted_prior = _tenseal().bfv_vector(self._bfv_context, prior)
        result = encrypted_prior if self._aggregate is None else self._aggregate + encrypted_prior
        serialized = result.serialize()
        output = EncryptedPosterior(
            self.round_id, self.context_id, serialized, tuple(sorted(self._seen)),
            self.config.prior_precision + self._accepted_precision,
        )
        self._finalized = True
        return output


class AuthorizedDecryptor:
    """Keep this secret-context holder separate from TrustedController."""

    def __init__(self, config: ProtocolConfig, bfv_secret_context: Any,
                 expected_context_id: str) -> None:
        if not bfv_secret_context.is_private():
            raise ValueError("AuthorizedDecryptor requires the BFV secret context")
        self.config = config
        self._secret_context = bfv_secret_context
        self.context_id = expected_context_id

    def decrypt_posterior(self, encrypted: EncryptedPosterior) -> Posterior:
        if not isinstance(encrypted, EncryptedPosterior):
            raise TypeError("Expected EncryptedPosterior from the trusted controller")
        if encrypted.context_id != self.context_id:
            raise ValueError("Posterior context mismatch")
        if (len(encrypted.participants) > self.config.max_nodes
                or len(set(encrypted.participants)) != len(encrypted.participants)):
            raise ValueError("Invalid posterior participant list")
        vector = _tenseal().bfv_vector_from(self._secret_context, encrypted.serialized_stats)
        if vector.size() != self.config.slots + 1:
            raise ValueError("Posterior sufficient-statistics length mismatch")
        stats = vector.decrypt()
        if len(stats) != self.config.slots + 1 or any(type(value) is not int for value in stats):
            raise ValueError("Unexpected BFV plaintext representation")
        total_precision = stats[-1]
        _require_int(total_precision, "posterior precision", self.config.prior_precision,
                     self.config.max_total_precision)
        if total_precision != encrypted.expected_total_precision:
            raise ValueError("Encrypted precision differs from the accepted-node policy total")
        bound = (self.config.prior_precision * abs(self.config.prior_mean)
                 + len(encrypted.participants) * self.config.max_precision
                 * self.config.max_abs_reading)
        if any(abs(value) > bound for value in stats[:-1]):
            raise ValueError("Posterior numerator exceeds the declared honest-input bound")
        return Posterior(
            tuple(Fraction(value, total_precision) for value in stats[:-1]),
            Fraction(1, total_precision), total_precision, encrypted.participants,
        )


# No example, installation, key generation, encryption or test is run here.
