# SPDX-License-Identifier: Apache-2.0
# Packaged implementation; migrated from IoT Application on 2026-10-14.
"""LA-IoT sensitive reports using ML-KEM-768, HKDF, and AES-256-GCM.

Evaluation-bundle revision: HKDF-SHA-256 is shared with the KEM comparison.
Version 5 binds calibration and encoding settings through an authenticated
configuration fingerprint. Older chapter examples retain their original format.

Python 3.10+, cryptography>=47, and the existing TenSEAL dependency. Keep
la_iot_bayesian.py and its companion la_iot_ring_lwe.py beside this module.
Those unchanged modules supply the common framing, source MAC, BFV statistics,
and posterior interfaces. Their custom lattice encryption is never called by
this module. ML-KEM's standardized internal encoding and compression belong
entirely to cryptography; this module does not change coefficient parameters.

Generated and reviewed as text only: no Python was run, imported, compiled,
parsed with an AST, or tested; no dependency was installed or key generated.
Imports do not generate keys or open persistent state. Crypto dependencies
are loaded only by explicitly invoked setup or protocol operations.

The sensitive encryption claim is conditional post-quantum IND-CCA security
for equal-length encoded sensitive units, assuming the KEM and authenticated
encryption security in the classical-oracle post-quantum model. It is not a
security claim for BFV, a numerical post-quantum security estimate, or a proof
of the whole application. The controller intentionally sees sensitive data.
The security wrapper supplies persistent replay control and authenticated
delivery of the final Bayesian result. Provision public keys/fingerprints
over a trusted channel. Parameter inspection checks BFV encoding sanity only.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from contextlib import contextmanager
from time import perf_counter_ns
from typing import Any, Callable, Iterator, Mapping, Sequence

from . import la_iot_bayesian as core


VERSION = 5
SUITE = "ML-KEM-768+HKDF-SHA-256+AES-256-GCM"
MLKEM_PUBLIC_BYTES = 1184
MLKEM_SEED_BYTES = 64
MLKEM_CIPHERTEXT_BYTES = 1088
SHARED_SECRET_BYTES = 32
AEAD_NONCE_BYTES = 12
AEAD_TAG_BYTES = 16
ENVELOPE_PREFIX = b"LA-IoT/CCA/v5\x00ML-KEM-768+HKDF-SHA-256+AES-256-GCM\x00"
AAD_DOMAIN = b"LA-IoT/CCA/v5/ML-KEM-768+HKDF-SHA-256+AES-256-GCM/aad\x00"
KEY_ID_DOMAIN = b"LA-IoT/CCA/v5/ML-KEM-768+HKDF-SHA-256+AES-256-GCM/public-key\x00"
KDF_DOMAIN = b"LA-IoT/KEM-AEAD/v1\x00"
REJECTION_MESSAGE = "Report rejected"

# Preserve the types and helpers used by the existing security wrapper.
ProtocolConfig = core.ProtocolConfig
NodePolicy = core.NodePolicy
Packet = core.Packet
EncryptedPosterior = core.EncryptedPosterior
Posterior = core.Posterior
HEADER_KEYS = core.HEADER_KEYS
MAX_RAW_BYTES = core.MAX_RAW_BYTES
MAX_PACKET_BYTES = core.MAX_PACKET_BYTES
_identifier = core._identifier
_no_duplicate_pairs = core._no_duplicate_pairs
_source_tag = core._source_tag
_public_context = core._public_context
_tenseal = core._tenseal
_decompress = core._decompress
bfv_context_id = core.bfv_context_id
adaptive_compress = core.adaptive_compress


class PacketRejected(ValueError):
    """One public failure response for malformed or rejected received reports."""

    def __init__(self) -> None:
        super().__init__(REJECTION_MESSAGE)


def _crypto() -> tuple[Any, Any, Any, Any, Any]:
    """Load official cryptography APIs only when explicitly needed."""
    try:
        from cryptography.hazmat.primitives.asymmetric.mlkem import (
            MLKEM768PrivateKey,
            MLKEM768PublicKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError as exc:
        raise ImportError("ML-KEM-768 reports require cryptography>=47") from exc
    return MLKEM768PrivateKey, MLKEM768PublicKey, AESGCM, Encoding, PublicFormat


def _config(config: ProtocolConfig) -> ProtocolConfig:
    if not isinstance(config, ProtocolConfig):
        raise TypeError("Expected ProtocolConfig")
    return config


def _fingerprint(value: Any) -> str:
    if (not isinstance(value, str) or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)):
        raise ValueError("Expected a trusted ML-KEM-768 public-key fingerprint")
    return value


def _public_bytes(public_key: Any) -> bytes:
    _, PublicKey, _, Encoding, PublicFormat = _crypto()
    if not isinstance(public_key, PublicKey):
        raise TypeError("Expected MLKEM768PublicKey")
    encoded = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    if not isinstance(encoded, bytes) or len(encoded) != MLKEM_PUBLIC_BYTES:
        raise ValueError("Invalid ML-KEM-768 public-key serialization")
    return encoded


def lattice_key_id(public_key_bytes: bytes) -> str:
    """Fingerprint an authenticated, raw ML-KEM-768 public key for this suite."""
    if (not isinstance(public_key_bytes, bytes)
            or len(public_key_bytes) != MLKEM_PUBLIC_BYTES):
        raise ValueError("An ML-KEM-768 public key must contain 1184 raw bytes")
    # Metadata retains the historical field name lattice_key_id for wrappers.
    return hashlib.sha256(KEY_ID_DOMAIN + public_key_bytes).hexdigest()


def generate_lattice_keys() -> tuple[bytes, Any]:
    """Explicit setup only: return (raw_public_key_bytes, private_key_object).

    Authenticate the public bytes before provisioning devices. Keep the
    private object with the trusted controller. A separately provisioned
    64-byte seed is also accepted by TrustedController; it is never a public
    key and must be protected as private key material. No keys are generated
    by importing this module or constructing a client/controller.
    """
    PrivateKey, _, _, _, _ = _crypto()
    private_key = PrivateKey.generate()
    return _public_bytes(private_key.public_key()), private_key


def _private_key(value: Any) -> Any:
    PrivateKey, _, _, _, _ = _crypto()
    if isinstance(value, bytes):
        if len(value) != MLKEM_SEED_BYTES:
            raise ValueError("An ML-KEM-768 private seed must contain 64 bytes")
        value = PrivateKey.from_seed_bytes(value)
    if not isinstance(value, PrivateKey):
        raise TypeError("Expected MLKEM768PrivateKey or its 64-byte private seed")
    return value


def _validate_bfv_parameters(context: Any, config: ProtocolConfig) -> None:
    """Check actual scheme, degree, and odd batching modulus against config.

    With batching enabled the actual plaintext modulus is odd. Its SEAL
    plain_upper_half_threshold is (t+1)//2, so equality identifies that modulus
    exactly when the configured modulus is also odd. These are encoding
    checks, not a numerical lattice-security assessment or a CCA guarantee.
    """
    _config(config)
    if config.plain_modulus % 2 != 1:
        raise ValueError("BFV configuration requires an odd plaintext modulus")
    try:
        native = context.seal_context().data
        if not native.parameters_set():
            raise ValueError("Invalid BFV encryption parameters")
        data = native.first_context_data()
        parameters = data.parms()
        if (parameters.scheme() != _tenseal().SCHEME_TYPE.BFV.value
                or parameters.poly_modulus_degree() != config.poly_modulus_degree
                or not data.qualifiers().using_batching
                or data.plain_upper_half_threshold() != (config.plain_modulus + 1) // 2):
            raise ValueError("BFV parameters differ from the configured integer bounds")
    except (AttributeError, TypeError) as exc:
        raise ValueError("Cannot inspect BFV parameters with this TenSEAL API") from exc


def generate_bfv_contexts(config: ProtocolConfig | None = None) -> tuple[bytes, Any]:
    """Explicit BFV setup; retain the unchanged core's public/secret interface."""
    cfg = ProtocolConfig() if config is None else _config(config)
    public_bytes, secret_context = core.generate_bfv_contexts(cfg)
    _validate_bfv_parameters(secret_context, cfg)
    return public_bytes, secret_context


def _sensitive_raw_bytes(config: ProtocolConfig) -> int:
    return (len(ENVELOPE_PREFIX) + MLKEM_CIPHERTEXT_BYTES + AEAD_NONCE_BYTES
            + config.sensitive_frame_bytes + AEAD_TAG_BYTES)


def _aad(header: Mapping[str, Any], kem_ciphertext: bytes) -> bytes:
    """Domain-separated, length-delimited canonical metadata and KEM binding."""
    binding = core._canonical_json({key: header[key] for key in core.MARKER_BINDING_KEYS})
    return (AAD_DOMAIN + len(binding).to_bytes(4, "big") + binding
            + len(kem_ciphertext).to_bytes(4, "big") + kem_ciphertext)


def _watermark_header(header: Mapping[str, Any], frame_length: int) -> None:
    """Check the sensitive-unit fields shared by WC and authenticated recovery."""
    if not isinstance(header, Mapping):
        raise TypeError("Expected sensitive packet metadata")
    core._require_int(header["version"], "version", VERSION, VERSION)
    core._require_int(header["alpha"], "alpha", 1, 1)
    core._require_int(header["beta"], "beta", 1, 1)
    core._require_int(header["frame_len"], "frame_len", frame_length, frame_length)
    # Canonical, length-delimited metadata is covered by the inner MAC.
    core._marker_binding(header)


def watermark_compress(payload: bytes, device_secret: bytes,
                       header: Mapping[str, Any]) -> bytes:
    """WC: jointly compress, pad, and authenticate original reading bytes.

    The shared helper derives a watermark-only key from device_secret.
    It stores codec/lengths and an independent random 16-byte value, and
    authenticates all stored bytes and metadata using truncated HMAC-SHA-256.
    AES-GCM encryption is subsequently applied by DeviceClient.make_report.
    """
    overhead = (core.MARKER_PREFIX_BYTES + core.MARKER_NONCE_BYTES
                + core.MARKER_TAG_BYTES)
    if (not isinstance(payload, bytes)
            or not 0 < len(payload) <= MAX_RAW_BYTES - overhead):
        raise ValueError("Invalid original reading bytes")
    expected_length = overhead + len(payload)
    _watermark_header(header, expected_length)
    return core._embed_marker(payload, core._psk(device_secret), header)


def watermark_restore(frame: bytes, device_secret: bytes,
                      header: Mapping[str, Any]) -> bytes:
    """Restore WC after successful AES-GCM verification; release no partial data.

    This operation is used only on the authenticated frame returned by
    _open_sensitive. The inner MAC is checked before lengths/padding are
    interpreted and before the original data is decompressed. All receive
    failures expose the same public exception. This is not a timing claim.
    """
    try:
        if not isinstance(frame, bytes) or not 0 < len(frame) <= MAX_RAW_BYTES:
            raise ValueError("Invalid authenticated watermark frame")
        _watermark_header(header, len(frame))
        return core._remove_marker(frame, core._psk(device_secret), header)
    except Exception:
        raise PacketRejected() from None


def _aead_key(shared_key: bytes) -> bytes:
    """Use the same key derivation as the five-KEM component comparison."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=KDF_DOMAIN + b"ML-KEM-768\x00aead").derive(shared_key)


def _seal_sensitive(frame: bytes, header: Mapping[str, Any], public_key: Any) -> bytes:
    _, _, AESGCM, _, _ = _crypto()
    if len(frame) != header["frame_len"]:
        raise ValueError("Sensitive frame length mismatch")
    # One fresh encapsulation and independent 96-bit AEAD nonce per report.
    shared_key, kem_ciphertext = public_key.encapsulate()
    if (not isinstance(shared_key, bytes) or len(shared_key) != SHARED_SECRET_BYTES
            or not isinstance(kem_ciphertext, bytes)
            or len(kem_ciphertext) != MLKEM_CIPHERTEXT_BYTES):
        raise ValueError("Unexpected ML-KEM-768 encapsulation output")
    nonce = secrets.token_bytes(AEAD_NONCE_BYTES)
    ciphertext = AESGCM(_aead_key(shared_key)).encrypt(nonce, frame, _aad(header, kem_ciphertext))
    if len(ciphertext) != len(frame) + AEAD_TAG_BYTES:
        raise ValueError("Unexpected AES-GCM ciphertext length")
    return ENVELOPE_PREFIX + kem_ciphertext + nonce + ciphertext


def _open_sensitive(raw: bytes, header: Mapping[str, Any], private_key: Any,
                    config: ProtocolConfig) -> bytes:
    """Decapsulate and verify AEAD before any watermark restoration occurs."""
    if len(raw) != _sensitive_raw_bytes(config) or not raw.startswith(ENVELOPE_PREFIX):
        raise ValueError("Invalid sensitive envelope")
    kem_start = len(ENVELOPE_PREFIX)
    nonce_start = kem_start + MLKEM_CIPHERTEXT_BYTES
    ciphertext_start = nonce_start + AEAD_NONCE_BYTES
    kem_ciphertext = raw[kem_start:nonce_start]
    nonce = raw[nonce_start:ciphertext_start]
    ciphertext = raw[ciphertext_start:]
    _, _, AESGCM, _, _ = _crypto()
    shared_key = private_key.decapsulate(kem_ciphertext)
    if not isinstance(shared_key, bytes) or len(shared_key) != SHARED_SECRET_BYTES:
        raise ValueError("Unexpected ML-KEM-768 decapsulation output")
    # InvalidTag and decapsulation/parsing failures share the public receive
    # response. ML-KEM implicit rejection is followed by the same GCM check.
    frame = AESGCM(_aead_key(shared_key)).decrypt(nonce, ciphertext, _aad(header, kem_ciphertext))
    if len(frame) != config.sensitive_frame_bytes:
        raise ValueError("Sensitive frame length mismatch")
    return frame


class DeviceClient:
    """Create the existing source packet format with a replaced sensitive path."""

    def __init__(self, config: ProtocolConfig, node_id: str, policy: NodePolicy,
                 psk: bytes, bfv_public_context: bytes,
                 lattice_public_key: bytes) -> None:
        self.config = _config(config)
        self.node_id = _identifier(node_id, "node_id")
        core._validate_policy(policy, config)
        self.policy = policy
        self._psk = core._psk(psk)
        self.context_id = bfv_context_id(bfv_public_context)
        self.lattice_key_id = lattice_key_id(lattice_public_key)
        _, PublicKey, _, _, _ = _crypto()
        self._lattice_public_key = PublicKey.from_public_bytes(lattice_public_key)
        # Sensitive devices bind the BFV context identity but perform no BFV
        # arithmetic. Inspect parameters whenever a BFV context is actually used.
        self._bfv_context = None
        if policy.alpha == 0:
            self._bfv_context = _public_context(bfv_public_context)
            _validate_bfv_parameters(self._bfv_context, config)

    def make_report(self, readings: Sequence[int], round_id: str, seq: int) -> Packet:
        values = core._readings(readings, self.config)
        round_id = _identifier(round_id, "round_id")
        core._require_int(seq, "seq", 0, (1 << 63) - 1)
        sensitive = self.policy.alpha == 1
        header: dict[str, Any] = {
            "version": VERSION, "node": self.node_id, "round": round_id,
            "seq": seq, "alpha": self.policy.alpha, "beta": self.policy.beta,
            "slots": self.config.slots, "precision": self.policy.precision,
            "context_id": self.context_id,
            "lattice_key_id": self.lattice_key_id if sensitive else "",
            "frame_len": self.config.sensitive_frame_bytes if sensitive else 0,
            "config_id": self.config.config_id,
        }
        if sensitive:
            payload = core._pack_readings(values, self.config)
            # WC's independently sampled 16-byte watermark nonce is authenticated
            # inside the encrypted frame; it is distinct from the GCM nonce.
            frame = watermark_compress(payload, self._psk, header)
            raw = _seal_sensitive(frame, header, self._lattice_public_key)
        else:
            stats = core._statistics(values, self.policy.precision)
            raw = _tenseal().bfv_vector(self._bfv_context, stats).serialize()
        codec, body = adaptive_compress(raw)
        header.update(codec=codec, raw_len=len(raw))
        return Packet(header, body, _source_tag(self._psk, header, body))


class TrustedController(core.TrustedController):
    """Reuse Bayesian finalization, replacing sensitive ciphertext processing.

    Call receive sequentially. This object's in-memory duplicate check is not
    persistent replay protection; use the accompanying persistent wrapper.
    Every receive/header failure exposes the same exception and message. This
    is an error-interface guarantee, not a constant-time network-server claim.
    """

    def __init__(self, config: ProtocolConfig, round_id: str,
                 policies: Mapping[str, NodePolicy], psks: Mapping[str, bytes],
                 bfv_public_context: bytes, lattice_secret_key: Any,
                 expected_lattice_key_id: str,
                 observer: Callable[..., None] | None = None) -> None:
        # Do not call the old constructor: its key and message-size checks
        # apply to a different lattice encryption construction.
        self.config = _config(config)
        self._observer = observer
        self.round_id = _identifier(round_id, "round_id")
        self._policies = dict(policies)
        if not self._policies or len(self._policies) > config.max_nodes:
            raise ValueError("Authorized-node count is out of bounds")
        if set(psks) != set(self._policies):
            raise ValueError("PSK registry must exactly match the policy registry")
        self._psks = {node: core._psk(value) for node, value in psks.items()}
        for node, policy in self._policies.items():
            _identifier(node, "node_id")
            core._validate_policy(policy, config)
        self._lattice_secret_key = _private_key(lattice_secret_key)
        self._lattice_key_id = _fingerprint(expected_lattice_key_id)
        actual_key_id = lattice_key_id(_public_bytes(self._lattice_secret_key.public_key()))
        if not hmac.compare_digest(self._lattice_key_id, actual_key_id):
            raise ValueError("ML-KEM private key does not match the provisioned public-key fingerprint")
        self._bfv_context = _public_context(bfv_public_context)
        _validate_bfv_parameters(self._bfv_context, config)
        self.context_id = bfv_context_id(bfv_public_context)
        self._seen: set[str] = set()
        self._aggregate: Any | None = None
        self._accepted_precision = 0
        self._finalized = False

    @contextmanager
    def _measure(self, stage: str, node_id: str = "") -> Iterator[None]:
        """Observe one nonoverlapping operation, including failed attempts."""
        start = perf_counter_ns()
        try:
            yield
        finally:
            if self._observer is not None:
                self._observer(stage, (perf_counter_ns() - start) / 1_000_000,
                               node_id=node_id, round_id=self.round_id)

    def _validate_header(self, header: Mapping[str, Any]) -> tuple[str, NodePolicy]:
        # The persistent wrapper also uses this entry point during admission.
        try:
            return self._checked_header(header)
        except Exception:
            raise PacketRejected() from None

    def _checked_header(self, header: Mapping[str, Any]) -> tuple[str, NodePolicy]:
        if not isinstance(header, Mapping) or set(header) != HEADER_KEYS:
            raise ValueError("Unexpected or missing metadata fields")
        core._require_int(header["version"], "version", VERSION, VERSION)
        node = _identifier(header["node"], "node_id")
        if node not in self._policies:
            raise ValueError("Unauthorized node")
        policy = self._policies[node]
        if header["round"] != self.round_id:
            raise ValueError("Report belongs to a different round")
        core._require_int(header["seq"], "seq", 0, (1 << 63) - 1)
        core._require_int(header["alpha"], "alpha", policy.alpha, policy.alpha)
        core._require_int(header["beta"], "beta", policy.beta, policy.beta)
        core._require_int(header["slots"], "slots", self.config.slots, self.config.slots)
        core._require_int(header["precision"], "precision", policy.precision, policy.precision)
        if header["context_id"] != self.context_id:
            raise ValueError("BFV context mismatch")
        if header["config_id"] != self.config.config_id:
            raise ValueError("Authenticated calibration or encoding configuration mismatch")
        expected_key = self._lattice_key_id if policy.alpha else ""
        if header["lattice_key_id"] != expected_key:
            raise ValueError("ML-KEM public-key fingerprint mismatch")
        expected_frame_len = self.config.sensitive_frame_bytes if policy.alpha else 0
        core._require_int(header["frame_len"], "frame_len", expected_frame_len, expected_frame_len)
        if header["codec"] not in ("identity", "zlib"):
            raise ValueError("Unsupported compression codec")
        core._require_int(header["raw_len"], "raw_len", 1, MAX_RAW_BYTES)
        if policy.alpha and header["raw_len"] != _sensitive_raw_bytes(self.config):
            raise ValueError("Sensitive envelope length mismatch")
        return node, policy

    def receive(self, packet: Packet | bytes) -> None:
        """Accept only after MAC, bounded unpacking, AEAD, WC, and BFV checks."""
        try:
            self._receive(packet)
        except Exception:
            # No parser, decapsulation, InvalidTag, or watermark failure detail
            # is propagated through the received-packet interface.
            raise PacketRejected() from None

    def _receive(self, packet: Packet | bytes) -> None:
        if self._finalized:
            raise ValueError("This round has already been finalized")
        if isinstance(packet, bytes):
            encoded = packet
            packet = Packet.from_bytes(encoded)
            if packet.to_bytes() != encoded:
                raise ValueError("Source packet serialization must be canonical")
        if not isinstance(packet, Packet):
            raise TypeError("Expected Packet or serialized packet bytes")
        node, policy = self._validate_header(packet.metadata)
        with self._measure("CONTROLLER_VERIFY", node):
            expected_mac = _source_tag(self._psks[node], packet.metadata, packet.body)
            if not hmac.compare_digest(packet.source_mac, expected_mac):
                raise ValueError("Source authentication failed")
            if node in self._seen or len(self._seen) >= self.config.max_nodes:
                raise ValueError("Duplicate source or full round")
            # Authenticate the complete transmitted packet before outer unpacking.
            raw = _decompress(packet.metadata["codec"], packet.body, packet.metadata["raw_len"])
        if policy.alpha:
            with self._measure("RECOVERY", node):
                frame = _open_sensitive(raw, packet.metadata, self._lattice_secret_key, self.config)
                payload = watermark_restore(frame, self._psks[node], packet.metadata)
                values = core._unpack_readings(payload, self.config)
            with self._measure("BFV_REENCRYPT", node):
                contribution = _tenseal().bfv_vector(
                    self._bfv_context, core._statistics(values, policy.precision))
        else:
            with self._measure("CONTROLLER_VERIFY", node):
                contribution = _tenseal().bfv_vector_from(self._bfv_context, raw)
        with self._measure("RECONSTRUCTION", node):
            if contribution.size() != self.config.slots + 1:
                raise ValueError("BFV sufficient-statistics length mismatch")
            candidate = contribution if self._aggregate is None else self._aggregate + contribution
        # A failed observer must not turn a rejected receive into a counted input.
        self._aggregate = candidate
        self._accepted_precision += policy.precision
        self._seen.add(node)

    def finalize(self, require_all: bool = True) -> EncryptedPosterior:
        previous = self._finalized
        try:
            with self._measure("RECONSTRUCTION"):
                return super().finalize(require_all=require_all)
        except BaseException:
            self._finalized = previous
            raise

    # core.TrustedController.finalize uses exactly the attributes set above;
    # it adds the same prior once and returns the unchanged EncryptedPosterior.


class AuthorizedDecryptor(core.AuthorizedDecryptor):
    """Retain posterior recovery while checking actual BFV encoding parameters."""

    def __init__(self, config: ProtocolConfig, bfv_secret_context: Any,
                 expected_context_id: str) -> None:
        _validate_bfv_parameters(bfv_secret_context, _config(config))
        super().__init__(config, bfv_secret_context, expected_context_id)


# Deliberately no __main__, executable example, installation, or automatic setup.

