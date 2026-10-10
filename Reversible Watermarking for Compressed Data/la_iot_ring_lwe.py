"""Ring-LWE-style binary-polynomial PKE with coefficient compression.

Python 3.10+; standard library only. Generated without execution.

This module implements the custom Ring-LWE construction described in
compression_lattice_encryption.tex: key generation, binary-message encryption,
decryption, coefficient compression and packed serialization. The companion
la_iot_bayesian.py provides packet marking and BFV aggregation.

The ring is Z_q[X]/(X^n + 1); multiplication uses an O(n^2) coefficient loop.
Small coefficients use a centered binomial sampler. Parameter validation
checks a deterministic sufficient bound for correct message recovery.
No test or example was run.

Definitions:
  https://cims.nyu.edu/~regev/papers/ideal-lwe.pdf
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf (Section 4.2.1)
  https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import isqrt
import secrets
from typing import Sequence


Poly = tuple[int, ...]  # Coefficient order: 1, X, ..., X^(n-1).


def _is_prime(value: int) -> bool:
    """Simple parameter check for demonstration-size moduli."""
    if value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    return all(value % divisor != 0
               for divisor in range(3, isqrt(value) + 1, 2))


def _round_div_nonnegative(numerator: int, denominator: int) -> int:
    """Round numerator/denominator to nearest integer, with half ties up."""
    if numerator < 0 or denominator <= 0:
        raise ValueError("Expected a nonnegative numerator and positive divisor")
    return (2 * numerator + denominator) // (2 * denominator)


def quantization_error_bound(q: int, d: int) -> int:
    """Conservative centered integer error for decompress(compress(x))."""
    scale = 1 << d
    return (q + scale) // (2 * scale)


@dataclass(frozen=True)
class Parameters:
    n: int = 512
    q: int = 12289
    eta: int = 1
    d_u: int = 12
    d_v: int = 10

    def __post_init__(self) -> None:
        values = (self.n, self.q, self.eta, self.d_u, self.d_v)
        if any(type(value) is not int for value in values):
            raise TypeError("All parameters must be integers")
        if self.n < 8 or self.n & (self.n - 1):
            raise ValueError("n must be a power of two and at least 8")
        if self.q <= 2 or not _is_prime(self.q):
            raise ValueError("q must be an odd prime")
        if self.eta < 1:
            raise ValueError("eta must be positive")
        if not (1 <= self.d_u <= self.q.bit_length()):
            raise ValueError("d_u must lie between 1 and ceil(log2(q))")
        if not (1 <= self.d_v <= self.q.bit_length()):
            raise ValueError("d_v must lie between 1 and ceil(log2(q))")
        if 2 * self.worst_case_error_bound >= self.delta:
            raise ValueError(
                "Parameters must satisfy the message-recovery condition "
                "2*B < floor(q/2)"
            )

    @property
    def delta(self) -> int:
        return self.q // 2

    @property
    def worst_case_error_bound(self) -> int:
        delta_u = quantization_error_bound(self.q, self.d_u)
        delta_v = quantization_error_bound(self.q, self.d_v)
        return (2 * self.n * self.eta * self.eta + self.eta
                + delta_v + self.n * self.eta * delta_u)

    @property
    def ciphertext_payload_bytes(self) -> int:
        # n is divisible by eight, so each packed component is byte-aligned.
        return self.n * (self.d_u + self.d_v) // 8


def _check_poly(coefficients: Sequence[int], n: int,
                lower: int, upper: int, name: str) -> Poly:
    coefficients = tuple(coefficients)
    if len(coefficients) != n:
        raise ValueError(f"{name} must contain exactly {n} coefficients")
    if any(type(x) is not int or not lower <= x <= upper
           for x in coefficients):
        raise ValueError(f"{name} coefficients must be integers in [{lower}, {upper}]")
    return coefficients


@dataclass(frozen=True)
class PublicKey:
    params: Parameters
    a: Poly
    b: Poly

    def __post_init__(self) -> None:
        p = self.params
        object.__setattr__(self, "a", _check_poly(self.a, p.n, 0, p.q - 1, "a"))
        object.__setattr__(self, "b", _check_poly(self.b, p.n, 0, p.q - 1, "b"))


@dataclass(frozen=True)
class SecretKey:
    params: Parameters
    s: Poly = field(repr=False)

    def __post_init__(self) -> None:
        p = self.params
        object.__setattr__(self, "s", _check_poly(self.s, p.n, -p.eta, p.eta, "s"))


@dataclass(frozen=True)
class Ciphertext:
    params: Parameters
    u_c: Poly
    v_c: Poly

    def __post_init__(self) -> None:
        p = self.params
        object.__setattr__(self, "u_c", _check_poly(
            self.u_c, p.n, 0, (1 << p.d_u) - 1, "u_c"))
        object.__setattr__(self, "v_c", _check_poly(
            self.v_c, p.n, 0, (1 << p.d_v) - 1, "v_c"))

    def to_bytes(self) -> bytes:
        """Bit-packed polynomial payload only; no header, key ID, or tag."""
        return (_pack_coefficients(self.u_c, self.params.d_u)
                + _pack_coefficients(self.v_c, self.params.d_v))

    @classmethod
    def from_bytes(cls, params: Parameters, payload: bytes) -> Ciphertext:
        """Decode a payload using externally agreed parameters."""
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if len(payload) != params.ciphertext_payload_bytes:
            raise ValueError("Unexpected ciphertext payload length")
        split = params.n * params.d_u // 8
        u_c = _unpack_coefficients(payload[:split], params.n, params.d_u)
        v_c = _unpack_coefficients(payload[split:], params.n, params.d_v)
        return cls(params, u_c, v_c)


def _pack_coefficients(coefficients: Sequence[int], bits: int) -> bytes:
    """Pack coefficients consecutively, least-significant bits first."""
    output = bytearray()
    accumulator = 0
    available = 0
    for value in coefficients:
        if not 0 <= value < (1 << bits):
            raise ValueError("Coefficient does not fit the requested bit width")
        accumulator |= value << available
        available += bits
        while available >= 8:
            output.append(accumulator & 0xFF)
            accumulator >>= 8
            available -= 8
    if available:
        output.append(accumulator & 0xFF)
    return bytes(output)


def _unpack_coefficients(payload: bytes, count: int, bits: int) -> Poly:
    if len(payload) != (count * bits + 7) // 8:
        raise ValueError("Unexpected packed polynomial length")
    values = []
    accumulator = 0
    available = 0
    position = 0
    mask = (1 << bits) - 1
    for _ in range(count):
        while available < bits:
            accumulator |= payload[position] << available
            position += 1
            available += 8
        values.append(accumulator & mask)
        accumulator >>= bits
        available -= bits
    if accumulator != 0:
        raise ValueError("Nonzero padding bits")
    return tuple(values)


def poly_mul(left: Sequence[int], right: Sequence[int], q: int) -> Poly:
    """Negacyclic product modulo (X^n + 1, q), using integer arithmetic."""
    if not left or len(left) != len(right):
        raise ValueError("Polynomials must have the same positive length")
    n = len(left)
    result = [0] * n
    for i, x in enumerate(left):
        for j, y in enumerate(right):
            degree = i + j
            if degree < n:
                result[degree] += x * y
            else:
                # X^n = -1; i+j never exceeds 2*n-2.
                result[degree - n] -= x * y
    return tuple(value % q for value in result)


def compress_poly(poly: Sequence[int], q: int, d: int) -> Poly:
    """Round 2^d*x/q and reduce modulo 2^d, coefficient by coefficient."""
    scale = 1 << d
    return tuple(_round_div_nonnegative((x % q) * scale, q) % scale
                 for x in poly)


def decompress_poly(poly: Sequence[int], q: int, d: int) -> Poly:
    """Round q*y/2^d, coefficient by coefficient."""
    scale = 1 << d
    if any(type(y) is not int or not 0 <= y < scale for y in poly):
        raise ValueError("Compressed coefficient out of range")
    return tuple(_round_div_nonnegative(y * q, scale) % q for y in poly)


def _sample_small(params: Parameters) -> Poly:
    """Independent CBD_eta coefficients: Binomial(eta,1/2) minus another."""
    return tuple(secrets.randbits(params.eta).bit_count()
                 - secrets.randbits(params.eta).bit_count()
                 for _ in range(params.n))


def keygen(params: Parameters | None = None) -> tuple[PublicKey, SecretKey]:
    p = Parameters() if params is None else params
    a = tuple(secrets.randbelow(p.q) for _ in range(p.n))
    s = _sample_small(p)
    e = _sample_small(p)
    a_s = poly_mul(a, s, p.q)
    b = tuple((x + y) % p.q for x, y in zip(a_s, e))
    return PublicKey(p, a, b), SecretKey(p, s)


def encrypt(public_key: PublicKey, message: Sequence[int]) -> Ciphertext:
    """Encrypt exactly n binary coefficients with fresh independent noise."""
    p = public_key.params
    m = _check_poly(message, p.n, 0, 1, "message")
    r = _sample_small(p)
    e_1 = _sample_small(p)
    e_2 = _sample_small(p)
    a_r = poly_mul(public_key.a, r, p.q)
    b_r = poly_mul(public_key.b, r, p.q)
    u = tuple((x + noise) % p.q for x, noise in zip(a_r, e_1))
    v = tuple((x + noise + p.delta * bit) % p.q
              for x, noise, bit in zip(b_r, e_2, m))
    return Ciphertext(p, compress_poly(u, p.q, p.d_u),
                      compress_poly(v, p.q, p.d_v))


def _circular_distance(x: int, y: int, q: int) -> int:
    return min((x - y) % q, (y - x) % q)


def decrypt(secret_key: SecretKey, ciphertext: Ciphertext) -> Poly:
    """Binary decoding only; no authenticity or wrong-key detection."""
    p = secret_key.params
    if p != ciphertext.params:
        raise ValueError("Secret-key and ciphertext parameters differ")
    u = decompress_poly(ciphertext.u_c, p.q, p.d_u)
    v = decompress_poly(ciphertext.v_c, p.q, p.d_v)
    s_u = poly_mul(secret_key.s, u, p.q)
    w = tuple((x - y) % p.q for x, y in zip(v, s_u))
    return tuple(0 if _circular_distance(x, 0, p.q)
                 <= _circular_distance(x, p.delta, p.q) else 1 for x in w)


def bytes_to_message(payload: bytes, params: Parameters) -> Poly:
    """Map bytes to little-endian bits and zero-pad to n coefficients.

    The original byte length must be tracked externally. This helper does
    not create an authenticated length or a multi-block encryption protocol.
    """
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if len(payload) * 8 > params.n:
        raise ValueError("Payload exceeds the capacity of one polynomial")
    bits = [(value >> offset) & 1
            for value in payload for offset in range(8)]
    bits.extend([0] * (params.n - len(bits)))
    return tuple(bits)


def message_to_bytes(message: Sequence[int]) -> bytes:
    """Convert a complete binary polynomial to bytes, retaining padding."""
    bits = tuple(message)
    if not bits or len(bits) % 8:
        raise ValueError("Message length must be a positive multiple of eight")
    if any(type(bit) is not int or bit not in (0, 1) for bit in bits):
        raise ValueError("Message coefficients must be binary integers")
    return bytes(sum(bits[start + offset] << offset for offset in range(8))
                 for start in range(0, len(bits), 8))


def example() -> dict[str, int | bool]:
    """Optional round-trip example. Written for the user; not executed."""
    params = Parameters()
    public_key, secret_key = keygen(params)
    message = bytes_to_message(b"LA-IoT", params)
    ciphertext = encrypt(public_key, message)
    packed = ciphertext.to_bytes()
    restored = Ciphertext.from_bytes(params, packed)
    recovered = decrypt(secret_key, restored)
    if recovered != message:
        raise RuntimeError("Unexpected failure of the stated correctness bound")
    return {
        "round_trip_ok": recovered == message,
        "ciphertext_payload_bytes": len(packed),
        "worst_case_error_bound": params.worst_case_error_bound,
        "delta": params.delta,
    }


# Nothing is executed on import. To try it later, explicitly call example().
