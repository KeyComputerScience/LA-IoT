"""Homomor-bayes entry points for sensitive and non-sensitive reports.

Generated source only: no Python execution, import, installation, or test.
Keep this file beside la_iot_bayesian.py and la_iot_ring_lwe.py.

alpha=1, beta=1: joint watermark-compression unit followed by lattice encryption.
alpha=0, beta=0: BFV encryption of weighted readings and their weight.
The unit uses a nonce-bound Random MAC. The controller verifies it,
restores sensitive readings, and encrypts their
weighted values with the common BFV public key. It then combines both
paths and adds the prior once. An authorized receiver decrypts the combined
values and calculates the estimate and variance using exact fractions.

Readings in a round refer to the same quantity under independent Gaussian
measurement errors. The configured integer weights are reciprocals of the
calibrated error variances. BFV performs the additions required here; the
final division takes place after decryption.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

import la_iot_ring_lwe as lattice
from la_iot_bayesian import (
    AuthorizedDecryptor,
    DeviceClient,
    EncryptedPosterior,
    NodePolicy,
    Packet,
    Posterior,
    ProtocolConfig,
    TrustedController,
    bfv_context_id,
    lattice_key_id,
)


def prepare_report(
    readings: Sequence[int],
    *,
    alpha: int,
    weight: int,
    node_id: str,
    round_id: str,
    sequence: int,
    device_key: bytes,
    bfv_public_context: bytes,
    lattice_public_key: lattice.PublicKey,
    config: ProtocolConfig,
) -> Packet:
    """Select the encryption path and set beta=alpha in the authenticated packet.

    The weight must agree with the controller's calibrated node policy.
    The device key authenticates the packet and the sensitive-path marker.
    """
    policy = NodePolicy(alpha=alpha, precision=weight)
    device = DeviceClient(
        config, node_id, policy, device_key,
        bfv_public_context, lattice_public_key,
    )
    return device.make_report(readings, round_id, sequence)


def homomor_bayes_aggregate(
    reports: Iterable[Packet | bytes],
    *,
    round_id: str,
    policies: Mapping[str, NodePolicy],
    device_keys: Mapping[str, bytes],
    bfv_public_context: bytes,
    lattice_public_key: lattice.PublicKey,
    lattice_secret_key: lattice.SecretKey,
    config: ProtocolConfig,
    require_all: bool = True,
) -> EncryptedPosterior:
    """Combine beta=0/1 reports and add the prior exactly once.

    The BFV secret key remains with the authorized receiver. The trusted
    controller uses the lattice secret key to restore sensitive reports.
    Each registered node contributes at most once in the selected round.
    The caller delivers the returned aggregate through an authenticated
    channel and persists round identifiers when continuing across restarts.
    """
    if lattice_public_key.params != lattice_secret_key.params:
        raise ValueError("Lattice public and secret key parameters must match")

    controller = TrustedController(
        config, round_id, policies, device_keys, bfv_public_context,
        lattice_secret_key, lattice_key_id(lattice_public_key),
    )
    for report in reports:
        controller.receive(report)
    return controller.finalize(require_all=require_all)


def recover_bayesian_estimate(
    aggregate: EncryptedPosterior,
    *,
    bfv_secret_context: Any,
    bfv_public_context: bytes,
    config: ProtocolConfig,
) -> Posterior:
    """Decrypt the authenticated aggregate and return Fraction results.

    means[k] = combined weighted reading[k] / combined weight
    variance = 1 / combined weight
    The combined values already include the configured prior once.
    """
    receiver = AuthorizedDecryptor(
        config, bfv_secret_context, bfv_context_id(bfv_public_context),
    )
    return receiver.decrypt_posterior(aggregate)


# Functions are defined only. No report or cryptographic operation is run.
