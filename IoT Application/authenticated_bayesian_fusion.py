"""Authenticated Bayesian fusion for LA-IoT. Generated source; not executed.

The supplied reference profile processes four reading channels per report.
Each channel follows the scalar manuscript equation independently. Precisions
are positive integers in the stated measurement units, not arbitrary scores.

No keys, reports, databases, experiments, or examples are created automatically.
Keep the supporting modules beside this file. Provision keys and schedules
through the application's trusted configuration process.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import la_iot_cca as protocol
import la_iot_cca_security as security

ProtocolConfig = protocol.ProtocolConfig
NodePolicy = protocol.NodePolicy
Credential = security.Credential
PersistentStore = security.PersistentStore
IncompleteRound = security.IncompleteRound
SecurityError = security.SecurityError
Posterior = protocol.Posterior

# Explicit setup functions only; assigning these names does not call them.
generate_bfv_contexts = protocol.generate_bfv_contexts
generate_mlkem_keys = protocol.generate_lattice_keys


@dataclass(frozen=True)
class TrustedRound:
    """Deliver with trusted scheduling, separately from the result packet.

    spec_id binds the complete configuration, prior, source policies, expected
    sequences, key identifiers, BFV context, and controller identity. The BFV
    secret context must be the one paired with this provisioned public context.
    """

    config: ProtocolConfig
    round_id: str
    controller_id: str
    spec_id: str
    context_id: str
    participants: tuple[str, ...]
    total_precision: int


def protect_report(
    readings: Sequence[int], *, config: ProtocolConfig, node_id: str,
    round_id: str, sequence: int, policy: NodePolicy,
    source_key: Credential, bfv_public_context: bytes,
    mlkem_public_key: bytes,
) -> bytes:
    """Produce an authenticated report with beta=alpha.

    alpha=1: joint compression/watermark -> ML-KEM/HKDF/AES-GCM.
    alpha=0: BFV encryption of [tau*x_1, ..., tau*x_4, tau].
    Both paths authenticate the complete header and ciphertext. Source and
    watermark MAC keys are derived for separate purposes from the source secret.
    Retransmit these same returned bytes; use a new sequence for a new report.
    """
    if not isinstance(source_key, Credential):
        raise TypeError("Expected a provisioned source Credential")
    source = protocol.DeviceClient(
        config, node_id, policy, source_key.secret,
        bfv_public_context, mlkem_public_key,
    )
    return source.make_report(readings, round_id, sequence).to_bytes()


def provisional_fusion(
    non_sensitive_reports: Sequence[bytes], *, config: ProtocolConfig,
    bfv_public_context: bytes, round_id: str,
) -> security.RelayBatch:
    """Relay BFV addition with the unchanged original reports attached.

    The relay adds no prior and holds no source-authentication keys. Sensitive
    reports are forwarded unchanged using the normal report-delivery path.
    A partial ciphertext alone is insufficient for authenticated acceptance.
    """
    return security.relay_partial(
        non_sensitive_reports, config, bfv_public_context, round_id,
    )


class AuthenticatedBayesianFusion:
    """Trusted controller for one scheduled round; BFV public key only.

    store must be persistent and owned by this controller process. The ML-KEM
    private key opens sensitive reports; no BFV secret key is supplied here.
    All expected original reports are required before finish can return.
    """

    def __init__(
        self, *, store: PersistentStore, config: ProtocolConfig,
        round_id: str, policies: Mapping[str, NodePolicy],
        source_keys: Mapping[str, Credential],
        expected_sequences: Mapping[str, int], bfv_public_context: bytes,
        mlkem_private_key: Any, mlkem_public_key: bytes,
        controller_id: str, result_key: Credential,
    ) -> None:
        self._round = security.ControllerRound(
            store, config, round_id, policies, source_keys,
            expected_sequences, bfv_public_context, mlkem_private_key,
            protocol.lattice_key_id(mlkem_public_key), controller_id, result_key,
        )
        self.trusted_round = TrustedRound(
            config=config, round_id=self._round.round_id,
            controller_id=self._round.controller_id,
            spec_id=self._round.spec_id, context_id=self._round.context_id,
            participants=self._round.participants,
            total_precision=(config.prior_precision
                             + sum(p.precision for p in self._round.policies.values())),
        )

    def accept(self, report: bytes) -> bool:
        """Record a source-authenticated report once; identical retries return False.

        Conflicts, unexpected sequences, and revoked keys are rejected. Inner
        sensitive-data verification and BFV parsing complete during finish.
        """
        return self._round.submit(report)

    def accept_relay(self, batch: security.RelayBatch) -> int:
        """Admit the batch's originals; its provisional sum is not trusted."""
        return self._round.submit_batch(batch)

    def finish(self) -> bytes:
        """Verify all originals, reconstruct BFV statistics, and add the prior once.

        Sensitive readings are restored and BFV-encrypted after their checks.
        The result MAC binds final ciphertext, round, roster, input hashes, and
        context. The saved result is returned unchanged on repeated calls.
        Missing sources raise IncompleteRound rather than producing a complete
        result. A failed inner authentication or malformed BFV report is rejected.
        """
        return self._round.finalize()


def recover_fusion(
    result: bytes, *, trusted_round: TrustedRound,
    receiver_store: PersistentStore, bfv_secret_context: Any,
    result_key: Credential,
) -> Posterior:
    """Authenticate the result before BFV decryption; return exact Fractions.

    trusted_round comes from trusted scheduling, never from the result packet.
    The receiver uses a separate persistent store and a controller-to-recipient
    MAC key. Each completed round may be delivered once. Returned fields are
    means, variance, total_precision, and participants.
    """
    receiver = security.ResultReceiver(
        receiver_store, trusted_round.config, bfv_secret_context,
        trusted_round.context_id, trusted_round.controller_id, result_key,
    )
    return receiver.receive(
        result, trusted_round.round_id, trusted_round.spec_id,
        trusted_round.participants, trusted_round.total_precision,
    )


# Deliberately no executable example or __main__ block.

