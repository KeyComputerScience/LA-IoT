"""LA-IoT security-mechanism workflow, generated without executing Python.

Keep la_iot_cca.py, la_iot_cca_security.py, la_iot_bayesian.py, and
la_iot_ring_lwe.py beside this file. Dependencies: requirements_cca.txt.
No key generation, database creation, examples, or tests run on import.
Each setup or protocol operation requires an explicit call.

Sensitive encryption: ML-KEM-768 + AES-256-GCM, conditionally IND-CCA.
Homomorphic statistics: BFV with its IND-CPA confidentiality goal.
This code implements processing, not a quantum-security proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import secrets
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

import la_iot_cca as protocol
import la_iot_cca_security as security


@dataclass(frozen=True)
class PublicParameters:
    """Distribute these public values through authenticated provisioning."""

    config: protocol.ProtocolConfig
    bfv_public_context: bytes
    mlkem_public_key: bytes

    @property
    def mlkem_key_id(self) -> str:
        return protocol.lattice_key_id(self.mlkem_public_key)

    @property
    def bfv_context_id(self) -> str:
        return protocol.bfv_context_id(self.bfv_public_context)


@dataclass(frozen=True)
class DeviceProvisioning:
    policy: protocol.NodePolicy
    credential: security.Credential = field(repr=False)


@dataclass(frozen=True)
class ControllerSecrets:
    """Keep the decapsulation key at the trusted controller."""

    mlkem_private_key: Any = field(repr=False)
    result_credential: security.Credential = field(repr=False)


@dataclass(frozen=True)
class RecipientSecrets:
    """Give the BFV secret context only to the authorized recipient."""

    bfv_secret_context: Any = field(repr=False)
    result_credential: security.Credential = field(repr=False)


@dataclass(frozen=True)
class Provisioning:
    """Trusted setup output; distribute secrets only to their intended parties."""

    public: PublicParameters
    devices: Mapping[str, DeviceProvisioning] = field(repr=False)
    controller: ControllerSecrets = field(repr=False)
    recipient: RecipientSecrets = field(repr=False)


def provision(policies: Mapping[str, protocol.NodePolicy],
              config: protocol.ProtocolConfig | None = None) -> Provisioning:
    """Explicit setup only: generates keys when the caller invokes this function.

    NodePolicy sets beta=alpha: 1 for sensitive data and 0 for other data.
    Common parameters bound exact integer statistics to avoid BFV wraparound.
    The existing encoding uses four integer readings per source report.
    """
    cfg = protocol.ProtocolConfig() if config is None else config
    if not isinstance(cfg, protocol.ProtocolConfig):
        raise TypeError("Expected ProtocolConfig")
    if not policies or len(policies) > cfg.max_nodes:
        raise ValueError("Invalid number of provisioned devices")
    for node, policy in policies.items():
        protocol._identifier(node, "node_id")
        protocol.core._validate_policy(policy, cfg)

    bfv_public, bfv_secret = protocol.generate_bfv_contexts(cfg)
    mlkem_public, mlkem_private = protocol.generate_lattice_keys()
    used_secrets: set[bytes] = set()

    def new_credential(prefix: str) -> security.Credential:
        secret = secrets.token_bytes(32)
        while secret in used_secrets:
            secret = secrets.token_bytes(32)
        used_secrets.add(secret)
        return security.Credential(prefix + secrets.token_hex(16), secret)

    devices = {
        node: DeviceProvisioning(policy, new_credential("source-"))
        for node, policy in policies.items()
    }
    result_key = new_credential("result-")
    return Provisioning(
        PublicParameters(cfg, bfv_public, mlkem_public),
        MappingProxyType(devices),
        ControllerSecrets(mlkem_private, result_key),
        RecipientSecrets(bfv_secret, result_key),
    )


def create_source_report(public: PublicParameters, node_id: str,
                         device: DeviceProvisioning, readings: Sequence[int],
                         round_id: str, sequence: int) -> bytes:
    """Create an authenticated sensitive or non-sensitive source packet.

    The sensitive path jointly compresses/watermarks the readings and applies
    ML-KEM/AES-GCM. Its watermark random value, GCM nonce, key purposes, and
    packet MAC are handled by the protocol. The other path BFV-encrypts
    integer sufficient statistics under the common public context.
    """
    client = protocol.DeviceClient(
        public.config, node_id, device.policy, device.credential.secret,
        public.bfv_public_context, public.mlkem_public_key,
    )
    return client.make_report(readings, round_id, sequence).to_bytes()


def create_controller_round(store: security.PersistentStore,
                            public: PublicParameters,
                            controller_secrets: ControllerSecrets,
                            devices: Mapping[str, DeviceProvisioning],
                            expected_sequences: Mapping[str, int],
                            round_id: str, controller_id: str
                            ) -> security.ControllerRound:
    """Register the trusted roster and expected sequence for every participant.

    Explicitly create PersistentStore with a persistent path before calling.
    Preserve it across restarts. Source and watermark keys are separated by
    purpose, and the result credential is independent of every device secret.
    """
    return security.ControllerRound(
        store=store,
        config=public.config,
        round_id=round_id,
        policies={node: device.policy for node, device in devices.items()},
        credentials={node: device.credential for node, device in devices.items()},
        expected_sequences=expected_sequences,
        bfv_public_context=public.bfv_public_context,
        lattice_secret_key=controller_secrets.mlkem_private_key,
        expected_lattice_key_id=public.mlkem_key_id,
        controller_id=controller_id,
        result_key=controller_secrets.result_credential,
    )


def record_original_reports(round_processor: security.ControllerRound,
                            reports: Iterable[bytes]) -> int:
    """Authenticate originals, counting only newly admitted source reports.

    Identical retries do not add another contribution. Conflicting reports,
    wrong sequences, and invalid source MACs are rejected. Full ciphertext
    and watermark verification occurs during authoritative finalization.
    """
    count = 0
    for report in reports:
        count += int(round_processor.submit(report))
    return count


def finalize_authenticated_result(round_processor: security.ControllerRound
                                  ) -> bytes:
    """Restore sensitive readings, recompute BFV statistics, and authenticate.

    Requires every scheduled original report. Source MAC, AES-GCM, and inner
    Random MAC verification precede restoration. Recovered sensitive readings
    enter the same BFV context; both paths are combined and the prior is added
    once. Provisional relay sums do not enter authoritative recomputation.
    Failed recovery releases no reading. The result MAC binds ciphertext,
    round, context, participants, and original-report hashes.
    """
    return round_processor.finalize()


def receive_authenticated_result(store: security.PersistentStore,
                                  public: PublicParameters,
                                  recipient_secrets: RecipientSecrets,
                                  controller_id: str, encoded_result: bytes,
                                  expected_round_id: str, expected_spec_id: str,
                                  expected_participants: Sequence[str]
                                  ) -> protocol.Posterior:
    """Verify delivery before decrypting exact Fraction means and variance.

    Supply the expected schedule through trusted provisioning. Use a separate
    recipient store and preserve it across restarts. The receiver rejects
    result substitution and repeated delivery before releasing a posterior.
    """
    receiver = security.ResultReceiver(
        store, public.config, recipient_secrets.bfv_secret_context,
        public.bfv_context_id, controller_id, recipient_secrets.result_credential,
    )
    return receiver.receive(
        encoded_result, expected_round_id, expected_spec_id, expected_participants,
    )


# Optional interfaces; merely exported, never invoked by this module.
relay_partial = security.relay_partial
PersistentStore = security.PersistentStore
NodePolicy = protocol.NodePolicy
ProtocolConfig = protocol.ProtocolConfig

# No __main__ block, executable experiment, or automatic setup.

