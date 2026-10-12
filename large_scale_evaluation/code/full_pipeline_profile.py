"""Explicit host profiling of the existing complete ML-KEM/BFV processing path.

Generated as source only: not executed, imported, compiled, or tested.
This is serial functional/processing profiling, not a network experiment.
Its elapsed time is not a Cooja JCT, MCU execution time, or measured energy.
Other KEMs are compared by pqc_benchmark.py; this wrapper does not silently
replace the sensitive-path encryption suite or claim full-system variants.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import asdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import platform
import random
import sys
import time


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--sources", type=int, default=15)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--sensitive-fraction", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=20261012)
    parser.add_argument("--no-relay-partials", action="store_true")
    parser.add_argument("--protocol-dir", type=Path,
                        default=Path(__file__).resolve().parent / "protocol")
    args = parser.parse_args()
    if (not 1 <= args.sources <= 5000 or args.rounds < 1
            or not 0 <= args.sensitive_fraction <= 1 or not args.run_id.strip()):
        parser.error("Invalid source count, round count, fraction, or run ID")
    sys.path.insert(0, str(args.protocol_dir.resolve()))
    import security_mechanism_workflow as workflow
    args.output.mkdir(parents=True, exist_ok=False)
    records = []

    def measured(stage, role, operation, *values, node="", round_id=""):
        start = time.perf_counter_ns()
        result = operation(*values)
        records.append({"run_id": args.run_id, "round_id": round_id,
                        "node_id": node, "role": role, "stage": stage,
                        "duration_ms": (time.perf_counter_ns() - start) / 1e6,
                        "serialized_bytes": len(result) if isinstance(result, bytes) else ""})
        return result

    nodes = [f"source-{index:04d}" for index in range(args.sources)]
    rng = random.Random(args.seed)  # Workload only; never a cryptographic RNG.
    n_sensitive = int(args.sources * args.sensitive_fraction + 0.5)
    sensitive = set(rng.sample(nodes, n_sensitive))
    policies = {node: workflow.NodePolicy(int(node in sensitive), 1) for node in nodes}
    cfg = workflow.ProtocolConfig(max_nodes=args.sources)
    provisioning = measured("provisioning", "trusted_setup", workflow.provision, policies, cfg)
    # Export actual parameters or fail; do not guess a library's defaults.
    seal = provisioning.recipient.bfv_secret_context.seal_context().data
    parms = seal.first_context_data().parms()
    coefficient_moduli = [int(value.value()) for value in parms.coeff_modulus()]
    if not coefficient_moduli:
        raise RuntimeError("Actual BFV coefficient moduli could not be exported")
    controller_store = workflow.PersistentStore(args.output / "controller.sqlite")
    recipient_store = workflow.PersistentStore(args.output / "recipient.sqlite")
    correctness = []
    workload_digest = hashlib.sha256()
    try:
        for round_index in range(args.rounds):
            round_id = f"{args.run_id}/round-{round_index}"
            readings = {node: tuple(rng.randint(-100, 100) for _ in range(cfg.slots)) for node in nodes}
            workload_digest.update(json.dumps(readings, sort_keys=True).encode("ascii"))
            round_processor = measured(
                "register_roster", "controller", workflow.create_controller_round,
                controller_store, provisioning.public, provisioning.controller,
                provisioning.devices, {node: round_index for node in nodes},
                round_id, "controller-1", round_id=round_id,
            )
            packets = {}
            for node in nodes:
                packets[node] = measured(
                    "protect_sensitive" if node in sensitive else "protect_bfv",
                    "source", workflow.create_source_report,
                    provisioning.public, node, provisioning.devices[node],
                    readings[node], round_id, round_index, node=node, round_id=round_id,
                )
            # Three logical relay groups on this one host. No radio is simulated.
            if not args.no_relay_partials:
                for relay_index in range(3):
                    batch = [packets[node] for index, node in enumerate(nodes)
                             if index % 3 == relay_index and node not in sensitive]
                    if batch:
                        partial = measured(
                            "provisional_bfv", "relay", workflow.relay_partial,
                            batch, cfg, provisioning.public.bfv_public_context,
                            round_id, node=f"relay-{relay_index}", round_id=round_id,
                        )
                        records.append({"run_id": args.run_id, "round_id": round_id,
                                        "node_id": f"relay-{relay_index}", "role": "relay",
                                        "stage": "provisional_stats_bytes", "duration_ms": "",
                                        "serialized_bytes": len(partial.provisional_stats)})
            measured("admit_originals", "controller", workflow.record_original_reports,
                     round_processor, packets.values(), round_id=round_id)
            encoded = measured("verify_restore_reencrypt_finalize", "controller",
                               workflow.finalize_authenticated_result,
                               round_processor, round_id=round_id)
            posterior = measured(
                "verify_result_decrypt", "authorized_receiver",
                workflow.receive_authenticated_result,
                recipient_store, provisioning.public, provisioning.recipient,
                "controller-1", encoded, round_id, round_processor.spec_id,
                nodes, round_id=round_id,
            )
            # Independent integer arithmetic; no BFV helper constructs the answer.
            denominator = cfg.prior_precision + sum(policies[node].precision for node in nodes)
            expected = tuple(Fraction(
                cfg.prior_precision * cfg.prior_mean
                + sum(policies[node].precision * readings[node][slot] for node in nodes),
                denominator) for slot in range(cfg.slots))
            valid = (posterior.means == expected
                     and posterior.variance == Fraction(1, denominator)
                     and posterior.total_precision == denominator
                     and posterior.participants == tuple(sorted(nodes)))
            correctness.append({"round_id": round_id, "exact_statistics_match": valid})
            if not valid:
                raise RuntimeError("Accepted posterior differs from independent integer reference")
    finally:
        controller_store.close()
        recipient_store.close()
    with (args.output / "host_stage_profile.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=("run_id", "round_id", "node_id", "role", "stage", "duration_ms", "serialized_bytes"))
        writer.writeheader()
        writer.writerows(records)
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in args.protocol_dir.glob("*.py")}
    manifest = {"run_id": args.run_id, "scope": "serial_host_complete_processing_path",
                "network_executed": False, "mcu_validated": False, "energy_measured": False,
                "raw_reading_bytes": cfg.sensitive_payload_bytes,
                "sources": args.sources, "rounds": args.rounds, "seed": args.seed,
                "actual_sensitive_count": n_sensitive, "relay_partials": not args.no_relay_partials,
                "config": asdict(cfg), "coefficient_moduli": coefficient_moduli,
                "bfv_context_id": provisioning.public.bfv_context_id,
                "python": sys.version, "platform": platform.platform(),
                "protocol_sha256": hashes, "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "synthetic_workload_sha256": workload_digest.hexdigest(), "correctness": correctness,
                "stage_csv_sha256": hashlib.sha256((args.output / "host_stage_profile.csv").read_bytes()).hexdigest(),
                "no_private_key_or_plaintext_log": True}
    (args.output / "host_profile_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
