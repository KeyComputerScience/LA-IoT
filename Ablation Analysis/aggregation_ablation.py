"""Aggregation-only ablation of the existing LA-IoT reference implementation.

Source only; NOT executed, imported, compiled, or tested during delivery.
Four controls: full, equal_weights, no_prior, relay_off. All retain the
existing ML-KEM/HKDF/AES-GCM path, WC, source MAC, persistent records, verified
originals, BFV reconstruction, and result MAC. Only explicit main() invocation
loads the reference dependencies, generates evaluation keys, or opens stores.

This runner profiles real local crypto/verification execution on user-supplied
readings. It does not simulate a radio or estimate traffic/energy. Network
measurements can use the same JSONL schema with their own evidence label.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from fractions import Fraction
import hashlib
import importlib
from importlib import metadata
import json
import math
from pathlib import Path
import platform
import random
import secrets
import sys
from time import perf_counter_ns
from typing import Any, Mapping


@dataclass(frozen=True)
class Variant:
    name: str
    calibrated_weights: bool = True
    include_prior: bool = True
    relay_aggregation: bool = True


VARIANTS = (
    Variant("full"),
    Variant("equal_weights", calibrated_weights=False),
    Variant("no_prior", include_prior=False),
    Variant("relay_off", relay_aggregation=False),
)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def integer(value: Any, name: str, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f"{name} must be an integer in [{lower}, {upper}]")
    return value


def identifier(value: Any, name: str) -> str:
    if (not isinstance(value, str) or not value or value.strip() != value
            or len(value.encode("utf-8")) > 128):
        raise ValueError(f"Invalid {name}")
    return value


def fraction(value: Any) -> Fraction:
    # Strings such as "7/2" and integers preserve exact reference values.
    if type(value) is int or isinstance(value, str):
        return Fraction(value)
    raise ValueError("Reference values must be integers or fraction strings")


def validate_workload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Each workload must be a JSON object")
    required = {"pair_id", "seed", "prior_mean", "prior_precision", "truth",
                "sources", "prior_case", "variance_provenance"}
    if set(value) != required:
        raise ValueError(f"Workload fields must be {sorted(required)}")
    identifier(value["pair_id"], "pair_id")
    integer(value["seed"], "seed", 0, (1 << 63) - 1)
    integer(value["prior_mean"], "prior_mean", -(1 << 31), (1 << 31) - 1)
    integer(value["prior_precision"], "prior_precision", 1, 1032192)
    identifier(value["prior_case"], "prior_case")
    if not isinstance(value["variance_provenance"], str) or not value["variance_provenance"].strip():
        raise ValueError("Record the calibration/variance source")
    if not isinstance(value["truth"], list) or len(value["truth"]) != 4:
        raise ValueError("Provide four exact reference values")
    for item in value["truth"]:
        fraction(item)
    sources = value["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 5000:
        raise ValueError("Provide 1--5000 recorded sources")
    seen: set[str] = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) != {
            "node", "alpha", "precision", "readings", "relay"
        }:
            raise ValueError("Invalid source fields")
        node = identifier(source["node"], "node")
        if node in seen:
            raise ValueError("A source can occur only once")
        seen.add(node)
        identifier(source["relay"], "relay")
        integer(source["alpha"], "alpha", 0, 1)
        integer(source["precision"], "precision", 1, 1032192)
        readings = source["readings"]
        if not isinstance(readings, list) or len(readings) != 4:
            raise ValueError("Each source needs four integer readings")
        for reading in readings:
            integer(reading, "reading", -(1 << 31), (1 << 31) - 1)
    return value


def exact_statistics(workload: Mapping[str, Any], variant: Variant) -> tuple[int, ...]:
    tau0 = workload["prior_precision"] if variant.include_prior else 0
    numerators = [tau0 * workload["prior_mean"]] * 4
    denominator = tau0
    for source in workload["sources"]:
        tau = source["precision"] if variant.calibrated_weights else 1
        denominator += tau
        for slot, reading in enumerate(source["readings"]):
            numerators[slot] += tau * reading
    return (*numerators, denominator)


def exact_estimate(workload: Mapping[str, Any], variant: Variant) -> tuple[Fraction, ...]:
    stats = exact_statistics(workload, variant)
    return tuple(Fraction(value, stats[-1]) for value in stats[:-1])


def load_reference(directory: Path) -> tuple[Any, Any, Any, dict[str, str]]:
    """Load the fixed, previously delivered standard-ML-KEM entry point."""
    directory = directory.resolve()
    names = ("joint_watermarking_iot", "authenticated_bayesian_fusion",
             "la_iot_cca", "la_iot_cca_security", "la_iot_bayesian",
             "la_iot_ring_lwe")
    hashes = {}
    for name in names:
        path = directory / (name + ".py")
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        # Avoid accidentally mixing a previously loaded reference revision.
        if name in sys.modules:
            loaded = Path(sys.modules[name].__file__).resolve()
            if loaded != path:
                raise RuntimeError(f"Already loaded a different {name}")
    sys.path.insert(0, str(directory))
    try:
        app = importlib.import_module("joint_watermarking_iot")
        fusion = importlib.import_module("authenticated_bayesian_fusion")
        protocol = importlib.import_module("la_iot_cca")
    finally:
        sys.path.pop(0)
    if protocol.SUITE != "ML-KEM-768+HKDF-SHA-256+AES-256-GCM":
        raise ValueError("Use the standard ML-KEM reference bundle")
    return app, fusion, protocol, hashes


def experimental_config_type(base: type) -> type:
    """Permit prior precision zero only in this experimental configuration.

    Production ProtocolConfig remains unchanged and requires a positive prior.
    All ordinary reference checks are retained. Zero-prior input is validated
    conservatively with precision one before using the zero-prior formulas.
    """
    @dataclass(frozen=True)
    class ExperimentalConfig(base):
        def __post_init__(self) -> None:
            if type(self.prior_precision) is int and self.prior_precision == 0:
                fields = asdict(self)
                fields["prior_precision"] = 1
                base(**fields)
            else:
                base.__post_init__(self)
    return ExperimentalConfig


def make_config(workload: Mapping[str, Any], variant: Variant, config_type: type) -> Any:
    # Same conservative input bounds for all four variants in a paired run.
    sources = workload["sources"]
    return config_type(
        max_nodes=len(sources),
        max_abs_reading=max(abs(x) for source in sources for x in source["readings"]),
        max_precision=max(source["precision"] for source in sources),
        prior_mean=workload["prior_mean"],
        prior_precision=workload["prior_precision"] if variant.include_prior else 0,
    )


def elapsed_ms(start: int) -> float:
    return (perf_counter_ns() - start) / 1_000_000


def run_variant(
    workload: Mapping[str, Any], variant: Variant, *, app: Any, fusion: Any,
    config_type: type, public_bfv: bytes, secret_bfv: Any,
    public_mlkem: bytes, private_mlkem: Any, source_keys: Mapping[str, Any],
    result_key: Any, directory: Path, environment_hash: str,
) -> dict[str, Any]:
    """Execute only when called by the user's local profiling command.

    Fusion cost is the sequential sum of relay processing, complete admission,
    controller reconstruction/authentication, and recipient verification/opening.
    It is a host processing profile, not a wireless end-to-end latency.
    """
    sources = workload["sources"]
    run_id = variant.name + "-" + secrets.token_hex(12)
    record: dict[str, Any] = {
        "run_id": run_id, "pair_id": workload["pair_id"],
        "variant": variant.name, "nodes": len(sources), "seed": workload["seed"],
        "sensitive_fraction": sum(s["alpha"] for s in sources) / len(sources),
        "evidence": "local_fusion_profile", "network_profile": "local-no-network",
        "workload_hash": digest(dict(workload)),
        "topology_hash": digest(sorted((s["node"], s["relay"]) for s in sources)),
        "environment_hash": environment_hash, "prior_case": workload["prior_case"],
        "scheduled_rounds": 1, "completed_rounds": 0,
        "squared_error_sum": 0.0, "estimate_count": 0, "exact_match": None,
        "fusion_ms_per_completed_round": None,
        "energy_mj_per_scheduled_round": None,
        "traffic_kib_per_scheduled_round": None,
    }
    stores: list[Any] = []
    stages: dict[str, float] = {}
    try:
        config = make_config(workload, variant, config_type)
        record["config"] = asdict(config)
        policies = {
            s["node"]: app.NodePolicy(
                s["alpha"], s["precision"] if variant.calibrated_weights else 1,
            ) for s in sources
        }
        round_id = run_id
        sequence = workload["seed"]
        start = perf_counter_ns()
        reports = {
            s["node"]: fusion.protect_report(
                s["readings"], config=config, node_id=s["node"],
                round_id=round_id, sequence=sequence, policy=policies[s["node"]],
                source_key=source_keys[s["node"]],
                bfv_public_context=public_bfv, mlkem_public_key=public_mlkem,
            ) for s in sources
        }
        stages["source_protection_ms"] = elapsed_ms(start)
        record["protected_original_bytes"] = sum(map(len, reports.values()))

        controller_store = app.PersistentStore(directory / (run_id + "-controller.sqlite3"))
        stores.append(controller_store)
        receiver_store = app.PersistentStore(directory / (run_id + "-receiver.sqlite3"))
        stores.append(receiver_store)
        controller = app.AuthenticatedBayesianFusion(
            store=controller_store, config=config, round_id=round_id,
            policies=policies, source_keys=source_keys,
            expected_sequences={s["node"]: sequence for s in sources},
            bfv_public_context=public_bfv, mlkem_private_key=private_mlkem,
            mlkem_public_key=public_mlkem, controller_id="ablation-controller",
            result_key=result_key,
        )
        inbox = app.VerifiedReportInbox(controller)

        start = perf_counter_ns()
        partials = []
        if variant.relay_aggregation:
            groups: dict[str, list[bytes]] = {}
            for source in sources:
                if source["alpha"] == 0:
                    groups.setdefault(source["relay"], []).append(reports[source["node"]])
            for relay in sorted(groups):
                partials.append(fusion.provisional_fusion(
                    groups[relay], config=config,
                    bfv_public_context=public_bfv, round_id=round_id,
                ))
        stages["relay_ms"] = elapsed_ms(start) if variant.relay_aggregation else 0.0
        record["provisional_ciphertext_bytes"] = sum(len(p.provisional_stats) for p in partials)
        # Above application byte counts deliberately exclude network overhead.
        # They are NOT substituted for all-hop measured traffic.

        start = perf_counter_ns()
        for source in sorted(sources, key=lambda s: s["node"]):
            inbox.accept_report(reports[source["node"]])
        stages["admission_ms"] = elapsed_ms(start)
        start = perf_counter_ns()
        result = inbox.finish()
        stages["controller_finish_ms"] = elapsed_ms(start)
        start = perf_counter_ns()
        posterior = fusion.recover_fusion(
            result, trusted_round=controller.trusted_round,
            receiver_store=receiver_store, bfv_secret_context=secret_bfv,
            result_key=result_key,
        )
        stages["recipient_ms"] = elapsed_ms(start)
        expected_stats = exact_statistics(workload, variant)
        means = tuple(posterior.means)
        matched = (means == exact_estimate(workload, variant)
                   and posterior.variance == Fraction(1, expected_stats[-1])
                   and posterior.total_precision == expected_stats[-1]
                   and tuple(posterior.participants) == tuple(sorted(policies)))
        record["exact_match"] = matched
        if not matched:
            raise ArithmeticError("BFV result differs from its exact reference")
        squared_error = sum(
            (estimate - fraction(truth)) ** 2
            for estimate, truth in zip(means, workload["truth"])
        )
        error_float = float(squared_error)
        if not math.isfinite(error_float):
            raise ArithmeticError("Reference error exceeds the reporting range")
        record.update(
            completed_rounds=1, squared_error_sum=error_float,
            estimate_count=len(means),
            fusion_ms_per_completed_round=sum(stages[name] for name in (
                "relay_ms", "admission_ms", "controller_finish_ms", "recipient_ms"
            )),
            exact_numerators=list(expected_stats[:-1]),
            exact_denominator=expected_stats[-1],
            posterior_means=[str(value) for value in means],
            posterior_variance=str(posterior.variance),
        )
    except Exception as error:
        # Local experiment diagnostics, not a network decryption response.
        record["failure_type"] = type(error).__name__
        record["failure_message"] = str(error)
    finally:
        record["stages_ms"] = stages
        for store in reversed(stores):
            store.close()
    return record


def environment_record(reference_hashes: Mapping[str, str], note: str) -> dict[str, Any]:
    versions = {}
    for name in ("cryptography", "tenseal"):
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = "unavailable"
    return {
        "python": sys.version, "platform": platform.platform(),
        "machine": platform.machine(), "libraries": versions,
        "reference_hashes": dict(reference_hashes), "operator_environment_note": note,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workloads", type=Path, help="Recorded paired workload JSON")
    parser.add_argument("--reference", type=Path,
                        default=Path(__file__).resolve().parents[1] / "joint_watermark_iot")
    parser.add_argument("--output", type=Path, required=True,
                        help="New output directory; existing directories are not reused")
    parser.add_argument("--environment-note", required=True,
                        help="Board/CPU governor/placement and acquisition details")
    args = parser.parse_args()
    document = json.loads(args.workloads.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or set(document) != {"runs"}:
        raise ValueError("Workload file must contain only a runs array")
    if not isinstance(document["runs"], list) or not document["runs"]:
        raise ValueError("Supply recorded workloads before profiling")
    workloads = [validate_workload(item) for item in document["runs"]]
    pair_ids = [item["pair_id"] for item in workloads]
    if len(set(pair_ids)) != len(pair_ids):
        raise ValueError("pair_id must identify one independent workload")
    app, fusion, protocol, hashes = load_reference(args.reference)
    config_type = experimental_config_type(app.ProtocolConfig)
    # Validate all encoding bounds before generating keys or profiling.
    for workload in workloads:
        for variant in VARIANTS:
            make_config(workload, variant, config_type)
    args.output.mkdir(parents=True, exist_ok=False)
    environment = environment_record(hashes, args.environment_note)
    env_hash = digest(environment)
    (args.output / "environment.json").write_text(
        json.dumps(environment, indent=2, ensure_ascii=False), encoding="utf-8",
    )
    (args.output / "workloads.json").write_bytes(canonical(document))
    runtime_dir = args.output / "records"
    runtime_dir.mkdir()
    with (args.output / "runs.jsonl").open("x", encoding="utf-8") as output:
        for workload in workloads:
            config = make_config(workload, VARIANTS[0], config_type)
            start = perf_counter_ns()
            public_bfv, secret_bfv = fusion.generate_bfv_contexts(config)
            public_mlkem, private_mlkem = fusion.generate_mlkem_keys()
            source_keys = {
                source["node"]: app.Credential("source-evaluation", secrets.token_bytes(32))
                for source in workload["sources"]
            }
            result_key = app.Credential("result-evaluation", secrets.token_bytes(32))
            setup_ms = elapsed_ms(start)
            # Warm only a disposable BFV arithmetic operation; preserve fresh
            # encryption randomness and persistent state for each actual run.
            warm_vector = protocol._tenseal().bfv_vector(
                protocol._public_context(public_bfv), [0, 0, 0, 0, 1],
            )
            warm_vector.decrypt(secret_bfv.secret_key())
            del warm_vector
            order = list(VARIANTS)
            random.Random(workload["seed"]).shuffle(order)
            records = []
            for variant in order:
                record = run_variant(
                    workload, variant, app=app, fusion=fusion,
                    config_type=config_type, public_bfv=public_bfv,
                    secret_bfv=secret_bfv, public_mlkem=public_mlkem,
                    private_mlkem=private_mlkem, source_keys=source_keys,
                    result_key=result_key, directory=runtime_dir,
                    environment_hash=env_hash,
                )
                record["setup_ms_excluded"] = setup_ms
                record["variant_order"] = [item.name for item in order]
                records.append(record)
            by_variant = {row["variant"]: row for row in records}
            left, right = by_variant["full"], by_variant["relay_off"]
            if left["completed_rounds"] and right["completed_rounds"]:
                equal = (left["exact_numerators"] == right["exact_numerators"]
                         and left["exact_denominator"] == right["exact_denominator"]
                         and left["posterior_means"] == right["posterior_means"])
                left["relay_off_result_equal"] = equal
                right["full_result_equal"] = equal
                if not equal:
                    raise ArithmeticError("Relay control changed the recovered result")
            for record in records:
                output.write(canonical(record).decode("ascii") + "\n")
                output.flush()


if __name__ == "__main__":
    main()
