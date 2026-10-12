"""Explicitly run comparable KEM + authenticated-encryption microbenchmarks.

Generated as source only; not run, imported, compiled, or tested. This is not
the complete LA-IoT pipeline: watermarking, compression, BFV, forwarding,
persistent verification, and final delivery must be measured separately.
The Linux worker's peak RSS is not firmware RAM or Cortex-M3 memory usage.
Install the official liboqs-python binding against the recorded liboqs build;
do not install an unrelated package named ``oqs``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import resource
import secrets
import subprocess
import sys
import time

ALGORITHMS = (
    "ML-KEM-768", "HQC-3", "FrodoKEM-976-SHAKE",
    "NTRU-HPS-2048-677", "Classic-McEliece-460896",
)
FIELDS = (
    "run_id", "algorithm", "trial", "status", "reason", "keygen_ms",
    "encaps_ms", "decaps_ms", "kdf_sender_ms", "kdf_receiver_ms",
    "aead_encrypt_ms", "aead_decrypt_ms", "source_mac_ms", "source_verify_ms",
    "public_key_bytes", "kem_ciphertext_bytes", "plaintext_bytes", "aad_bytes", "bound_aad_bytes",
    "protected_body_bytes", "actual_micro_envelope_bytes", "worker_peak_rss_bytes",
)
DOMAIN = b"LA-IoT/KEM-AEAD/v1\x00"


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def environment() -> dict:
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL,
            text=True, timeout=10,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        commit = None
    return {
        "python": sys.version, "platform": platform.platform(),
        "machine": platform.machine(), "processor": platform.processor(),
        "cpu_count": os.cpu_count(), "git_commit": commit,
        "source_sha256": digest_file(Path(__file__)),
        "binding_distribution_version": package_version("liboqs-python"),
        "cryptography_version": package_version("cryptography"),
        "measurement_clock": "time.perf_counter_ns",
        "memory_scope": "peak RSS of one whole Python worker per algorithm",
        "memory_is_target_firmware_ram": False,
        "comparison_scope": "KEM + HKDF + AES-256-GCM + source MAC only",
    }


def elapsed(function, *args):
    start = time.perf_counter_ns()
    result = function(*args)
    return result, (time.perf_counter_ns() - start) / 1_000_000


def peak_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def worker(args) -> dict:
    """No fallback or parameter substitution when a requested KEM is absent."""
    import hmac
    try:
        import oqs
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except (ImportError, OSError) as exc:
        return {"status": "unavailable", "reason": type(exc).__name__, "rows": []}
    enabled = list(oqs.get_enabled_kem_mechanisms())
    metadata = {
        "enabled_mechanisms": enabled,
        "liboqs_version": getattr(oqs, "oqs_version", lambda: "unavailable")(),
        "liboqs_python_version": getattr(oqs, "oqs_python_version", lambda: "unavailable")(),
    }
    if metadata["liboqs_version"] != args.liboqs_version:
        return {**metadata, "status": "unavailable",
                "reason": "required liboqs version mismatch", "rows": []}
    if args.algorithm not in enabled:
        return {**metadata, "status": "unavailable", "reason": "not enabled", "rows": []}
    # Identical synthetic bytes and AAD for every algorithm. These are test data.
    plaintext = bytes(index % 251 for index in range(args.payload_bytes))
    aad = json.dumps(
        {"round": 1, "node": "benchmark-node", "alpha": 1, "beta": 1},
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    rows = []

    def derive(shared_secret: bytes, purpose: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=DOMAIN + args.algorithm.encode("ascii") + b"\x00" + purpose,
        ).derive(shared_secret)

    for trial in range(-args.warmup, args.trials):
        # Constructor and RNG setup are outside operation-specific timers.
        with oqs.KeyEncapsulation(args.algorithm) as recipient:
            metadata["parameter_details"] = dict(recipient.details)
            public_key, keygen_ms = elapsed(recipient.generate_keypair)
            with oqs.KeyEncapsulation(args.algorithm) as sender:
                (kem_ciphertext, shared_sender), encaps_ms = elapsed(
                    sender.encap_secret, public_key,
                )
            shared_receiver, decaps_ms = elapsed(recipient.decap_secret, kem_ciphertext)
        if not hmac.compare_digest(shared_sender, shared_receiver):
            raise RuntimeError("KEM correctness check failed")
        key_sender, kdf_sender_ms = elapsed(derive, shared_sender, b"aead")
        key_receiver, kdf_receiver_ms = elapsed(derive, shared_receiver, b"aead")
        nonce = secrets.token_bytes(12)
        bound_aad = DOMAIN + len(aad).to_bytes(4, "big") + aad + kem_ciphertext
        ciphertext, aead_encrypt_ms = elapsed(
            AESGCM(key_sender).encrypt, nonce, plaintext, bound_aad,
        )
        recovered, aead_decrypt_ms = elapsed(
            AESGCM(key_receiver).decrypt, nonce, ciphertext, bound_aad,
        )
        if recovered != plaintext:
            raise RuntimeError("AEAD correctness check failed")
        # A separate pre-provisioned source-authentication key; not a KEM key.
        source_key = secrets.token_bytes(32)
        packet = bound_aad + nonce + ciphertext
        tag, source_mac_ms = elapsed(hmac.digest, source_key, packet, "sha256")

        def verify() -> bool:
            return hmac.compare_digest(tag, hmac.digest(source_key, packet, "sha256"))

        valid, source_verify_ms = elapsed(verify)
        if not valid:
            raise RuntimeError("Source MAC correctness check failed")
        if trial >= 0:
            rows.append(dict(
                run_id=args.run_id, algorithm=args.algorithm, trial=trial,
                status="ok", reason="", keygen_ms=keygen_ms, encaps_ms=encaps_ms,
                decaps_ms=decaps_ms, kdf_sender_ms=kdf_sender_ms,
                kdf_receiver_ms=kdf_receiver_ms, aead_encrypt_ms=aead_encrypt_ms,
                aead_decrypt_ms=aead_decrypt_ms, source_mac_ms=source_mac_ms,
                source_verify_ms=source_verify_ms, public_key_bytes=len(public_key),
                kem_ciphertext_bytes=len(kem_ciphertext), plaintext_bytes=len(plaintext),
                aad_bytes=len(aad), bound_aad_bytes=len(bound_aad),
                # Binary envelope body only: excludes CoAP/radio headers and public key.
                protected_body_bytes=len(kem_ciphertext) + 12 + len(ciphertext) + 32,
                actual_micro_envelope_bytes=len(packet) + len(tag),
            ))
    memory = peak_rss_bytes()
    for row in rows:
        row["worker_peak_rss_bytes"] = memory
    return {**metadata, "status": "ok", "reason": "", "rows": rows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("benchmark_results"))
    parser.add_argument("--run-id", default="manual-benchmark")
    parser.add_argument("--algorithms", nargs="+", default=list(ALGORITHMS))
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--payload-bytes", type=int, default=96)
    parser.add_argument("--timeout-s", type=float, default=3600)
    parser.add_argument("--liboqs-version", default="0.16.0")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--algorithm", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if (args.trials < 1 or args.warmup < 0 or args.timeout_s <= 0
            or not args.run_id.strip() or len(set(args.algorithms)) != len(args.algorithms)
            or not 1 <= args.payload_bytes <= 1_048_576):
        parser.error("Use positive trials, nonnegative warmup, and 1..1048576 payload bytes")
    if args.worker:
        try:
            result = worker(args)
        except Exception as exc:
            result = {"status": "error", "reason": type(exc).__name__, "rows": []}
        print(json.dumps(result, allow_nan=False))
        return
    args.output.mkdir(parents=True, exist_ok=False)
    rows, algorithms = [], {}
    for algorithm in args.algorithms:
        command = [
            sys.executable, str(Path(__file__).resolve()), "--worker", "--algorithm",
            algorithm, "--run-id", args.run_id, "--trials", str(args.trials),
            "--warmup", str(args.warmup), "--payload-bytes", str(args.payload_bytes),
            "--liboqs-version", args.liboqs_version,
        ]
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, check=True,
                timeout=args.timeout_s,
            )
            result = json.loads(completed.stdout)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            result = {"status": "error", "reason": type(exc).__name__, "rows": []}
        rows.extend(result.pop("rows", []))
        algorithms[algorithm] = result
        if result["status"] != "ok":
            rows.append({"run_id": args.run_id, "algorithm": algorithm,
                         "status": result["status"], "reason": result["reason"]})
    csv_path = args.output / "benchmark_raw.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    manifest = {
        "environment": environment(), "run_id": args.run_id,
        "trials": args.trials, "warmup": args.warmup,
        "payload_bytes": args.payload_bytes, "algorithms": algorithms,
        "required_liboqs_version": args.liboqs_version,
        "raw_csv_sha256": digest_file(csv_path),
        "energy_measured": False, "target_firmware_validated": False,
        "secret_keys_or_shared_secrets_logged": False,
        "note": "Single-process trials are not independent hardware deployments.",
    }
    (args.output / "benchmark_manifest.json").write_text(
        json.dumps(manifest, indent=2, allow_nan=False) + "\n", encoding="utf-8",
    )


if __name__ == "__main__":
    main()
