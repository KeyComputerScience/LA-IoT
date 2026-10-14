# SPDX-License-Identifier: Apache-2.0
"""Trusted, local role configuration and explicit key provisioning.

No configuration, key, socket or database is created on import. Configuration
files are operator-provisioned; incoming reports cannot select their own keys,
participants, precision, units or encryption context.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any
from urllib.parse import urlsplit

from . import authenticated_bayesian_fusion as fusion
from . import la_iot_cca as protocol


MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024 * 1024


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON configuration field")
        result[key] = value
    return result


def encode_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def integer(value: Any, name: str, minimum: int = 0, maximum: int = (1 << 63) - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"Invalid {name}")
    return value


def identifier(value: Any, name: str) -> str:
    return protocol._identifier(value, name)


def report_uri(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Expected a CoAP report URI")
    parsed = urlsplit(value)
    if (parsed.scheme != "coap" or not parsed.hostname
            or parsed.path != "/laiot/reports" or parsed.query or parsed.fragment
            or parsed.username is not None or parsed.password is not None):
        raise ValueError("Use coap://host[:port]/laiot/reports")
    if parsed.port is not None:
        integer(parsed.port, "CoAP port", 1, 65535)
    return value


def atomic_private_write(path: Path, content: bytes, *, replace: bool = False) -> None:
    """Write a local private file, fsync it, then publish atomically.

    The containing directory is controlled by the operator. With replace=False
    os.link atomically refuses an existing destination; no key is overwritten.
    """
    path = Path(path)
    if not isinstance(content, bytes):
        raise TypeError("Expected file bytes")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(12))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
            temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def private_bytes(path: Path, maximum: int = MAX_KEY_BYTES) -> bytes:
    """Read an operator-owned non-symlink file with no group/other access."""
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or info.st_uid != os.getuid() or not 0 < info.st_size <= maximum):
            raise ValueError(f"Expected an owned private regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(maximum + 1)
        if len(content) > maximum:
            raise ValueError("Private file exceeds its limit")
        return content
    finally:
        os.close(descriptor)


def read_json(path: Path, *, private: bool = False) -> dict[str, Any]:
    if private:
        encoded = private_bytes(path, MAX_CONFIG_BYTES)
    else:
        with Path(path).open("rb") as handle:
            encoded = handle.read(MAX_CONFIG_BYTES + 1)
        if len(encoded) > MAX_CONFIG_BYTES:
            raise ValueError("Configuration exceeds its size limit")
    value = json.loads(encoded, object_pairs_hook=unique_object,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON value")))
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON configuration object")
    return value


def load_credential(path: Path) -> fusion.Credential:
    value = read_json(path, private=True)
    if set(value) != {"key_id", "secret_b64"} or not isinstance(value["secret_b64"], str):
        raise ValueError("Invalid credential file")
    return fusion.Credential(value["key_id"], base64.b64decode(value["secret_b64"], validate=True))


@dataclass(frozen=True)
class RoleConfig:
    path: Path
    value: dict[str, Any]
    protocol: fusion.ProtocolConfig

    @property
    def role(self) -> str:
        return self.value["role"]

    @property
    def round_id(self) -> str:
        return self.value["round_id"]

    def file(self, field: str) -> Path:
        relative = self.value.get(field)
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            raise ValueError(f"Expected a relative local path: {field}")
        return (self.path.parent / relative).absolute()

    def public_bytes(self, field: str) -> bytes:
        # Public files also use mode 0600 so a privileged setup can distribute
        # the exact role directory without granting other users write access.
        return private_bytes(self.file(field))

    def bind(self) -> tuple[str, int]:
        host = self.value.get("bind_host")
        if not isinstance(host, str) or not host:
            raise ValueError("Missing bind_host")
        return host, integer(self.value.get("bind_port"), "bind_port", 1, 65535)


def load_role(path: Path, expected_role: str) -> RoleConfig:
    path = Path(path).absolute()
    value = read_json(path, private=True)
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1 or value.get("role") != expected_role:
        raise ValueError("Unexpected role configuration")
    for field in ("run_id", "round_id", "controller_id"):
        identifier(value.get(field), field)
    integer(value.get("seed"), "seed")
    cfg = fusion.ProtocolConfig(**value["protocol"])
    keys = value.get("policies")
    if not isinstance(keys, dict) or not 0 < len(keys) <= cfg.max_nodes:
        raise ValueError("Missing scheduled source policies")
    policies(value)
    return RoleConfig(path, value, cfg)


def policies(value: dict[str, Any]) -> dict[str, fusion.NodePolicy]:
    result = {}
    for node, item in value["policies"].items():
        identifier(node, "node_id")
        if not isinstance(item, dict) or set(item) != {"alpha", "precision", "sequence"}:
            raise ValueError("Each policy needs alpha, precision and sequence")
        integer(item["sequence"], "sequence")
        result[node] = fusion.NodePolicy(item["alpha"], item["precision"])
    return result


def trusted_round(role: RoleConfig) -> fusion.TrustedRound:
    value = role.value["trusted_round"]
    if not isinstance(value, dict) or set(value) != {"spec_id", "context_id", "config_id", "participants", "total_precision"}:
        raise ValueError("Invalid trusted round")
    if value["config_id"] != role.protocol.config_id:
        raise ValueError("Trusted round and local encoding configuration differ")
    participants = tuple(value["participants"])
    if participants != tuple(sorted(set(role.value["policies"]))):
        raise ValueError("Trusted participant list differs from the provisioned policies")
    for field in ("spec_id", "context_id"):
        token = value[field]
        if not isinstance(token, str) or len(token) != 64 or any(ch not in "0123456789abcdef" for ch in token):
            raise ValueError("Invalid trusted round hash")
    expected = role.protocol.prior_precision + sum(p.precision for p in policies(role.value).values())
    if integer(value["total_precision"], "total_precision", 1) != expected:
        raise ValueError("Trusted precision differs from the schedule")
    return fusion.TrustedRound(role.protocol, role.round_id, role.value["controller_id"],
                              value["spec_id"], value["context_id"], participants, expected)


def provision(plan_path: Path, output: Path) -> list[Path]:
    """Explicit CLI setup: generate and write role-separated private material.

    If setup is interrupted, remove the incomplete output only after inspecting
    it and rerun with a fresh directory. Existing files are never overwritten.
    """
    plan = read_json(plan_path)
    if set(plan) - {"schema_version", "run_id", "seed", "round_id", "controller_id", "protocol",
                    "policies", "sources", "controller", "recipient", "relays", "transport", "deadline_s"}:
        raise ValueError("Unknown provisioning-plan field")
    if type(plan.get("schema_version")) is not int or plan["schema_version"] != 1:
        raise ValueError("Unsupported plan schema")
    for field in ("run_id", "round_id", "controller_id"):
        identifier(plan.get(field), field)
    integer(plan.get("seed"), "seed")
    node_policies = policies(plan)
    if set(plan.get("sources", {})) != set(node_policies):
        raise ValueError("Every scheduled source needs a source endpoint")
    for endpoint in plan["sources"].values():
        if not isinstance(endpoint, dict) or set(endpoint) != {"upstream_uri"}:
            raise ValueError("Invalid source endpoint")
        report_uri(endpoint["upstream_uri"])
    cfg_values = dict(plan.get("protocol", {}))
    cfg_values.setdefault("max_nodes", len(node_policies))
    cfg = fusion.ProtocolConfig(**cfg_values)
    if not node_policies or len(node_policies) > cfg.max_nodes:
        raise ValueError("Invalid scheduled source count")
    for policy in node_policies.values():
        protocol.core._validate_policy(policy, cfg)
    integer(plan.get("deadline_s", 120), "deadline_s", 1, 86400)
    relays = plan.get("relays", {})
    if not isinstance(relays, dict):
        raise ValueError("Invalid relay map")
    all_groups: set[str] = set()
    for relay, options in relays.items():
        identifier(relay, "relay_id")
        roster = options.get("participants")
        if not isinstance(roster, list) or not roster or len(set(roster)) != len(roster):
            raise ValueError("Invalid relay roster")
        if set(roster) - set(node_policies) or all_groups.intersection(roster):
            raise ValueError("Relay groups must be disjoint scheduled subsets")
        all_groups.update(roster)
        report_uri(options["controller_uri"])
        if set(options) - {"participants", "bind_host", "bind_port", "controller_uri", "partial_deadline_s", "max_cache_bytes"}:
            raise ValueError("Unknown relay endpoint field")
        integer(options.get("bind_port"), "relay bind_port", 1, 65535)
    if not isinstance(plan.get("controller"), dict) or set(plan["controller"]) != {"bind_host", "bind_port", "recipient_uri"}:
        raise ValueError("Invalid controller endpoint")
    if not isinstance(plan.get("recipient"), dict) or set(plan["recipient"]) != {"bind_host", "bind_port"}:
        raise ValueError("Invalid recipient endpoint")
    for name in ("controller", "recipient"):
        if not isinstance(plan[name]["bind_host"], str) or not plan[name]["bind_host"]:
            raise ValueError("Missing bind_host")
        integer(plan[name]["bind_port"], "bind_port", 1, 65535)
    report_uri(plan["controller"]["recipient_uri"])
    output = Path(output).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    written: list[Path] = []

    def write(relative: str, content: bytes) -> None:
        destination = output / relative
        atomic_private_write(destination, content)
        written.append(destination)

    def json_file(relative: str, value: Any) -> None:
        write(relative, encode_json(value) + b"\n")

    # Every operator-chosen key directory carries its own exclusion marker.
    write(".gitignore", b"*\n")

    def credential(prefix: str) -> fusion.Credential:
        return fusion.Credential(prefix + secrets.token_hex(16), secrets.token_bytes(32))

    def key_json(key: fusion.Credential) -> dict[str, str]:
        return {"key_id": key.key_id, "secret_b64": base64.b64encode(key.secret).decode("ascii")}

    # The standardized seed import already used by the protocol avoids guessing
    # a private-key export format. Only the controller receives this seed.
    mlkem_seed = secrets.token_bytes(protocol.MLKEM_SEED_BYTES)
    private_key = protocol._private_key(mlkem_seed)
    public_key = protocol._public_bytes(private_key.public_key())
    public_bfv, secret_bfv = fusion.generate_bfv_contexts(cfg)
    source_keys = {node: credential("source-") for node in node_policies}
    result_key = credential("result-")
    common = {"schema_version": 1, "run_id": plan["run_id"], "seed": plan["seed"],
              "round_id": plan["round_id"], "controller_id": plan["controller_id"],
              "protocol": asdict(cfg), "policies": plan["policies"],
              "transport": plan.get("transport", {}), "deadline_s": plan.get("deadline_s", 120)}
    write("public/bfv.public", public_bfv)
    write("public/mlkem.public", public_key)
    write("controller/mlkem.seed", mlkem_seed)
    write("recipient/bfv.secret", secret_bfv.serialize(save_public_key=True, save_secret_key=True,
                                                       save_galois_keys=False, save_relin_keys=False))
    json_file("controller/sources.json", {node: key_json(key) for node, key in source_keys.items()})
    json_file("controller/result.json", key_json(result_key))
    json_file("recipient/result.json", key_json(result_key))
    # Registration produces the exact descriptor hash required by the recipient.
    # This controller-owned database is retained, rather than discarded after setup.
    store = fusion.PersistentStore(output / "controller/state.sqlite")
    try:
        registered = fusion.AuthenticatedBayesianFusion(
            store=store, config=cfg, round_id=plan["round_id"], policies=node_policies,
            source_keys=source_keys,
            expected_sequences={node: item["sequence"] for node, item in plan["policies"].items()},
            bfv_public_context=public_bfv, mlkem_private_key=mlkem_seed,
            mlkem_public_key=public_key, controller_id=plan["controller_id"], result_key=result_key)
        trusted = registered.trusted_round
    finally:
        store.close()
    os.chmod(output / "controller/state.sqlite", 0o600)
    trusted_json = {"spec_id": trusted.spec_id, "context_id": trusted.context_id, "config_id": cfg.config_id,
                    "participants": list(trusted.participants), "total_precision": trusted.total_precision}
    controller_options = dict(plan["controller"])
    json_file("controller/config.json", {**common, **controller_options, "role": "controller",
              "bfv_public": "../public/bfv.public", "mlkem_public": "../public/mlkem.public",
              "mlkem_seed": "mlkem.seed", "source_credentials": "sources.json",
              "result_credential": "result.json", "database": "state.sqlite", "relay_ids": sorted(relays),
              "trusted_round": trusted_json})
    json_file("recipient/config.json", {**common, **plan["recipient"], "role": "recipient",
              "bfv_secret": "bfv.secret", "result_credential": "result.json",
              "database": "state.sqlite", "posterior_output": "posterior.json",
              "trusted_round": trusted_json})
    for node in node_policies:
        # Paths are generated from an independent safe directory name; node IDs
        # themselves may contain slashes and are never interpreted as paths.
        directory = "source-" + str(list(sorted(node_policies)).index(node) + 1)
        json_file(directory + "/source.json", key_json(source_keys[node]))
        json_file(directory + "/config.json", {**common, **plan["sources"][node], "role": "source",
                  "node_id": node, "bfv_public": "../public/bfv.public", "mlkem_public": "../public/mlkem.public",
                  "source_credential": "source.json", "outbox": "outbox.sqlite"})
    for index, (relay, options) in enumerate(sorted(relays.items()), 1):
        json_file(f"relay-{index}/config.json", {**common, **options, "role": "relay", "relay_id": relay,
                  "bfv_public": "../public/bfv.public", "database": "relay.sqlite"})
    json_file("provisioning.json", {"schema_version": 1, "run_id": plan["run_id"],
              "round_id": plan["round_id"], "trusted_round": trusted_json,
              "source_directories": {node: "source-" + str(index) for index, node in enumerate(sorted(node_policies), 1)},
              "relay_directories": {relay: f"relay-{index}" for index, relay in enumerate(sorted(relays), 1)}})
    return written
