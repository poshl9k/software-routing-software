"""Secret-safe views, JSON Pointer differences and offline validation."""
import warnings
import os

from ..secrets import encrypt_secret
from ipaddress import ip_address, ip_network
from threading import RLock
from pydantic import ValidationError

from ..generators import generate_kea, generate_nftables, generate_unbound, generate_networkd
from ..schema import Configuration, ConfigurationVersion
from ..validators import expand_aliases, port_range
from .errors import APIError, issue, validation_details

REDACTED = {"redacted": True}
_validation_lock = RLock()


def redact(value):
    if isinstance(value, dict):
        if value.get("encrypted") is True and "ciphertext" in value:
            return REDACTED.copy()
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def restore_secrets(value, previous):
    """A returned marker retains a secret only at the same named identity."""
    if value == REDACTED:
        if isinstance(previous, dict) and previous.get("encrypted") is True:
            return previous
        raise APIError(422, "secret.missing")
    if isinstance(value, dict):
        old = previous if isinstance(previous, dict) else {}
        return {k: restore_secrets(v, old.get(k)) for k, v in value.items()}
    if isinstance(value, list):
        old = previous if isinstance(previous, list) else []
        named = {v[key]: v for v in old if isinstance(v, dict)
                 for key in ("name", "tag") if key in v}
        return [restore_secrets(v, named.get(v.get("name", v.get("tag")))
                                if isinstance(v, dict) else None)
                for v in value]
    return value


def encrypt_inputs(value):
    """Accept plaintext only at schema secret fields; never persist plaintext."""
    if not isinstance(value, dict):
        return value
    value = {**value}
    def convert(row, fields):
        if not isinstance(row, dict):
            return row
        row = {**row}
        for field in fields:
            secret = row.get(field)
            if isinstance(secret, dict) and set(secret) == {"plaintext"}:
                if not isinstance(secret["plaintext"], str) or not secret["plaintext"]:
                    raise APIError(422, "secret.empty")
                try:
                    row[field] = encrypt_secret(secret["plaintext"], os.environ.get(
                        "VS_ROUTER_SECRET_KEY", "").encode()).model_dump(mode="json")
                except (ValueError, TypeError):
                    raise APIError(503, "secret.encryption_unavailable") from None
        return row
    for collection, fields in (("tunnels", ("private_key",)),
                               ("sites", ("certificate", "private_key", "dns_api_token")),
                               ("ddns", ("api_token",))):
        if isinstance(value.get(collection), list):
            value[collection] = [convert(row, fields) for row in value[collection]]
    if isinstance(value.get("tunnels"), list):
        for tunnel in value["tunnels"]:
            if isinstance(tunnel, dict) and isinstance(tunnel.get("peers"), list):
                tunnel["peers"] = [convert(peer, ("preshared_key", "private_key"))
                                   for peer in tunnel["peers"]]
    if isinstance(value.get("proxies"), dict):
        proxies = {**value["proxies"]}
        if isinstance(proxies.get("outbounds"), list):
            proxies["outbounds"] = [convert(outbound, ("secret",))
                                    for outbound in proxies["outbounds"]]
        value["proxies"] = proxies
    return value


def parse_configuration(value, previous=None):
    try:
        return Configuration.model_validate(restore_secrets(encrypt_inputs(value), previous))
    except ValidationError as exc:
        raise APIError(422, "configuration.invalid", validation_details(exc)) from None


def check_roles(configuration, previous):
    roles = {t.name: t.role for t in previous.tunnels}
    if any(t.name in roles and t.role != roles[t.name] for t in configuration.tunnels):
        raise APIError(422, "tunnel.role_immutable")


def validate(value, previous=None):
    errors = []
    with _validation_lock, warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            configuration = parse_configuration(value, previous)
            if previous is not None:
                check_roles(configuration, Configuration.model_validate(previous))
        except APIError as exc:
            errors.append(issue(exc.code, exc.details))
        else:
            if aliases_overlap(configuration):
                warnings.warn("alias.overlap", UserWarning)
            version = ConfigurationVersion(configuration=configuration)
            for name, generator in (("nftables", generate_nftables),
                                    ("unbound", generate_unbound), ("kea", generate_kea),
                                    ("networkd", generate_networkd)):
                try:
                    generator(version)
                except (ValueError, TypeError, KeyError, NotImplementedError):
                    errors.append(issue("generator.failed", [{"generator": name}]))
        # Only known validator warning codes are safe to return verbatim.
        warning_codes = sorted({str(w.message) for w in caught
                                if str(w.message) in {"alias.large", "alias.overlap"}})
    return {"valid": not errors, "errors": errors,
            "warnings": [issue(code) for code in warning_codes]}


def structural_diff(before, after, path=""):
    """Deterministic JSON Pointer paths; compare secrets before redacting values."""
    if not isinstance(before, (dict, list)) and type(before) is type(after) and before == after:
        return []
    if isinstance(before, dict) and isinstance(after, dict):
        if before.get("encrypted") is True or after.get("encrypted") is True:
            return [{"op": "replace", "path": path, "before": redact(before), "after": redact(after)}]
        result = []
        for key in sorted(before.keys() | after.keys()):
            child = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in before:
                result.append({"op": "add", "path": child, "after": redact(after[key])})
            elif key not in after:
                result.append({"op": "remove", "path": child, "before": redact(before[key])})
            else:
                result.extend(structural_diff(before[key], after[key], child))
        return result
    if isinstance(before, list) and isinstance(after, list):
        result = []
        for i in range(max(len(before), len(after))):
            child = f"{path}/{i}"
            if i >= len(before):
                result.append({"op": "add", "path": child, "after": redact(after[i])})
            elif i >= len(after):
                result.append({"op": "remove", "path": child, "before": redact(before[i])})
            else:
                result.extend(structural_diff(before[i], after[i], child))
        return result
    return [{"op": "replace", "path": path, "before": redact(before), "after": redact(after)}]


def aliases_overlap(configuration):
    """Sweep address/port intervals; no quadratic comparisons or host expansion."""
    expanded = expand_aliases(configuration.aliases)
    intervals = {}
    for alias in configuration.aliases:
        for value in expanded[alias.name]:
            if alias.type == "port":
                family, ports = value.split("/", 1)
                start, end = port_range(ports)
            elif "-" in value:
                first, last = map(ip_address, value.split("-", 1))
                family, start, end = first.version, int(first), int(last)
            else:
                network = ip_network(value)
                family, start, end = network.version, int(network.network_address), int(network.broadcast_address)
            intervals.setdefault(family, []).append((start, end))
    for group in intervals.values():
        previous_end = -1
        for start, end in sorted(group):
            if start <= previous_end:
                return True
            previous_end = max(previous_end, end)
    return False
