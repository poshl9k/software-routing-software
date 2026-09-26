"""DDNS update worker: Cloudflare API and RFC 2136 via nsupdate.

The panel generates a ddns.conf listing update jobs; a timer runs
`python3 -m vs_router.agent.ddns_update` to push the current WAN address.
Token/key never leaves the file in /etc/vs-router/ddns.conf (0600).
"""
import base64
import json
import os
import subprocess
from ipaddress import ip_address
from urllib.error import URLError
from urllib.request import Request, ProxyHandler, build_opener

CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"


def http_json(opener, url, token, payload=None, method=None):
    request = Request(
        url,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method=method or ("POST" if payload is not None else "GET"),
    )
    with opener(request, timeout=15) as response:
        return json.load(response)


def wan_address(interface: str) -> str:
    out = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "dev", interface,
         "scope", "global"],
        capture_output=True, text=True, timeout=10,
    ).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            return parts[3].split("/")[0]
    raise ValueError("ddns.no_wan_address")


def cloudflare_zone_id(opener, token: str, zone: str) -> str:
    data = http_json(opener, f"{CLOUDFLARE_API}/zones?name={zone}", token)
    for row in data.get("result", []):
        if row.get("name") == zone:
            return row["id"]
    raise ValueError("ddns.zone_not_found")


def cloudflare_record_ids(opener, token: str, zone_id: str, hostname: str):
    data = http_json(
        opener,
        f"{CLOUDFLARE_API}/zones/{zone_id}/dns_records?type=A&name={hostname}",
        token,
    )
    return [row["id"] for row in data.get("result", [])]


def cloudflare_update(opener, token: str, zone: str, hostname: str, address: str):
    zone_id = cloudflare_zone_id(opener, token, zone)
    ids = cloudflare_record_ids(opener, token, zone_id, hostname)
    if ids:
        for record_id in ids:
            http_json(
                opener,
                f"{CLOUDFLARE_API}/zones/{zone_id}/dns_records/{record_id}",
                token,
                {"type": "A", "name": hostname, "content": address, "ttl": 300},
                method="PUT",
            )
    else:
        http_json(
            opener,
            f"{CLOUDFLARE_API}/zones/{zone_id}/dns_records",
            token,
            {"type": "A", "name": hostname, "content": address, "ttl": 300},
        )


def rfc2136_update(server: str, key_name: str, key: str, hostname: str,
                   address: str, ttl: int = 300) -> None:
    script = (
        f"server {server}\n"
        f"key {key_name}:{key}\n"
        f"update delete {hostname}. A\n"
        f"update add {hostname}. {ttl} A {address}\n"
        "send\n"
    )
    result = subprocess.run(
        ["nsupdate", "-v"], input=script, capture_output=True, text=True, timeout=30,
    )
    if result.returncode:
        raise ValueError("ddns.rfc2136_failed")


def reveal(secret: dict) -> str:
    from ..secrets import decrypt_secret
    key = os.environ.get("VS_ROUTER_SECRET_KEY", "").encode()
    return decrypt_secret(secret, key)


def update_all(config: dict, opener=None, address_provider=None) -> list[dict]:
    """Push the WAN address for every ddns job; returns per-job statuses."""
    opener = opener or build_opener(ProxyHandler({}))
    provider_of = address_provider or wan_address
    results = []
    for job in config.get("ddns", []):
        entry = {
            "name": job["name"], "provider": job["provider"],
            "hostname": job["hostname"], "status": "ok",
        }
        try:
            address = provider_of(job["wan_interface"])
            token = reveal(job["api_token"])
            if job["provider"] == "cloudflare":
                cloudflare_update(opener, token, job["zone"], job["hostname"], address)
            else:
                rfc2136_update(
                    job["server"], job["key_name"], token,
                    job["hostname"], address,
                )
        except (OSError, URLError, ValueError, KeyError) as exc:
            entry["status"] = "failed"
            entry["error"] = str(exc)
        results.append(entry)
    return results


def main() -> int:
    path = os.environ.get(
        "VS_ROUTER_DDNS_CONF", "/etc/vs-router/applied/ddns.conf",
    )
    if not os.path.exists(path):
        return 0
    with open(path) as handle:
        config = json.load(handle)
    statuses = update_all(config)
    status_path = os.environ.get(
        "VS_ROUTER_DDNS_STATUS", "/run/vs-router/ddns-status.json",
    )
    os.makedirs(os.path.dirname(status_path), exist_ok=True)
    with open(status_path, "w") as handle:
        json.dump(statuses, handle)
    failed = sum(1 for entry in statuses if entry["status"] == "failed")
    print(json.dumps(statuses))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
