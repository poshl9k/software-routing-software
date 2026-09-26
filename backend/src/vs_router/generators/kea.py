import json
from ..schema import ConfigurationVersion


def generate_kea(version: ConfigurationVersion) -> str:
    c = version.configuration
    subnets = []
    for s in c.dhcp_subnets:
        options = []
        for name, values in (("routers", s.routers), ("domain-name-servers", s.dns_servers)):
            if values:
                options.append({"name": name, "data": ", ".join(values)})
        subnets.append({
            "id": s.id, "subnet": s.subnet, "interface": s.interface,
            "valid-lifetime": s.valid_lifetime,
            "pools": [{"pool": f"{p.start} - {p.end}"} for p in s.pools],
            "reservations-in-subnet": True, "reservations-out-of-pool": False,
            "reservations": [dict({"hw-address": r.hw_address.lower(), "ip-address": r.ip_address},
                                  **({"hostname": r.hostname} if r.hostname else {})) for r in s.reservations],
            "option-data": options,
        })
    return json.dumps({"Dhcp4": {
        "interfaces-config": {"interfaces": sorted({s.interface for s in c.dhcp_subnets})},
        "lease-database": {"type": "memfile", "persist": True},
        "valid-lifetime": 3600, "subnet4": subnets,
    }}, indent=2) + "\n"
