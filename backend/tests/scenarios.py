from vs_router.schema import ConfigurationVersion


def scenario(name):
    if name == "empty":
        return ConfigurationVersion()
    config = {
        "interfaces": [
            {"name": "eth0", "zone": "wan", "addresses": ["203.0.113.2/24", "203.0.113.3/32"]},
            {"name": "eth1", "zone": "lan", "addresses": ["192.168.10.1/24"]},
            {"name": "eth2"},
        ],
        "firewall_rules": [{"name": "lan_allow", "ingress_zone": "lan", "action": "pass"}],
        "dhcp_subnets": [{"id": 1, "interface": "eth1", "subnet": "192.168.10.0/24",
                          "pools": [{"start": "192.168.10.100", "end": "192.168.10.200"}],
                          "routers": ["192.168.10.1"], "dns_servers": ["192.168.10.1"],
                          "reservations": [{"hw_address": "aa:bb:cc:dd:ee:01", "ip_address": "192.168.10.110"}]}],
        "dns": {"interfaces": ["eth1"], "access_control": ["192.168.10.0/24"],
                "upstreams": ["9.9.9.9"],
                "records": [{"name": "router.home.arpa", "value": "192.168.10.1"}]},
    }
    if name == "edge":
        config["aliases"] = [
            {"name": "web", "type": "port", "elements": ["tcp/443", "tcp/8000-8080", "udp/53"]},
            {"name": "services", "type": "port", "includes": ["web"]},
            {"name": "hosts", "type": "address", "elements": ["192.168.10.10-192.168.10.20", "2001:db8::/64"]},
            {"name": "clients", "type": "address", "includes": ["hosts"]},
        ]
        config["firewall_rules"] = [
            {"name": "blocked", "ingress_zone": "lan", "src": "192.168.10.15", "action": "block", "order": 0},
            {"name": "web_allow", "ingress_zone": "lan", "protocol": "tcp", "src": "@clients",
             "destination_ports": "@services", "action": "pass", "order": 1},
            {"name": "reject_rest", "ingress_zone": "lan", "action": "reject", "order": 2, "log": True},
        ]
        config["port_forwards"] = [{"name": "https", "interface": "eth0", "protocol": "tcp",
                                    "external_port": 443, "wan_address": "203.0.113.3",
                                    "target": "192.168.10.10", "target_port": 8443}]
        config["outbound_nat"] = [
            {"name": "no_nat", "src": "192.168.10.20", "do_not_nat": True, "order": 0},
            {"name": "secondary", "src": "@clients", "translation": "203.0.113.3", "order": 1},
        ]
        config["dhcp_subnets"][0]["reservations"].append(
            {"hw_address": "aa:bb:cc:dd:ee:02", "ip_address": "192.168.10.10", "hostname": "server"})
        config["dns"]["forwards"] = [{"domain": "corp.example", "upstreams": ["192.168.10.53"]}]
        config["dns"]["records"].append({"name": "note.home.arpa", "type": "TXT", "value": '"hello router"'})
    return ConfigurationVersion(configuration=config)
