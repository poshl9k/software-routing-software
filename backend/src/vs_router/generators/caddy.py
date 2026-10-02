"""Native Caddy JSON; DNS-01 uses Cloudflare in the schema's provider-less MVP."""
import json
from ipaddress import ip_interface
from urllib.parse import urlsplit
from .bundle import serialize as serialize_caddy, deserialize as deserialize_caddy
from .wireguard import reveal

CERT_DIR = '/etc/caddy/vs-router'


def bind(address, port):
    return f'[{address}]:{port}' if ':' in address else f'{address}:{port}'


def upstream(value, layer4=False):
    parsed = urlsplit(value if '://' in value else '//' + value)
    if parsed.scheme not in ('', 'http', 'https') or not parsed.hostname or parsed.path not in ('', '/') or parsed.username or parsed.query or parsed.fragment:
        raise ValueError('caddy.invalid_upstream')
    port = parsed.port or (443 if parsed.scheme == 'https' or layer4 else 80)
    return bind(parsed.hostname, port), parsed


def generate_caddy_json(version, management=None) -> dict:
    sites = sorted(version.configuration.sites, key=lambda s: s.name)
    apps, servers, l4, policies, automate, certificates = {}, {}, {}, [], [], []
    if management is not None:
        from ..management import TLS_DIR, validate_site_bindings
        validate_site_bindings(version, management)
        servers['management'] = {
            'listen': [bind(management.ip, 443)],
            'routes': [{'handle': [{'handler': 'reverse_proxy', 'upstreams': [
                {'dial': 'unix//run/vs-router/web/web.sock'}]}]}],
            'tls_connection_policies': [{'default_sni': management.ip,
                                         'certificate_selection': {'any_tag': ['management']}}],
            'automatic_https': {'disable': True}}
        certificates.append({'certificate': str(TLS_DIR / 'server.crt'),
                             'key': str(TLS_DIR / 'server.key'), 'tags': ['management']})
    groups = {}
    # Unbound sites use the primary WAN; if WAN is dynamic, use an explicit
    # site's binding before falling back to a wildcard listener.
    default_address = next((str(ip_interface(i.addresses[0]).ip)
                            for i in version.configuration.interfaces
                            if i.zone == 'wan' and i.addresses),
                           next((s.wan_address for s in sites if s.wan_address), ''))
    for site in sites:
        groups.setdefault(site.wan_address or default_address, []).append(site)
    for index, (address, group) in enumerate(sorted(groups.items())):
        passthrough = [s for s in group if s.certificate_mode == 'passthrough']
        terminating = [s for s in group if s.certificate_mode != 'passthrough']
        local = f'127.0.0.1:{18000 + index}'
        if passthrough:
            routes = [{'match': [{'tls': {'sni': [s.hostname]}}],
                       'handle': [{'handler': 'proxy', 'upstreams': [
                           {'dial': [upstream(s.upstream, True)[0]]}]}]} for s in passthrough]
            if terminating:
                routes.append({'match': [{'tls': {'sni': [s.hostname for s in terminating]}}],
                               'handle': [{'handler': 'proxy', 'upstreams': [{'dial': [local]}]}]})
            l4[f'wan{index}'] = {'listen': [bind(address, 443)], 'routes': routes}
        if terminating:
            routes = []
            for s in terminating:
                dial, parsed = upstream(s.upstream)
                handler = {'handler': 'reverse_proxy', 'upstreams': [{'dial': dial}]}
                if parsed.scheme == 'https':
                    handler['transport'] = {'protocol': 'http', 'tls': {'server_name': parsed.hostname}}
                routes.append({'match': [{'host': [s.hostname]}], 'handle': [handler]})
            servers[f'https{index}'] = {'listen': [local if passthrough else bind(address, 443)],
                                      'routes': routes, 'tls_connection_policies': [{}],
                                      'automatic_https': {'disable': True}}
        http_sites = [s for s in group if s.certificate_mode == 'http01']
        if http_sites:
            servers[f'http{index}'] = {'listen': [bind(address, 80)],
                'routes': [{'match': [{'host': [s.hostname for s in http_sites]}],
                            'handle': [{'handler': 'static_response', 'status_code': 308,
                                        'headers': {'Location': ['https://{http.request.host}{http.request.uri}']}}]}]}
    for s in sites:
        mode = s.certificate_mode
        if mode == 'manual':
            certificates.append({'certificate': f'{CERT_DIR}/{s.name}.crt',
                                 'key': f'{CERT_DIR}/{s.name}.key'})
        elif mode in ('http01', 'dns01'):
            challenges = {'tls-alpn': {'disabled': True}}
            if mode == 'dns01':
                if s.dns_api_token is None:
                    raise ValueError('caddy.dns_token_required')
                challenges.update({'http': {'disabled': True}, 'dns': {'provider': {
                    'name': 'cloudflare', 'api_token': reveal(s.dns_api_token)}}})
            automate.append(s.hostname)
            policies.append({'subjects': [s.hostname], 'issuers': [
                {'module': 'acme', 'challenges': challenges}]})
    if servers:
        apps['http'] = {'servers': servers}
    if l4:
        apps['layer4'] = {'servers': l4}
    if certificates or automate:
        apps['tls'] = {'certificates': {}}
        if certificates:
            apps['tls']['certificates']['load_files'] = certificates
        if automate:
            apps['tls']['certificates']['automate'] = automate
            apps['tls']['automation'] = {'policies': policies}
    return {'admin': {'listen': '127.0.0.1:2019'}, 'apps': apps}


def generate_caddy_bundle(version, management=None):
    files = {'caddy.json': json.dumps(generate_caddy_json(version, management), indent=2, sort_keys=True) + '\n'}
    for site in version.configuration.sites:
        if site.certificate_mode == 'manual':
            files[f'{site.name}.crt'] = reveal(site.certificate)
            files[f'{site.name}.key'] = reveal(site.private_key)
    return files
