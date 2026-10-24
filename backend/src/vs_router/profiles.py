"""Explicit module ownership for three product profiles (ADR-0018/0026/0035).

Every Python module in the guarded ``vs_router`` and ``vs_master`` inventories,
including package initializers, must have an exact entry in MODULE_PROFILES.
``vs_portal.models`` is classified as a panel target without making the entire
``vs_portal`` tree part of that inventory. Unknown guarded modules are errors,
never implicitly core. Package initializers use their import name
(``vs_router.agent``, not ``.__init__``). Core must not import router/panel/master
code; router, panel, and master must not import each other. In particular,
``vs_router`` cannot import ``vs_master``. Only the exact, reason-bearing edges
below grandfather existing coupling. The AST guard also follows imported symbols
through re-exports, so a core facade cannot conceal a profile-specific dependency.
This is policy data, not runtime profile selection; host capabilities and the
installer marker remain unchanged.

Mixed modules keep their current public entrypoints. Management/schema/service
orchestration remain core; the console with single-uplink/domain provisioning is
assigned to panel, with its legacy router dependencies recorded explicitly.
Interface-scoped SSH ownership follows the router split target even though the
shared pipeline still invokes it today. The DNS generator is core, not router:
ADR-0020 makes the panel the subscriber resolver, and the panel host runs Unbound
with its own applied configuration, so both products share the generator while the
policy they compose into it differs. Proxy subscription imports are shared
outbound functionality, not the future panel-only subscriber model.
"""
from typing import Literal

ModuleProfile = Literal['core', 'router', 'panel', 'master']

MODULE_PROFILES: dict[str, ModuleProfile] = {
    'vs_master': 'master',
    'vs_master.accounts': 'master',
    'vs_master.admin_api': 'master',
    'vs_master.app': 'master',
    'vs_master.auth': 'master',
    'vs_master.bridge': 'master',
    'vs_master.exports': 'master',
    'vs_master.migrate_node': 'master',
    'vs_master.models': 'master',
    'vs_master.portal_api': 'master',
    'vs_master.worker': 'master',
    'vs_portal.errors': 'panel',
    'vs_portal.models': 'panel',
    'vs_portal.security': 'panel',
    'vs_router': 'core',
    'vs_router.app': 'core',
    'vs_router.db': 'core',
    'vs_router.management': 'core',
    'vs_router.profile': 'core',
    'vs_router.profiles': 'core',
    'vs_router.schema': 'core',
    'vs_router.secrets': 'core',
    'vs_router.telegram_bot': 'panel',
    'vs_router.telegram_bot.__main__': 'panel',
    'vs_router.validators': 'core',
    'vs_router.agent': 'core',
    'vs_router.agent.apply': 'core',
    'vs_router.agent.boot_restore': 'core',
    'vs_router.agent.bootstrap_dns': 'core',
    'vs_router.agent.clash': 'core',
    'vs_router.agent.console_menu': 'router',
    'vs_router.agent.setup_wizard': 'panel',
    'vs_router.agent.daemon': 'core',
    'vs_router.agent.ddns_update': 'core',
    'vs_router.agent.dnscrypt_service': 'core',
    'vs_router.agent.downloader': 'core',
    'vs_router.agent.engine': 'core',
    'vs_router.agent.management_console': 'panel',
    'vs_router.agent.network_ownership': 'core',
    'vs_router.agent.policy_route': 'core',
    'vs_router.agent.pppoe_apply': 'router',
    'vs_router.agent.presets': 'core',
    'vs_router.agent.rollback_check': 'core',
    'vs_router.agent.rpc': 'core',
    'vs_router.agent.rulesets': 'core',
    'vs_router.agent.services': 'core',
    'vs_router.agent.singbox_service': 'core',
    'vs_router.agent.source_schedule': 'core',
    'vs_router.agent.source_update_job': 'core',
    'vs_router.agent.ssh': 'router',
    'vs_router.agent.subscription_parse': 'core',
    'vs_router.agent.subscriptions': 'core',
    'vs_router.agent.tproxy_apply': 'core',
    'vs_router.agent.tunnel_start': 'core',
    'vs_router.agent.unbound_service': 'router',
    'vs_router.agent.update': 'core',
    'vs_router.api': 'core',
    'vs_router.api.aliases_io': 'core',
    'vs_router.api.auth': 'core',
    'vs_router.api.backup': 'core',
    'vs_router.api.configuration': 'core',
    'vs_router.api.diag': 'core',
    'vs_router.api.errors': 'core',
    'vs_router.api.host': 'core',
    'vs_router.api.keygen': 'core',
    'vs_router.api.leases': 'router',
    'vs_router.api.portal_admin': 'panel',
    'vs_router.api.release': 'core',
    'vs_router.api.rulesets': 'core',
    'vs_router.api.runtime': 'core',
    'vs_router.api.status': 'core',
    'vs_router.api.subscriptions_runtime': 'core',
    'vs_router.api.tunnel_peers': 'core',
    'vs_router.api.tunnels': 'core',
    'vs_router.api.update': 'core',
    'vs_router.api.versions': 'core',
    'vs_router.generators': 'core',
    'vs_router.generators.amnezia': 'core',
    'vs_router.generators.bundle': 'core',
    'vs_router.generators.caddy': 'core',
    'vs_router.generators.dnscrypt': 'core',
    'vs_router.generators.kea': 'router',
    'vs_router.generators.marks': 'core',
    'vs_router.generators.networkd': 'router',
    'vs_router.generators.nftables': 'core',
    'vs_router.generators.pppoe': 'router',
    'vs_router.generators.singbox': 'core',
    'vs_router.generators.tproxy_dns': 'core',
    'vs_router.generators.unbound': 'core',
    'vs_router.generators.wireguard': 'core',
    'vs_router.internal_app': 'panel',
}

# Exact edges only: no source-wide skips or prefix/glob exceptions. Tests reject
# empty reasons and stale entries, and prove removing each exception fails.
KNOWN_CROSS_PROFILE_EDGES: dict[tuple[str, str], str] = {
    ('vs_master.accounts', 'vs_router.api.errors'):
        'Master subscriber authentication uses the shared public error contract.',
    ('vs_master.admin_api', 'vs_portal.security'):
        'Master admin API reads the shared installation secret key for encrypted node credentials.',
    ('vs_master.admin_api', 'vs_router.api.errors'):
        'Master admin API uses the shared public error contract.',
    ('vs_master.admin_api', 'vs_router.schema'):
        'Master admin API reuses the strict shared Pydantic model base.',
    ('vs_master.admin_api', 'vs_router.secrets'):
        'Master admin API encrypts and decrypts persisted node credentials.',
    ('vs_master.app', 'vs_portal.errors'):
        'Master app reuses the portal nested-error response handlers.',
    ('vs_master.auth', 'vs_router.api.errors'):
        'Master authentication uses the shared public error contract.',
    ('vs_master.bridge', 'vs_router.api.errors'):
        'Master bridge translates shared API error contracts.',
    ('vs_master.exports', 'vs_portal.security'):
        'Master exports decrypt subscriber material with the shared installation key.',
    ('vs_master.exports', 'vs_router.api.errors'):
        'Master exports use the shared public error contract.',
    ('vs_master.exports', 'vs_router.generators.amnezia'):
        'Master exports reuse the deterministic Amnezia container generator.',
    ('vs_master.exports', 'vs_router.generators.wireguard'):
        'Master exports preserve the shared AmneziaWG parameter order.',
    ('vs_master.exports', 'vs_router.secrets'):
        'Master exports decrypt stored subscriber material for authenticated downloads.',
    ('vs_master.models', 'vs_portal.models'):
        'Master reuses portal UTC and Secret column-type helpers.',
    ('vs_master.models', 'vs_router.schema'):
        'Master reuses the shared EncryptedSecret schema type.',
    ('vs_master.portal_api', 'vs_portal.security'):
        'Master portal decrypts node credentials with the shared installation key.',
    ('vs_master.portal_api', 'vs_router.api.errors'):
        'Master portal uses the shared public error contract.',
    ('vs_master.portal_api', 'vs_router.secrets'):
        'Master portal decrypts persisted node bridge credentials.',
    ('vs_master.migrate_node', 'vs_portal.models'):
        'Migration reads the node portal schema it copies into the master.',
    ('vs_master.migrate_node', 'vs_router.secrets'):
        'Migration re-encrypts device key material across installation keys.',
    ('vs_master.worker', 'vs_portal.security'):
        'Master worker reads the shared installation secret key without owning portal state.',
    ('vs_master.worker', 'vs_router.secrets'):
        'Master worker encrypts persisted device material and decrypts bridge credentials.',
    ('vs_router.app', 'vs_router.api.leases'):
        'The shared application still registers the router DHCP lease API.',
    ('vs_router.app', 'vs_router.api.portal_admin'):
        'The shared application registers the admin API into the portal database (ADR-0032).',
    ('vs_router.generators', 'vs_router.generators.kea'):
        'The existing generator facade re-exports the router DHCP generator.',
    ('vs_router.generators', 'vs_router.generators.networkd'):
        'The existing generator facade re-exports router network configuration.',
    ('vs_router.generators', 'vs_router.generators.pppoe'):
        'The existing generator facade re-exports the router PPPoE generator.',
    ('vs_router.agent.apply', 'vs_router.generators.kea'):
        'The shared apply pipeline renders DHCP and gates its phase by host capability.',
    ('vs_router.agent.apply', 'vs_router.generators.networkd'):
        'The shared apply pipeline still renders and serializes router interfaces.',
    ('vs_router.agent.apply', 'vs_router.agent.pppoe_apply'):
        'Apply and rollback still own router PPPoE artifact validation and readiness.',
    ('vs_router.agent.apply', 'vs_router.agent.unbound_service'):
        'The gated TProxy apply lifecycle still starts and stops split Unbound services.',
    ('vs_router.api.configuration', 'vs_router.generators.kea'):
        'Shared configuration validation still exercises the DHCP generator.',
    ('vs_router.api.configuration', 'vs_router.generators.networkd'):
        'Shared configuration validation still exercises the interface generator.',
    ('vs_router.agent.boot_restore', 'vs_router.agent.pppoe_apply'):
        'Boot restoration still decodes and restores router PPPoE artifacts.',
    ('vs_router.agent.boot_restore', 'vs_router.agent.unbound_service'):
        'Boot restoration still re-establishes the gated split Unbound lifecycle.',
    ('vs_router.agent.boot_restore', 'vs_router.agent.ssh'):
        'Boot restoration still invokes interface-scoped router SSH recovery.',
    ('vs_router.agent.boot_restore', 'vs_router.agent.management_console'):
        'Boot restoration shares the provisioning console management identity check.',
    ('vs_router.agent.daemon', 'vs_router.agent.ssh'):
        'The shared daemon still wires the router SSH controller into apply.',
    ('vs_router.agent.daemon', 'vs_router.agent.management_console'):
        'The shared set_panel_domain RPC delegates to Console.publish_panel_domain.',
    ('vs_router.agent.services', 'vs_router.generators.networkd'):
        'The mixed service adapter still decodes and writes router networkd bundles.',
    ('vs_router.agent.services', 'vs_router.agent.pppoe_apply'):
        'The mixed service adapter still decodes router PPPoE bundles for reload.',
    ('vs_router.agent.console_menu', 'vs_router.agent.management_console'):
        'The router menu still uses the mixed provisioning console for LAN setup.',
    ('vs_router.agent.console_menu', 'vs_router.agent.setup_wizard'):
        'The shared console entry point exposes portal setup only on panel-profile hosts.',
    ('vs_router.agent.management_console', 'vs_router.generators.networkd'):
        'The panel provisioning console still contains legacy router LAN provisioning.',
}


def module_profile(module: str) -> ModuleProfile:
    """Return exact ownership; an unclassified module raises KeyError."""
    return MODULE_PROFILES[module]
