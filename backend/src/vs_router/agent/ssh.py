"""Interface-scoped SSH lifecycle. No web-supplied commands or service names.

The emergency nft table survives failed stops, first apply and failed rollback.
A separate Fail2Ban instance uses Debian's sshd filter and journald backend;
real IPv4/IPv6 test bans must reach the kernel before the listener is released.
"""
import json
from pathlib import Path
import subprocess
import time

from .apply import ApplyError, LocalFileSystem, SubprocessExecutor, APPLIED_DIR, CONFIRMED_DIR
from ..schema import SSH, ConfigurationVersion

ROOT = Path('/etc/vs-router-ssh')
READY = Path('/run/vs-router-ssh/ready')
SOCKET = '/run/vs-router-ssh/guard.sock'
GUARD = 'vs-router-ssh-guard.service'
LOCK = '''destroy table inet vs_router_ssh_lock
table inet vs_router_ssh_lock {
 chain input { type filter hook input priority -200; policy accept; tcp dport 22 drop; }
}
'''
SSHD = '''Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 3
MaxStartups 3:50:10
LoginGraceTime 30
LogLevel VERBOSE
Subsystem sftp internal-sftp
'''
FAIL2BAN = '''[Definition]
loglevel = INFO
logtarget = STDERR
socket = /run/vs-router-ssh/guard.sock
pidfile = /run/vs-router-ssh/guard.pid
dbfile = /var/lib/vs-router-ssh/guard.sqlite3
dbpurgeage = 86400
'''
JAIL = '''[vs-router-ssh]
enabled = true
filter = sshd
backend = systemd
journalmatch = _SYSTEMD_UNIT=ssh.service
usedns = no
maxretry = 5
findtime = 600
bantime = 3600
ignoreip =
ignoreself = false
action = vs-router
'''
ACTION = '''[Definition]
actionstart = /usr/sbin/nft list set inet vs_router_ssh_bans <set>
actioncheck = /usr/sbin/nft list set inet vs_router_ssh_bans <set>
actionstop =
actionban = /usr/sbin/nft add element inet vs_router_ssh_bans <set> { <ip> }
actionunban = /usr/sbin/nft delete element inet vs_router_ssh_bans <set> { <ip> }
[Init]
set = banned4
[Init?family=inet6]
set = banned6
'''


def guard_rules(policy):
    names = ', '.join(f'"{name}"' for name in sorted(policy.interfaces))
    return '''destroy table inet vs_router_ssh_bans
table inet vs_router_ssh_bans {
 set banned4 { type ipv4_addr; flags interval; }
 set banned6 { type ipv6_addr; flags interval; }
 chain input {
  type filter hook input priority -10; policy accept;
  tcp dport 22 ip saddr @banned4 drop
  tcp dport 22 ip6 saddr @banned6 drop
  tcp dport 22 ct state new meter ssh4 { ip saddr timeout 10m limit rate over 6/minute burst 3 packets } drop
  tcp dport 22 ct state new meter ssh6 { ip6 saddr timeout 10m limit rate over 6/minute burst 3 packets } drop
''' + (f'  iifname {{ {names} }} tcp dport 22 accept\n' if names else '') + '''  tcp dport 22 drop
 }
}
'''


class SSHController:
    def __init__(self, executor=None, filesystem=None, sleep=time.sleep):
        self.executor = executor or SubprocessExecutor()
        self.fs = filesystem or LocalFileSystem()
        self.sleep = sleep

    def checked(self, argv):
        if self.executor.run(argv, 15).returncode:
            raise ApplyError('ssh.service_failed')

    def nft(self, name, content):
        path = ROOT / name
        self.fs.write(path, content)
        self.checked(['nft', '-f', str(path)])

    def close(self):
        # Attempt every independent containment measure even when one fails.
        errors = []
        for operation in (
            lambda: self.fs.remove(READY),
            lambda: self.nft('closed.nft', LOCK),
            lambda: self.checked(['systemctl', 'mask', 'ssh.service', 'ssh.socket']),
            lambda: self.checked(['systemctl', 'stop', 'ssh.socket', 'ssh.service']),
        ):
            try:
                operation()
            except (OSError, subprocess.SubprocessError, ApplyError) as exc:
                errors.append(exc)
        if errors:
            raise ApplyError('ssh.close_failed') from errors[0]

    def client(self, *args):
        self.checked(['fail2ban-client', '-s', SOCKET, *args])

    def verify_guard(self):
        self.checked(['systemctl', 'is-active', '--quiet', GUARD])
        self.client('status', 'vs-router-ssh')
        # Verify the actual action, both families, not merely a running process.
        # These documentation-only addresses never belong to real clients.
        for address, name in [('192.0.2.254', 'banned4'), ('2001:db8::ffff', 'banned6')]:
            try:
                self.client('set', 'vs-router-ssh', 'banip', address)
                for attempt in range(20):
                    result = self.executor.run(
                        ['nft', 'get', 'element', 'inet', 'vs_router_ssh_bans', name,
                         '{', address, '}'], 15)
                    if result.returncode == 0:
                        break
                    self.sleep(0.1)
                else:
                    raise ApplyError('ssh.protection_unverified')
            finally:
                self.client('set', 'vs-router-ssh', 'unbanip', address)

    def activate(self, data, *, start_listener=True):
        policy = SSH.model_validate(data)
        if not policy.interfaces:
            return  # _install/restore already closed and masked the service.
        try:
            self.fs.write(ROOT / 'sshd_config', SSHD)
            self.fs.write(ROOT / 'fail2ban.conf', FAIL2BAN)
            self.fs.write(ROOT / 'jail.conf', JAIL)
            self.fs.write(ROOT / 'action.d/vs-router.conf', ACTION)
            # Reuse the complete packaged filter/include tree, with no copied regex.
            self.checked(['ln', '-sfn', '/etc/fail2ban/filter.d', str(ROOT / 'filter.d')])
            self.checked(['install', '-d', '-m', '0755', '/run/sshd'])
            self.checked(['/usr/sbin/sshd', '-t', '-f', str(ROOT / 'sshd_config')])
            self.checked(['fail2ban-client', '-c', str(ROOT), '-t'])
            self.checked(['systemctl', 'stop', GUARD])
            self.nft('guard.nft', guard_rules(policy))
            self.checked(['systemctl', 'start', GUARD])
            for attempt in range(30):
                if self.executor.run(['fail2ban-client', '-s', SOCKET, 'ping'], 15).returncode == 0:
                    break
                self.sleep(0.1)
            self.verify_guard()
            self.fs.write(READY, 'protected\n')
            self.checked(['systemctl', 'unmask', 'ssh.service'])
            self.checked(['systemctl', 'enable', 'ssh.service'])
            if start_listener:
                self.checked(['systemctl', 'restart', 'ssh.service'])
                self.checked(['systemctl', 'is-active', '--quiet', 'ssh.service'])
                self.verify_guard()
            # During boot-restore, SSH depends on that oneshot completing. Queue
            # the start without waiting, or systemd deadlocks on its own order.
            else:
                self.checked(['systemctl', '--no-block', 'start', 'ssh.service'])
            self.checked(['nft', 'delete', 'table', 'inet', 'vs_router_ssh_lock'])
        except (OSError, subprocess.SubprocessError, ValueError, ApplyError):
            self.close()
            raise

    def restore(self, engine, *, start_listener=False):
        self.close()
        marker = engine.status()
        if marker and marker['status'] not in ('confirmed', 'rolled_back'):
            return  # An interrupted/failed first apply must never expose SSH.
        try:
            backup = json.loads(self.fs.read(CONFIRMED_DIR / 'snapshot.json'))
            applied = json.loads(self.fs.read(APPLIED_DIR / 'snapshot.json'))
        except FileNotFoundError:
            return
        if applied != backup['version_snapshot']:
            raise ApplyError('ssh.snapshot_mismatch')
        version = ConfigurationVersion.model_validate(applied)
        self.activate(version.configuration.ssh.model_dump(), start_listener=start_listener)
