# vs-router installer ISO

Production installs are semi-automatic: the operator chooses the OS password and
confirms partitioning. Sudo requires that password. SSH is masked, and an initial
nftables input/forward deny policy permits loopback, established replies and DHCPv4.
Use the local console. **Software installation does not yet provide initial LAN
HTTPS access:** console LAN assignment, certificates and first-apply guards remain
unimplemented. Do not treat this image as ready for production deployment.

Build with `xorriso` and `isolinux` already installed:

```sh
VS_ROUTER_REVISION=<reviewed-full-40-character-commit> \
VS_ROUTER_ISO_SHA256=<independently-verified-Debian-ISO-sha256> \
bash installer/make-iso.sh /path/to/debian-13-amd64-netinst.iso
```

Obtain the ISO hash through a trusted verification process (including Debian's
signed checksum verification). The builder checks that hash and the ISO's Debian
13 label; it does not authenticate a hash supplied by an attacker. No ISO is
automatically downloaded. Output: `vs-router-installer-amd64.iso`. Both BIOS and
UEFI production paths use the semi-automatic preseed; the lab password is excluded
from the production image. The source checkout is detached at the supplied commit.
That commit must contain these installer changes; the builder does not publish
local edits or commit them for you.

Unattended destructive lab installation requires `VS_ROUTER_UNATTENDED_LAB=1` at
build time. Only that image contains the known lab account `vsr-admin / vsr-install`.
It still requires a sudo password and keeps SSH closed. Never deploy that image
on an untrusted network. Static-network and Wi-Fi build hooks are lab-only;
automatic bootstrap migration currently supports **one wired DHCP uplink only**.
`VS_ROUTER_TEST_GIT_URL` and `VS_ROUTER_TEST_POWER_OFF` are lab-only test hooks:
they enable local source checkout and power off before the test install's first
boot, so the host can switch boot order without restarting d-i.

The installer records the uplink name and MAC in the root-only directory
`/var/lib/vs-router-bootstrap`. Bootstrap writes DHCP configuration only for that
port and journals it in the agent's networkd manifest for first-apply cleanup.
Before disabling ifupdown at future boots it requires networkd wait-online, a DHCP
lease, a default route and DNS resolution. It does not stop ifupdown mid-install.
Static installs, an ambiguous uplink or changed MAC fail for console review.

Firstboot logs to `/root/bootstrap.log` with mode 0600. A failed or interrupted
attempt keeps the unit enabled but records an attempt marker, preventing automatic
retries across reboots. After fixing the cause, run from the console:

```sh
sudo bash /opt/vs-router/backend/packaging/firstboot-bootstrap.sh --retry
```

Success disables firstboot. Bootstrap reruns migrate the existing database and
restart runtime services; they preserve existing encryption keys and Kea passwords.
The web service receives its Kea password through systemd `LoadCredential`; the
password is not embedded in a unit or printed. Kea service readiness still depends
on the eventual applied DHCP configuration.

## Remaining release and validation gaps

`npm ci` uses the committed lockfile. Python runtime dependencies are pinned with
SHA-256 wheel hashes for Debian 13 amd64 / CPython 3.13 in
`backend/requirements-runtime.txt`, checked against `uv.lock` by tests. Bootstrap
pins Caddy 2.11.4, caddy-l4 v0.1.2, Cloudflare DNS module v0.2.4, xcaddy v0.4.7
and AmneziaWG v3.1.20260812; it checks AmneziaWG tag commits and fetches
WireGuard Go at a fixed commit. Caddy and tunnel sources are built with Go
1.25.1; Node.js 20.19.2 / npm 9.2.0 are required at build time. Go module
checksums are verified through Go's checksum database. These pins were selected
from the successful clean-VM build; they are not signed-artifact attestations.
Bootstrap resolves Debian packages and transitive dependencies from the signed
snapshot in `backend/packaging/apt-snapshot.sources` (2026-10-02 00:00 UTC),
using the archive keyring and disabling only snapshot expiry checks. It leaves
machine APT sources unchanged for later operator-managed updates. Python wheel
build dependencies (`python3-setuptools`, `python3-wheel`) come from this same
snapshot; builds disable pip build isolation to avoid floating PyPI backends.
The base Debian packages installed by d-i are now resolved only from this same
snapshot: both preseeds pin the installer mirror, udeb suite, updates, and
security archive; source-specific `check-valid-until=no` applies only to the
immutable snapshot entries. The official Debian netinst ISO is separately
verified against its detached Debian CD signing-key signature and SHA-256 before
repacking. A release manifest must record that ISO hash and the source commit.
ADR-0005 remains incomplete until the production ISO completes a clean end-to-end
install; the current checks do not yet establish that.

New tests exercise shell failure propagation, retry behavior and network-manager
handoff with isolated files/fake commands. They do not prove DHCP continuity or
firewall behavior on real hosts. Rebuild/boot the ISO on a disposable Debian 13 VM
and test failures, reboot and rerun before deployment. Historical lab reports do
not validate this revision. LAN-only HTTPS, identity checks at every boot, safe
management endpoint transitions, UI-controlled SSH and WAN brute-force protection
remain separate unfinished work. One-port panel provisioning is not provided.
