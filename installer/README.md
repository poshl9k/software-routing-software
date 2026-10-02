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

`npm ci` uses the committed lockfile. Caddy 2.11.4, caddy-l4 v0.1.2 and AmneziaWG
v3.1.20260812 use versions recorded in the existing lab reports, not a newly
verified release. Source tags are not signed-artifact verification. APT packages,
Python runtime/build dependencies, Go/Node toolchains, xcaddy, Cloudflare plugin
and wireguard-go still require a reviewed release manifest and verified pins;
bootstrap still resolves those downloads from upstream. Existing helper binaries
are reused without release attestation. ADR-0005 is therefore **not complete**.

New tests exercise shell failure propagation, retry behavior and network-manager
handoff with isolated files/fake commands. They do not prove DHCP continuity or
firewall behavior on real hosts. Rebuild/boot the ISO on a disposable Debian 13 VM
and test failures, reboot and rerun before deployment. Historical lab reports do
not validate this revision. LAN-only HTTPS, identity checks at every boot, safe
management endpoint transitions, UI-controlled SSH and WAN brute-force protection
remain separate unfinished work. One-port panel provisioning is not provided.
