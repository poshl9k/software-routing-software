# Lab 46 — fresh VM deploy (695476d)

Verdict: **PASS** for clean install, current-code identity, served-build identity, and authenticated runtime-engine read. Path **A** (self-contained, pinned ISO); path B was unnecessary. This is a baseline for later sing-box runtime acceptance, **not** a TProxy-enabled or transit-traffic acceptance test.

## Target and artifacts

- Domain: `vsr-fresh-695476d` on `qemu:///system`; left **running**. Fresh 20 GiB qcow2; 2 vCPU, 3072 MiB RAM.
- Source commit: `695476df4c6bcd6769a409db73a8863b567f4239` (`main` at install time). Local clone from `/home/poshl9k/GitHub/software-routing-software`; only the **clone's** `installer/preseed.cfg` added `qemu-guest-agent` to `pkgsel/include`. No source push; original repo's installer unmodified.
- Debian netinst SHA-256: `a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355` (locally computed and checked by `make-iso.sh`; no independent signature verification recorded).
- ISO: `/home/poshl9k/VMs/vsr-fresh-695476d.iso`; source vendored by `git archive` from pinned commit. Extracted `/vs-router/REVISION` is `695476df4c6bcd6769a409db73a8863b567f4239`. Extracted preseed includes `qemu-guest-agent`, `debian-installer/exit/poweroff boolean true`, and local `/cdrom/vs-router/install-source.sh` late command (not a GitHub clone).
- NICs: uplink `enp1s0` / `52:54:00:07:32:68` on libvirt NAT `default`, management `enp2s0` / `52:54:00:55:71:68` on host-only `vsr-verify-lan`. Host bridge is `192.168.10.254/24`; selected guest management endpoint `192.168.10.1/24` was provisioned via management console. Its host-owned `/var/lib/vs-router-bootstrap/management.json` subsequently reads `{"interface":"enp2s0","mac":"52:54:00:55:71:68","address":"192.168.10.1/24"}`. CA: `/home/poshl9k/VMs/vsr-fresh-ca.crt`; local admin credential file (mode 0600): `/home/poshl9k/VMs/vsr-fresh-admin.json` — do not commit credentials.
- Disk-only pre-acceptance snapshot: `pre-acceptance-695476d` (`disk-snapshot`).

## Reproduction: exact principal commands

Run from repository root unless indicated; clone is a separate lab copy:

```sh
virsh -c qemu:///system list --all
virsh -c qemu:///system net-list --all
virsh -c qemu:///system net-dumpxml vsr-verify-lan
sha256sum '/home/poshl9k/Загрузки/debian-13.7.0-amd64-netinst.iso'
git clone --local /home/poshl9k/GitHub/software-routing-software /home/poshl9k/.hermes/cache/scratch/vsr-fresh-source
# Only in the clone: replace the pkgsel/include line to append qemu-guest-agent.
cd /home/poshl9k/.hermes/cache/scratch/vsr-fresh-source
env -u PYTHONPATH VS_ROUTER_REVISION=695476df4c6bcd6769a409db73a8863b567f4239 VS_ROUTER_ISO_SHA256=a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355 VS_ROUTER_UNATTENDED_LAB=1 VS_ROUTER_TEST_POWER_OFF=1 OUT=/home/poshl9k/VMs/vsr-fresh-695476d.iso bash installer/make-iso.sh '/home/poshl9k/Загрузки/debian-13.7.0-amd64-netinst.iso'
xorriso -osirrox on -indev /home/poshl9k/VMs/vsr-fresh-695476d.iso -extract /preseed.cfg /home/poshl9k/VMs/vsr-fresh-preseed-check.cfg -extract /install.amd/vmlinuz /home/poshl9k/VMs/vsr-fresh-vmlinuz -extract /install.amd/initrd.gz /home/poshl9k/VMs/vsr-fresh-initrd.gz -extract /vs-router/REVISION /home/poshl9k/VMs/vsr-fresh-REVISION
chmod 0644 /home/poshl9k/VMs/vsr-fresh-{695476d.iso,vmlinuz,initrd.gz}
/usr/bin/python3 /usr/bin/virt-install --connect qemu:///system --name vsr-fresh-695476d --memory 3072 --vcpus 2 --disk path=/home/poshl9k/VMs/vsr-fresh-695476d.qcow2,size=20,format=qcow2 --network network=default,model=virtio --network network=vsr-verify-lan,model=virtio --cdrom /home/poshl9k/VMs/vsr-fresh-695476d.iso --boot kernel=/home/poshl9k/VMs/vsr-fresh-vmlinuz,initrd=/home/poshl9k/VMs/vsr-fresh-initrd.gz,kernel_args='auto=true priority=critical preseed/file=/cdrom/preseed.cfg file=/cdrom/preseed.cfg locale=en_US.UTF-8 console=ttyS0,115200n8' --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0 --os-variant debian13 --graphics vnc --noautoconsole --wait 0
# On automatic installer poweroff, remove installer boot fields and CDROM without touching other domains:
python3 -c 'import subprocess,xml.etree.ElementTree as E; c=["virsh","-c","qemu:///system"]; r=E.fromstring(subprocess.check_output(c+["dumpxml","vsr-fresh-695476d"])); os=r.find("os"); [os.remove(n) for tag in ("kernel","initrd","cmdline") for n in os.findall(tag)]; d=r.find("devices"); [d.remove(n) for n in d.findall("disk") if n.get("device")=="cdrom"]; p=subprocess.run(c+["define","/dev/stdin"],input=E.tostring(r),capture_output=True); print(p.returncode,p.stdout.decode(),p.stderr.decode()); raise SystemExit(p.returncode)'
virsh -c qemu:///system start vsr-fresh-695476d
virsh -c qemu:///system qemu-agent-command vsr-fresh-695476d '{"execute":"guest-ping"}'
python3 /home/poshl9k/.hermes/skills/devops/vs-router-lab-ops/scripts/guest-exec.py vsr-fresh-695476d "script -qec 'python3 -m vs_router.agent.management_console --mac 52:54:00:55:71:68 --address 192.168.10.1/24' /dev/null"
# Host checkout: npm ci && npm run build in frontend; uv build --wheel backend.
virsh -c qemu:///system snapshot-create-as vsr-fresh-695476d pre-acceptance-695476d --disk-only --atomic
virsh -c qemu:///system reboot vsr-fresh-695476d
```

Provisioning reported `Local HTTPS check passed: https://192.168.10.1/` and CA fingerprint `87:cd:47:56:77:b0:45:8a:3d:af:2f:c4:76:b6:a7:40:be:5b:5e:6c:cf:1c:50:fe:ae:3a:93:d2:32:7d:8a:3b`. The public CA was copied via qemu guest-file-read; setup/login were performed over CA-validated HTTPS; credential kept outside the repo.

## Evidence

- Firstboot `/var/lib/vs-router-bootstrap/succeeded` present; `/root/bootstrap.log` ends `Completed stage: summary`; services on bootstrap completion and after reboot: `vs-router-web=active`, `vs-router-agent=active`, `caddy=active`.
- Vendored source `/opt/vs-router/REVISION` equals `695476df4c6bcd6769a409db73a8863b567f4239`; `/opt/vs-router/.git` absent. `/etc/vs-router/version.json` is `{"commit":"695476df4c6bcd6769a409db73a8863b567f4239","semver":"0.1.0","installed_at":"2026-10-12T04:46:13Z","source":"iso"}`. Installed `vs-router-backend` 0.1.0 is at `/usr/local/lib/python3.13/dist-packages`. In-guest `python3 -c "import vs_router.schema as s; print('clash_api_port' in s.TProxy.model_fields, hasattr(s,'EngineTag'))"` returned `True True`.
- `curl --noproxy '*' --cacert /home/poshl9k/VMs/vsr-fresh-ca.crt https://192.168.10.1/`: HTTP **200**; `index.html` byte-exact match:
  `f8f7c642d938dc9a2c836fcba105f293beb1697f5946c4ee81a8c18358aace54` (both local `frontend/dist/index.html` and served index).
- The served index references `/assets/index-CZlK6NLb.js`. CA-validated GET returns HTTP **200**; SHA-256 local `frontend/dist/assets/index-CZlK6NLb.js` = served JS = post-reboot served JS: `03cd33553975dad79517d99a124680d86472236f6530ea94c3e6796b6c5575e6`.
- In the **served JS**: `Движок sing-box`, `Активные соединения`, `Журнал sing-box` and `Включить выборочную маршрутизацию` are present. Old-only copy `Загрузка и обновление прокси-подписок движком пока не выполняются` (present in `git grep` on `de32df4^:frontend/src/pages/RoutingProxy.tsx`) is **absent**. This tests runtime UI strings rather than assuming a hash alone implies the right source.
- Authenticated `GET https://192.168.10.1/api/runtime/engine` (after reboot): HTTP **200**, exact body `{"installed":true,"version":"1.14.2","running":false,"pid":null,"clash_api":false,"ip_forward":true,"nft_tproxy_tables":false}`. Unauthenticated GET returned HTTP 401 `{"code":"auth.required","message":"auth.required","details":[]}`; authentication is required. `running:false` is expected without TProxy enabled; no runtime forwarding success is claimed.
- Caddy listens only on `192.168.10.1:443`; host curl to WAN `192.168.122.237:443` timed out (`HTTP 000`). After reboot, `enp1s0` has one `192.168.122.236/24` NAT address and `default via 192.168.122.1`; management `enp2s0` still has `192.168.10.1/24`. Host-local management-LAN check passed, but no independent second LAN client was tested.

## Limitations

- Installer netinst hash was computed locally, not checked against Debian's signed checksums. The vendored revision and served build were independently cross-checked against the local Git commit and rebuild.
- No TProxy config/apply, actual sing-box start, transit forwarding, fail-closed packet path, or full `vm-feature-verification.md` battery was run; this task prepares the VM for that later acceptance. `npm ci` reported four advisory vulnerabilities (1 moderate, 1 high, 2 critical); build succeeded, no dependency changes made.
- The report is committed locally as a documentation-only commit so `git status` is clean; the installed software remains exactly `695476df4c6bcd6769a409db73a8863b567f4239`. No push performed.
