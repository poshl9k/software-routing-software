# Полный тест реализованных фич на тестовой VM — 2026-10-08

VM: `vsr-poke-20261007`, management `enp2s0 192.168.10.1/24`, панель `https://192.168.10.1`.
Снапшот отката: `pre-fulltest-20261008` (disk-only). `version.json.commit=1368ad8` (iso).
Код новее плана: API уже содержит `keygen/*`, `dhcp/leases`, `diag/rules-counters`, `rulesets`.
Пароль панели временно заменён на время прогона, затем восстановлен из `/root/.orig_admin_hash`
(проверено: временный пароль даёт 401). Черновики вычищены.

Метод: API-батарея (92 проверки) + «kitchen-sink» apply всех фич + проверка артефактов в госте +
reboot + локальные сьюты. Инструменты: `curl`/urllib по HTTPS, guest-exec (qemu agent).

## 0. Базовая доступность
- [x] Панель HTTPS 200 (host), auth/me admin, /health ok
- [x] Сервисы active: web/agent/caddy/unbound/kea-dhcp4-server/ssh-guard
- [x] Apply status confirmed, все 8 фаз applied
- [x] host/interfaces (lo,enp1s0,enp2s0), host/addresses
- [x] release (1368ad8) / update (configured:false)

## 1. Auth
- [x] login ok / wrong password 401 / me / logout; setup → 409 setup.completed
- [x] rate-limit код-путь есть (429 при ≥5)

## 2. Версии и черновик
- [x] GET /versions, /versions/{id}, 404 version.not_found, /diff/{i1}/{i2}
- [x] POST/PUT/DELETE /draft; повторный POST → 409 draft.exists; /draft/validate

## 3. Сеть (interfaces)
- [x] physical static (enp2s0+MAC match) / DHCP (enp1s0 UseRoutes/UseGateway=yes)
- [x] VLAN (parent+vlan_id), валидатор interface.vlan_parent
- [x] зоны wan/lan; router zone reserved (interface.router_zone_reserved)
- [x] смена конфига чистит старые `.network` (tun0/tun1 удалены после отката)

## 4. Firewall
- [x] правила pass/block, first-match, default deny, anti-lockout (nft)
- [x] alias в правиле → nftables set `a_weblocal_4`; вложенность, цикл/дубликат/тип отклоняются
- [x] port forward → авто filter-правило + dnat (auto_pf8080)
- [x] outbound NAT manual → masquerade (nat1)
- [x] API счётчиков GET /diag/rules-counters
- [x] alias export/import json/csv + import-preview (цикл/битая строка)
- [!] destination_ports принимает только одиночный порт или `N-M`, НЕ список через запятую

## 5. DHCP/DNS
- [x] Kea подсеть/пул/резервация сгенерированы; `kea-dhcp4 -t` под /run/vs-router/pending OK
- [x] GET /dhcp/leases, /dhcp/leases/search (result 3 = пусто, обработано)
- [x] Unbound records/forwards/upstreams; `unbound-checkconf`; local-data отвечает (query 127.0.0.1 → 192.168.10.1)
- [!] **dns.interfaces не активируется при apply** — unbound слушает только 127.0.0.1; после ручного restart биндится 192.168.10.1

## 6. Туннели/прокси/DDNS
- [x] keygen tunnel/peer/peer-keypair (автогенерация ключей + AWG-обфускация, п.22)
- [x] WireGuard server (kernel) tun0 up, listen 51820, peer psk+allowedips; авто-адрес 10.20.0.1/24
- [x] AmneziaWG client (userspace awg-go) tun1 up, обфускация jc/jmin/... применена; авто-адрес 10.66.66.2/24
- [x] AllowedIPs→routes: 0.0.0.0/0 → default metric 100
- [x] QR/бандл клиентского конфига GET .../qr → PNG 200
- [x] Caddy management JSON валиден, live reload (listen 192.168.10.1:443)
- [ ] импорт клиентского `.conf` — endpoint отсутствует (п.23 не реализован)
- [ ] TProxy enabled → 422 tproxy.not_available (не активен)

## 7. Диагностика
- [x] ping lo OK; injection host → 422 diag.invalid_input
- [!] **traceroute → 409 agent.internal_error** (бинарь `traceroute` не установлен; FileNotFoundError не ловится)

## 8. Бэкап
- [x] export redacted (markers), export include_secrets без пароля → 422 backup.password_required
- [x] restore redacted → 200 restored/skipped; повторный → 409 draft.exists
- [x] restore plaintext+пароль → 200; неверный пароль → 400 backup.bad_payload

## 9. Apply-движок
- [x] apply no-op → confirmed, все фазы applied
- [x] safe mode + confirm в окне → pending → confirmed
- [x] **safe mode автооткат по таймеру** → rolled_back, reason timeout, версия вернулась к предыдущей
- [x] management guard: смена LAN-адреса → 409 management.endpoint_required
- [x] management guard: port forward tcp/443 → 409 management.port_reserved
- [!] management guard: сайт при DHCP-WAN → 409 management.site_binding_conflict (обойти нельзя)
- [!] confirm уже подтверждённой версии → 409 agent.version_mismatch

## 10. Reboot
- [x] restore-on-boot: сервисы active, nft восстановлен (30 строк), маршруты/адреса целы, маркер confirmed

## Локальные сьюты (host)
- [x] backend `pytest -q` → 829 passed, EXIT 0
- [x] frontend `tsc --noEmit` → EXIT 0; `vitest run` → 92 passed, EXIT 0

## Дефекты и их фиксы (2026-10-08)
1. **Исправлено:** `traceroute` не ставился нигде → `diag_traceroute` падал в `agent.internal_error`.
   Теперь `daemon.py` ловит `FileNotFoundError` → код `diag.unavailable` (для ping и traceroute),
   а `bootstrap.sh` ставит пакет `traceroute`. Live: без бинаря → 409 `diag.unavailable`;
   после установки → 200 со списком хопов.
2. **Исправлено:** unbound-адаптер делал только `reload`, который не меняет listen-интерфейсы.
   Теперь `UnboundReloader` делает `systemctl restart unbound`. Live: apply с `dns.interfaces=enp2s0`
   → unbound сразу слушает `192.168.10.1:53`, ответ rc=0 (без ручного restart).
3. **Исправлено:** сайт при DHCP-WAN давал неинформативный `management.site_binding_conflict`.
   Теперь guard различает причины: явный wildcard/management-IP → `management.site_binding_conflict`,
   динамический WAN без якорного адреса → `caddy.wan_address_unavailable`. Live: apply → 409
   `caddy.wan_address_unavailable`. Остаточное ограничение: публикация сайта при динамическом WAN
   по-прежнему невозможна безопасно (нужна инъекция живого WAN-адреса) — отдельная задача.
4. Open (мелко): confirm уже подтверждённой версии → 409 `agent.version_mismatch`.

Сьюты после фиксов: backend **830 passed** (было 829).

## Наблюдения
- destination_ports: формат только порт ИЛИ `N-M` (не список через запятую), в UI нет подсказки.
- unbound по умолчанию `access-control: 0.0.0.0/0 refuse` — LAN-клиенты получают REFUSED без явных ACL.
- `vs-router-wg@tun0` inactive — by design (kernel wireguard); `awg@tun1` active (userspace).
