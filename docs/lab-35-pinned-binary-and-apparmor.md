# lab-35: доставка пиннутого бинарника sing-box и AppArmor-оверрайд Unbound

**Статус: подтверждено на одноразовой VM.** Закрыты две **deploy-задачи**,
оставшиеся открытыми после ADR-0012 и lab-34:

1. `agent/singbox_service.py` fail-closed ждёт пиннутый бинарник в
   `/usr/local/lib/vs-router/sing-box`, но **bootstrap его туда не кладёт** —
   теперь кладёт install-time шаг (ADR-0012).
2. Debian-профиль AppArmor `usr.sbin.unbound` ограничивает чтение
   `/etc/unbound/**` и блокирует сгенерированные split-конфиги в
   `/etc/vs-router/applied/` из lab-34. Теперь `install.sh` ставит локальный
   оверрайд с `/etc/vs-router/applied/** r,`.

Публичный gate `tproxy.not_available` **не открывался**. Golden не менялись.
`vsr-live-403ab3a` не трогалась. Коммитов/пушей нет.

## Файлы

| Файл | Роль |
| --- | --- |
| `backend/packaging/install-singbox.sh` | **новый**: аддитивный идемпотентный install-time шаг доставки пиннутого sing-box (скачать → сверить SHA256 архива → распаковать → сверить SHA256/version/provenance ELF → `install -m 0755`). |
| `backend/packaging/bootstrap.sh` | + `stage_singbox` (вызов `install-singbox.sh`) в `main()` между `awg` и `build`; существующие стадии не тронуты. |
| `backend/packaging/install.sh` | AppArmor-оверрайд Unbound: правило `/etc/vs-router/applied/unbound.conf r,` заменено на каталоговое `/etc/vs-router/applied/** r,` (надмножество), файл создаётся (`touch`) и создаётся каталог `/etc/apparmor.d/local`. |
| `backend/tests/test_installer_hardening.py` | +6 тестов: паритет пинов с адаптером; структурный fail-closed; идемпотентность без сети; отказ на подменённом архиве; wireing в bootstrap; оверрайд+идемпотентность AppArmor-блока. |

Хеши:
`install-singbox.sh` = `267e1d33eea30f50245f2069b8a94901f534146e72edb52fdda815aa9e4d8490`;
VM-скрипт `lab35/runchecks.sh` (scratch, не в репо) =
`dcd50088ec714232a7b0e0ba7eb562d373e53601c563e316b975a936b503a62b`.

## Схема доставки и верификации бинарника

Пин (совпадает с константами `singbox_service.py`, проверяется тестом):

| | Значение |
| --- | --- |
| тег | `v1.14.2` |
| URL | `https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-amd64.tar.gz` |
| SHA256 архива | `a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6` |
| SHA256 ELF | `fc9c6e6ab345f045b16a0ed10d1ff28d68e8e56e7749fca30738d1406e98d7b8` |
| provenance revision | `af6e64c3b69e6132ebaee0e1a3d24e93903f6709` |
| назначение | `/usr/local/lib/vs-router/sing-box` (0755 root:root) |

Порядок (всё fail-closed, `set -Eeuo pipefail`):

```
binary_ok "$DEST" ?  -> да: exit 0 (идемпотентно, сеть не трогается)
   нет ->
     curl --proto '=https' -o archive   URL (пиннутый по умолчанию)
     sha256sum -c  ARCHIVE_SHA256       archive   -> иначе ERROR
     tar -tzf | grep unsafe-paths       -> иначе ERROR
     tar -xzf -> $ARCHIVE_DIR/sing-box
     sha256sum -c  BINARY_SHA256        ELF       -> иначе ERROR
     ELF version == 1.14.2 && Revision == provenance -> иначе ERROR
     install -m 0755 -o root -g root    -> $DEST
```

Доверие держится на SHA256, а не на хосте загрузки: `VS_ROUTER_SINGBOX_URL`
(зеркало) и `VS_ROUTER_SINGBOX_ARCHIVE` (локальный архив, air-gap) — лишь
источники байт; несовпадающий архив всегда отвергается. Агент не участвует:
это install-time скрипт под root, без RPC и без произвольного shell; никакие
данные вызывающего в `argv` не попадают. `VS_ROUTER_SINGBOX_DEST` — тестовый
шов (адаптер всё равно использует жёсткий абсолютный путь).

Проверка ELF повторяет ту, что делает `singbox_service.verify_binary`
(`sha256sum` + `sing-box version`), поэтому установить бинарник, который агент
затем отвергнет, невозможно.

## AppArmor-оверрайд Unbound

Важная деталь, вскрытая на VM: `#include <local/usr.sbin.unbound>` в профиле
Debian — **активная директива AppArmor**, а не комментарий. Файл
`/etc/apparmor.d/local/usr.sbin.unbound` должен существовать, иначе
`apparmor_parser -r` падает и профиль вообще не перезагружается. Поэтому шаг:

```
install -d /etc/apparmor.d/local
touch  /etc/apparmor.d/local/usr.sbin.unbound
grep -qsF '/etc/vs-router/applied/** r,' FILE || echo '/etc/vs-router/applied/** r,' >> FILE
apparmor_parser -r /etc/apparmor.d/usr.sbin.unbound
```

Каталоговое правило `/etc/vs-router/applied/** r,` — надмножество прежнего
`unbound.conf r,`: покрывает и обычный, и оба split-конфига TProxy DNS-контура
(ADR-0014). Правило идемпотентно (повторный запуск не дублирует строку).

## Результат VM (одноразовая `vsr-tproxy-lab`, FAILS=0)

Debian 13, AppArmor `enforce`, Unbound 1.26.1. Выполнялся реальный прогон
(не эмуляция).

**A. Доставка бинарника** (реальная загрузка с GitHub из гостя):

| Контроль | Наблюдение |
| --- | --- |
| `install-singbox.sh` | exit 0; загрузил и установил; `[vs-router-singbox] installed … 1.14.2` |
| SHA256 установленного ELF | `fc9c6e6a…d7b8` == пин ADR-0012 |
| `sing-box version` | `1.14.2`, `Revision: af6e64c3…6709` |
| режим/владелец | `755 root:root` |
| повторный запуск | `already present and verified …; nothing to do` (сеть не трогалась) |
| подменённый архив | ERROR «archive SHA-256 does not match», ничего не установлено (exit 1) |

**B. AppArmor-оверрайд** (каузально, на сгенерированных split-конфигах из lab-34):

| Контроль | Наблюдение |
| --- | --- |
| без оверрайда (пустой local, reload ok) | `aa-exec -p unbound -- cat …/tproxy-unbound-selected.conf` → `Permission denied`; юнит `is-active=activating`, journal `Could not open … Permission denied` → процесс падает (fail-closed). |
| блок из `install.sh` | exit 0; local = `/etc/vs-router/applied/** r,`; профиль загружен (`aa-status`); конфайн-чтение теперь разрешено; повтор — одна строка (идемпотентно). |
| с оверрайдом | оба юнита `active`; реальные UID `/proc/<pid>/status` = 29092 (selected) / 29093 (ordinary); слушают `10.212.1.1:53` и `10.212.3.1:53`; `router.test`→`192.0.2.77`; selected unmatched → loopback-стаб `203.0.113.8`; ordinary unmatched → WAN-origin `203.0.113.7`. |

Cleanup подтверждён: бинарник и каталог удалены, юниты отсутствуют/`inactive`,
dummy-интерфейс и пользователи удалены, local-файл пуст, строка профиля
`#include` восстановлена.

## Что это доказывает

- Пиннутый бинарник sing-box **реально доставляется** install-time шагом:
  скачивается, сверяется по SHA256 архива и ELF, проверяется version+provenance,
  устанавливается в путь, который ждёт агент; повтор идемпотентен, подмена
  архива отвергается — всё fail-closed.
- Значения пинов в упаковке и в адаптере совпадают (тест), т.е. доставленный
  бинарник проходит `singbox_service.verify_binary`.
- AppArmor-оверрайд из `install.sh` **устраняет** блокировку Debian-профиля для
  сгенерированных конфигов: без оверрайда confined Unbound не читает конфиг и
  падает; с оверрайдом он стартует под непривилегированным UID и обслуживает DNS.
- Шаг упаковки аддитивен: существующие стадии bootstrap/update, golden и
  path-пути не изменены.

## Что это **НЕ** доказывает

- **Не** продуктовый apply/boot: VM-проба ставила юниты/конфиги и оверрайд
  напрямую, а не через реальный apply-цикл агента и не через полный
  `bootstrap.sh` (отдельно не запускался). Порядок фаз и readiness агента —
  предмет unit-тестов, не этого прогона.
- **Не** полная установка по релизу: bootstrap вызывается на чистой системе;
  здесь проверен только шаг `stage_singbox` в изоляции (скрипт).
- **Не** подпись sigstore: ADR-0012 допускает проверку аттестации, но
  install-time шаг опирается на HTTPS+SHA256 (пин), как и допустимо при
  недоступности `gh`/Fulcio; проверка подписи в этом шаге не выполняется.
- **Не** открытие gate: `tproxy.not_available` закрыт, TProxy не включается.
- **Не** IPv6, DoT/DoH, chroot-режим Unbound, другие Debian-ревизии профиля.
- **Не** замена golden и не претензия на «готовность» продукта.

## Как воспроизвести

```
# host: бандл lab-35 (install-singbox.sh + блок AppArmor из install.sh +
#       сгенерированные split-конфиги/юниты из lab-34 + runchecks.sh)
cd /home/poshl9k/GitHub/software-routing-software
# блок AppArmor извлекается из актуального install.sh (см. runchecks.sh рядом)
cd /home/poshl9k/.hermes/cache/scratch/vm-lab
tar czf lab35.tgz -C lab35 .
bash vm-push.sh lab35.tgz /root/vsr-probe \
  "rm -rf lab35 && mkdir -p lab35 && tar xzf lab35.tgz -C lab35 && bash lab35/runchecks.sh"
```

Штатная проверка репозитория: из `backend/` `uv run --no-sync pytest -q` →
**808 passed** (было 802; +6 новых, 0 падений). Golden не менялись.
