# TCP TProxy: INPUT-авторизация по conntrack mark, а не по подделываемому packet mark

## Граница эксперимента

Авторизованная одноразовая Debian VM `vsr-tproxy-lab` (kernel 6.12.107+deb13-amd64,
nftables 1.1.3, Python 3.13.5). Проба работает только в трёх временных network
namespace `vsr-tcp-router`, `vsr-tcp-client`, `vsr-tcp-origin`; сеть, маршруты и
firewall основного пространства VM не менялись. `vsr-live-403ab3a` не трогалась.
sing-box: `/var/cache/vsr-singbox-probe`, `sing-box version 1.14.2` linux/amd64,
SHA256 `fc9c6e6ab345f045b16a0ed10d1ff28d68e8e56e7749fca30738d1406e98d7b8` (совпадает
с окружением lab-08/09 по версии; хеш повторно снят в этой VM). Публичное
включение TProxy по-прежнему запрещено: `tproxy.not_available` не открывался.

Артефакты (не подключены к bundle/apply/boot, боевые генераторы не изменены):

- `backend/tests/lab/tproxy_tcp_ct_proof_probe.py` — standalone-проба
  (SHA256 `4a1bb324ad91e20a65aa636752c5adfd6c0aeb620ac50dbfd8e21c3061e6a1cd`),
  использует базовые хелперы `tproxy_tcp_probe.py`.
- `backend/tests/lab/generate_tproxy_preauth_cases.py --tcp-ct-proof` — opt-in
  fixture (`__ct_proof__`); обычный firewall/preauth/containment/sing-box JSON
  берутся из настоящих генераторов и не отличаются от baseline.
- `backend/tests/test_tproxy_input_authorization_lab.py` — host-free тесты узости
  и порядка.

## Механика коллизии lab-09 и что именно она ломала

lab-09: порядок `preauth -90 → proof reset -85 → interception/proof setter -80 →
INPUT proof guard -20`. Владение INPUT выводилось из **packet** `meta mark`:
reset обнулял бит `0x200` у каждого пакета, interception выставлял его после
успешного TProxy, guard в INPUT пропускал пакет только при `mark & 0x200`. Проба
lab-09 показала, что конкурирующее привилегированное правило, работающее **после**
reset (priority `-84`), делает `meta mark set meta mark | 0x200` и пропускает
established TCP через INPUT. Packet mark видоизменяем любым writer'ом, который
сработал раньше в пакетном пути, — «proof» из него неподделываемым быть не может.

## Новый дизайн: авторизация по conntrack mark

Владение INPUT выводится не из packet mark, а из **conntrack** mark
(`nf_conntrack`'s mark) — отдельного 32-битного пространства:

1. Reset (`prerouting -85`) очищает conntrack-бит у каждого выбранного пакета:
   `ct mark set ct mark & 0xfffffdff`.
2. Interception (`prerouting -80`) после успешного TProxy-выражения выставляет
   routing packet mark `0x100` **и** conntrack-бит: `ct mark set ct mark | 0x200`.
   `ct mark` хранится в conntrack-записи и общий для всех пакетов потока.
3. Независимый INPUT guard (`input -20`) пропускает выбранный established-пакет
   только при наличии `ct mark & 0x200`:
   `... ct mark & 0x200 == 0 counter drop`.

Почему это устойчиво к инъекции lab-09: инъектор делает `meta mark set meta mark |
0x200` — он не пишет `ct mark`. Reset очищает conntrack-бит, interception (если
удалена) его не восстанавливает, и guard по `ct mark` режет пакет, несмотря на
подделанный packet mark. Reset обязателен: без него conntrack-бит, выставленный во
время здоровой фазы, сохранился бы в записи и авторизовал бы поток после удаления
interception.

## Результат на пакетах (VM, exit 0)

Порядок как в lab-09; каждый опыт открывает отдельный исправный TCP-поток,
подтверждает `ct state established` для точного tuple до fault, затем новый token.
Позиция инъекции `-84` (после reset) — именно та, что обошла packet-mark guard.

| Инъекция | Вход/INPUT ct-drop | INJECTOR | Proxy OUTPUT | Origin/echo | Доставлен token |
| --- | --- | --- | --- | --- | --- |
| Нет (здоровая фаза) | 0 | — | +4 | +4 | да |
| lab-09: `meta mark \| 0x200`, `-84` | **+6** | +6 | 0 | 0 | **нет**, sender timeout |
| Привилегированный `ct mark \| 0x200`, `-84` | 0 | +2 | +2 | +2 | **да** (остаточная граница) |

Ключевая строка пробы: `ct-packet-forge` — `delivered=False`,
`ct_input_drop_delta=6`, `injector_delta=6`, ingress-токен наблюдался, origin и
echo пусты; sender timeout. Компенсирующий контроль `ct-mark-forge` (тот же
приоритет, но пишет `ct mark`) доставил token (`delivered=True`, `echoed=True`,
`ct_input_drop_delta=0`) — воспроизведение границы доверия. После каждого опыта
восстановление (interception + proxy) и положительный контроль
`*-recovered` проходят; explicit off и fresh default-deny handshake проходят.
После пробы `ip netns list` и `nft list tables` пусты, `ip rule` содержит только
стандартные правила.

## Что доказывает и чего НЕ доказывает

**Доказывает (в этих трёх namespace, на реальном пакетном тракте):** точная
инъекция lab-09 (подделка **packet** `meta mark` после reset) больше **не
доставляет** established TCP через INPUT — guard по `ct mark` режет пакет; при
этом здоровый TProxy-поток и recovery проходят. То есть packet-mark forge,
который обошёл дизайн lab-08, нейтрализован сменой пространства владения.

**НЕ доказывает:**

- Неподделываемость против **root/привилегированного writer'а**: правило
  `ct mark set ct mark | 0x200` успешно доставляет token (см. таблицу). Против
  конкурентного root-nftables-writer'а строгая неподделываемость **недостижима в
  принципе** — любой writer, сработавший раньше в пакетном пути, может записать и
  packet mark, и ct mark.
- Позицию инъекции `-86` (до reset) для conntrack-варианта отдельно не гоняли;
  поддержана в `packet_forge_injector`/`ct_forge_injector`, но в этом прогоне
  выполнен только сценарий `-84`, воспроизводящий lab-09.
- Не проверялись: уже буферизованные kernel/proxy байты, proxy OUTPUT, DNS/Unbound,
  IPv6, arbitrary policy routing/ECMP, bridge/offload, atomic apply/rollback/boot,
  failover, удаление самого reset/guard, полный жизненный цикл explicit-off.
- `ct mark` как владение проверен для одного TCP-потока и точного lab-tuple; это
  не доказательство для всех протоколов/потоков и не замена управления порядком
  hook'ов.

## Реальная граница доверия

Поскольку неподделываемость против root недостижима, корректное требование — не
«неподделываемый бит», а **единственный writer** пространства mark/table/hook:
rooth-owned путь apply роутера, который владеет таблицами `vsr_*`, приоритетами
hook'ов и резервированием битов. `ct mark`-дизайн поднимает планку: атакующий
должен быть привилегированным writer'ом conntrack-mark, а не просто любым
локальным nft-правилом, умеющим выставить packet mark. Резервирование
mark-пространства (`docs/tproxy-mark-ownership.md`) остаётся обязательным, но
именно как **контракт единственного владельца**, а не как средство безопасности.

## Тесты и реестр

- Backend suite: **557 passed** через `uv run --no-sync pytest -q` (baseline до
  правок — 516 passed; +41 host-free проверок, из них новый
  `test_tproxy_input_authorization_lab.py` и расширения fixture-тестов).
  Прогон через `env -u PYTHONPATH .venv/bin/python -m pytest -q tests/` даёт один
  pre-existing environmental провал (`test_installer_hardening.py::test_installed_db_migrates_on_rerun`):
  packaging-скрипт вызывает `python3` из системного PATH, где нет alembic —
  не связано с этим изменением.
- `backend/src/vs_router/generators/marks.py`: добавлены
  `MARK_TPROXY_CT_PROOF_{MASK,VALUE,CLEAR_MASK}` с явным комментарием, что это
  **отдельное** (conntrack) пространство, намеренно не внесённое в `REGISTRY`
  (реестр описывает packet-mark namespace), и что оно не является неподделываемым.
  Warning модуля обновлён: зафиксированы новая механика и граница доверия
  «единственный writer». Ни один генератор/bundle/apply/boot не изменён; golden
  не трогались.
