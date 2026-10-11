# REF-DOCS: sing-box в awg-manager

Источник: шесть HTML-снимков `/tmp/awgm-docs/`; ссылки ниже ведут на соответствующие опубликованные страницы. Это каталог понятий и требований из документации, а не утверждение о том, что возможности уже реализованы в vs-router. Keenetic/NDMS/Entware/OpkgTun — платформенные детали референса, не обязательная архитектура Linux-панели.

## Страница index.html

Назначение: обзор места sing-box в awg-manager: отдельный от AmneziaWG движок и навигация по туннелям, подпискам и маршрутизации. [Источник](https://awgm.hoaxisr.ru/guide/singbox/).

### Понятия

- Sing-box — дополнительный движок для VLESS/Reality, Trojan, Shadowsocks, Hysteria2, NaiveProxy, Mieru; работает параллельно с AmneziaWG, не заменяет его. [index.html](https://awgm.hoaxisr.ru/guide/singbox/).
- Уровни «Расширенный» и «Продвинутый» — ограничители видимости: разделы sing-box начиная с первого, Sing-box Router — со второго. Entware на внешнем USB — требование установки именно на целевом роутере awg-manager. [index.html](https://awgm.hoaxisr.ru/guide/singbox/).

### Процессы

1. Подготовить внешнее хранилище с Entware → установить/обновить sing-box из UI. 2. Импортировать туннель либо подписку. 3. Для маршрутизации устройств перейти к Sing-box Router, выбрать TProxy или Fake-IP (TUN). Подробности этих шагов — на специализированных страницах. [index.html](https://awgm.hoaxisr.ru/guide/singbox/).

### Требуемые возможности UI

- Установка/обновление движка; разделы «Sing-box туннели», «Sing-box подписки», «Sing-box Router» с уровневой видимостью и ссылками на настройку. [index.html](https://awgm.hoaxisr.ru/guide/singbox/).

## Страница tunnels_.html

Назначение: импорт и жизненный цикл отдельного sing-box-туннеля, плюс AWG3 endpoint внутри движка. [Источник](https://awgm.hoaxisr.ru/guide/singbox/tunnels/).

### Понятия

- Share-link — одна прокси-ссылка на сервер; отдельный импорт даёт отдельный туннель и Proxy-интерфейс NDMS. `tag` — имя выхода, из фрагмента `#` ссылки либо автоматически. Точный актуальный перечень схем — в подсказке мастера «Один сервер», а не фиксированный список из текста; `vmess://` распознаётся, но не импортируется. [tunnels_.html](https://awgm.hoaxisr.ru/guide/singbox/tunnels/).
- «Группа серверов» — несколько ссылок под общим Proxy NDMS с ручным/автоматическим выбором, в отличие от нескольких отдельных импортов. WG endpoint — AmneziaWG 3.0 как выход sing-box, а не kernel-туннель. Kernel-интерфейс (например `t2s0`) нужен для iperf3-теста скорости; проверка delay — отдельная операция. [tunnels_.html](https://awgm.hoaxisr.ru/guide/singbox/tunnels/).

### Процессы

1. Главная → таб «Sing-box туннели» → при отсутствии движка «Установить»; выбрать «Один сервер» (отдельные Proxy), «Группа серверов» (общий Proxy) или «Подписка по URL». [tunnels_.html](https://awgm.hoaxisr.ru/guide/singbox/tunnels/).
2. Вставить ссылки по одной на строку либо перетащить `.json/.txt/.yaml`; пустые строки и комментарии `#` пропускаются. Канонический JSON mieru (`mieru apply config`) учитывает `activeProfile`, игнорирует лишние клиентские поля; `mierus://` поддерживает несколько портов/диапазоны. Нажать «Импортировать ссылки» → получить число импортов и ошибки с номерами строк → вернуться к карточкам. [tunnels_.html](https://awgm.hoaxisr.ru/guide/singbox/tunnels/).
3. В карточке раскрыть сервер/порт, проверить задержку либо открыть «Изменить» → секции по протоколу → «Сохранить». Параметры WS из ссылки read-only. «Удалить» требует подтверждения; референс убирает связанные inbound/outbound/route-rule и Proxy NDMS, при удалении последнего туннеля останавливает движок и удаляет слот туннелей. [tunnels_.html](https://awgm.hoaxisr.ru/guide/singbox/tunnels/).
4. Опционально: таб «WG endpoints» → «Импорт AWG3» → tag + текст/файл JSON или `.conf` → проверка задержки, переименование или удаление. Для туннеля с kernel-интерфейсом: «Тест скорости» → выбрать iperf3-сервер → пинг, загрузка, отдача → увидеть Mbps либо отменить. [tunnels_.html](https://awgm.hoaxisr.ru/guide/singbox/tunnels/).

### Требуемые возможности UI

- Табы AWG / sing-box-туннели / подписки, счётчик туннелей, баннер установки с фазами, мастер импорта с подсказкой форматов и ошибками строк; строка статуса движка (версия, работает, PID). [tunnels_.html](https://awgm.hoaxisr.ru/guide/singbox/tunnels/).
- Карточка: tag, Proxy NDMS/kernel-интерфейс, протокол/транспорт/Reality/TLS, скрываемые сервер и порт, SNI либо логин, delay sparkline за 5 минут, статусы ok/slow/fail/stopped, ручная проверка, RX/TX счётчики и мини-график, «Изменить»/«Удалить»/условный тест скорости. Пороги delay: до 200 мс зелёный, 200–500 мс жёлтый, два таймаута подряд красный. [tunnels_.html](https://awgm.hoaxisr.ru/guide/singbox/tunnels/).
- Редактор: общие сервер/порт; VLESS UUID/Flow, TLS SNI/Fingerprint (chrome/firefox/safari/edge), Reality Public Key/Short ID, параметры gRPC/WS; Hysteria2 пароль, SNI, Insecure; NaiveProxy пользователь/пароль. WG endpoint: импорт JSON/`.conf`, tag, хост, delay, read-only серверные AWG-таймеры. [tunnels_.html](https://awgm.hoaxisr.ru/guide/singbox/tunnels/).
- Туннель как цель маршрутизации NDMS/DNS/IP/политики/устройства и как outbound в sing-box Router — разные способы использования одного выхода. [tunnels_.html](https://awgm.hoaxisr.ru/guide/singbox/tunnels/).

## Страница subscriptions_.html

Назначение: групповой выход с каталогом серверов, загрузкой из URL либо инлайн-источника и управлением его составом. [Источник](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).

### Понятия

- Подписка — один логический туннель/Proxy NDMS и один composite outbound `selector` или `urltest`; member — один внутренний сервер без собственного Proxy NDMS. Поэтому цель роутерного правила — подписка, не member. [subscriptions_.html](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).
- Источник — URL провайдера либо вручную вставленный список (inline). Разбор тела: base64 → извлечение share-link из HTML → построчный текст; поддержан канонический JSON mieru, `vmess://` пропускается. `selector` фиксирует выбранный member; `urltest` периодически проверяет URL и выбирает быстрейший. [subscriptions_.html](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).
- Стабильный tag member — детерминированный идентификатор по протоколу/адресу/порту/учётным данным для сопоставления после обновления; `activeMember` — сохранённый ручной выбор. Сирота — member, исчезнувший из источника, но оставшийся из-за возможных ссылок в правилах/выборе. Исключённый сервер сохраняет запрет на импорт после обновления; скрытый regex-фильтром сервер не материализуется в конфиге. [subscriptions_.html](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).
- Сводная группа — selector/urltest поверх серверов нескольких подписок, со своими фильтром, режимом выбора, портом и Proxy NDMS. [subscriptions_.html](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).

### Процессы

1. Главная → «Sing-box подписки» → «Подписка по URL» или «Группа серверов» (inline) → имя, URL/текст, режим ручной/auto; для URL — HTTP-заголовки и период (от часа до недели или вручную) → создать. [subscriptions_.html](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).
2. Открыть карточку (последняя загрузка, количество, активный сервер, время обновления) → «Серверы»; «Проверить всё» для delay. В `selector` выбрать карточку member (сохранить activeMember); в `urltest` читать текущий выход через Clash API, ручной выбор не доступен. Для inline добавлять/удалять member вручную; URL-список править обновлением источника. [subscriptions_.html](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).
3. Для URL-сервера нажать «Исключить» либо «Выбрать» → массовое исключение; на вкладке «Исключённые» вернуть один/несколько. Настроить regex «включать только»/«исключать» по имени (Go RE2, без lookahead); изменение сразу переприменяет состав. [subscriptions_.html](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).
4. «Настройки» → изменить имя/URL/заголовки/период/«Включена», режим selector/urltest и параметры проверки → сохранить. «Обновить сейчас» или дождаться периодического fetch: новые добавятся, прежние обновятся по tag, пропавшие станут сиротами. Проверить зависимости перед «Очистить сирот». При необходимости удалить всю подписку вместе с выходами и Proxy. Сводные группы собираются из актуальных источников при применении изменений. [subscriptions_.html](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).

### Требуемые возможности UI

- Вкладки «Серверы»/«Исключённые» (с бейджем)/«Настройки»; статусы загрузки, обновления и активного member, индивидуальные delay/sparkline; кнопки «Проверить всё», «Обновить сейчас», выбор, исключение/возврат, очистка сирот, удаление подписки. [subscriptions_.html](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).
- Форма источника: тип URL/inline, название, URL/текст, headers с пресетами User-Agent/устройства (sing-box, Clash/mihomo, Happ iOS), интервал, включена; режим selector/urltest с параметрами. Inline показывает бейдж «Список вручную» вместо полей URL/headers. Поля include/exclude regex и блок «Скрыто фильтром»; отдельная секция «Сводные группы». [subscriptions_.html](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).
- Различать автообновление серверов sing-box и автообновление DNS-подписок NDMS — это разные механизмы. [subscriptions_.html](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).

## Страница router-quickstart_.html

Назначение: ручной пример настройки RuTube через TProxy с отдельными маршрутом и DNS; альтернативы — шаблон и мастер. [Источник](https://awgm.hoaxisr.ru/guide/singbox/router-quickstart/).

### Понятия

- Источник — весь LAN либо устройства в политике доступа NDMS; `rule_set` `geosite-rutube` — remote `.srs` с доменами RuTube; download detour — выход для загрузки набора; DNS detour — выход для обращения к DNS-серверу. Эти detour настраиваются отдельно от выхода пользовательского трафика. [router-quickstart_.html](https://awgm.hoaxisr.ru/guide/singbox/router-quickstart/).

### Процессы

1. Установить sing-box, включить уровень «Продвинутый», иметь туннель/подписку; на Sing-box: TProxy выбрать «Устройства в политике» либо весь LAN. Создать/выбрать политику, назначить ей устройство и интерфейс провайдера. [router-quickstart_.html](https://awgm.hoaxisr.ru/guide/singbox/router-quickstart/).
2. Перейти в «Эксперт» → Rule-sets → «+ Набор»: Remote, tag `geosite-rutube`, Binary `.srs`, URL `https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-rutube.srs`, интервал `24h`, download detour auto/direct (или туннель при блокировке источника). [router-quickstart_.html](https://awgm.hoaxisr.ru/guide/singbox/router-quickstart/).
3. «Правила маршрутизации» → «+ Правило»: matcher Rule sets = `geosite-rutube`, действие «Направить», выход = нужный туннель (в примере `awg-sys-Wireguard0`). [router-quickstart_.html](https://awgm.hoaxisr.ru/guide/singbox/router-quickstart/).
4. «DNS-серверы» → «+ Сервер»: tag `rutube-dns`, UDP, порт 53, адрес публичного DNS, detour = тот же туннель, стратегия `prefer_ipv4`; «DNS-правила» → «+ Правило»: Rule sets `geosite-rutube` → `rutube-dns`. Иначе DNS может дать регионально неверный IP либо пойти в обход туннеля. [router-quickstart_.html](https://awgm.hoaxisr.ru/guide/singbox/router-quickstart/).
5. Сохранить (автоматическое применение/перезапуск), «Параметры sing-box» → «Включить»; проверить netfilter/TPROXY; с целевого устройства открыть сайт, в мониторе соединений проверить outbound, при проблеме — matcher и DEBUG-журнал DNS/rule-set. [router-quickstart_.html](https://awgm.hoaxisr.ru/guide/singbox/router-quickstart/).

### Требуемые возможности UI

- Карточка источника/политики, переключатель Простой/Эксперт, конструктор remote-набора (тип, tag, формат, URL, интервал, detour), редактор маршрутного правила (набор, действие, выход), DNS-сервера (tag, тип, адрес, порт, detour, стратегия), DNS-правила (набор, сервер), кнопка включения и диагностика зависимостей. [router-quickstart_.html](https://awgm.hoaxisr.ru/guide/singbox/router-quickstart/).
- Простой путь: шаблоны сервисов и мастер первичной настройки «политика + правила + DNS»; живые соединения и DEBUG-журнал для проверки результата. [router-quickstart_.html](https://awgm.hoaxisr.ru/guide/singbox/router-quickstart/).

## Страница router_.html

Назначение: справочник режимов перехвата, редакторов, объектов и наблюдаемости маршрутизации sing-box. [Источник](https://awgm.hoaxisr.ru/guide/singbox/router/).

### Понятия

- TProxy — netfilter-перехват без смены IP; источник: политика либо весь LAN. FakeIP — DNS выдаёт синтетический IP (пул по умолчанию `198.18.0.0/15`), запоминает домен и направляет трафик через TUN/OpkgTun; нужен DNS sing-box `172.18.0.2` (IPv6 `fdfe:dcba:9876::2`) у клиента/роутера; собственный DoH/DoT клиента обходит FakeIP. Policy-tun — выход политики Keenetic через OpkgTun, отдельный рекомендуемый способ завести трафик в движок. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).
- Правило маршрутизации — matcher по домену, IP/CIDR, source-IP, порту, протоколу либо rule-set + действие: направить в outbound/direct или `reject`; порядок сверху вниз, первое совпадение. Системные sniff/hijack-dns/локальный direct идут перед пользовательскими. `final` — выход по умолчанию при отсутствии совпадений (`direct` по умолчанию). Rule-set: remote `.srs`/URL/интервал/download detour, local-файл, inline-условия, быстрый Geosite/GeoIP. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).
- DNS-контур — UDP/TLS/HTTPS upstream, default server, hijack-dns, DNS-правила доменов/наборов, DNS Rewrite (домен/glob/regex → IP). Действия DNS-правил: Route/Маршрут (терминирует), Block (NXDOMAIN/REFUSED/Drop, терминирует), Evaluate (сохранить ответ с необязательным tag, продолжить), Respond (вернуть сохранённое, терминирует). По сохранённому ответу: Rcode/IP CIDR/RR Answer/NS/Extra, Race; для Route/Evaluate — спекулятивный запрос. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).
- Composite outbound — `selector`/`urltest` под единым tag; подписочные группы управляются только в подписках. «Интерфейс» — direct-выход, привязанный к сетевому интерфейсу роутера; отдельный LAN SOCKS5/HTTP-прокси даёт приложению выход через выбранный outbound без TProxy. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).

### Процессы

1. Простой TProxy: выбрать источник (политика/весь роутер) → при пустой конфигурации мастер «сервисы → туннель → устройства → Применить», иначе «+ Правило»: шаблон сервиса или домены/IP/CIDR/порты/geosite:/geoip: → туннель/direct/block → превью → упорядочить правила; системные строки не редактировать. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).
2. Открыть карточку движка → проверить версию, состояние и netfilter/TPROXY → включить/выключить/перезапустить. В эксперте настроить sniff, UDP timeout, обход портов/диапазонов/подсетей/GeoIP, TProxy DSCP-классы; missing netfilter показать как блокирующую зависимость. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).
3. Эксперт: добавить rule-set/выходы/правила/final, DNS upstream и правила; для DNS-цепочки Evaluate → правило с «Ответ evaluate» + условия ответа → Respond/Route/Block. Альтернатива — пресеты «Отказоустойчивый» и «Анти-подмена» с подозрительными CIDR; в FakeIP эти пресеты недоступны. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).
4. Массово выбрать обычные правила с выходом → заменить outbound и применить (TProxy через общий черновик, FakeIP сразу); аналогично заменить detour у remote-наборов. При невалидном элементе отклонить всю пачку. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).
5. В FakeIP отдельно настроить Inbounds/Outbounds/Rule sets/DNS/Маршруты/Устройства; дать целевому клиенту DNS sing-box и выбрать DNS-наборы для синтетических ответов; проверить ограничения DoH/DoT. Это изолированный от TProxy конфиг. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).
6. В редакторе слотов просмотреть автогенерируемые конфиги read-only, отредактировать пользовательский `90-user.json`: сохранить черновик → проверить теги и `sing-box check` → применить/отменить либо выключить слот. При ошибке после исчезновения зависимого tag не перезагружать сломанный конфиг, показать причину. По счётчику соединений открыть live-монитор, фильтровать, искать, смотреть сработавшее правило/выход/трафик и закрывать соединение. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).

### Требуемые возможности UI

- Вкладки TProxy/FakeIP при доступном движке, Простой/Эксперт для TProxy; в FakeIP — Обзор, Inbounds, Outbounds, Rule sets, DNS, Маршруты, Устройства, Соединения, Журнал; предупреждения об условиях DNS и зависимостях. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).
- Движок: enabled/version/netfilter/TPROXY, start/stop/restart, sniff, UDP timeout, bypass TCP/UDP портов и диапазонов/CIDR/GeoIP, до 8 DSCP→outbound; экспертные счётчики правил, наборов, выходов, DNS, rewrite, прокси. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).
- Правила: сортировка, шаблоны и ручные matcher'ы, действия и final, выбор существующих outbound-групп; формы remote/local/inline/Geosite/GeoIP rule-set с detour, массовые изменения с атомарной валидацией. DNS: тип/адрес/порт/выход upstream, default, правила/действия/evaluate-ответы, rewrite, пресеты и трассировка цепочки. [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).
- Секции Outbounds/composite/interface и LAN SOCKS5/HTTP-прокси; редактор автослотов и пользовательского слота с ошибками JSON, draft/check/apply; монитор Clash API (источник, назначение, правило, outbound, трафик, live-статус, закрытие). [router_.html](https://awgm.hoaxisr.ru/guide/singbox/router/).

## Страница glossary_.html

Назначение: модель пути пакета, сравнение способов завести трафик в sing-box и словарь терминов. [Источник](https://awgm.hoaxisr.ru/guide/singbox/glossary/).

### Понятия

- Inbound — вход в движок (tun/TPROXY/DNS). Sniff — извлечение имени из TLS SNI, HTTP Host или QUIC; при ECH/не-HTTP имени может не быть, остаётся IP. Outbound — выход: туннель, composite, direct; блокировка — действие `reject`. `final` — выход для unmatched-трафика. [glossary_.html](https://awgm.hoaxisr.ru/guide/singbox/glossary/).
- Rule set — повторно используемые условия (remote/local/inline/Geosite/GeoIP); detour — outbound собственных запросов движка (DNS или скачивание набора). hijack-dns — перехват клиентского DNS на порту 53 встроенным резолвером (DoH/DoT не перехватывается). FakeIP pool — адреса-заглушки, по умолчанию `198.18.0.0/15`; OpkgTun — Keenetic-интерфейс для tun и политики; сетевой стек — сборка TCP/UDP из IP-пакетов tun, `sing-tun` используется по умолчанию с sing-box 1.15. [glossary_.html](https://awgm.hoaxisr.ru/guide/singbox/glossary/).
- Путь: устройство → inbound → sniff → DNS-правила (для DNS-запроса) либо маршрутные правила (first match) → outbound из правила либо final. Политики+TUN пропускают весь трафик политики; TProxy перехватывает выбранные устройства/весь LAN; FakeIP затрагивает только домены, которым выдали синтетические адреса. [glossary_.html](https://awgm.hoaxisr.ru/guide/singbox/glossary/).

### Процессы

1. Выбрать вход: политика+OpkgTun (весь трафик политики и возможный kill-switch при единственном выходе), TProxy (netfilter, без подмены IP), FakeIP (клиент пользуется DNS `172.18.0.2`, получает fake-адрес → TUN). [glossary_.html](https://awgm.hoaxisr.ru/guide/singbox/glossary/).
2. Ставить системные sniff/DNS/local-direct правила перед пользовательскими; упорядочить пользовательские, выставить final (по умолчанию direct); для FakeIP ограничить DNS-правила нужными доменами и предупредить о собственном DoH/DoT. [glossary_.html](https://awgm.hoaxisr.ru/guide/singbox/glossary/).

### Требуемые возможности UI

- Схема «источник → inbound → sniff/DNS → правила → outbound/final», ясный выбор режима ввода трафика и аудит источника/охвата; опции sniff, DNS hijack, default outbound, fake-IP пул/DNS и стек TUN; пояснения ограничений ECH и DoH/DoT. [glossary_.html](https://awgm.hoaxisr.ru/guide/singbox/glossary/).

## Карта терминологии: awg-manager → vs-router

Ниже «→» означает рекомендуемое имя/аналог в vs-router, не гарантию функционального паритета. Текущие имена `ProxyOutbound`, `TProxyRule`, `TProxyDNS*`, «Простой/Эксперт», «Конечное действие» сверены с [docs/tproxy-ui-parity.md](tproxy-ui-parity.md); особенности референса — по [tunnels](https://awgm.hoaxisr.ru/guide/singbox/tunnels/), [subscriptions](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/), [router](https://awgm.hoaxisr.ru/guide/singbox/router/), [glossary](https://awgm.hoaxisr.ru/guide/singbox/glossary/).

| awg-manager | vs-router: термин / граница |
| --- | --- |
| Sing-box туннель, outbound, tag | «Прокси-выход» (`ProxyOutbound`), тег выхода; не путать с входом/системным интерфейсом. |
| Proxy-интерфейс NDMS | Сетевой интерфейс/привязка выхода, если существует; NDMS-объект не переносить буквально на Linux. |
| Подписка; member | «Подписка» / «сервер подписки»; один групповой выход, внутренний сервер не становится отдельным интерфейсом. URL-fetch пока отдельно от импорта ссылок. |
| Композит, selector, urltest; activeMember | «Группа выходов», «ручной выбор», «автовыбор по задержке», «активный сервер»; не считать импорт нескольких отдельных ссылок подпиской. |
| Sing-box Router / Sing-box: TProxy | «Выборочная маршрутизация (TProxy)», правила `TProxyRule`; простой/эксперт — разные представления одного конфига. |
| Правило, matcher, действие, final | «Правило», «условия», «действие/выход», «Конечное действие» (`TProxy.final`); direct/block/route сохраняют разную семантику. |
| Rule set, remote/local/inline, download detour | «Набор правил», «источник набора», «скачивать через выход»; отличный от DNS detour объект. |
| DNS-сервер, DNS-правило, hijack-dns | «DNS-политика sing-box» (`TProxyDNS*`), «перехват DNS»; не путать с общесистемным DNS и DNS-подписками NDMS. |
| Inbound, TProxy, FakeIP, Policy-tun/OpkgTun | «Вход», «TProxy-перехват», «Fake-IP/TUN», «источник через политику/TUN»; не приписывать Linux реализацию Keenetic-специфичного OpkgTun. |
| sniff, detour, delay check, speed test | «Анализ трафика», «выход собственных запросов», «проверка задержки», «тест скорости (iperf3)» — разные функции. |
| «Соединения», Clash API | «Монитор соединений»; runtime-функция, не эквивалент статического предпросмотра. |

## Функциональные требования для паритета

1. Управлять выходами по ссылкам/файлам и группами: поддерживаемые схемы, ошибки строк, сохранение параметров протокола, отдельные теги, карточки со статусами и задержкой. [tunnels](https://awgm.hoaxisr.ru/guide/singbox/tunnels/).
2. Подписка URL/inline с заголовками, автообновлением, стабильными member, исключениями/фильтрами/сиротами, selector/urltest и групповым выходом; не смешивать с DNS-подписками. [subscriptions](https://awgm.hoaxisr.ru/guide/singbox/subscriptions/).
3. Выбирать источник/режим входа и управлять состоянием движка, правилами first-match и final, rule-set источниками/обновлением/detour и привязанными выходами. FakeIP/TUN и policy-tun — отдельные режимы, не называть их уже готовыми из-за наличия TProxy. [router](https://awgm.hoaxisr.ru/guide/singbox/router/), [glossary](https://awgm.hoaxisr.ru/guide/singbox/glossary/).
4. Строить DNS-контур вместе с маршрутом: upstream UDP/TLS/HTTPS, detour, DNS-правила и hijack; для расширенного паритета — rewrite, evaluate/respond и диагностика цепочек. [quickstart](https://awgm.hoaxisr.ru/guide/singbox/router-quickstart/), [router](https://awgm.hoaxisr.ru/guide/singbox/router/).
5. Дать простой мастер/пресеты и экспертные формы, безопасное применение с проверкой, монитор соединений/журнал и ясные предупреждения о зависимостях и ограничениях DNS. [router](https://awgm.hoaxisr.ru/guide/singbox/router/), [quickstart](https://awgm.hoaxisr.ru/guide/singbox/router-quickstart/).

Граница текущей реализации по [документу vs-router](tproxy-ui-parity.md): импорт share-links и черновик TProxy/DNS UI описаны как сделанные слайсы; fetch URL-подписок и runtime-монитор отмечены отдельными/не готовыми, FakeIP/policy-TUN — вне объёма того слайса. Это не результат проверки работающего стенда.
