# Генерация и применение туннелей и Caddy

`wireguard.conf` и `caddy.conf` в pending/applied/confirmed — bundle с маркерами
`### FILE: имя`. Они содержат расшифрованные секреты: запись атомарная, режим
0600. Их нельзя отдавать в preview API или журналировать. Ключ Fernet агент
читает из `VS_ROUTER_SECRET_KEY`; systemd может получить его через root-only
`/etc/vs-router/secrets.env`. Схема snapshot не меняется.

## Туннели

`generate_wg_bundle(version, key_material)` возвращает `<tunnel.name>.conf`,
`<tunnel.name>.peer-<peer.name>.conf` и `manifest.json`. Имя Linux-интерфейса —
`tunnel.interface`, отображаемое имя туннеля может отличаться. Manifest связывает
интерфейс, протокол, setconf-файл, локальные адреса и маршруты.

Setconf-файлы не содержат Address. Адреса берутся из configuration.interfaces.
Хелпер `tunnel_addresses` документирует ограниченный fallback для старой схемы:
сервер — первый хост подсети AllowedIPs, иначе 10.66.66.1/24;
клиент — 10.66.66.2/24. Для нескольких туннелей необходимо явно задать адреса
интерфейсов. AllowedIPs клиента и AllowedIPs серверных пиров устанавливаются
отдельными маршрутами; default получает metric 100. Это MVP main-table routing,
без policy routing и автоматического исключения endpoint из default-маршрута.

Схема Peer хранит только публичный ключ. Поэтому без внешнего ключа экспорт —
явно помеченный TEMPLATE с `<CLIENT_PRIVATE_KEY>`, а не выдуманный приватный ключ.
Для полного экспорта передайте:

```python
key_material = {
    "vpn": {
        "endpoint": "203.0.113.1:51820",
        "peer_private_keys": {"alice": encrypted_secret},
    }
}
```

Приватные ключи клиентов здесь также EncryptedSecret (или его dict). Серверный
публичный ключ вычисляется из приватного X25519. Если endpoint не передан,
используется основной статический WAN IP и listen_port. При динамическом WAN
без известного адреса генератор требует endpoint; DDNS автоматически не угадывается.
Обычный apply передаёт пустой key_material и создаёт шаблоны экспортов.

Демоны устанавливаются как `/usr/local/bin/wg-go` и `/usr/local/bin/awg-go`;
для wireguard-go допустим симлинк wg-go. Инструменты wg/awg и ip нужны в PATH.
Релоадер включает соответствующий `vs-router-wg@` или `vs-router-awg@` экземпляр.
Живой интерфейс получает setconf без рестарта. При запуске ExecStart получает
только имя интерфейса, ExecStartPost ждёт UAPI, затем выполняет setconf, addr,
link up и route replace. Удалённые туннели отключаются; изменённые маршруты и
адреса удаляются. Boot-restore только раскладывает новые файлы, демоны запускает
systemd. Kernel-mode WG пока не управляется этим адаптером.

## Caddy

Нужен бинарник `caddy` с caddy-l4 и caddy-dns/cloudflare; для устанавливаемого
service override он должен быть доступен как `/usr/bin/caddy`. JSON установлен
в `/etc/caddy/caddy.json`, ручные сертификаты — `/etc/caddy/vs-router/`.
JSON и PEM доступны root:caddy с режимом 0640. Перед POST /load выполняется
`caddy validate`; localhost HTTP-транспорт не использует proxy из окружения.
Ошибки проверок возвращаются без stdout/stderr, потенциально содержащих секреты.

HTTP-01 использует ACME и конкретный WAN на 80/443. DNS-01 использует Cloudflare:
текущая схема не содержит выбора DNS-провайдера, токен обязателен. Никакого
internal CA в production JSON нет. Manual использует TLS load_files.
Passthrough получает SNI-route с dial-массивом. При общем WAN:443 L4 пересылает
TLS завершаемых сайтов на отдельный loopback listener (18000 + индекс WAN),
а passthrough — напрямую на upstream. Сайты без wan_address используют основной
статический WAN, либо явно заданный WAN другого сайта, либо wildcard listener.

Golden/fake-тесты проверяют конфиги и последовательности команд без запуска
демонов и без сетевых соединений. Проверка настоящими wg/awg/Caddy и ACME
остаётся интеграционной проверкой на хосте с установленными бинарниками.
