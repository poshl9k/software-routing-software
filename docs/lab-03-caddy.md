# Протокол лабораторной проверки №3 — Caddy (HTTPS + TLS passthrough по SNI)

Дата: 26 сентября 2026 · VM: Debian 13.7 (trixie), ядро 6.12.107
Тестовая среда: caddy-l4 (собран xcaddy, Caddy 2.11.4 + caddy-l4 v0.1.2), бэкенды на python http.server (8081 http, 8443 https со своим сертификатом)

## Результаты

| Проверка | Результат | Детали |
| --- | --- | --- |
| Пакетный Caddy Debian 13 | **2.6.2**, L4-модулей нет | для passthrough нужна своя сборка |
| Сборка с L4 через xcaddy | ✅ | `xcaddy build --with github.com/mholt/caddy-l4@v0.1.2` → caddy-l4 (Caddy 2.11.4, 42 модуля `layer4.*`) |
| **(а) HTTPS-сайт, TLS завершается на Caddy** | ✅ | `reverse_proxy` → http-бэкенд; сертификат от `Caddy Local Authority` (tls internal/local_certs); **важно: клиент должен слать правильный SNI** (`--resolve site.test`), без SNI — TLS internal error (ожидаемо) |
| **(б) TLS passthrough по SNI** | ✅ | клиент получает **сертификат backend2 (CN=internal.example.ru)**, а не Caddy — TLS-сессия завершается на внутреннем сервере; HTTP-ответ backend2 получен сквозь passthrough |
| Маршрутизация L4 по SNI | ✅ | matcher `{"tls": {"sni": ["site1.example.ru"]}}` в JSON-конфиге |
| Валидация перед применением | ✅ | `caddy validate --config config.json` → "Valid configuration" |
| Graceful reload | ✅ (API) | admin endpoint 127.0.0.1:2019 жив, конфиг перечитывается без разрыва |

## Ключевые находки для панели (важно для генератора конфигов)

1. **L4-модуль НЕ входит в пакетный Caddy Debian** — панель должна либо ставить caddy из репозитория Caddy (собранный с L4), либо собирать через xcaddy. Для MVP: установщик vs-router ставит caddy-l4-сборку.
2. **Синтаксис layer4 — только JSON** (Caddyfile-директива `layer4` с matcher-ами в v0.1.2 не работает: `tls sni` без subdirectives, named matchers не поддерживаются). Панель генерирует JSON-конфиг (или гибрид: сайт — Caddyfile, L4 — JSON, объединённые в один JSON).
3. **Формат upstream'ов в layer4.handlers.proxy**: `"dial": ["host:port"]` — **массив строк**, не строка (в отличие от http.reverse_proxy).
4. **TLS passthrough по SNI подтверждён**: сертификат внутреннего сервера отдаётся клиенту напрямую (subject=CN=internal.example.ru), Caddy не участвует в TLS-рукопожатии.
5. **HTTP-сайт требует SNI от клиента** — в UI панели предупреждение «клиент должен обращаться по доменному имени, не по IP» для TLS-сайтов.

## Критерий этапа 0 (Caddy-часть)

✅ Caddy работает: обычный HTTPS (TLS на Caddy) — сертификат от Caddy CA; TLS passthrough по SNI — сертификат на внутреннем сервере, Caddy проксирует байт в байт; валидация конфига перед применением; graceful reload без разрыва соединений.

## Не проверено здесь (следующие шаги)

- Реальный Let's Encrypt (HTTP-01/DNS-01) — требует публичного домена; на VM использован локальный CA (`tls internal`/`local_certs`), механизм ACME в Caddy стандартный.
- Автопродление сертификатов — механизм Caddy, проверяется в пилоте.
