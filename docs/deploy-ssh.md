# Флотовый SSH-ключ (деплой на любую ноду и мастер)

Один ed25519-ключ авторизуется на **root** всех хостов vs-router/vs-master —
текущих и будущих, — чтобы деплой и диагностика не зависели от того, чей
персональный ключ лежит на конкретной машине.

- Приватный ключ: `~/.ssh/vs-router-fleet` (0600, только на рабочей машине
  оператора; в репозиторий и в переписку не попадает).
- Публичный ключ:

  ```
  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICKiFtYFGUaepxZNmNF1Qp9nM4xsd6ClTPiy6/UyJa0F vs-router-fleet@hermes
  ```

- Отпечаток: `SHA256:OLFKM/M1IZ1Ufice14tkirEljb9rKnTvn99rVUfveAc`.

## Авторизация на новом хосте

В консоли хоста (root):

```sh
mkdir -p /root/.ssh && chmod 700 /root/.ssh
grep -q vs-router-fleet /root/.ssh/authorized_keys 2>/dev/null || \
  printf '%s\n' 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICKiFtYFGUaepxZNmNF1Qp9nM4xsd6ClTPiy6/UyJa0F vs-router-fleet@hermes' \
  >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

Идемпотентно: повторный запуск не добавляет дубль. С рабочей машины то же самое:

```sh
ssh root@<host> "mkdir -p /root/.ssh && chmod 700 /root/.ssh && (grep -q vs-router-fleet /root/.ssh/authorized_keys 2>/dev/null || echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICKiFtYFGUaepxZNmNF1Qp9nM4xsd6ClTPiy6/UyJa0F vs-router-fleet@hermes' >> /root/.ssh/authorized_keys) && chmod 600 /root/.ssh/authorized_keys"
```

Проверка:

```sh
ssh -i ~/.ssh/vs-router-fleet -o BatchMode=yes root@<host> 'hostname'
```

## Отпечатки хостов (сверять при первом подключении)

| Хост | Адрес | ED25519 fingerprint |
| --- | --- | --- |
| node rg3 | `rg3.poshl9k.ru` | `SHA256:hd1HUZ6xi6niOZGABnVt20PsPdwVvZ1q8sv7LbEYS98` |
| master | `85.209.159.130` | `SHA256:6Er8kUZgW/9R2BeRLKhGEUmUStlGsLpvc1WLgW0GjtI` |

Смена отпечатка = переустановка хоста или подмена; проверить причину до
подключения (в известных случаях новый отпечаток сохраняется в отдельный
`known_hosts`, как `~/.ssh/known_hosts.rg3`).

## Правила

- Ключ один на флот: он даёт root на всех нодах. Не копировать приватную часть на
  серверы, в бэкапы репозитория и в чужие машины.
- Утечка или уход оператора — ротация: сгенерировать пару, авторизовать новую
  публичную часть по таблице выше, затем вычистить строку с комментарием
  `vs-router-fleet@hermes` из `/root/.ssh/authorized_keys` на всех хостах.
- Персональные ключи (`rg3-diagnose`, `vs-portal-<ip>`) остаются как резервный
  вход; их отзыв — отдельный шаг, не часть ротации флотового ключа.
- Ключ без пароля: он для автоматизации. Компенсация — только root-доступ по
  ключу, отдельный комментарий в `authorized_keys` и перечисленные выше правила.
