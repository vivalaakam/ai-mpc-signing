# Подпись MPC

Десктоп-клиент, командная строка и сервер для пороговой подписи Ed25519 (FROST). Доля ключа хранится в SQLite на устройстве и на сервер не уходит. Раунд 2 генерации ключа запечатан ключом устройства.

## Сервер

Нужен PostgreSQL: база `ai-signing`, пользователь `postgres`, пароль `postgres`.

```bash
cargo run -p ai-signing-server
```

Слушает `127.0.0.1:8080`. Адрес задаётся переменной `BIND`, строка подключения — `DATABASE_URL`.

## Конфиг клиента

Адрес сервера задаётся в конфиге, поле `server`:

```toml
server = "http://127.0.0.1:8080"
```

Если файла ещё нет, клиент создаёт его с этим адресом. Пути к конфигу и к локальной базе можно передать при запуске окна и командной строки:

```bash
--config /путь/config.toml --database /путь/client.sqlite
```

Без этих флагов конфиг лежит в каталоге конфигурации, база — в каталоге данных (`ai-signing`). Переменная `AI_SIGNING_HOME` задаёт один каталог для обоих файлов: `config.toml` и `client.sqlite`.

## Пользователи сервера

`ai-signing-admin` создаёт учётную запись на сервере. Адрес берётся из конфига, локальная база не нужна.

```bash
cargo run -p ai-signing-cli --bin ai-signing-admin -- --config /tmp/alice.toml create-user eve password1 админ
cargo run -p ai-signing-cli --bin ai-signing-admin -- --config /tmp/alice.toml create-user alice password1 подписант
cargo run -p ai-signing-cli --bin ai-signing-admin -- --config /tmp/alice.toml users
cargo run -p ai-signing-cli --bin ai-signing-admin -- --config /tmp/alice.toml delete-user alice
```

Роль указывается при создании: `админ` или `подписант`. Группу создаёт администратор. Подписант входит в клиент и участвует в подписи. `delete-user` удаляет учётную запись и группы, которые этот пользователь создал. Из остальных групп он исключается.

## Окно

```bash
cargo run -p ai-signing-desktop --bin ai-signing-gui
```

Войдите под пользователем, которого создал администратор сервера. Пока окно открыто, оно держит связь с сервером и участвует в протоколе. Администратор создаёт группу и отмечает в ней активных подписантов. Подписант видит свои группы и запросы на подпись.

## Командная строка

Без команды открывается текстовый интерфейс. Он тоже держит связь и участвует в протоколе.

```bash
cargo run --bin ai-signing-cli -- --config /tmp/alice.toml --database /tmp/alice.sqlite
```

`q` закрывает интерфейс, `w` выходит из учётной записи, `u` обновляет списки. Администратор клавишей `n` создаёт группу: отмечает подписантов пробелом и подтверждает Enter. `d` запускает генерацию ключа. Подписант на вкладке запросов подтверждает подпись клавишей `a` и отклоняет её клавишей `r`.

Активный подписант — это пользователь с ролью подписанта, который уже входил в клиент и у которого есть ключ устройства. Список таких подписантов запрашивает вошедший администратор.

Остальные команды, пока открыты интерфейс, окно или `watch` с той же базой, передаются этому процессу. На время генерации ключа и подписи у каждого подписанта должен быть открыт клиент.

```bash
cargo run --bin ai-signing-cli -- --config /tmp/alice.toml --database /tmp/alice.sqlite login alice password1
cargo run --bin ai-signing-cli -- --config /tmp/eve.toml --database /tmp/eve.sqlite create-group treasury 2 alice bob
cargo run --bin ai-signing-cli -- --config /tmp/alice.toml --database /tmp/alice.sqlite watch
```

Команды: `login`, `logout`, `whoami`, `groups`, `group`, `signers`, `create-group`, `add-member`, `start-dkg`, `inbox`, `approve`, `reject`, `watch`.

Два клиента на одной машине держат данные отдельно:

```bash
AI_SIGNING_HOME=/tmp/alice cargo run --bin ai-signing-cli -- watch
AI_SIGNING_HOME=/tmp/bob cargo run --bin ai-signing-cli -- watch
```

## Запрос на подпись

Когда группа активна, у создателя есть токен API.

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/groups/GROUP_ID/requests \
  -H "Authorization: Bearer API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message_utf8":"invoice-42"}'
```

Статус и подпись:

```bash
curl -s http://127.0.0.1:8080/api/v1/groups/GROUP_ID/requests/REQUEST_ID \
  -H "Authorization: Bearer API_TOKEN"
```
