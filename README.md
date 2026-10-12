# Подпись MPC

Десктоп-клиент, командная строка и сервер для пороговой подписи Ed25519 (FROST). Личный ключ пользователя создаётся на его устройстве. Для каждой группы из него по пути HD считается отдельный ключ. Сервер хранит только публичные ключи: общий ключ пользователя и ключ участника в группе. Сам личный ключ и доли FROST на диске зашифрованы паролем. Пароль проверяется при каждом входе. Раунд 2 генерации ключа запечатан ключом участника этой группы.

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
cargo run -p ai-signing-cli --bin ai-signing-admin -- --config /tmp/alice.toml issue-cert alice /tmp/alice.cert.json
```

Роль указывается при создании: `админ` или `подписант`. Группу создаёт администратор. Подписант входит в клиент и участвует в подписи. `delete-user` удаляет учётную запись и группы, которые этот пользователь создал. Из остальных групп он исключается.

`issue-cert` выпускает сертификат для уже созданного пользователя. Файл содержит секрет. Им можно войти без имени и пароля: так запускается автоподписант. Пароль этой учётной записи по-прежнему открывает окно и командную строку на их собственной базе. Без пути сертификат печатается в вывод.

## Окно

```bash
cargo run -p ai-signing-desktop --bin ai-signing-gui
```

Войдите под пользователем, которого создал администратор сервера. Пароль нужен при каждом открытии: он проверяется сервером и открывает локальные ключи. Пока окно открыто, оно держит связь с сервером и участвует в протоколе. Администратор создаёт группу и отмечает в ней активных подписантов. Когда группа активна, создатель создаёт перевод SOL. Подписант видит получателя и сумму и подтверждает или отклоняет запрос.

## Командная строка

Без команды открывается текстовый интерфейс. Он тоже держит связь и участвует в протоколе.

```bash
cargo run --bin ai-signing-cli -- --config /tmp/alice.toml --database /tmp/alice.sqlite
```

`Ctrl+Q` выходит из учётной записи, `Ctrl+W` закрывает интерфейс, `u` обновляет списки. Администратор клавишей `n` создаёт группу: отмечает подписантов пробелом и подтверждает Enter. `d` запускает генерацию ключа. Подписант на вкладке запросов подтверждает перевод клавишей `a` и отклоняет его клавишей `r`.

Активный подписант — это пользователь с ролью подписанта, который уже входил в клиент и у которого есть ключ устройства. Список таких подписантов запрашивает вошедший администратор.

Остальные команды, пока открыты интерфейс, окно, `watch` или автоподписант с той же базой, передаются этому процессу. На время генерации ключа и подписи у каждого подписанта должен быть открыт клиент.

```bash
cargo run --bin ai-signing-cli -- --config /tmp/alice.toml --database /tmp/alice.sqlite login alice password1
cargo run --bin ai-signing-cli -- --config /tmp/eve.toml --database /tmp/eve.sqlite create-group treasury 2 alice bob
cargo run --bin ai-signing-cli -- --config /tmp/alice.toml --database /tmp/alice.sqlite watch password1
```

Команды: `login`, `logout`, `whoami`, `groups`, `group`, `signers`, `create-group`, `add-member`, `start-dkg`, `request-solana`, `inbox`, `approve`, `reject`, `watch`, `verify`.

Два клиента на одной машине держат данные отдельно:

```bash
AI_SIGNING_HOME=/tmp/alice cargo run --bin ai-signing-cli -- watch password1
AI_SIGNING_HOME=/tmp/bob cargo run --bin ai-signing-cli -- watch password1
```

## Автоподписант

Отдельный процесс. Он слушает тот же сокет, что окно и командная строка, и сам подтверждает каждый запрос, в котором участвует. База задаётся флагом `--database`. Вход — сертификат администратора, без имени и пароля. Сертификат же открывает локальные ключи этой базы, поэтому базе автоподписанта не подходит пароль от окна.

```bash
cargo run -p ai-signing-cli --bin ai-signing-auto -- --config /tmp/alice.toml --database /tmp/alice-auto.sqlite --certificate /tmp/alice.cert.json
```

Пока процесс запущен, команды `ai-signing-cli` с той же базой передаются ему.

## Перевод Solana

Когда группа активна, администратор, который её создал, создаёт перевод. Адрес получателя — base58, сумма указывается в lamports. Ключ группы после DKG является адресом кошелька-отправителя, поэтому его надо пополнить тестовыми SOL до создания перевода.

```bash
cargo run --bin ai-signing-cli -- --config /tmp/eve.toml --database /tmp/eve.sqlite request-solana GROUP_ID АДРЕС_ПОЛУЧАТЕЛЯ 1000000
```

В окне то же действие есть на карточке активной группы: поля получателя и суммы. Подписанты видят параметры перевода и подтверждают их. После кворума сервер собирает FROST-подпись в настоящую Solana-транзакцию и отправляет её в локальный RPC. Сигнатура сети доступна в `transaction.transaction_signature` ответа `inbox`.

По умолчанию сервер использует `http://127.0.0.1:8899`; другой RPC задаётся переменной `SOLANA_RPC_URL`.

Проверить подпись можно в отдельном окне, без входа в учётную запись:

```bash
cargo run --bin ai-signing-cli -- verify
```

Поля «Ключ», «Подпись» и «Сообщение». Ключ и подпись принимаются в hex или base64. Enter проверяет подпись. Верная подпись показывает «Подпись верна». Сообщение сравнивается байт в байт: пробелы и переводы строк входят в текст.

Внешний сервис по-прежнему может создать запрос токеном API группы:

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
