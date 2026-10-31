# Auth: общая аутентификация

Django остаётся источником пользователей и групп. Дополнительное приложение `sso`
не переименовывает существующие группы и не меняет ID пользователей. Рабочая ветка:
`feat/common-auth-sso`. Подготовка кода не означает миграцию production.

## Установка и локальные проверки

Python production: **3.13.18**; Poetry **2.5.1**. `poetry.lock` обязателен:
существующие runtime-версии закреплены, добавлены DOT **3.4.1** и bcrypt **4.3.0**.
BCrypt 4.3 сохраняет Devise-совместимое усечение UTF-8 до 72 байт; bcrypt 5
отклоняет длинные пароли, поэтому обновлять его без проверки нельзя. Предпочтительный
Django PBKDF2 автоматически заменяет импортированный hash после успешного входа.

```sh
poetry install --no-root --only main
DJANGO_SETTINGS_MODULE=auth.test_settings poetry run python manage.py test
DJANGO_SETTINGS_MODULE=auth.test_settings poetry run python manage.py makemigrations --check --dry-run
```

Для сборки psycopg2 нужны компилятор и `libpq-dev` / `pg_config`; SQLite-тесты
можно выполнять в отдельном временном venv без psycopg2. `auth.test_settings`
использует только SQLite `:memory:` и временный RSA-ключ. Никакие тесты не обращаются
к сервисам или production URL. Проверены также синтетические bcrypt-векторы
независимого libxcrypt: Unicode, 72 и 73 байта, многобайтовое усечение. Реальный
Ruby/Devise и фактический пароль проверяются отдельно при интеграции.

`auth.test_postgres_settings` предназначен **только** для синтетического PostgreSQL
fixture `common_auth_guard_fixture` на loopback 5432 в изолированном namespace
контейнера. Не использовать его с production БД. PostgreSQL-only тест проверяет
четыре одновременных callback на разных соединениях: один exchange, три отказа,
затем отказ replay. На PostgreSQL все 62 теста прошли; на SQLite один такой тест
ожидаемо пропускается. Docker fixture не публикует порты и не монтирует production
данные; нужные настройки и пароль в тестовом модуле исключительно синтетические.

Docker сохраняет Poetry multi-stage архитектуру, использует Python 3.13.18 и lock.
`collectstatic` при `SSO_ENABLED=false` не требует production-секретов. Запуск
контейнера по-прежнему выполняет `migrate`, затем Gunicorn: запускать только после
разрешённого backup/restore rehearsal. Сам код не выполняет deployment.

## Конфигурация и секреты

- `DJANGO_SECRET_KEY`: **сохранить прежнее значение**, иначе нарушится совместимость
  SimpleJWT и сессий. Не передавать через build args, Git или журналы.
- `DJANGO_DEBUG`: явно `true`, `1`, `yes` включают debug/локальный SQLite; по умолчанию
  `false`. Production использует прежние `POSTGRES_DB`, `POSTGRES_USER`,
  `POSTGRES_PASSWORD`, `POSTGRES_HOST`, `POSTGRES_PORT`.
- `SSO_ENABLED=true`: включает только `/o/` маршруты. Без корректного приватного
  RSA-ключа минимум 2048 бит приложение **не запускается**.
- `SSO_RSA_PRIVATE_KEY_FILE`: путь к read-only secret-файлу PEM (предпочтительно),
  либо `SSO_RSA_PRIVATE_KEY`: PEM через окружение. Файл имеет приоритет.
- `SSO_MINIO_PKCE_EXCEPTION_CLIENT_ID`: по умолчанию пусто. Только явно названный
  confidential RS256 authorization-code клиент, связанный с `minio`, может работать
  без PKCE и без nonce: Console v0.27 их не отправляет. State остаётся обязательным;
  если nonce запрошен, DOT возвращает его точно в ID token. Все остальные клиенты
  требуют nonce и S256. Включение исключения требует отдельного browser-state-binding
  guard, описанного ниже; одно исключение само по себе небезопасно.

Issuer фиксирован: `https://auth.i3alumba.ru/o`. Приложение доступно только через
ClusterIP и доверенный Traefik, который перезаписывает `X-Forwarded-Proto`;
`SECURE_PROXY_SSL_HEADER` учитывает HTTPS при построении discovery endpoints.
Не публиковать Gunicorn напрямую с недоверенным forwarded header.
Session/CSRF cookies: host-only, HttpOnly, SameSite=Lax, Secure и с префиксом
`__Host-` вне debug (защита от domain-cookie tossing соседними сервисами). Cookies
авторизации не расширяются на весь домен. Credentialed CORS и CSRF allowlist:
только `https://main.i3alumba.ru`, `https://auth.i3alumba.ru` и
`https://monitor.i3alumba.ru`, без wildcard.

### Guard для legacy MinIO Console

`SSO_MINIO_GUARD_ENABLED=true` включает только малые login API; по умолчанию guard
отключён (503). `SSO_MINIO_CONSOLE_URL` — доверенная операторская настройка,
по умолчанию `http://minio:9001`. Public host фиксирован: `minio.i3alumba.ru`.
Весь префикс `/api/v1/login` должен проходить через method-aware router, без
обхода через дополнительные callback paths. GET metadata и POST OAuth callback
направляются в этот guard; **точный native POST `/api/v1/login` — прямо в Console**,
чтобы аварийный вход не зависел от доступности Auth. Остальной Console остаётся
на MinIO. Не проксировать все методы через Auth как единственный recovery path.

- `GET /api/v1/login`: переписывает state в `redirectRules[].redirect`, связывает
  его digest с Secure/HttpOnly/host-only cookie `__Host-minio-sso-browser`.
- `POST /api/v1/login/oauth2/auth`: проверяет точный Origin, cookie, state, TTL
  10 минут и атомарный однократный consume; только затем восстанавливает исходный
  Console state и пересылает code. Не `/authcallback` (это несуществующий route).
- `POST /api/v1/login`: компонент поддерживает same-origin proxy для совместимости,
  но production router обходит Auth и направляет этот метод в Console независимо.
  Router проверяет Origin и добавляет Secure к backend cookies, сохраняя 204/body.
  GET `/oauth_callback` обслуживает прежний Console frontend.

Если guard недоступен, **только GET initialization** может получить статический
200 JSON `{loginStrategy:"form",redirectRules:[],animatedLogin:true,isK8S:true}`
без upstream state/redirect URL. OAuth callback всегда fail-closed; native POST
не использует этот fallback. `/login` показывает native форму при обеих стратегиях
`form`/`redirect`; SSO выбирается отдельно, специальный URL-параметр не нужен.

Code, пароли и browser cookie не записываются в БД; сохраняются только digests,
исходный Console state и timestamps. Истёкшие записи удаляются при новом login.
Прокси не следует redirects, не использует системный HTTP proxy, ограничивает
размер login payload/response; S3/STS порт 9000 остаётся приватным и не проксируется.
Нужны интеграционные тесты двух браузеров и конкурентного consume на PostgreSQL.
Legacy отсутствие строгого issuer comparison/`azp` fallback в MinIO не исправлено:
сохранять единственный доверенный issuer/key и точный audience при выдаче Auth.

Сохраняются legacy `/api/token/`, `/api/token/refresh/`, `/api/token/verify/`.
SimpleJWT blacklist app добавлен, refresh ротация сохраняется. Dashboard обязан
сохранять **новый refresh**. REST registration routes не были и не стали доступны;
конфигурация установленной библиотеки сохранена.

## Доступ и API

`Service`: один slug `drive|matrix|gitlab|minio|jenkins`, защищённая Group FK,
необязательный уникальный `oidc_client_id`. `ServiceIdentity`: защищённые User и
Service FK, уникальные `(user,service)` и `(service,external_id)`, явные
`external_username`, `minio_policy`, `jenkins_admin`. Никакого произвольного JSON claims.
Доступ разрешён только активному пользователю с **группой и явной identity**.
Auth superuser не обходит проверку. Старые группы/ID остаются:
Drive=2, Minio=3, Gitlab=4, Matrix=5. `service_<slug>` — производный OIDC claim,
не новая группа/копия entitlement.

Исключение — новый `monitor`: доступен всем аутентифицированным активным
пользователям с `is_staff=true`, как Django admin. Группа, `ServiceIdentity` и
OIDC client для него не создаются; `is_superuser=true` без `is_staff` не даёт
доступ. `/api/access/` и boolean map `/api/user/` вычисляют право заново при каждом
запросе: снятие `is_staff` действует и для ранее выданного JWT. Старые сервисы
по-прежнему требуют группу **и** явную identity, без обхода для администраторов.
Monitor обязан проверять точный boolean `services.monitor` сервером при каждом
запросе данных; карточка Dashboard сама по себе не является защитой.

JWT-authenticated `GET /api/access/`:

```json
{
  "services": {
    "drive": { "enabled": false, "url": "https://drive.i3alumba.ru" },
    "matrix": { "enabled": false, "url": "https://matrix.i3alumba.ru" },
    "gitlab": { "enabled": false, "url": "https://gitlab.i3alumba.ru" },
    "minio": { "enabled": false, "url": "https://minio.i3alumba.ru" },
    "jenkins": { "enabled": false, "url": "https://jenkins.i3alumba.ru" },
    "monitor": { "enabled": false, "url": "https://monitor.i3alumba.ru" }
  }
}
```

В `/api/user/` и `/api/user/{id}/` добавлена **boolean map**
`services: {drive:false,matrix:true,gitlab:false,minio:false,jenkins:false,monitor:false}`,
без объектов `{enabled,url}`: Go consumer требует точный bool. `/api/access/`
сохраняет object map из примера выше. В user serializer `id`, username, email,
first_name, last_name и исходные groups `{id,name}` сохранены.

Browser API (каждый ответ `no-store`):

1. `GET /api/session/` → `{authenticated,csrfToken[,user]}`, **без JWT**.
2. JSON `POST /api/session/login/` `{username,password}` с `X-CSRFToken`, credentials
   included → `{access,refresh,csrfToken}`; Django session и CSRF token ротируются.
3. `POST /api/session/token/` с действующей сессией и CSRF → `{access,refresh}`.
4. `POST /api/session/logout/` с CSRF, необязательный JSON `{refresh}` →
   `{authenticated:false}`; session flush и blacklist только собственного refresh.
   Чужой/некорректный refresh отклоняется без logout (403/400).

Dashboard должен посылать credentials и брать CSRF token из JSON (cookie HttpOnly).
Повторно получить CSRF после login/logout. Native HTML `/sso/login/?next=...`
используется как LOGIN_URL для RP, защищён CSRF и проверяет next на same-host.
Ни JWT в URL, ни session creation из bearer не поддерживаются.
Нативный и JSON login используют общую DB-backed HMAC(username+REMOTE_ADDR)
квоту: 5 попыток за 15 минут, включая успешные. Истёкшие записи удаляются при
следующем входе. Настроить proxy так, чтобы REMOTE_ADDR имел ожидаемую семантику;
X-Forwarded-For не считается доверенным. Legacy `/api/token/` использует **ту же**
DB-квоту: попытки через native/API/JWT суммируются. Формат username/password,
ответ `{access,refresh}` и ошибки SimpleJWT сохранены; bearer/session не создаётся.
Refresh/verify не тратят login-квоту.

## OIDC

Опубликованы только discovery, JWKS, authorize/code, token/refresh, revoke и
userinfo. Нет client/self/dynamic registration, introspection, device, implicit,
password, client_credentials или RP logout маршрутов.

- `/o/.well-known/openid-configuration`
- `/o/.well-known/jwks.json`
- `/o/authorize/`, `/o/token/`, `/o/revoke_token/`, `/o/userinfo/`

Только отдельные confidential authorization-code RS256 клиенты, точные HTTPS
redirects, scopes `openid` (обязателен), `profile`, `groups`, `email`. DOT/oauthlib
проверяют PKCE, код, срок, client binding и replay; provider требует непустые
state и nonce (nonce необязателен только для описанного MinIO exception).
RP обязан проверять state/nonce против browser session, подпись, issuer и audience;
issuer не может определить «неправильный» nonce без состояния RP.
Authorization view и code issuance/exchange, refresh, userinfo проверяют живую
группу/identity/active user. Refresh rotation/reuse protection включены, grace=0.
Access token: 15 минут, refresh lifetime ограничен настройкой DOT (86400 секунд
после срока связанного access token). Не рассчитывать на logout для удаления
всех уже выданных JWT или чужих service sessions.

Claims строго своего клиента:

- `sub=str(Auth.pk)`, `preferred_username=identity.external_username`,
  `groups=[service_<свой slug>]`, `email_verified=false`; email не связывает accounts.
- Matrix: `matrix_localpart` из явной identity, не mutable Auth username.
- MinIO: `policy` только из явного `minio_policy`, в том числе в ID token.
- Jenkins: `jenkins_uid=external_username`, для i3alumba **точно `i3alumba`**, не `i3`;
  `jenkins_eligible="true"` только при явном `jenkins_admin=true`.

## Явное provisioning: private JSON

Команда не обнаруживает пользователей и не обращается к Synapse/GitLab. Входной
файл должен быть приватным (например, mode 0600), вне Git. Секреты/hash не писать
в аргументы, shell history, отчёты или логи. Пример **формата**, не production config:

```json
{
  "users": [
    { "id": 1, "username": "i3alumba" },
    { "id": 2, "username": "gore" },
    { "username": "procsima", "unusable_password": true }
  ],
  "services": [
    {
      "slug": "gitlab",
      "group": { "id": 4, "name": "Gitlab" },
      "client": {
        "id": "common-auth-gitlab",
        "secret": "REPLACE_FROM_PRIVATE_SECRET_INPUT_MINIMUM_32_CHARACTERS",
        "redirect_uris": [
          "https://gitlab.i3alumba.ru/users/auth/openid_connect/callback"
        ]
      }
    }
  ],
  "identities": [
    {
      "username": "i3alumba",
      "service": "gitlab",
      "external_id": "4",
      "external_username": "i3alumba"
    },
    {
      "username": "procsima",
      "service": "gitlab",
      "external_id": "8",
      "external_username": "procsima"
    }
  ]
}
```

Корневые поля ровно `users`, `services`, `identities` (массивы). Неизвестные поля,
включая `claims`, отклоняются. Существующие users допускаются только как точные
пары ID1/i3alumba, ID2/gore; никаких updates. Единственный новый user — procsima,
с ID >2; выбрать **либо** `unusable_password:true`, **либо** `import_bcrypt` с
проверенным private raw `$2a$13$...` hash. Импорт требует подтверждённых отсутствия
Devise pepper/custom preprocessing и 2FA; команда не может сама это проверить.
Ни пароль, ни hash не придумываются. Исходный hash хранится как `bcrypt$` + raw.
Повторный запуск не заменяет уже rehashed пароль. После первого apply legacy hash
нужно удалить из private config: для **ранее созданного этим bootstrap** пользователя
допустимо `{username:"procsima"}`. Provenance проверяется по исходному ledger и PK,
а не по текущему password hash. Чужой существующий procsima или новый пользователь
без явного import/unusable-password input отклоняются. Если исходный import/flag
всё ещё передан, его HMAC должен соответствовать первому apply. Отдельного activation flow нет:
при unusable password нужен отдельно согласованный reset/out-of-band процесс.

Каждый service требует `slug` и `group:{id,name}`; legacy пары проверяются строго.
Только Jenkins может создать группу через `group:{name,create:true}`. Поле `client`
необязательно (например, Drive без OIDC); формат точно `{id,secret,redirect_uris}`.
Redirects уникальные точные HTTPS без fragment/wildcard/userinfo; collision с
другим клиентом отклоняется. Существующий client должен иметь тот же secret,
redirects и строгие параметры code/confidential/RS256/hash-secret/skip-consent.
Секреты клиентов сохраняются hashed средствами DOT; skip-consent получают только
явно provisioned доверенные клиенты.

Каждая identity требует `username`, `service`, `external_id`, `external_username`.
Необязательные `minio_policy` (строка, только minio) и `jenkins_admin` (bool, только
jenkins) — отдельные явные полномочия. Связанные users/services должны быть в
этом input. Только **первый apply** добавляет явно описанные memberships и задаёт
initial minio_policy/jenkins_admin. Последующие Pod restarts запускают проверку,
но **не восстанавливают** удалённые memberships, не сбрасывают admin-changed роли,
пароли и не создают заново удалённые после bootstrap объекты. Неизвестные
существующие memberships не удаляются. Нельзя тихо переназначить identity, external ID,
service group/client или secret. Коллизия откатывает всю транзакцию.

```sh
poetry run python manage.py provision_sso --config /private/common-auth.json
poetry run python manage.py provision_sso --config /private/common-auth.json --apply
# stdin также поддержан; не использовать echo с реальными секретами в history:
poetry run python manage.py provision_sso --config - < /private/common-auth.json
```

Без `--apply` все записи, включая ledger, откатываются. PostgreSQL sequences
нетранзакционны: dry-run может расходовать значения ID даже при rollback.
Новый Auth ID procsima нельзя предсказывать как `3` или копировать из GitLab ID;
после apply прочитать фактический ID и только затем выполнить явную привязку RP.
Apply атомарен и идемпотентен; вывод только общий результат, без private input. `ProvisionRun` содержит HMAC
fingerprint, timestamp и созданные IDs users/groups/services/applications/identities,
пары добавленных memberships, HMAC происхождения password import и полный snapshot
PK всех исходных bindings (включая reused объекты). Canonical fingerprint исключает
import_bcrypt/unusable flag/client secret и mutable initial roles; порядок массивов
и redirect URI не важен. Первый apply фиксирует **один immutable bootstrap manifest**;
изменение users/service/group/client URI/external bindings отклоняется, а не создаёт
новый ledger. Секрет клиента при каждом rerun проверяется против живого DOT hash,
но не входит в fingerprint. Удалённый/подменённый объект вызывает fail-closed, без
recreation. Расширение/изменение immutable manifest требует отдельной операторской
миграции, не повторного bootstrap. Ledger никогда не перезаписывается при rerun.
Ledger доступен
read-only в admin; Service/ServiceIdentity редактируются только доверенным оператором.
Доступ к Django admin и DOT application admin — привилегия управления SSO.

## Откат и ограничения выпуска

Перед apply сохранить backup, baseline ID/identity и private config, проверить
restore в изоляции. По выбору оператора backups **root-only, unencrypted**;
обязательное шифрование здесь не навязывается. Их доступ и хранение контролирует
оператор. После apply оператор читает ledger и подтверждает созданные
IDs; автоматической destructive rollback команды нет. Для компенсации отключить
новые clients/SSO config, отозвать выданные токены, удалить только созданные данным
run identity/membership/application, затем при необходимости service/group/user
с учётом PROTECT и новых зависимостей. Не удалять старые группы/пользователей,
не откатывать PBKDF2 rehash, не восстанавливать stale DB после новых записей.
Внешние bindings компенсирует отдельно ответственный за каждый сервис.

Не доказаны этим компонентом: сохранность production данных, backup/restore,
реальная bcrypt аутентификация procsima, MinIO Console nonce/PKCE/STS lifetime,
GitLab/Synapse binding и старые сессии, Jenkins plugins/recovery, PostgreSQL
конкурентность, browser CORS/cookie flow за production proxy. Group removal
блокирует новую выдачу и userinfo, но не аннулирует уже созданные service sessions,
SSH/PAT, STS или все SimpleJWT access tokens. Внешние consumers обязаны отдельно
проверять свой entitlement и audience. Ротация RSA требует отдельного плана overlap
ключей; этот компонент не генерирует production keys и не публикует private keys.
