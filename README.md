# Starter Kit

Backend starter template for Go services with:
- Gin HTTP router
- PostgreSQL via GORM
- JWT authentication
- permission-first RBAC
- runtime application configurations from database
- optional Redis-based session management and rate limiting
- one explicit startup and shutdown flow (`cmd/api` -> `internal/app`)

This repository is intended to be the foundation for future projects. The current structure is generic on purpose and should be extended by adding new business modules on top of the existing patterns (see [Adding a module](#adding-a-module)).

## Core Principles

### Permission-First RBAC

RBAC in this starter kit is designed with these rules:
- `permission` is the runtime source of truth for access control
- `role` is a label and a grouping mechanism for permissions
- `superadmin` is the only exception and bypasses permission checks
- menu visibility is derived from permissions, not from manual menu assignment

Practical implications:
- endpoint access is checked by `d.Kit.Can(resource, action)` (authkit's permission middleware)
- `/api/menus/me` is built from the permissions owned by the current user
- if a role has at least one permission for a module resource, the menu for that module can appear automatically
- parent menus are included automatically when a permitted child menu exists

### Runtime Configuration

Application configuration values can be stored in `app_configs` and changed without restarting the service.

Use this for values such as:
- external URLs
- feature toggles
- integration settings
- module-specific runtime configuration

Built-in auth feature flags:
- `auth.public_registration_enabled`: enable or disable public self-registration endpoints
- `auth.register_otp_enabled`: require OTP verification for public registration
- `auth.password_reset_email_enabled`: send password reset tokens through the email sender instead of returning a development token in the API response

The starter kit now includes a typed helper on top of `app_configs`, so services do not need to parse raw strings manually for common cases such as:
- `GetString`
- `GetBool`
- `GetInt`
- `GetDuration`
- `IsEnabled`
- `DecodeJSON`

Behavior:
- if a config key does not exist, the helper returns the provided fallback
- if a config exists but `is_active = false`, the helper also returns the fallback
- parsing errors are returned only when an active config exists but contains an invalid value

For feature flags, `is_active` controls whether the stored config overrides the code fallback. The actual on/off value is stored in `value`.

Public registration example:
- missing config: allowed, because code fallback is `true`
- `is_active = false`: allowed, because the config is ignored and fallback `true` is used
- `is_active = true`, `value = true`: allowed
- `is_active = true`, `value = false`: disabled

Default auth config rows are seeded by authkit's embedded baseline, applied by `kit.Migrate`:
- `auth.public_registration_enabled`: active, value `true`
- `auth.register_otp_enabled`: active, value `false`
- `auth.password_reset_email_enabled`: active, value `false`

## Current Modules

Provided by [`authkit`](https://github.com/zazhedho/authkit) (mounted with `Kit.Mount(api)`, tables created by `Kit.Migrate`):
- Authentication and user profile
- Users
- Roles
- Permissions
- Menus
- Configurations
- Audit trails
- Sessions when Redis is enabled

Implemented in this project:
- Locations
- Media upload and owner-controlled deletion when `MEDIA_ENABLED=true`

Shared plumbing comes from three modules, each imported through one path: [`github.com/zazhedho/gokit`](https://github.com/zazhedho/gokit) (responses, messages, filters, generic repository, middlewares, utils), [`github.com/zazhedho/authkit`](https://github.com/zazhedho/authkit) (authentication, RBAC, audit, mailer) and [`github.com/zazhedho/logus`](https://github.com/zazhedho/logus) (logging). They are pinned to tagged versions in `go.mod`; upgrade them deliberately with `go get <module>@<version>`.

## Project Structure

```text
starter-kit/
├── cmd/api/                       # main(): signal handling, exit code (nothing else)
├── internal/
│   ├── app/                       # lifecycle and composition: Run, New, Migrate, Serve, Close
│   ├── config/                    # the one config package: Config, FromEnv, Validate, LoadDotEnv, LoadRemote (Consul/file)
│   ├── router/                    # gin engine, global middleware, one register<Module> per module; wires repository -> service -> handler
│   ├── domain/<module>/           # entities and domain errors; no framework except gorm.DeletedAt
│   ├── dto/<module>/              # request and response shapes shared by handler and service
│   ├── services/<module>/         # business rules; declares the ports it needs (Repository, Cache, Storage) in ports.go
│   ├── repositories/<module>/     # GORM adapters; translate gorm errors into domain errors
│   ├── handlers/
│   │   └── http/<module>/         # gin handlers; declare the Service interface they call (ports.go); map errors to HTTP
│   ├── infrastructure/            # adapters for the outside world
│   │   ├── cache/<module>/        # Redis implementations of a service's Cache port
│   │   ├── database/              # PostgreSQL pool, Redis client
│   │   └── storage/               # object storage providers (MinIO, Cloudflare R2) and InitStorage
│   ├── architecture/              # guard tests: the dependency rule, import aliases, package names
│   └── testutil/                  # test helpers (log capture)
├── migrations/                    # this project's own migrations (start at 000005)
├── deploy/entrypoint.sh           # container entrypoint (runs the migration when asked)
├── docs/                          # smoke-test.md, postman/ (API collection)
├── Dockerfile
├── Makefile
└── go.mod
```

All Go code lives under `cmd/` or `internal/`; the repository root has no other Go packages.

Pattern for each module:

```text
route -> handler -> service -> repository -> database
```

### Transports: `handlers/<transport>/<module>`

Handlers sit one level below their transport. This service has one transport, HTTP, so handlers are in `internal/handlers/http/<module>`. A second transport gets its own sibling folder with the same per-module layout, for example `internal/handlers/grpc/<module>` or `internal/handlers/queue/<module>`, and calls the same service. Do not flatten `http/` away: it is what keeps a gRPC or queue handler from sharing a package with the gin handlers.

### Dependency rule

Dependencies point inward only: everything depends on `domain` (and `dto`), and nothing in the middle layers imports its neighbours. A layer reaches its neighbour through an interface that the consumer declares.

```text
  handlers/http   --> domain, dto       calls the Service interface it declares
  services        --> domain, dto       calls the Repository, Cache and Storage interfaces it declares
  repositories    --> domain, dto       satisfies services' Repository by method set
  infrastructure  --> domain, dto       satisfies services' Cache and Storage by method set (and reads config)

  router, app     --> everything        the only code that constructs the pieces and joins them:
                                        handler(service(repository)), so Go checks every fit at compile time
```

- `domain` imports nothing from the project, and nothing outside the standard library except `gorm.io/gorm`, for `gorm.DeletedAt`. Entities double as persistence models (gorm and json tags); this is the one documented exception.
- `dto` imports `domain` at most, never gin, gorm or go-redis.
- `services` import `domain` and `dto`, never gin, gorm, go-redis, a storage SDK, `gokit`, `authkit`, `config`, `router`, `app`, or anything in `repositories`, `handlers` or `infrastructure`. IDs are injected (`NewID`), the caller's identity arrives as plain input (`domainmedia.Actor`, a user id), and persistence, cache and storage are interfaces the service declares in its own `ports.go`. Logging through `logus` is the one deliberate global.
- `handlers` never import `services`, `repositories`, gorm or `infrastructure`; they talk to a `Service` interface they declare themselves. They are where `authkit` and `gokit` belong: they turn the request into plain input and domain errors into HTTP statuses.
- `repositories` and `infrastructure` never import `services` or `handlers`; they satisfy the services' ports by method set, so Go checks the fit when the router wires them together.
- Constructors return concrete structs (`NewService`, `NewRepository`, `New`); interfaces live with their consumer, never in a shared `interfaces` package.

`internal/architecture` enforces all of this on every `go test ./...` with `go/parser`, with no extra dependency.

### Names and import aliases

A package is named after its directory (`package location` in `domain/location`, `services/location`, ...), and module names are not repeated inside it: `location.Service`, `location.NewService`, `location.NewRepository`, `location.New` for a handler. Because every module package has the same name, importers always use one alias, `<layer><module>`:

| Directory | Alias for module `location` |
|---|---|
| `internal/domain/location` | `domainlocation` |
| `internal/dto/location` | `dtolocation` |
| `internal/services/location` | `servicelocation` |
| `internal/repositories/location` | `repositorylocation` |
| `internal/handlers/http/location` | `httplocation` (transport plus module) |
| `internal/infrastructure/cache/location` | `cachelocation` |

The same applies to `media` and to every module you add. goimports and gopls suggest the bare name `location`; the alias is a convention that `internal/architecture` checks, so a wrong alias fails `go test`. Import groups are standard library, third party, then `starter-kit/...`; `make fmt` (`golangci-lint fmt`) keeps them that way.

Rules that keep the structure uniform:
- Only `cmd/api` calls `os.Exit`; everything else returns errors. Nothing outside `internal/config` reads the environment, and nothing outside `internal/app` opens connections: the router and modules receive a `router.Deps` value.
- Repositories use the generic repository `gokit.Repository` (`gokit.NewRepository`) from `github.com/zazhedho/gokit` for common CRUD and list queries; module repository files hold only custom queries (joins, aggregates, transactions).
- Protect project routes with `d.Kit.Auth()` and `d.Kit.Can(resource, action)`; get the audit service from `d.Kit.Audit()`.
- For mutation handlers, embed `authkit.AuditWriter` (`github.com/zazhedho/authkit`) instead of creating per-handler audit wrapper methods.
- Background work a module starts (the location sync job) stops through `router.Deps.Lifecycle`: register a hook with `d.Lifecycle.OnClose(name, fn)` and `App.Close` runs it before closing Redis and the database.

## Startup Flow

```text
cmd/api/main.go
  signal.NotifyContext(SIGINT, SIGTERM)
  app.Run(ctx, os.Args[1:])                 any error -> log "service exited with error: ...", exit code 1
    |
    |- 1. load configuration (internal/app.loadConfig), in this order:
    |      a. .env            godotenv, never overrides variables that are already set;
    |                         a missing file is an error only when APP_ENV is not set
    |      b. CONFIG_ID       config.LoadRemote(): Consul or config file fills the environment
    |      c. environment     config.FromEnv() builds the typed Config (database, Redis, SMTP, ...)
    |      d. flags           -port, -appname, -migrate, -migrate-only
    |      e. Validate()      every problem reported at once, naming variables, never values
    |
    |- 2. open the dependencies (internal/app.New); a failure closes whatever is already open
    |      a. load APP_TIMEZONE
    |      b. open PostgreSQL (session time zone = APP_TIMEZONE) and apply the pool limits
    |      c. open Redis, only if REDIS_URL or REDIS_HOST is set (PING must succeed)
    |      d. open object storage, only if MEDIA_ENABLED=true
    |      e. authkit.New; the mailer is built from the SMTP section of Config and handed
    |         over only when Redis is open and SMTP_HOST, SMTP_PASS and SMTP_FROM are all set
    |
    |- 3. migrate, when -migrate is on (RUN_MIGRATION, default true) or -migrate-only:
    |      authkit migrations first, then this project's migrations
    |      -migrate-only stops here with exit code 0: no routes are built, no port is opened
    |
    |- 4. build the routes (router.New: middleware, /healthcheck, /readyz, authkit, modules)
    |      and the http.Server with the HTTP_* timeouts
    |
    `- 5. serve until SIGINT/SIGTERM, then shut down gracefully
           stop accepting connections, wait up to HTTP_SHUTDOWN_TIMEOUT for running
           requests, stop background work (a running location sync is canceled and
           waited for, at most HTTP_SHUTDOWN_TIMEOUT), close Redis, close the database
```

The routes are built after the migrations because some modules read their tables when they are registered (`registerLocation` calls `RecoverInterruptedJobs`, which marks sync jobs left over from a previous run as failed), so the first start against an empty database is as quiet as every other start. If that write fails, route registration fails and the service does not start.

## Environment

Copy `.env.example` to `.env` and adjust the values as needed. The `.env` file is optional when `APP_ENV` is already set in the environment (this is how containers run). Variables that are already set always win over `.env`.

Minimum required variables:
- `APP_NAME` (unique per application; authkit binds tokens to it)
- `APP_ENV`
- `PORT` (no default)
- `DATABASE_URL` (used as it is), or these database parts when `DATABASE_URL` is empty (values may contain spaces, quotes, backslashes, `@`, `:` and `/`):
  - `DB_HOST`
  - `DB_PORT`
  - `DB_USERNAME`
  - `DB_NAME`
  - `DB_PASS`
  - `DB_SSLMODE` (default `disable`)
- `JWT_KEY` (minimum 32 characters; use a random secret for production)
- `JWT_EXP`
- `OTP_SECRET` and `RESET_SECRET`, only when both Redis and SMTP are configured (no defaults)
- `PATH_MIGRATE` (default `file://migrations`)

Configuration is validated once at startup. An invalid value stops the service with exit code 1 and a message that names the variable but never prints its value, for example `HTTP_READ_TIMEOUT must be a duration such as 30s or 2m`.

### HTTP, time zone, and database pool

Durations use Go syntax (`30s`, `2m`, `1h`). Every duration must be greater than zero.

| Variable | Default | Meaning |
|---|---|---|
| `APP_TIMEZONE` | `Asia/Jakarta` | IANA time zone of the process and the database session |
| `HTTP_READ_HEADER_TIMEOUT` | `5s` | time to read request headers |
| `HTTP_READ_TIMEOUT` | `30s` | time to read the whole request |
| `HTTP_WRITE_TIMEOUT` | `30s` | time to write the response |
| `HTTP_IDLE_TIMEOUT` | `60s` | keep-alive idle time |
| `HTTP_SHUTDOWN_TIMEOUT` | `15s` | time running requests get to finish after SIGINT/SIGTERM |
| `HTTP_MAX_BODY_MB` | `10` | largest request body, 1-1024 MB; must exceed `MEDIA_MAX_FILE_SIZE_MB` when media is enabled |
| `MEDIA_UPLOAD_TIMEOUT` | `2m` | read deadline for one `POST /api/media` (replaces `HTTP_READ_TIMEOUT` for that route) |
| `DB_MAX_OPEN_CONNS` | `100` | pool: open connections, greater than zero |
| `DB_MAX_IDLE_CONNS` | `10` | pool: idle connections, zero or more |
| `DB_CONN_MAX_LIFETIME` | `1h` | pool: longest life of a connection |
| `DB_CONN_MAX_IDLE_TIME` | `5m` | pool: longest idle time of a connection |

A request whose declared `Content-Length` exceeds `HTTP_MAX_BODY_MB` is answered with `413`. A body without a declared length is cut off at the limit while it is read, and the handler answers (most JSON handlers with `400`, the media handler with `413`).

### Database connection

The connection is made with pgx. With the `DB_*` parts the session time zone is always `APP_TIMEZONE`, even if the process environment sets `PGTZ`; with `DATABASE_URL` it is `APP_TIMEZONE` too, unless the URL itself sets its own (`?timezone=...`), which then wins.

`DB_SSLMODE` defaults to `disable` and must be one of `disable`, `allow`, `prefer`, `require`, `verify-ca`, or `verify-full`. Use `require` or stricter outside local development.

After startup, SQL errors and slow queries (200ms or more) are logged at warn level through the service logger. The log shows the SQL with its placeholders (`$1`, `$2`) and never the parameter values; a query that finds no row is not logged.

A failed connection is reported without the driver's text, which can quote the connection string, and without any credential. The message names the kind of problem, so a configuration error can be told from a network one:

| Message | Meaning |
|---|---|
| `connect to database: invalid configuration` | `DATABASE_URL` or the `DB_*` parts cannot be parsed |
| `connect to database: authentication failed` | the server answered and refused the user, the password, or the host (host-access rules also produce this) |
| `connect to database: server rejected the connection parameters` | the server answered and refused something else, such as an unknown database |
| `connect to database: connection refused` | nothing is listening at that host and port |
| `connect to database: timed out` | the host did not answer in time |
| `connect to database: unreachable` | any other failure to reach the server (for example an unknown host name) |

### Redis

Redis is optional. It counts as configured when `REDIS_URL` or `REDIS_HOST` is not empty (`REDIS_PORT` defaults to `6379`; `REDIS_PASSWORD` and `REDIS_DB` are optional).

- Not configured: no connection is attempted, startup is immediate, and the features that need Redis are off (sessions and their routes, login/register rate limiting, OTP, email password reset, the permission cache, the media upload rate limit). authkit logs one `WARN` that says so.
- Configured but unreachable (or wrong password): the service refuses to start, exit code 1, with `open redis: ping redis: connection refused` (or the matching reason). The URL and password are never logged.
- Configured: the format of `REDIS_URL`, `REDIS_PORT`, and `REDIS_DB` is validated.

`.env.example` ships with the Redis lines commented out; uncomment them to enable Redis.

### Optional settings

- Permission cache settings such as `PERMISSION_CACHE_TTL` or `PERMISSION_CACHE_TTL_SECONDS` (default `5m`). These only apply when Redis is available; otherwise permission checks read from the database. Cache entries are invalidated after role-permission, permission, user-role, and user-delete mutations; TTL remains the fallback when Redis invalidation fails.
- Location Service settings: `LOCATION_SERVICE_BASE_URL` (default `https://location-service-y7si.onrender.com`) and `LOCATION_SERVICE_TIMEOUT_SECONDS` (default `20`). Location sync imports from this shared service.
- Media/storage settings for file upload use cases. Set `MEDIA_ENABLED=true` to register media routes. Storage remains optional while disabled; enabling media requires valid MinIO or Cloudflare R2 credentials and an explicit `STORAGE_BASE_URL`; a storage provider that cannot start is a startup failure.
- `MEDIA_MAX_FILE_SIZE_MB` controls maximum file size (default `5`). `MEDIA_ALLOWED_CONTENT_TYPES` controls accepted MIME types after server-side byte sniffing; client extensions and `Content-Type` headers are not trusted.
- Media upload rate limiting uses Redis when available. Configure `MEDIA_UPLOAD_RATE_LIMIT` and `MEDIA_UPLOAD_RATE_WINDOW_SECONDS`; without Redis it degrades safely to no distributed rate limit.
- `GOOGLE_CLIENT_ID` or `GOOGLE_CLIENT_IDS` for Google login
- SMTP settings for register OTP and password reset email flows, read into the `SMTP` section of `Config`: `SMTP_HOST`, `SMTP_PORT` (default `587`), `SMTP_USER` (default `apikey`), `SMTP_PASS`, `SMTP_FROM`, `SMTP_SUBJECT`, `RESET_SUBJECT`, `AUTH_EMAIL_APP_NAME`. These stay optional; as soon as one of `SMTP_HOST`, `SMTP_PASS` or `SMTP_FROM` is set, all three are required and `SMTP_PORT` and `SMTP_FROM` are validated. The mailer is only passed to authkit when Redis is configured too; if it cannot be built, the service logs a warning and continues without it. The password never appears in `String`/`%+v` output of the configuration.

## Run Locally

Install dependencies and prepare `.env`, then:

```bash
go run ./cmd/api                  # migrate (RUN_MIGRATION, default true), then serve
go run ./cmd/api -migrate=false   # serve without migrating
go run ./cmd/api -migrate-only    # migrate, then exit 0 without serving or opening a port
```

Flags (all optional; the environment supplies the defaults):

| Flag | Meaning |
|---|---|
| `-port` | overrides `PORT` |
| `-appname` | overrides `APP_NAME` |
| `-migrate` | run migrations before serving (default is `RUN_MIGRATION`, which defaults to `true`) |
| `-migrate-only` | run migrations and exit |
| `-h` | print usage and exit 0 |

`make run` is the same as `go run ./cmd/api`. In Docker, `deploy/entrypoint.sh` (copied to `/app/entrypoint.sh` in the image) adds `-migrate` when `RUN_MIGRATION` is `true` or `1`.

### Exit codes

| Code | When |
|---|---|
| `0` | clean shutdown after SIGINT/SIGTERM; `-migrate-only` finished; `-h` |
| `1` | invalid configuration, unreachable database, or Redis configured but unreachable; migration failure; listen/serve error; running requests still open when `HTTP_SHUTDOWN_TIMEOUT` ran out. The log line is `service exited with error: <cause>` for every one of these; the cause says whether it happened during startup, serving, or shutdown |
| killed by the signal | a second SIGINT/SIGTERM while the graceful shutdown is still waiting (see below) |

### Health, readiness, and shutdown

Both probes are on the engine root, outside `/api`:

| Probe | Checks | Answers |
|---|---|---|
| `GET /healthcheck` | nothing; the process is up | `200 {"message":"OK!!"}` |
| `GET /readyz` | `PING` on PostgreSQL, and on Redis when configured, within 2 s | `200 {"status":"ok"}`, or `503 {"status":"unavailable"}` |

Use `/healthcheck` for liveness and `/readyz` to decide whether to send traffic. The reason for a `503` is in the log (`readyz; database ping failed: ...`), never in the response.

On SIGINT or SIGTERM the service logs `Shutdown started`, stops accepting connections, closes idle keep-alive connections, and waits up to `HTTP_SHUTDOWN_TIMEOUT` for requests that are already running. Then it stops background work, closes Redis and the database, and logs `Shutdown complete`, exit code `0`. A location sync that is still running is canceled and marked failed with the message `Location sync interrupted` (the state a restart would give it); the service waits for that write, at most `HTTP_SHUTDOWN_TIMEOUT` again, before it closes the connections. If requests are still running when the time limit passes, they are cut off and the exit code is `1` (`app: shutdown timed out with requests still in flight`). A second SIGINT or SIGTERM while the service is still waiting ends the process at once, without waiting for the remaining requests (the first signal restores the default signal handling). Set the orchestrator's termination grace period above `HTTP_SHUTDOWN_TIMEOUT`.

### Tests

```bash
go build ./... && go vet ./... && go test -race -count=1 ./... && make lint
```

`make fmt` formats the code and the import groups (`golangci-lint fmt`). `internal/architecture` fails the build when a package imports what the dependency rule forbids, uses the wrong import alias, or declares a package name that differs from its directory.

The unit tests need no services. `internal/infrastructure/database` also has integration tests that connect to a real PostgreSQL through both the `DATABASE_URL` and the `DB_*` paths, check the session time zone, and check a role whose password contains spaces, quotes, a backslash, `@`, `:` and `/`. They are skipped unless `STARTER_KIT_TEST_DATABASE_URL` is set, for example `postgres://postgres:test@127.0.0.1:55434/postgres?sslmode=disable` against a throwaway container; the role they create is dropped afterwards. The tests compile and vet on Linux, macOS, and Windows (`GOOS=windows go vet ./...`).

### Migrations

- This project's own migrations (`migrations/`) start at `000005`. The core tables (users, RBAC, audit trails, app configs) come from `Kit.Migrate`, which runs first and keeps its own version table (`authkit_schema_migrations`). The project's migrations use the default `schema_migrations` table and run through the already open database pool, under golang-migrate's advisory lock.
- A database whose `schema_migrations` version is 1 to 4 (it never reached 5) cannot be started with this version. Bring it to version 6 with the previous release first, then upgrade.
- The three modules (`authkit`, `gokit`, `logus`) are fetched as ordinary public Go modules, so Docker and CI builds need no extra credentials. Upgrade them deliberately with `go get <module>@<version>`.

## Main Routes

The current route set includes:

- `POST /api/user/register`
- `POST /api/user/register/otp/send`
- `POST /api/user/login`
- `POST /api/user/google/login`
- `POST /api/user/refresh-token`
- `POST /api/user/forgot-password`
- `POST /api/user/reset-password`
- `POST /api/user/logout`
- `GET /api/user`
- `GET /api/users`

- `GET /api/roles`
- `POST /api/role`
- `GET /api/role/:id`
- `PUT /api/role/:id`
- `DELETE /api/role/:id`
- `POST /api/role/:id/permissions`

- `GET /api/permissions`
- `GET /api/permissions/me`
- `POST /api/permission`
- `GET /api/permission/:id`
- `PUT /api/permission/:id`
- `DELETE /api/permission/:id`

- `GET /api/menus/active`
- `GET /api/menus/me`
- `GET /api/menus`
- `GET /api/menu/:id`
- `PUT /api/menu/:id`

- `GET /api/configs`
- `GET /api/config/:id`
- `PUT /api/config/:id`

- `GET /api/location/province`
- `GET /api/location/city?province_code=11`
- `GET /api/location/district?city_code=1101`
- `GET /api/location/village?district_code=110101`
- `POST /api/location/sync`
- `GET /api/location/sync/:id`

- `GET /api/audits`
- `GET /api/audit/:id`

Media routes are registered only when `MEDIA_ENABLED=true`:
- `POST /api/media` using multipart field `file`
- `DELETE /api/media/:id`

Uploaded media metadata is stored in PostgreSQL. Object names are generated by the server. Delete accepts only a media UUID; the owner or `superadmin` may delete it. A failed metadata insert triggers storage cleanup, and upload/delete attempts are written to the audit trail.

Additional session routes are registered only when Redis is available:
- `GET /api/user/sessions`
- `DELETE /api/user/session/:session_id`
- `POST /api/user/sessions/revoke-others`

Location architecture:
- PostgreSQL is the source of truth for provinces, cities, districts, and villages
- Redis is used only as runtime cache
- shared Location Service is used only for sync/import to the database
- location sync runs asynchronously; start the job with `POST /api/location/sync` and poll its status via `GET /api/location/sync/:id`
- use scoped sync for regular updates; `level=all` is intended for initial bootstrap because it performs a full hierarchical import
- the sync job belongs to the running process: on shutdown it is canceled and recorded as failed (`Location sync interrupted`), and a job left queued or running by a crashed process is failed the same way when the next one starts

## Adding a module

Follow these steps in order. The example adds a `projects` module: a user with `projects:list` can list projects, and a user with `projects:create` can create one. The Go code below was compiled, vetted and tested (including `internal/architecture` and `TestRouteTable`) in a scratch copy of this repository on 2026-11-18; it is a recipe to copy and adapt, not part of this repository.

The module name `projects` is used for the menu name, the permission resource, the table, and the audit resource. Keep them identical, because menus are derived from permissions by that name. Every package of the module is named `projects` and imported under the alias `<layer>projects` (see [Names and import aliases](#names-and-import-aliases)).

### 1. Migration: table, menu, and permissions

The next free number after the existing files is `000007`. Create `migrations/000007_create_projects_table.up.sql` with the table, then append the menu and permission seed that authkit generates:

```bash
go run github.com/zazhedho/authkit/cmd/module-seed \
  --name projects \
  --display-name "Projects" \
  --path /projects \
  --icon bi-folder \
  --order-index 905 \
  >> migrations/000007_create_projects_table.up.sql
```

The command prints SQL for one `menu_items` row, the `permissions` rows for the resource (`list`, `view`, `create`, `update`, `delete` unless `--actions` says otherwise), and default `role_permissions` grants (`admin,superadmin` unless `--grant-roles` says otherwise). Other flags: `--parent-name` for a nested menu, `--resource` when the permission resource differs from the name.

```sql
-- migrations/000007_create_projects_table.up.sql (before the generated seed)
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id UUID NOT NULL,
    name VARCHAR(200) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_projects_owner FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_projects_owner_user_id ON projects(owner_user_id);
```

```sql
-- migrations/000007_create_projects_table.down.sql
DELETE FROM permissions WHERE resource = 'projects';
DELETE FROM menu_items WHERE name = 'projects';
DROP TABLE IF EXISTS projects;
```

The migration runs on the next start (or with `-migrate-only`).

### 2. Domain

`internal/domain/projects/entity.go`:

```go
package projects

import "time"

func (Project) TableName() string { return "projects" }

type Project struct {
	ID          string    `json:"id" gorm:"column:id;primaryKey"`
	OwnerUserID string    `json:"owner_user_id" gorm:"column:owner_user_id"`
	Name        string    `json:"name" gorm:"column:name"`
	CreatedAt   time.Time `json:"created_at" gorm:"column:created_at"`
}
```

`internal/domain/projects/errors.go` holds the errors callers match with `errors.Is`. A repository that looks a row up returns a domain `ErrNotFound` instead of the ORM's error (see `internal/domain/media`):

```go
package projects

import "errors"

// ErrNameRequired is returned when a project is created without a name.
var ErrNameRequired = errors.New("project name is required")
```

### 3. DTO

`internal/dto/projects/projects.go` holds request shapes that the handler and the service share. Add it only when they share something; it must not import gin or gorm:

```go
// Package projects holds the request shapes the projects handler and service
// share. It must not import gin or gorm.
package projects

// ListRequest is a parsed list query: the handler fills it from the URL, the
// repository applies it.
type ListRequest struct {
	Search         string
	OrderBy        string
	OrderDirection string
	Page           int
	Limit          int
	Offset         int
}
```

### 4. Service

The service declares the ports it needs in `ports.go`, next to the code that uses them, and holds the business rules. It imports only `domain` and `dto` from this project and no framework: the ID generator is injected, and the caller's identity is a plain argument.

`internal/services/projects/ports.go`:

```go
package projects

import (
	"context"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// Repository is the persistence the service needs. The GORM adapter in
// internal/repositories/projects satisfies it by method set.
type Repository interface {
	Store(ctx context.Context, p domainprojects.Project) error
	List(ctx context.Context, req dtoprojects.ListRequest) ([]domainprojects.Project, int64, error)
}
```

`internal/services/projects/service.go`:

```go
package projects

import (
	"context"
	"strings"
	"time"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// Service holds the projects business rules. It imports no framework: ids are
// injected, and the caller's identity arrives as a plain argument.
type Service struct {
	repo  Repository
	newID func() string
}

// NewService builds the service. newID returns a new row id; the router passes
// gokit.CreateUUID, which issues UUIDv7.
func NewService(repo Repository, newID func() string) *Service {
	return &Service{repo: repo, newID: newID}
}

func (s *Service) Create(ctx context.Context, ownerUserID, name string) (domainprojects.Project, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return domainprojects.Project{}, domainprojects.ErrNameRequired
	}
	p := domainprojects.Project{ID: s.newID(), OwnerUserID: ownerUserID, Name: name, CreatedAt: time.Now()}
	if err := s.repo.Store(ctx, p); err != nil {
		return domainprojects.Project{}, err
	}
	return p, nil
}

func (s *Service) List(ctx context.Context, req dtoprojects.ListRequest) ([]domainprojects.Project, int64, error) {
	return s.repo.List(ctx, req)
}
```

Unit-test the service with a fake of its port, no database (`internal/services/projects/service_test.go`):

```go
package projects

import (
	"context"
	"errors"
	"testing"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// fakeRepository satisfies Repository; services are tested without a database.
type fakeRepository struct {
	stored domainprojects.Project
	err    error
}

func (f *fakeRepository) Store(_ context.Context, p domainprojects.Project) error {
	f.stored = p
	return f.err
}

func (f *fakeRepository) List(context.Context, dtoprojects.ListRequest) ([]domainprojects.Project, int64, error) {
	return nil, 0, f.err
}

func TestCreateTrimsTheNameAndUsesTheInjectedID(t *testing.T) {
	repo := &fakeRepository{}
	svc := NewService(repo, func() string { return "p-1" })

	p, err := svc.Create(context.Background(), "u-1", "  First  ")
	if err != nil {
		t.Fatalf("Create = %v", err)
	}
	if p.ID != "p-1" || p.Name != "First" || repo.stored.OwnerUserID != "u-1" {
		t.Fatalf("unexpected project %+v, stored %+v", p, repo.stored)
	}
}

func TestCreateRejectsABlankName(t *testing.T) {
	svc := NewService(&fakeRepository{}, func() string { return "p-1" })
	if _, err := svc.Create(context.Background(), "u-1", "   "); !errors.Is(err, domainprojects.ErrNameRequired) {
		t.Fatalf("Create = %v, want ErrNameRequired", err)
	}
}
```

### 5. Repository

`internal/repositories/projects/repository.go` is the adapter that satisfies the service's `Repository` port by method set. It returns a concrete `*Repository`; nothing declares an interface for it here. It embeds the generic repository for `Store`, `GetByID`, `Update` and `Delete`, and adds only the list query. Test it with sqlmock like `internal/repositories/media/repository_test.go`.

```go
package projects

import (
	"context"

	"github.com/zazhedho/gokit"
	"gorm.io/gorm"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// Repository is the GORM adapter for the projects table. It embeds the generic
// gokit repository for Store, GetByID, Update and Delete, and adds only the
// list query. Translate gorm.ErrRecordNotFound into a domain ErrNotFound for
// any lookup the service exposes, as repositories/media does.
type Repository struct {
	*gokit.Repository[domainprojects.Project]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainprojects.Project](db)}
}

func (r *Repository) List(ctx context.Context, req dtoprojects.ListRequest) ([]domainprojects.Project, int64, error) {
	params := gokit.BaseParams{
		Search:         req.Search,
		OrderBy:        req.OrderBy,
		OrderDirection: req.OrderDirection,
		Page:           req.Page,
		Limit:          req.Limit,
		Offset:         req.Offset,
	}
	return r.GetAll(ctx, params, gokit.QueryOptions{
		Search:              gokit.BuildSearchFunc("name"),
		AllowedOrderColumns: []string{"name", "created_at"},
		DefaultOrders:       []string{"created_at DESC"},
	})
}
```

Searchable columns, allowed filters, and sortable columns are configured through `gokit.QueryOptions`; add custom repository methods only for business-specific queries.

### 6. Handler

The handler declares the `Service` interface it calls, in `ports.go`, so it never imports the service package.

`internal/handlers/http/projects/ports.go`:

```go
package projects

import (
	"context"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// Service is what the handlers call. The concrete service is in
// internal/services/projects; the router wires it in.
type Service interface {
	Create(ctx context.Context, ownerUserID, name string) (domainprojects.Project, error)
	List(ctx context.Context, req dtoprojects.ListRequest) ([]domainprojects.Project, int64, error)
}
```

`internal/handlers/http/projects/handler.go` embeds `authkit.AuditWriter` and writes an audit event for the success and failure of every mutation. The caller comes from `authkit.ScopeFrom`, which `d.Kit.Auth()` fills in, and is passed to the service as a plain value. Domain errors become status codes here. Test the handler with a fake `Service` and `httptest`, as `internal/handlers/http/media/handler_test.go` does.

```go
package projects

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// Handler embeds authkit.AuditWriter to record every mutation.
type Handler struct {
	service  Service
	pageSize int
	authkit.AuditWriter
}

func New(svc Service, audit authkit.AuditService, pageSize int) *Handler {
	return &Handler{
		service:     svc,
		pageSize:    pageSize,
		AuditWriter: authkit.NewAuditWriter(audit, "ProjectsHandler"),
	}
}

type createRequest struct {
	Name string `json:"name" binding:"required"`
}

func (h *Handler) List(ctx *gin.Context) {
	logID := gokit.GenerateLogId(ctx)
	params, err := gokit.GetBaseParams(ctx.Request.URL.Query(), "created_at", "desc", h.pageSize)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, err.Error()))
		return
	}
	items, total, err := h.service.List(ctx.Request.Context(), dtoprojects.ListRequest{
		Search:         params.Search,
		OrderBy:        params.OrderBy,
		OrderDirection: params.OrderDirection,
		Page:           params.Page,
		Limit:          params.Limit,
		Offset:         params.Offset,
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gokit.InternalServerError(logID))
		return
	}
	ctx.JSON(http.StatusOK, gokit.PaginationResponse(http.StatusOK, int(total), params.Page, params.Limit, logID, items))
}

func (h *Handler) Create(ctx *gin.Context) {
	logID := gokit.GenerateLogId(ctx)
	var req createRequest
	if !gokit.BindJSON(ctx, logID, "[ProjectsHandler][Create]", &req) {
		return
	}

	// The handler turns the authenticated scope into the plain input the
	// service needs; services never import authkit.
	scope := authkit.ScopeFrom(ctx.Request.Context())
	p, err := h.service.Create(ctx.Request.Context(), scope.UserID, req.Name)
	if err != nil {
		h.WriteAudit(ctx, authkit.AuditEvent{
			Action: authkit.ActionCreate, Resource: "projects",
			Status: authkit.StatusFailed, Message: "Failed to create project", ErrorMessage: err.Error(),
		})
		if errors.Is(err, domainprojects.ErrNameRequired) {
			ctx.JSON(http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, err.Error()))
			return
		}
		ctx.JSON(http.StatusInternalServerError, gokit.InternalServerError(logID))
		return
	}

	h.WriteAudit(ctx, authkit.AuditEvent{
		Action: authkit.ActionCreate, Resource: "projects", ResourceID: p.ID,
		Status: authkit.StatusSuccess, Message: "Created project", AfterData: p,
	})
	ctx.JSON(http.StatusCreated, gokit.Response(http.StatusCreated, "Project created successfully", logID, p))
}
```

### 7. Route registrar

`internal/router/projects.go` is one function with the registrar signature `func(r gin.IRouter, d Deps) error`. It builds its own repository, service, and handler from `Deps` (`Config`, `DB`, `SQLDB`, `Redis` which may be nil, `Kit`, `Storage` which is nil when media is disabled, `Lifecycle`), mounts routes relative to the group it receives, and returns an error instead of panicking or exiting. It opens no connections. The router is the one place that passes `gokit.CreateUUID` as the ID generator. Protect routes with `d.Kit.Auth()` first, then `d.Kit.Can(resource, action)`:

```go
package router

import (
	"github.com/gin-gonic/gin"
	"github.com/zazhedho/gokit"

	httpprojects "starter-kit/internal/handlers/http/projects"
	repositoryprojects "starter-kit/internal/repositories/projects"
	serviceprojects "starter-kit/internal/services/projects"
)

func registerProjects(r gin.IRouter, d Deps) error {
	repo := repositoryprojects.NewRepository(d.DB)
	svc := serviceprojects.NewService(repo, gokit.CreateUUID)
	h := httpprojects.New(svc, d.Kit.Audit(), d.Config.Projects.PageSize)

	projects := r.Group("/projects").Use(d.Kit.Auth())
	{
		projects.GET("", d.Kit.Can("projects", "list"), h.List)
		projects.POST("", d.Kit.Can("projects", "create"), h.Create)
	}
	return nil
}
```

If the module starts background work, register its stop function with `d.Lifecycle.OnClose("projects job", svc.Close)`, and call any startup recovery (like `registerLocation` does with `RecoverInterruptedJobs`) in the registrar, never in the constructor. Avoid role-name checks for module access (`d.Kit.Role(...)`) unless the case is explicitly special, like `superadmin`.

### 8. One line in `router.New`

Add the module to the registrar list in `internal/router/router.go`. Modules under `/api` go in `apiRegistrars` (mounted after authkit's own routes); only probes belong in `rootRegistrars`. A registrar error stops startup with `register projects routes: ...`.

```go
var apiRegistrars = []registrar{
	{"location", registerLocation},
	{"media", registerMedia},
	{"projects", registerProjects},
}
```

### 9. Optional: configuration

If the module needs settings, add them to `internal/config`, never read the environment from the module:

1. a type and a field on `Config` in `config.go`:

   ```go
   type Projects struct{ PageSize int }
   // in type Config:
   Projects Projects
   ```

2. read it in `FromEnv` in `load.go` (`l.integer`, `l.duration`, `l.str`, and `l.megabytes` record unparsable values for `Validate` and fall back to the default):

   ```go
   Projects: Projects{PageSize: l.integer("PROJECTS_PAGE_SIZE", 20)},
   ```

3. validate it in `validate.go`, naming the variable and never the value, and call it from `Validate`:

   ```go
   func (c Config) validateProjects() []string {
   	if n := c.Projects.PageSize; n < 1 || n > 100 {
   		return []string{"PROJECTS_PAGE_SIZE must be between 1 and 100"}
   	}
   	return nil
   }

   // in Validate:
   problems = append(problems, c.validateProjects()...)
   ```

4. document the variable, with its default as a comment, in `.env.example`, and use it from the registrar as `d.Config.Projects.PageSize`.

### 10. Add the routes to the route-table test

`internal/router/routes_test.go` lists this service's own routes by hand, in the variables `ownRoutesWithoutMedia` (and `mediaRoutes` for the media routes). A new module's routes make `TestRouteTable` fail until they are added there, so add them on purpose:

```go
ownRoutesWithoutMedia = []string{
	// ...existing routes...
	"GET /api/projects",
	"POST /api/projects",
}
```

### 11. Check it

```bash
go build ./... && go vet ./... && go test -race -count=1 ./... && make lint
go run ./cmd/api -migrate-only   # applies migration 000007
go run ./cmd/api
```

`go test` runs `internal/architecture`: a wrong import, alias or package name in the new module fails there with the offending file. With the seed above, `admin` and `superadmin` hold the `projects` permissions. A new user has the `viewer` role, so `GET /api/projects` answers `401` without a token and `403` with a viewer token until a role is granted `projects:list` (see the role flow below). `POST /api/projects` with `{"name":"First project"}` answers `201`, and `GET /api/projects?search=first` lists it. The audit trail gets a `projects` / `create` entry.

## Role Management Flow

Recommended admin flow:

1. Create a role.
2. Assign permissions to the role.
3. Do not assign menus manually.
4. Let menu visibility be derived from permissions automatically.

Menu management note:
- `menus` is code-defined, but selected presentation fields may still be updated at runtime
- do not create or delete menus through admin API
- structural changes such as adding new menus should still go through code and migration

This prevents drift between:
- what a user can see
- what a user can actually access

## Notes

- `role_menus` still exists in the base schema for compatibility, but runtime access control does not depend on it.
- For new modules, prefer permission-based design from the start.
- If you introduce nested menus, parent menu visibility will be resolved automatically when the child menu is permitted.
