# Starter Kit

A Go service template to start a project from. It gives you:

- Gin HTTP router and PostgreSQL through GORM
- JWT authentication and permission-first RBAC, provided by [`authkit`](https://github.com/zazhedho/authkit)
- runtime application configuration stored in the database (`app_configs`)
- optional Redis for sessions, rate limiting and caches
- one explicit startup and shutdown flow (`cmd/api` -> `internal/app`)
- a layered module structure whose dependency rule is enforced by tests

Two example modules show the pattern: [`location`](docs/modules/location.md) (reference data and a background
sync job) and [`media`](docs/modules/media.md) (authenticated file upload, list and delete on object storage, with `_any` permissions for other users' files, see [Ownership and the `_any` permissions](docs/adding-a-module.md#ownership-and-the-_any-permissions)). Build your own
business features the same way; see [Adding a module](docs/adding-a-module.md). Per-module routes,
permissions, environment variables and operational notes are in [`docs/modules/`](docs/modules/).

Shared plumbing comes from three modules, each imported through one path: [`gokit`](https://github.com/zazhedho/gokit)
(responses, filters, generic repository, middlewares, utils), [`authkit`](https://github.com/zazhedho/authkit)
(authentication, RBAC, audit, mailer) and [`logus`](https://github.com/zazhedho/logus) (logging). They are pinned
to tagged versions in `go.mod`; upgrade them deliberately with `go get <module>@<version>`.

## Quick start

You need Go (the version in `go.mod`) and a PostgreSQL database.

```bash
cp .env.example .env              # then adjust APP_NAME, DB_*, JWT_KEY
make run                          # same as: go run ./cmd/api
curl -s localhost:8080/healthcheck
```

The first start migrates the database (`RUN_MIGRATION` defaults to `true`), including authkit's core tables
(users, roles, permissions, menus, audit trails, app configs). Register a user with `POST /api/user/register`
and log in with `POST /api/user/login`. The [Postman collection](docs/postman/README.md) has a request for
every route. `docs/smoke-test.md` is a full check of a fresh checkout.

## Core principles

### Permission-first RBAC

- `permission` is the runtime source of truth for access control; `role` is a label that groups permissions.
- `superadmin` is the only exception and bypasses permission checks.
- Menu visibility is derived from permissions, not assigned by hand: `/api/menus/me` is built from the
  permissions of the current user, and a parent menu appears when a permitted child exists.
- Endpoints are protected with `d.Kit.Auth()` and `d.Kit.Can(resource, action)` (authkit's middleware).

Admin flow: create a role, assign it permissions, and let menus follow. Menus are defined in code and
migrations (a module's migration seeds its menu and permissions); the admin API does not create or delete them.

### Runtime configuration

Values in `app_configs` change without a restart: external URLs, feature toggles, integration settings.
The built-in auth flags are `auth.public_registration_enabled`, `auth.register_otp_enabled` and
`auth.password_reset_email_enabled`, seeded by authkit's migrations. A key that is missing or has
`is_active = false` falls back to the value in code; an active row overrides it through its `value`.

## Project structure

```text
starter-kit/
├── cmd/api/                       # main(): signal handling, exit code (nothing else)
├── internal/
│   ├── app/                       # lifecycle and composition: Run, New, Migrate, Serve, Close
│   ├── config/                    # the one config package: Config, FromEnv, Validate, LoadDotEnv, LoadRemote
│   │   ├── config.go load.go validate.go   # shared sections, composition, shared validators
│   │   └── <module>.go            # one file (and _test.go) per module with settings: type, parsing, validation
│   ├── router/                    # gin engine, global middleware, probes
│   │   ├── modules.go             # the alphabetical list of mounted modules
│   │   ├── module/                # leaf: Deps, Lifecycle, Entry (imports no feature module)
│   │   └── <module>/              # wire.go builds repository -> service -> handler; register.go mounts the routes; routes_test.go pins them
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
│   ├── architecture/              # guard tests: the dependency rule, import aliases, package names, migration names
│   └── testutil/                  # test helpers: logcapture, routertest (shared router test Deps and helpers)
├── migrations/                    # this project's migrations: <UTC timestamp>_<module>_<change>.{up,down}.sql, see migrations/README.md
├── deploy/entrypoint.sh           # container entrypoint (runs the migration when asked)
├── docs/
│   ├── adding-a-module.md         # checklist and a worked example
│   ├── modules/<module>.md        # routes, permissions, env variables, operational notes per module
│   ├── postman/                   # API collection (see its README)
│   └── smoke-test.md              # end-to-end check of a fresh checkout
├── .env.example                   # every variable, grouped by section and by module
├── .github/                       # CI and lint workflows, Dependabot
├── .githooks/                     # pre-commit and pre-push hooks (make hook-install)
├── Dockerfile
├── Makefile
└── go.mod
```

All Go code lives under `cmd/` or `internal/`; the repository root has no other Go packages.

Every module has the same shape:

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
  infrastructure  --> config            owns its types and satisfies services' Cache and Storage by method set;
                                        imports no domain or dto, except infrastructure/cache/<module>, which
                                        implements that module's port and may import its domain

  router, app     --> everything        the only code that constructs the pieces and joins them:
                                        handler(service(repository)), so Go checks every fit at compile time
```

What `internal/architecture` checks on every `go test ./...` (it parses the source with `go/parser`; no extra dependency):

- `domain` imports none of `dto`, `services`, `handlers`, `repositories`, `infrastructure`, `router`, `app` or `config`, and no other module's packages. Outside the standard library it may import only `gorm.io/gorm`, for `gorm.DeletedAt`; any other external import, gin and go-redis included, is banned. Entities double as persistence models (gorm and json tags); this is the one documented exception. The guard does not list `internal/testutil`, so a domain package importing it would pass.
- `dto` imports only the standard library and `domain`.
- `services` import neither `infrastructure`, `repositories`, `handlers`, `router`, `app` nor `config`, and none of gin, gorm, go-redis, `github.com/minio/minio-go`, `gokit` or `authkit`. IDs are injected (`NewID`), the caller's identity arrives as plain input (`domainmedia.Actor`, a user id), and persistence, cache and storage are interfaces the service declares in its own `ports.go`. Logging through `logus` is the one deliberate global.
- `handlers` import neither `services`, `repositories`, `infrastructure`, `router`, `app` nor `config`, and neither gorm, go-redis nor `github.com/minio/minio-go`; they talk to a `Service` interface they declare themselves. They are where `authkit` and `gokit` belong: they turn the request into plain input and domain errors into HTTP statuses.
- `repositories` import neither `services`, `handlers`, `infrastructure`, `router`, `app` nor `config`, and not gin. `infrastructure` imports neither `services`, `handlers`, `repositories`, `router` nor `app`, and no `domain` either: it owns its types (`storage.Provider`, not a domain interface). The one exception is `infrastructure/cache/<module>`, which implements that module's port and may import that module's domain. `config` imports nothing from this module, and `router` does not import `app`.
- A module's peer layers never import each other: no service-to-service, handler-to-handler, repository-to-repository or router-to-router imports across modules. The one allowance is another module's `domain` and `dto` packages, which services, repositories, handlers, `infrastructure/cache` and `router` may import (a `projects` module referencing users); `domain` and `dto` themselves import no other module. Modules otherwise meet only in `router` and `app`.
- A `shared` directory (`<tree>/shared`, for example `handlers/http/shared` for pagination or response helpers, or `dto/shared`) is the one reserved name in a per-module tree. It is not a module: any module of that tree may import it, and it must not import any business module of any tree (it may import the `shared` packages of layers its own layer may import). The layer rules of its tree still apply (`dto/shared` stays standard library plus domain), the import alias is the prefix plus `shared` (`dtoshared`, `httpshared`), and no module may be named `shared`. Create one only when two modules need the same helper; no `shared` package exists yet.
- Every top-level directory of `internal/` is a known layer (`TestInternalLayersAreKnown`): a new layer needs a rule in `internal/architecture/architecture_test.go` and a line in this dependency rule. Every `internal/router/<module>` is mounted in `modules.go` under its own name (`TestEveryRouterDirectoryIsMounted`), so an unlisted package fails instead of serving no routes.
- Exported `New*` constructors in `services`, `repositories` and `handlers` return a pointer to a struct (and optionally an error), never an interface. Interfaces live with their consumer: there is no shared `interfaces` package and no `Interface` suffix.

Internal-import rules apply to non-test files only. Test files are checked only against the external bans, and only for `domain`, `dto`, `services` and `handlers`. The cross-module rule covers test files too.

Infrastructure factories such as `storage.NewStorageProvider` may return an interface, because they select an implementation.

Also checked: no `log.Fatal` or `os.Exit` outside `cmd/`, no package-level gorm, sql or Redis connections, the import aliases, and package names matching their directories.

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
| `internal/router/location` | `routerlocation` |

Handler aliases follow the transport directory, so `internal/handlers/grpc/location` is `grpclocation` with no guard edit. `internal/router/module` is the shared leaf, not a module: import it as `module`.

The same applies to `media` and to every module you add. goimports and gopls suggest the bare name `location`; the alias is a convention that `internal/architecture` checks, so a wrong alias fails `go test`. Import groups are standard library, third party, then `starter-kit/...`; `make fmt` (`golangci-lint fmt`) keeps them that way.

Rules that keep the structure uniform:
- Nothing outside `cmd/` calls `os.Exit` or `log.Fatal` (the guard checks this); everything else returns errors. Nothing outside `internal/config` reads the environment. Connections are opened only from `internal/app`, through `internal/infrastructure/database`; the router and modules receive a `module.Deps` value (`internal/router/module`).
- A repository can embed the generic `gokit.Repository` from `github.com/zazhedho/gokit`, built with `gokit.NewRepository[T](db)`, for common CRUD and list queries. `internal/repositories/media` does this and overrides `GetByID` and `Delete` to translate gokit's `ErrNotFound` (also returned by `Update` and `SoftDelete` when no row matched). `Store` and `Update` take a pointer, and `GetAll` caps the page size at `QueryOptions.MaxLimit` (default 100): report `opts.PageSize(params)` as the page's `limit`, as the media `List` does. Keep a module's own repository methods for what the generic one does not cover (joins, aggregates, transactions, error translation); `internal/repositories/location` has no embedded `gokit.Repository` and only custom methods.
- Protect project routes with `d.Kit.Auth()` and `d.Kit.Can(resource, action)`; get the audit service from `d.Kit.Audit()`. `d.Kit` is the `*authkit.Kit` in `module.Deps`.
- For mutation handlers, embed `authkit.AuditWriter` (`github.com/zazhedho/authkit`) instead of creating per-handler audit wrapper methods; `internal/handlers/http/media/handler.go` is the example.
- Background work a module starts (the location sync job) stops through `module.Deps.Lifecycle`. Register a hook with `d.Lifecycle.OnClose(name, fn)`, where `fn` is a `func(context.Context) error` that must return when its context ends; `internal/router/location/wire.go` registers the sync service's `Close` this way. `App.Close` runs the hooks in reverse order of registration with the shutdown context, before it closes Redis and the database.


## Startup, shutdown and migrations

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
    |                         (including authkit.ConfigFromEnv's error for its own variables)
    |
    |- 2. open the dependencies (internal/app.New); a failure closes whatever is already open
    |      a. load APP_TIMEZONE
    |      b. open PostgreSQL (session time zone = APP_TIMEZONE) and apply the pool limits
    |      c. open Redis, only if REDIS_URL or REDIS_HOST is set (PING must succeed)
    |      d. open object storage, only if MEDIA_ENABLED=true
    |      e. authkit.New; the mailer is built from the SMTP section of Config and handed
    |         over only when Redis is open and SMTP_HOST, SMTP_PASS and SMTP_FROM are all set;
    |         Kit.Close is registered first on the lifecycle (it runs last of the hooks)
    |
    |- 3. migrate, when -migrate is on (RUN_MIGRATION, default true) or -migrate-only:
    |      authkit migrations first, then this project's migrations
    |      -migrate-only stops here with exit code 0: no routes are built, no port is opened
    |
    |- 4. build the routes (router.New: middleware, /healthcheck, /readyz, authkit, modules)
    |      and the http.Server with the HTTP_* timeouts
    |
    `- 5. serve until SIGINT/SIGTERM, then shut down gracefully
           stop accepting connections, wait for running requests, stop background work
           (a running location sync is canceled and waited for), then authkit.Kit.Close drains
           in-flight mail sends, all within one HTTP_SHUTDOWN_TIMEOUT counted from the signal;
           then close Redis, close the database
```

The routes are built after the migrations because a module may read its tables while it is registered (the
location module fails sync jobs a previous process left behind; see [`docs/modules/location.md`](docs/modules/location.md)).
A module whose registration fails stops the service with `register <module> routes: ...`. With
`RUN_MIGRATION=false` the schema must already exist.

### Migrations

- This project's migrations (`migrations/`) are named `<UTC YYYYMMDDHHMMSS>_<module>_<change>.{up,down}.sql`; the
  rules (naming, one change per pair, rebase rule) are in [`migrations/README.md`](migrations/README.md), and
  `TestMigrationsAreWellFormed` enforces the format.
- Authkit's core tables (users, RBAC, audit trails, app configs) come from `Kit.Migrate`, which runs first and
  keeps its own version table (`authkit_schema_migrations`). The project's migrations use the default
  `schema_migrations` table and run through the already open database pool, under golang-migrate's advisory lock.
- A module's migration also seeds its menu and permissions (`go run github.com/zazhedho/authkit/cmd/module-seed`,
  see [Adding a module](docs/adding-a-module.md)).

### Run flags and exit codes

```bash
go run ./cmd/api                  # migrate (RUN_MIGRATION, default true), then serve
go run ./cmd/api -migrate=false   # serve without migrating
go run ./cmd/api -migrate-only    # migrate, then exit 0 without serving or opening a port
```

| Flag | Meaning |
|---|---|
| `-port` | overrides `PORT` |
| `-appname` | overrides `APP_NAME` |
| `-migrate` | run migrations before serving (default is `RUN_MIGRATION`, which defaults to `true`) |
| `-migrate-only` | run migrations and exit |
| `-h` | print usage and exit 0 |

In Docker, `deploy/entrypoint.sh` (copied to `/app/entrypoint.sh` in the image) adds `-migrate` when
`RUN_MIGRATION` is `true` or `1`.

| Code | When |
|---|---|
| `0` | clean shutdown after SIGINT/SIGTERM; `-migrate-only` finished; `-h` |
| `1` | invalid configuration, unreachable database, or Redis configured but unreachable; migration failure; listen/serve error; running requests still open when `HTTP_SHUTDOWN_TIMEOUT` ran out. The log line is `service exited with error: <cause>` for every one of these |
| killed by the signal | a second SIGINT/SIGTERM while the graceful shutdown is still waiting |

### Health, readiness and shutdown

Both probes are on the engine root, outside `/api`:

| Probe | Checks | Answers |
|---|---|---|
| `GET /healthcheck` | nothing; the process is up | `200 {"message":"OK!!"}` |
| `GET /readyz` | `PING` on PostgreSQL, and on Redis when configured, within 2 s | `200 {"status":"ok"}`, or `503 {"status":"unavailable"}` |

Use `/healthcheck` for liveness and `/readyz` to decide whether to send traffic. The reason for a `503` is in the
log (`readyz; database ping failed: ...`), never in the response.

On SIGINT or SIGTERM the service logs `Shutdown started`, stops accepting connections, closes idle keep-alive
connections and waits up to `HTTP_SHUTDOWN_TIMEOUT` for running requests. Then it stops background work (the
`Lifecycle` hooks, in reverse order of registration), still inside that one deadline, closes Redis and the
database, logs `Shutdown complete` and exits `0`. If requests are still running when the limit passes they are cut
off and the exit code is `1` (`app: shutdown timed out with requests still in flight`). A second SIGINT or SIGTERM
while the service is still waiting ends the process at once. Set the orchestrator's termination grace period above
`HTTP_SHUTDOWN_TIMEOUT` plus a few seconds for closing Redis and the database (those closes are not bounded).

## Environment

Copy `.env.example` to `.env`; it lists every variable, grouped by section and by module, with the defaults noted
in comments. The `.env` file is optional when `APP_ENV` is already set in the environment (this is how containers
run). Variables that are already set always win over `.env`. Module variables (`LOCATION_*`, `MEDIA_*`,
`STORAGE_*`) are documented in [`docs/modules/`](docs/modules/).

Required: `APP_NAME` (unique per application; authkit binds tokens to it), `APP_ENV`, `PORT` (no default),
`DATABASE_URL` or the `DB_*` parts (`DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_NAME`, `DB_PASS`; `DB_SSLMODE`
defaults to `disable`) and `JWT_KEY` (at least 32 characters). `JWT_EXP_MINUTES` is the access-token lifetime (default 15). `OTP_SECRET` and `RESET_SECRET` are
required only when both Redis and SMTP are configured, and must be at least 32 characters whenever they are set. `PATH_MIGRATE` defaults to `file://migrations`.

Configuration is validated once at startup. An invalid value stops the service with exit code 1 and a message
that names the variable but never prints its value, for example `HTTP_READ_TIMEOUT must be a valid duration such as 60, 30s, 1m or 1h`.
Config is read only through `gokit.GetEnv` (unset or blank means the default; an unparsable value falls back and is
reported) and checked once with `gokit.EnvErrors()`, which `Validate` folds into its error.

### HTTP, time zone and database pool

Durations accept bare seconds (`60`) or Go syntax (`30s`, `1m`, `1h`) and must be greater than zero.

| Variable | Default | Meaning |
|---|---|---|
| `APP_TIMEZONE` | `Asia/Jakarta` | IANA time zone of the process and the database session |
| `HTTP_READ_HEADER_TIMEOUT` | `5s` | time to read request headers |
| `HTTP_READ_TIMEOUT` | `30s` | time to read the whole request |
| `HTTP_WRITE_TIMEOUT` | `30s` | time to write the response |
| `HTTP_IDLE_TIMEOUT` | `60s` | keep-alive idle time |
| `HTTP_SHUTDOWN_TIMEOUT` | `15s` | time the whole shutdown gets after SIGINT/SIGTERM, counted from the signal |
| `HTTP_MAX_BODY_MB` | `10` | largest request body, 1-1024 MB |
| `DB_MAX_OPEN_CONNS` | `100` | pool: open connections, greater than zero |
| `DB_MAX_IDLE_CONNS` | `10` | pool: idle connections, zero or more |
| `DB_CONN_MAX_LIFETIME` | `1h` | pool: longest life of a connection |
| `DB_CONN_MAX_IDLE_TIME` | `5m` | pool: longest idle time of a connection |

A request whose declared `Content-Length` exceeds `HTTP_MAX_BODY_MB` is answered with `413`; a body without a
declared length is cut off at the limit while it is read.

### Database connection

The connection is made with pgx. With the `DB_*` parts the session time zone is always `APP_TIMEZONE`; with
`DATABASE_URL` it is `APP_TIMEZONE` too, unless the URL sets its own (`?timezone=...`). `DB_SSLMODE` must be one of
`disable`, `allow`, `prefer`, `require`, `verify-ca` or `verify-full`; use `require` or stricter outside local
development. SQL errors and slow queries (200 ms or more) are logged at warn level with placeholders, never with
parameter values.

A failed connection is reported without the driver's text (which can quote the connection string) and without any
credential:

| Message | Meaning |
|---|---|
| `connect to database: invalid configuration` | `DATABASE_URL` or the `DB_*` parts cannot be parsed |
| `connect to database: authentication failed` | the server refused the user, the password, or the host |
| `connect to database: server rejected the connection parameters` | the server refused something else, such as an unknown database |
| `connect to database: connection refused` | nothing is listening at that host and port |
| `connect to database: timed out` | the host did not answer in time |
| `connect to database: unreachable` | any other failure to reach the server |

### Redis

Redis is optional. It counts as configured when `REDIS_URL` or `REDIS_HOST` is not empty (`REDIS_PORT` defaults to
`6379`; `REDIS_PASSWORD` and `REDIS_DB` are optional).

- Not configured: no connection is attempted and the features that need Redis are off (sessions and their routes,
  login/register rate limiting, OTP, email password reset, the permission cache, module caches and rate limits).
  authkit logs one `WARN` that says so.
- Configured but unreachable (or wrong password): the service refuses to start, exit code 1, with
  `open redis: ping redis: connection refused` (or the matching reason). The URL and password are never logged.

`.env.example` ships with the Redis lines commented out.

### Logging

Logging goes through `logus`: `logus.Logf(level, format, args...)` for formatted messages, `logus.Log(level, args...)`
(arguments are joined with single spaces, so do not add separators), and `LogContext`/`LogContextf` inside a request so the
line carries the request id. `LOG_LEVEL`, `LOG_FORMAT` and `NODE` are read once. `SERVER_IP` (logus still reads the legacy
`ServerIP` when it is empty) is written as `server_ip` on every line; the service sets it at startup to the host's first
non-loopback IPv4 address.

### Responses and middleware

Every response uses gokit's envelope: `log_id`, `code`, `status`, `message`, `data`, and on failure `error`, which is always
a list of `{field, code, message}`. `message` is a fixed text chosen by the handler (never an error's text); the detail
for the caller is in `error`. Nil slices are sent as `[]`. The engine's middleware order is `RequestIDMiddleware`,
`Recovery`, `CORS(CORSOptions{})` (open: any origin, no credentials), authkit's request logger, then the body limit, so
every component of a request logs and answers with the same `log_id`. A repository built on `gokit.Repository` returns
`gokit.ErrNotFound` when `Update`, `Delete` or `SoftDelete` match no row; translate it to the module's domain error
(`internal/repositories/media` does for `GetByID` and `Delete`).

## Development

```bash
make test        # go build ./... && go vet ./... && go test -race -count=1 ./...
make lint        # golangci-lint (install with: make lint-install)
make fmt         # golangci-lint fmt: formats the code and the import groups
make hook-install   # git hooks: lint on commit, lint and tests on push
```

The Docker image builds from `golang:1.27-alpine` and ships a static binary, the migrations and `deploy/entrypoint.sh`. Dependabot (`.github/dependabot.yml`) opens weekly pull requests for Go modules, GitHub Actions and the Docker base image; the base image is pinned to the minor line, so only a new minor opens a PR.

CI (`.github/workflows/ci.yml`, every action pinned by commit SHA) runs four jobs: golangci-lint (revive, goimports and the rest of `.golangci.yml`), `go vet` with a `go mod tidy` diff check, build and tests (with a PostgreSQL service container and `STARTER_KIT_TEST_DATABASE_URL` set), and `govulncheck`. The unit tests need no services.
`internal/infrastructure/database` also has integration tests against a real PostgreSQL; they are skipped unless
`STARTER_KIT_TEST_DATABASE_URL` is set, for example `postgres://postgres:test@127.0.0.1:55434/postgres?sslmode=disable`
against a throwaway container.

`internal/architecture` fails the build when a package imports what the dependency rule forbids, uses the wrong
import alias, imports another module, returns an interface from a constructor, declares a package name that
differs from its directory, or when a migration file breaks the naming rules.

## More documentation

- [`docs/adding-a-module.md`](docs/adding-a-module.md): checklist and a worked example
- [`docs/modules/`](docs/modules/): [location](docs/modules/location.md), [media](docs/modules/media.md)
- [`docs/postman/`](docs/postman/README.md): API collection
- [`docs/smoke-test.md`](docs/smoke-test.md): end-to-end check of a fresh checkout
- [`migrations/README.md`](migrations/README.md): migration naming and rules
