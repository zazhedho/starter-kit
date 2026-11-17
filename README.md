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

Shared plumbing comes from [`gokit`](https://github.com/zazhedho/gokit) (responses, messages, filters, generic repository, middlewares, utils) and [`logus`](https://github.com/zazhedho/logus) (logging). All three modules are pinned to tagged versions in `go.mod`.

## Project Structure

```text
starter-kit/
├── cmd/api/                 # main(): signal handling, exit code (nothing else)
├── internal/
│   ├── app/                 # lifecycle: Run, New, Migrate, Serve, Close
│   ├── config/              # the one config package: Config, FromEnv, Validate, LoadDotEnv, LoadRemote (Consul/file)
│   ├── router/              # gin engine, global middleware, one register<Module> per module
│   ├── domain/              # entities and domain errors
│   ├── dto/
│   ├── interfaces/          # repository and service contracts
│   ├── repositories/
│   ├── services/
│   ├── handlers/http/
│   ├── cache/
│   └── testutil/            # test helpers (log capture)
├── infrastructure/
│   ├── database/            # PostgreSQL pool, Redis client
│   └── media/               # object storage provider setup
├── migrations/              # this project's own migrations (start at 000005)
├── pkg/storage/             # object storage providers (MinIO, Cloudflare R2)
├── Dockerfile
└── entrypoint.sh
```

Pattern for each module:

```text
route -> handler -> service -> repository -> database
```

Rules that keep the structure uniform:
- Only `cmd/api` calls `os.Exit`; everything else returns errors. Nothing outside `internal/config` reads the environment, and nothing outside `internal/app` opens connections: the router and modules receive a `router.Deps` value.
- Repositories use the generic repository from `github.com/zazhedho/gokit/repository/generic` for common CRUD and list queries; module repository files hold only custom queries (joins, aggregates, transactions).
- Protect project routes with `d.Kit.Auth()` and `d.Kit.Can(resource, action)`; get the audit service from `d.Kit.Audit()`.
- For mutation handlers, embed `auditwriter.AuditWriter` (`github.com/zazhedho/authkit/handlers/auditwriter`) instead of creating per-handler audit wrapper methods.

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
           requests, close Redis, close the database
```

The routes are built after the migrations because some modules read their tables when they are registered (the location service marks sync jobs that were interrupted by a previous run), so the first start against an empty database is as quiet as every other start.

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

`make run` is the same as `go run ./cmd/api`. In Docker, `entrypoint.sh` adds `-migrate` when `RUN_MIGRATION` is `true` or `1`.

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

On SIGINT or SIGTERM the service logs `Shutdown started`, stops accepting connections, closes idle keep-alive connections, and waits up to `HTTP_SHUTDOWN_TIMEOUT` for requests that are already running. Then it closes Redis and the database and logs `Shutdown complete`, exit code `0`. If requests are still running when the time limit passes, they are cut off and the exit code is `1` (`app: shutdown timed out with requests still in flight`). A second SIGINT or SIGTERM while the service is still waiting ends the process at once, without waiting for the remaining requests (the first signal restores the default signal handling). Set the orchestrator's termination grace period above `HTTP_SHUTDOWN_TIMEOUT`.

### Tests

```bash
go build ./... && go vet ./... && go test -race -count=1 ./... && make lint
```

The unit tests need no services. `infrastructure/database` also has integration tests that connect to a real PostgreSQL through both the `DATABASE_URL` and the `DB_*` paths, check the session time zone, and check a role whose password contains spaces, quotes, a backslash, `@`, `:` and `/`. They are skipped unless `STARTER_KIT_TEST_DATABASE_URL` is set, for example `postgres://postgres:test@127.0.0.1:55434/postgres?sslmode=disable` against a throwaway container; the role they create is dropped afterwards. The tests compile and vet on Linux, macOS, and Windows (`GOOS=windows go vet ./...`).

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

## Adding a module

Follow these steps in order. The example adds a `projects` module: a user with `projects:list` can list projects, and a user with `projects:create` can create one. Every file below was compiled and exercised against a real PostgreSQL before it was written here; the code is a recipe to copy and adapt, not part of this repository.

The module name `projects` is used for the menu name, the permission resource, the table, and the audit resource. Keep them identical, because menus are derived from permissions by that name.

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
package domainprojects

import "time"

func (Project) TableName() string { return "projects" }

type Project struct {
	ID          string    `json:"id" gorm:"column:id;primaryKey"`
	OwnerUserID string    `json:"owner_user_id" gorm:"column:owner_user_id"`
	Name        string    `json:"name" gorm:"column:name"`
	CreatedAt   time.Time `json:"created_at" gorm:"column:created_at"`
}
```

### 3. Repository

Declare the contracts in `internal/interfaces/projects/projects.go`, so handlers and services depend on interfaces:

```go
package interfaceprojects

import (
	"context"

	"github.com/zazhedho/gokit/filter"

	domainprojects "starter-kit/internal/domain/projects"
)

type RepoProjectsInterface interface {
	Store(ctx context.Context, p domainprojects.Project) error
	List(ctx context.Context, params filter.BaseParams) ([]domainprojects.Project, int64, error)
}

type ServiceProjectsInterface interface {
	Create(ctx context.Context, ownerUserID, name string) (domainprojects.Project, error)
	List(ctx context.Context, params filter.BaseParams) ([]domainprojects.Project, int64, error)
}
```

`internal/repositories/projects/projects.go` embeds the generic repository for `Store`, `GetByID`, `Update`, and `Delete`, and adds only the list query:

```go
package repositoryprojects

import (
	"context"

	"github.com/zazhedho/gokit/filter"
	repositorygeneric "github.com/zazhedho/gokit/repository/generic"
	"gorm.io/gorm"

	domainprojects "starter-kit/internal/domain/projects"
	interfaceprojects "starter-kit/internal/interfaces/projects"
)

type repo struct {
	*repositorygeneric.GenericRepository[domainprojects.Project]
}

func NewProjectsRepo(db *gorm.DB) interfaceprojects.RepoProjectsInterface {
	return &repo{GenericRepository: repositorygeneric.New[domainprojects.Project](db)}
}

func (r *repo) List(ctx context.Context, params filter.BaseParams) ([]domainprojects.Project, int64, error) {
	return r.GetAll(ctx, params, repositorygeneric.QueryOptions{
		Search:              repositorygeneric.BuildSearchFunc("name"),
		AllowedOrderColumns: []string{"name", "created_at"},
		DefaultOrders:       []string{"created_at DESC"},
	})
}

var _ interfaceprojects.RepoProjectsInterface = (*repo)(nil)
```

Searchable columns, allowed filters, and sortable columns are configured through `repositorygeneric.QueryOptions`; add custom repository methods only for business-specific queries.

### 4. Service

`internal/services/projects/service.go` holds the business rules and returns plain errors that the handler maps to status codes:

```go
package serviceprojects

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zazhedho/gokit/filter"

	domainprojects "starter-kit/internal/domain/projects"
	interfaceprojects "starter-kit/internal/interfaces/projects"
)

var ErrNameRequired = errors.New("project name is required")

type service struct {
	repo interfaceprojects.RepoProjectsInterface
}

func NewProjectsService(repo interfaceprojects.RepoProjectsInterface) interfaceprojects.ServiceProjectsInterface {
	return &service{repo: repo}
}

func (s *service) Create(ctx context.Context, ownerUserID, name string) (domainprojects.Project, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return domainprojects.Project{}, ErrNameRequired
	}
	p := domainprojects.Project{ID: uuid.NewString(), OwnerUserID: ownerUserID, Name: name, CreatedAt: time.Now()}
	if err := s.repo.Store(ctx, p); err != nil {
		return domainprojects.Project{}, err
	}
	return p, nil
}

func (s *service) List(ctx context.Context, params filter.BaseParams) ([]domainprojects.Project, int64, error) {
	return s.repo.List(ctx, params)
}
```

### 5. Handler

`internal/handlers/http/projects/projects.go` embeds `auditwriter.AuditWriter` and writes an audit event for the success and failure of every mutation. The caller comes from `authscope.FromContext`, which `d.Kit.Auth()` fills in:

```go
package handlerprojects

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit/authscope"
	domainaudit "github.com/zazhedho/authkit/domain/audit"
	"github.com/zazhedho/authkit/handlers/auditwriter"
	interfaceaudit "github.com/zazhedho/authkit/interfaces/audit"
	"github.com/zazhedho/gokit/filter"
	"github.com/zazhedho/gokit/handlercommon"
	"github.com/zazhedho/gokit/messages"
	"github.com/zazhedho/gokit/response"
	"github.com/zazhedho/gokit/utils"

	interfaceprojects "starter-kit/internal/interfaces/projects"
	serviceprojects "starter-kit/internal/services/projects"
)

type ProjectsHandler struct {
	Service  interfaceprojects.ServiceProjectsInterface
	pageSize int
	auditwriter.AuditWriter
}

func NewProjectsHandler(svc interfaceprojects.ServiceProjectsInterface, audit interfaceaudit.ServiceAuditInterface, pageSize int) *ProjectsHandler {
	return &ProjectsHandler{
		Service:     svc,
		pageSize:    pageSize,
		AuditWriter: auditwriter.NewAuditWriter(audit, "ProjectsHandler"),
	}
}

type createRequest struct {
	Name string `json:"name" binding:"required"`
}

func (h *ProjectsHandler) List(ctx *gin.Context) {
	logID := utils.GenerateLogId(ctx)
	params, err := filter.GetBaseParams(ctx.Request.URL.Query(), "created_at", "desc", h.pageSize)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, response.ErrorResponse(http.StatusBadRequest, messages.InvalidRequest, logID, err.Error()))
		return
	}
	items, total, err := h.Service.List(ctx.Request.Context(), params)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, response.InternalServerError(logID))
		return
	}
	ctx.JSON(http.StatusOK, response.PaginationResponse(http.StatusOK, int(total), params.Page, params.Limit, logID, items))
}

func (h *ProjectsHandler) Create(ctx *gin.Context) {
	logID := utils.GenerateLogId(ctx)
	var req createRequest
	if !handlercommon.BindJSON(ctx, logID, "[ProjectsHandler][Create]", &req) {
		return
	}

	scope := authscope.FromContext(ctx.Request.Context())
	p, err := h.Service.Create(ctx.Request.Context(), scope.UserID, req.Name)
	if err != nil {
		h.WriteAudit(ctx, domainaudit.AuditEvent{
			Action: domainaudit.ActionCreate, Resource: "projects",
			Status: domainaudit.StatusFailed, Message: "Failed to create project", ErrorMessage: err.Error(),
		})
		if errors.Is(err, serviceprojects.ErrNameRequired) {
			ctx.JSON(http.StatusBadRequest, response.ErrorResponse(http.StatusBadRequest, messages.InvalidRequest, logID, err.Error()))
			return
		}
		ctx.JSON(http.StatusInternalServerError, response.InternalServerError(logID))
		return
	}

	h.WriteAudit(ctx, domainaudit.AuditEvent{
		Action: domainaudit.ActionCreate, Resource: "projects", ResourceID: p.ID,
		Status: domainaudit.StatusSuccess, Message: "Created project", AfterData: p,
	})
	ctx.JSON(http.StatusCreated, response.Response(http.StatusCreated, "Project created successfully", logID, p))
}
```

### 6. Route registrar

`internal/router/projects.go` is one function with the registrar signature `func(r gin.IRouter, d Deps) error`. It builds its own repository, service, and handler from `Deps` (`Config`, `DB`, `SQLDB`, `Redis` which may be nil, `Kit`, `Storage` which is nil when media is disabled), mounts routes relative to the group it receives, and returns an error instead of panicking or exiting. It opens no connections. Protect routes with `d.Kit.Auth()` first, then `d.Kit.Can(resource, action)`:

```go
package router

import (
	"github.com/gin-gonic/gin"

	handlerprojects "starter-kit/internal/handlers/http/projects"
	repositoryprojects "starter-kit/internal/repositories/projects"
	serviceprojects "starter-kit/internal/services/projects"
)

func registerProjects(r gin.IRouter, d Deps) error {
	repo := repositoryprojects.NewProjectsRepo(d.DB)
	svc := serviceprojects.NewProjectsService(repo)
	h := handlerprojects.NewProjectsHandler(svc, d.Kit.Audit(), d.Config.Projects.PageSize)

	projects := r.Group("/projects").Use(d.Kit.Auth())
	{
		projects.GET("", d.Kit.Can("projects", "list"), h.List)
		projects.POST("", d.Kit.Can("projects", "create"), h.Create)
	}
	return nil
}
```

Avoid role-name checks for module access (`d.Kit.Role(...)`) unless the case is explicitly special, like `superadmin`.

### 7. One line in `router.New`

Add the module to the registrar list in `internal/router/router.go`. Modules under `/api` go in `apiRegistrars` (mounted after authkit's own routes); only probes belong in `rootRegistrars`. A registrar error stops startup with `register projects routes: ...`.

```go
var apiRegistrars = []registrar{
	{"location", registerLocation},
	{"media", registerMedia},
	{"projects", registerProjects},
}
```

### 8. Optional: configuration

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

### 9. Add the routes to the route-table test

`internal/router/routes_test.go` lists this service's own routes by hand, in the variables `ownRoutesWithoutMedia` (and `mediaRoutes` for the media routes). A new module's routes make `TestRouteTable` fail until they are added there, so add them on purpose:

```go
ownRoutesWithoutMedia = []string{
	// ...existing routes...
	"GET /api/projects",
	"POST /api/projects",
}
```

### 10. Check it

```bash
go build ./... && go vet ./... && go test -race -count=1 ./... && make lint
go run ./cmd/api -migrate-only   # applies migration 000007
go run ./cmd/api
```

With the seed above, `admin` and `superadmin` hold the `projects` permissions. A new user has the `viewer` role, so `GET /api/projects` answers `401` without a token and `403` with a viewer token until a role is granted `projects:list` (see the role flow below). `POST /api/projects` with `{"name":"First project"}` answers `201`, and `GET /api/projects?search=first` lists it. The audit trail gets a `projects` / `create` entry.

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
