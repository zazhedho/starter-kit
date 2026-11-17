# Smoke test

Smoke test of starter-kit (branch `feat/app-bootstrap`, commit 896ba7a) against a real, throwaway
PostgreSQL, after the startup flow was rebuilt (`cmd/api` -> `internal/app`: explicit lifecycle,
graceful shutdown, migrate step, optional Redis, `/readyz`). It repeats the 17 checks of the
previous adoption smoke test (empty database `fresh`, "legacy" database `legacy`) and adds the
checks for the new flow. Run on 2026-11-17.

Overall result: **one check FAILS** and every other check passes.

- **FAIL (check 1a, blocker):** starting with the database configured through the `DB_*` variables
  does not work against a real PostgreSQL. The service exits with `connect to database: unavailable`
  because the server rejects the time zone setting `'Asia/Jakarta'` (with the quotes). Cause and
  analysis are in [Finding](#finding-db_-connection-fails-against-a-real-postgresql).
- Because of that, every other check was run with the same database configured through
  `DATABASE_URL` (a key=value connection string without quotes, see "How to reproduce"). That is a
  workaround for this run, not a verification of the `DB_*` path; everything below it passes.

## How to reproduce

All values are fake. Nothing here uses a `.env` file; configuration comes from exported variables
(the service accepts a missing `.env` when `APP_ENV` is set). Scratch files (binary, logs) live
outside the repository.

```sh
# 1. Throwaway database (host port 55434, bound to localhost only)
docker run --rm -d --name starter-kit-bootstrap-test -e POSTGRES_PASSWORD=test \
  -p 127.0.0.1:55434:5432 postgres:latest
# wait until it accepts connections (the image restarts once while initialising), then:
docker exec starter-kit-bootstrap-test psql -U postgres \
  -c "CREATE DATABASE fresh" -c "CREATE DATABASE legacy" -c "CREATE DATABASE fresh2"

# 2. Build outside the repo and set the environment
go build -o "$SCRATCH/starter-kit-smoke" ./cmd/api
export APP_NAME=starter-kit-smoke APP_ENV=development GIN_MODE=release
export JWT_KEY=fake-smoke-test-jwt-key-0123456789abcdef
export MEDIA_ENABLED=false PATH_MIGRATE=file://migrations
# no REDIS_* and no SMTP_* variables unless a check says so

# 3a. Database through the DB_* parts (check 1a: this is the configuration that FAILS today)
export DB_HOST=127.0.0.1 DB_PORT=55434 DB_USERNAME=postgres DB_PASS=test DB_SSLMODE=disable
PORT=18090 DB_NAME=fresh "$SCRATCH/starter-kit-smoke" -migrate

# 3b. Workaround used for every other check: one unquoted key=value string
unset DB_HOST DB_PORT DB_USERNAME DB_PASS DB_SSLMODE
export DATABASE_URL="host=127.0.0.1 port=55434 user=postgres password=test dbname=fresh sslmode=disable TimeZone=Asia/Jakarta"

# 4. Fresh path (run from the repo root so file://migrations resolves)
PORT=18080 "$SCRATCH/starter-kit-smoke" -migrate &
# 5. Cross-application token check: other APP_NAME, same JWT_KEY and database
PORT=18081 APP_NAME=other-app "$SCRATCH/starter-kit-smoke" -migrate=false &

# 6. Legacy path: the OLD six migrations from main, then golang-migrate's bookkeeping
for f in 000001_create_users_table 000002_create_rbac_tables 000003_create_audit_trails_table \
         000004_create_app_configs_table 000005_create_locations_tables 000006_create_media_table; do
  git show main:migrations/$f.up.sql | docker exec -i starter-kit-bootstrap-test \
    psql -U postgres -d legacy -v ON_ERROR_STOP=1 -q
done
docker exec -i starter-kit-bootstrap-test psql -U postgres -d legacy -c \
 "CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL); INSERT INTO schema_migrations VALUES (6, false);"
# remove one admin role_permissions row (via ctid), record counts, then:
DATABASE_URL="host=127.0.0.1 port=55434 user=postgres password=test dbname=legacy sslmode=disable TimeZone=Asia/Jakarta" \
  PORT=18086 "$SCRATCH/starter-kit-smoke" -migrate &

# 7. New checks
PORT=18090 DATABASE_URL=<fresh2> "$SCRATCH/starter-kit-smoke" -migrate-only        # exit 0, no listener
docker pause starter-kit-bootstrap-test; curl -m 10 -i http://127.0.0.1:18080/readyz  # 503
docker unpause starter-kit-bootstrap-test; curl -i http://127.0.0.1:18080/readyz       # 200
kill -TERM <pid>                                                                       # idle shutdown
PORT=18085 REDIS_HOST=127.0.0.1 REDIS_PORT=56999 REDIS_PASSWORD=fake-redis-secret-xyz "$SCRATCH/starter-kit-smoke" -migrate=false
docker build -q -t starter-kit-bootstrap-check . ; docker run --rm starter-kit-bootstrap-check -h
docker run --rm -e APP_ENV=development starter-kit-bootstrap-check -h ; docker rmi starter-kit-bootstrap-check

# 8. Cleanup
kill <pids>; docker stop starter-kit-bootstrap-test   # --rm removes the container
```

For the shutdown checks with an open connection, a small Python client (`socket`) opened a
connection to the service, either completed one keep-alive request or sent a request line, headers,
and a part of the body (`Content-Length: 100`, 20 bytes sent), then the script sent SIGTERM to the
service and timed how long the process lived.

HTTP checks used `curl` against `127.0.0.1` only. Registration body (fields from authkit
`dto.UserRegister`):

```sh
curl -X POST http://127.0.0.1:18080/api/user/register -H 'Content-Type: application/json' \
  -d '{"name":"Smoke User","email":"smoke@example.test","phone":"081234567890","password":"SmokePass123!"}'
curl -X POST http://127.0.0.1:18080/api/user/login -H 'Content-Type: application/json' \
  -d '{"email":"smoke@example.test","password":"SmokePass123!"}'
```

## Results: empty database (`fresh`)

Checks 1b to 12 use `DATABASE_URL` (see the finding for check 1a). Times are from launch to the first
`GET /healthcheck` 200, including the migrations.

| # | Check | Expected | Actual | Result |
|---|---|---|---|---|
| 1a | Start with `-migrate`, database configured through `DB_*` | starts without error | exit 1. Log: `database.Open; connect to database: unavailable`, then `startup failed: open database: connect to database: unavailable`. PostgreSQL log: `FATAL: invalid value for parameter "TimeZone": "'Asia/Jakarta'"`. Reproduced on every attempt (2 runs: `-migrate` on `fresh`, `-migrate-only` on `fresh2`) | **FAIL** |
| 1b | Start with `-migrate`, database through `DATABASE_URL` (workaround) | starts without error | healthcheck 200 after 0.56 s; log shows `Migration Success`, `All routes registered successfully`, `Listening on [::]:18080` | PASS |
| 2 | `authkit_schema_migrations` | version 4, not dirty | `4 / f` | PASS |
| 3 | `schema_migrations` | version 6, not dirty | `6 / f` | PASS |
| 4 | `GET /healthcheck` | 200 | 200 `{"message":"OK!!"}` | PASS |
| 5 | `GET /api/user/register/status` | 200 | 200 `{"enabled":true,"otp_cooldown":60,"otp_enabled":false}` | PASS |
| 6 | `GET /api/users` without token | 401 | 401 `Invalid or expired token. Please login again.` | PASS |
| 7 | `POST /api/user/register` (fake user) | success | 201, `"role":"viewer"`, phone normalised to `6281234567890` | PASS |
| 8 | `POST /api/user/login` | 200 with `access_token` | 200, `access_token` present (408 chars); token claims `iss` = `aud` = `starter-kit-smoke` | PASS |
| 9 | `GET /api/user` with token | 200, role `viewer` | 200, `"role":"viewer"`, permissions `view_dashboard, list_menus, view_menu, view_profile` | PASS |
| 10 | `GET /api/users` with viewer token | 403 | 403 `Access denied. You do not have the required permissions.` | PASS |
| 11 | `GET /api/location/province` | not 401/403 | 200, list of provinces (Aceh, Bali, ...) | PASS |
| 12 | Same token on instance 2 (`APP_NAME=other-app`, same `JWT_KEY`, same DB) | 401 | 401 `Invalid or expired token. Please login again.`; the same token still gave 200 on instance 1; instance 2 exited 0 on SIGTERM | PASS |

## Results: legacy database (`legacy`)

Legacy state: old migrations 000001-000006 from `main`, `schema_migrations` = 6 (not dirty).
Before the run, one `role_permissions` row of role `admin` was deleted (admin 34 -> 33). Started
through `DATABASE_URL` (the `DB_*` path was not repeated here; check 1a applies to it equally).

| # | Check | Expected | Actual | Result |
|---|---|---|---|---|
| 13 | Start with `-migrate` | starts without error | healthcheck 200 after 0.12 s; `Migration Success`, `All routes registered successfully`; no `WARN` about location sync (the tables already exist) | PASS |
| 14 | `authkit_schema_migrations` | version 4 | `4 / f` | PASS |
| 15 | `schema_migrations` | stays 6 | `6 / f` | PASS |
| 16 | Row counts unchanged | `role_permissions`, `permissions`, `roles`, `menu_items` same as before | before and after: 77 / 34 / 4 / 7; the deleted admin row was not re-added (admin still 33) | PASS |
| 17 | `GET /api/user/register/status` | 200 | 200 `{"enabled":true,"otp_cooldown":60,"otp_enabled":false}` | PASS |

A second start on the migrated legacy database also worked (0.08 s, `Migration Success` with nothing
to apply, SIGTERM exit 0).

## Results: new startup flow

| # | Check | Expected | Actual | Result |
|---|---|---|---|---|
| 18 | `-migrate-only` on an empty database (`fresh2`) | exit 0; both version tables filled; no port opened | exit 0 after 0.87 s; `authkit_schema_migrations` 4 / f, `schema_migrations` 6 / f; log ends with `Migration finished; not serving (migrate-only)` and has no `Listening on`; no listener on the port (`lsof` 0 lines, `curl` exit 7) | PASS |
| 19 | `GET /readyz` with a healthy database | 200 | 200 `{"status":"ok"}` | PASS |
| 20 | `GET /readyz` after `docker pause` of the PostgreSQL container | 503 | 503 `{"status":"unavailable"}` after 2.0 s (the 2 s readiness limit); log `WARN readyz; database ping failed: driver: bad connection`; the reason is not in the response | PASS |
| 21 | `GET /readyz` after `docker unpause` | 200 | 200 `{"status":"ok"}` about 1 s after unpausing; `/healthcheck` 200 | PASS |
| 22 | SIGTERM while idle | exit 0 in under 2 s | exit 0 in 0.005 s (measured with `wait`); log `Shutdown started`, `Shutdown complete` | PASS |
| 23 | SIGTERM with an idle keep-alive connection open (one request already answered) | prompt exit 0, the idle connection closed | process gone after 0.02 s, exit 0, the client saw the connection closed (empty read) | PASS |
| 24 | SIGTERM with a request half-written (headers and 20 of 100 body bytes sent) | the service waits for it up to `HTTP_SHUTDOWN_TIMEOUT` (15 s), then cuts it off with exit 1 | process gone after 15.03 s, exit 1; log `Shutdown started`, then `ERROR startup failed: app: shutdown timed out with requests still in flight`; the client saw the connection closed | PASS |
| 25 | `REDIS_HOST=127.0.0.1 REDIS_PORT=56999` (closed port), fake `REDIS_PASSWORD` | exit 1, message names Redis, no DSN or password in the log | exit 1 after 1.84 s; log `OpenRedis; ping redis: connection refused` and `startup failed: open redis: ping redis: connection refused`; the fake password and the database password appear 0 times in the log; no listener opened | PASS |
| 26 | No Redis variables: start time | no 2 s pause (it was 2-3 s before) | healthcheck 200 after 0.08 s without migrations, 0.56 s on an empty database including all migrations, 0.12 s on the legacy database | PASS |
| 27 | Body limit: 11 MB declared `Content-Length` to `POST /api/user/login` | 413 | 413 `request body too large` | PASS |
| 28 | `docker build` | image built | built (2 min 5 s with the base layers); `migrations/` contains only 000005 and 000006 | PASS |
| 29 | `docker run --rm <image> -h`, no environment | binary runs, configuration error | `startup failed: load environment: load .env (and APP_ENV is not set): open .env: no such file or directory` (exit code not recorded) | PASS |
| 30 | `docker run --rm -e APP_ENV=development <image> -h` | usage printed | prints `Usage of api:` with `-appname`, `-migrate` (default true), `-migrate-only`, `-port` (exit code not recorded). The check image was removed afterwards | PASS |
| 31 | The README "Adding a module" recipe (extra) | compiles, migrates, enforces permissions | in a scratch copy of the repository (never in this one): migration 000007 applied (`schema_migrations` 7 / f); 5 `projects` permissions and 10 role grants (admin, superadmin) created; `GET /api/projects` 401 without token, 403 for a viewer; after granting the viewer role the five permissions, 200 with an empty list, `POST` 201, `?search=first` lists it; audit row `projects / create / success`; the down migration runs | PASS |

### What the shutdown checks show, and what they do not

- Shown: the process exits 0 within milliseconds when idle or when only an idle keep-alive
  connection is open (checks 22 and 23). When a request is still being received after SIGTERM, the
  service keeps waiting for it for the full `HTTP_SHUTDOWN_TIMEOUT`, then cuts it off and exits 1
  with `ErrShutdownTimeout` (check 24). The half-written request was able to hold the shutdown
  open because `HTTP_READ_TIMEOUT` (30 s) is longer than `HTTP_SHUTDOWN_TIMEOUT` (15 s).
- Not shown: a request that is being processed at SIGTERM and still completes normally with its
  response delivered. No route of this service is slow enough to observe that without changing the
  code, so it was not demonstrated here; it is covered by the unit tests in `internal/app`.

## Finding: `DB_*` connection fails against a real PostgreSQL

Check 1a. Symptom: with `DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_PASS`, `DB_NAME`, `DB_SSLMODE` set,
every start fails with only `connect to database: unavailable`. The cause is visible in the
PostgreSQL server log, not in the service log:

```text
FATAL:  invalid value for parameter "TimeZone": "'Asia/Jakarta'"
```

Analysis (the code was not changed):

- `config.Database.DSN` (commit 5d8001f, "never leak database credentials") builds a key=value DSN
  and single-quotes every value, so the time zone part is `TimeZone='Asia/Jakarta'`.
- `pgx.ParseConfig` handles that correctly (checked in a scratch test: `RuntimeParams` holds
  `Asia/Jakarta`). But `gorm.io/driver/postgres` v1.6.3 does not leave it to pgx: it applies its own
  regular expression `(time_zone|TimeZone|timezone)=(.*?)($|&| )` to the raw DSN and copies the
  match into the connection's run-time parameters. The match includes the quotes, so the server
  receives `'Asia/Jakarta'` and refuses the session.
- A key=value string with `TimeZone=Asia/Jakarta` unquoted works (all other checks), and a URL form
  without `TimeZone` would not hit this code path, but the `DB_*` parts always go through `DSN()`.
- Why it was not caught: no automated test connects to a PostgreSQL. The credential-leak tests only
  use refused or malformed targets, which fail before the time zone is sent.
- Secondary: `classify` maps this failure to the generic `unavailable`, so the service log gives no
  hint of a configuration problem.
- Directions for a fix (not applied): keep quoting for the credential values and stop putting the
  time zone in the DSN text (set it on the parsed pgx config's `RuntimeParams` instead), or leave the
  time zone value unquoted (IANA names contain no space, quote, or backslash, and `Validate` already
  requires a known zone). Either way, add a test that connects to a real database.

## Observations

- Startup time without Redis: 0.08 s to a working `/healthcheck` (no migration), 0.56 s on an empty
  database including all migrations. The old flow spent about 2 s on Redis retries even when Redis
  was not configured; there are no `redis:` lines at all now.
- Log lines seen during a clean shutdown (idle or with an idle keep-alive connection):
  `Shutdown started`, `Shutdown complete`, and nothing else. When the time limit runs out:
  `Shutdown started`, then `ERROR startup failed: app: shutdown timed out with requests still in flight`.
  That second message says "startup failed" for a shutdown problem, because `cmd/api/main.go` uses
  one message for every error returned by `app.Run`.
- With Redis configured but unreachable the service takes about 1.8 s to give up (most likely the Redis client's
  own retries; not investigated) and exits 1; the log lines name the problem (`ping redis: connection refused`) and
  contain no URL or password.
- On the first start against an empty database the log has one `WARN failed to mark interrupted
  location sync jobs: ... relation "location_sync_jobs" does not exist`. The routes (and the
  location service that runs this clean-up) are built before the migrations run. It is harmless and
  does not appear on later starts or on the legacy database.
- Log line `Loading config: config - development.env ... Not Found in [.../config]` (ERROR level)
  still appears because `APP_ENV=development` makes `GetAppConf` look for an optional config file
  that does not exist. The service continues normally.
- authkit logs two `WARN` lines in this setup: `AppEnv is a development value ...` (password reset
  tokens are returned in the API response) and `Redis is not configured: login rate limiting, register
  rate limiting, sessions, OTP and email password reset are inactive`.
- The login handler logs its response body at DEBUG level with the tokens shown as `[REDACTED]`; the
  real access token and the password appeared 0 times in the service log.
- In the earlier smoke test, a first registration attempt with `SmokePass123` got 400
  `password must contain at least 1 symbol (!@#$%^&*...)`; that is the authkit password rule, not a
  defect. `SmokePass123!` succeeds.
- Migration order works for the legacy database: authkit migrations ran against tables created by the
  old starter-kit migrations without altering seeded counts. The old `main` migration files
  000001-000004 no longer exist in this branch (only 000005 and 000006); on the fresh database
  `schema_migrations` still reaches 6 because golang-migrate numbers by file prefix.
- `docker run <image> -h` without `APP_ENV` stops at the missing `.env` file before it prints usage,
  because `.env` is loaded before the flags are parsed. That is the documented behavior (`.env` is
  optional only when `APP_ENV` is set).
