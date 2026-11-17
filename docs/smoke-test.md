# Smoke test

Smoke test of starter-kit (branch `feat/app-bootstrap`) against a real, throwaway PostgreSQL, run on
2026-11-17 after the fix wave. The run was made on the code at `dc9cf41`; later commits changed
documentation, validation rules (`DB_SSLMODE`, `APP_TIMEZONE`), and the database logger only (plus the
session time zone selection on the `DB_*` path), and were checked by their own tests, not by this run.

The run repeats the 31 checks of the previous run (empty
database `fresh`, "legacy" database `legacy`, the new startup flow, the "Adding a module" recipe) and
adds the checks for the fixes. This time the database is configured through the `DB_*` variables
everywhere; `DATABASE_URL` is a separate check (1b, 1c).

Overall result: **37 checks, 37 PASS, 0 FAIL.**

The previous run found one failure (check 1a): the `DB_*` configuration could not connect because
the time zone reached the server with quotes. It is fixed; see
[Resolved: `DB_*` connection](#resolved-db_-connection-failed-against-a-real-postgresql). Every other
fix of the wave is exercised below (rows 32 to 35 are new).

## How to reproduce

All values are fake. Nothing here uses a `.env` file; configuration comes from exported variables
(the service accepts a missing `.env` when `APP_ENV` is set). Scratch files (binaries, logs, helper
scripts) live outside the repository.

```sh
# 1. Throwaway database (host port 55434, bound to localhost only)
docker run --rm -d --name starter-kit-bootstrap-test -e POSTGRES_PASSWORD=test \
  -p 127.0.0.1:55434:5432 postgres:latest
# wait until it accepts connections (the image restarts once while initialising), then:
docker exec starter-kit-bootstrap-test psql -U postgres \
  -c "CREATE DATABASE fresh" -c "CREATE DATABASE legacy" -c "CREATE DATABASE fresh2" \
  -c "CREATE DATABASE urlpath" -c "CREATE DATABASE urlkv"

# 2. Build outside the repo and set the environment
go build -o "$SCRATCH/starter-kit-smoke" ./cmd/api
export APP_NAME=starter-kit-smoke APP_ENV=development GIN_MODE=release
export JWT_KEY=fake-smoke-test-jwt-key-0123456789abcdef
export MEDIA_ENABLED=false PATH_MIGRATE=file://migrations
# no REDIS_* and no SMTP_* variables unless a check says so

# 3a. Database through the DB_* parts (primary path, check 1a): no DATABASE_URL
export DB_HOST=127.0.0.1 DB_PORT=55434 DB_USERNAME=postgres DB_PASS=test DB_SSLMODE=disable
PORT=18080 DB_NAME=fresh "$SCRATCH/starter-kit-smoke" -migrate

# 3b. DATABASE_URL instead (checks 1b and 1c; the DB_* variables are then unset)
unset DB_HOST DB_PORT DB_USERNAME DB_PASS DB_SSLMODE DB_NAME
DATABASE_URL="postgres://postgres:test@127.0.0.1:55434/urlpath?sslmode=disable" PORT=18089 "$SCRATCH/starter-kit-smoke" -migrate
DATABASE_URL="host=127.0.0.1 port=55434 user=postgres password=test dbname=urlkv sslmode=disable" PORT=18090 "$SCRATCH/starter-kit-smoke" -migrate

# 4. Fresh path (run from the repo root so file://migrations resolves; DB_* exported again)
PORT=18080 DB_NAME=fresh "$SCRATCH/starter-kit-smoke" -migrate &
# 5. Cross-application token check: other APP_NAME, same JWT_KEY and database
PORT=18081 APP_NAME=other-app DB_NAME=fresh "$SCRATCH/starter-kit-smoke" -migrate=false &

# 6. Legacy path: the OLD six migrations from main, then golang-migrate's bookkeeping
for f in 000001_create_users_table 000002_create_rbac_tables 000003_create_audit_trails_table \
         000004_create_app_configs_table 000005_create_locations_tables 000006_create_media_table; do
  git show main:migrations/$f.up.sql | docker exec -i starter-kit-bootstrap-test \
    psql -U postgres -d legacy -v ON_ERROR_STOP=1 -q
done
docker exec -i starter-kit-bootstrap-test psql -U postgres -d legacy -c \
 "CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL); INSERT INTO schema_migrations VALUES (6, false);"
# remove one admin role_permissions row (via ctid), record counts, then:
PORT=18086 DB_NAME=legacy "$SCRATCH/starter-kit-smoke" -migrate &

# 7. New-flow checks
PORT=18092 DB_NAME=fresh2 "$SCRATCH/starter-kit-smoke" -migrate-only                  # exit 0, no listener
docker pause starter-kit-bootstrap-test; curl -m 10 -i http://127.0.0.1:18080/readyz  # 503
docker unpause starter-kit-bootstrap-test; curl -i http://127.0.0.1:18080/readyz       # 200
kill -TERM <pid>                                                                       # idle shutdown
PORT=18085 REDIS_HOST=127.0.0.1 REDIS_PORT=56999 REDIS_PASSWORD=fake-redis-secret-xyz "$SCRATCH/starter-kit-smoke" -migrate=false
docker build -q -t starter-kit-bootstrap-check . ; docker run --rm starter-kit-bootstrap-check -h ; echo $?
docker run --rm -e APP_ENV=development starter-kit-bootstrap-check -h ; echo $? ; docker rmi starter-kit-bootstrap-check

# 8. Cleanup
kill <pids>; docker stop starter-kit-bootstrap-test   # --rm removes the container
```

For the shutdown checks with an open connection, a small Python client (`socket`) opened a
connection to the service, either completed one keep-alive request or sent a request line, headers,
and a part of the body (`Content-Length: 100`, 20 bytes sent), then sent SIGTERM to the service and
timed how long the process lived. For the second-signal checks the same half-written request holds
the graceful shutdown open: after the first signal the client waits 1.5 s, confirms the process is
still alive, sends the second signal, and times how long the process takes to disappear; the exit
status comes from `wait` (shell) or `Popen.wait` (Python).

HTTP checks used `curl` against `127.0.0.1` only. Registration body (fields from authkit
`dto.UserRegister`):

```sh
curl -X POST http://127.0.0.1:18080/api/user/register -H 'Content-Type: application/json' \
  -d '{"name":"Smoke User","email":"smoke@example.test","phone":"081234567890","password":"SmokePass123!"}'
curl -X POST http://127.0.0.1:18080/api/user/login -H 'Content-Type: application/json' \
  -d '{"email":"smoke@example.test","password":"SmokePass123!"}'
```

The automated integration test of the same fix
(`infrastructure/database`, run with `STARTER_KIT_TEST_DATABASE_URL` pointing at this container)
also passes: both connection paths, `SHOW TimeZone` = `Asia/Jakarta`, a role with the password
`p ass'w\ord@:/` connecting through the `DB_*` path, and a wrong password reported as
`authentication failed` with no part of either password in the error or the captured log output.

## Results: empty database (`fresh`, `urlpath`, `urlkv`)

Checks 1a and 2 to 12 use the `DB_*` parts. Times are from launch to the first `GET /healthcheck`
200, including the migrations.

| # | Check | Expected | Actual | Result |
|---|---|---|---|---|
| 1a | Start with `-migrate`, database configured through `DB_*` (no `DATABASE_URL`) | starts without error | healthcheck 200 after 1.71 s; log shows `Migration Success`, `All routes registered successfully`, `Listening on [::]:18080`. The PostgreSQL log has no `TimeZone` error from this run | PASS |
| 1b | Start with `-migrate`, `DATABASE_URL` in URL form (`postgres://...`, empty database `urlpath`) | starts without error | healthcheck 200 after 0.21 s; `/readyz` 200; `authkit_schema_migrations` 4 / f, `schema_migrations` 6 / f; clean SIGTERM, exit 0 | PASS |
| 1c | Start with `-migrate`, `DATABASE_URL` in key=value form (database `urlkv`) | starts without error | healthcheck 200 after 0.21 s; `/readyz` 200; clean SIGTERM, exit 0 | PASS |
| 2 | `authkit_schema_migrations` | version 4, not dirty | `4 / f` | PASS |
| 3 | `schema_migrations` | version 6, not dirty | `6 / f` | PASS |
| 4 | `GET /healthcheck` | 200 | 200 `{"message":"OK!!"}` | PASS |
| 5 | `GET /api/user/register/status` | 200 | 200 `{"enabled":true,"otp_cooldown":60,"otp_enabled":false}` | PASS |
| 6 | `GET /api/users` without token | 401 | 401 `Invalid or expired token. Please login again.` | PASS |
| 7 | `POST /api/user/register` (fake user) | success | 201, `"role":"viewer"`, phone normalised to `6281234567890` | PASS |
| 8 | `POST /api/user/login` | 200 with `access_token` | 200, `access_token` present (408 chars); token claims `iss` = `aud` = `starter-kit-smoke` | PASS |
| 9 | `GET /api/user` with token | 200, role `viewer` | 200, user `Smoke User`, role `viewer` | PASS |
| 10 | `GET /api/users` with viewer token | 403 | 403 `Access denied. You do not have the required permissions.` | PASS |
| 11 | `GET /api/location/province` | not 401/403 | 200, list of provinces (Aceh, Bali, ...) | PASS |
| 12 | Same token on instance 2 (`APP_NAME=other-app`, same `JWT_KEY`, same DB) | 401 | 401 `Invalid or expired token. Please login again.`; the same token still gave 200 on instance 1; instance 2 exited 0 on SIGTERM | PASS |

## Results: legacy database (`legacy`)

Legacy state: old migrations 000001-000006 from `main`, `schema_migrations` = 6 (not dirty).
Before the run, one `role_permissions` row of role `admin` was deleted (admin 34 -> 33). Started
through the `DB_*` parts.

| # | Check | Expected | Actual | Result |
|---|---|---|---|---|
| 13 | Start with `-migrate` | starts without error | healthcheck 200 after 0.11 s; `Migration Success`, `All routes registered successfully`; no `WARN` or `ERROR` about location sync or missing tables | PASS |
| 14 | `authkit_schema_migrations` | version 4 | `4 / f` | PASS |
| 15 | `schema_migrations` | stays 6 | `6 / f` | PASS |
| 16 | Row counts unchanged | `role_permissions`, `permissions`, `roles`, `menu_items` same as before | before and after: 77 / 34 / 4 / 7; the deleted admin row was not re-added (admin still 33) | PASS |
| 17 | `GET /api/user/register/status` | 200 | 200 `{"enabled":true,"otp_cooldown":60,"otp_enabled":false}` | PASS |

A second start on the migrated legacy database also worked (0.08 s, `Migration Success` with nothing
to apply, SIGTERM exit 0, no missing-table lines).

## Results: new startup flow

| # | Check | Expected | Actual | Result |
|---|---|---|---|---|
| 18 | `-migrate-only` on an empty database (`fresh2`), `DB_*` | exit 0; both version tables filled; no routes built; no port opened | exit 0 after 0.35 s; `authkit_schema_migrations` 4 / f, `schema_migrations` 6 / f; log ends with `Migration finished; not serving (migrate-only)`; 0 `Listening on` lines and 0 `All routes registered` lines; no listener on the port (`lsof` 0 lines, `curl` exit 7) | PASS |
| 19 | `GET /readyz` with a healthy database | 200 | 200 `{"status":"ok"}` | PASS |
| 20 | `GET /readyz` after `docker pause` of the PostgreSQL container | 503 | 503 `{"status":"unavailable"}` after 2.00 s (the 2 s readiness limit); log `WARN readyz; database ping failed: driver: bad connection`; the reason is not in the response | PASS |
| 21 | `GET /readyz` after `docker unpause` | 200 | 200 `{"status":"ok"}` on the first retry; `/healthcheck` 200 | PASS |
| 22 | SIGTERM while idle | exit 0 in under 2 s | exit 0 in 0.57 s (measured with `wait`; this was right after the rejected 11 MB request of check 27 and the pause cycle, and the previous run measured 0.005 s; the cause of the difference was not investigated); log `Shutdown started`, `Shutdown complete` | PASS |
| 23 | SIGTERM with an idle keep-alive connection open (one request already answered) | prompt exit 0, the idle connection closed | process gone after 0.03 s, exit 0, the client saw the connection closed (empty read) | PASS |
| 24 | SIGTERM with a request half-written (headers and 20 of 100 body bytes sent) | the service waits for it up to `HTTP_SHUTDOWN_TIMEOUT` (15 s), then cuts it off with exit 1 | process gone after 15.01 s, exit 1; log `Shutdown started`, then `ERROR service exited with error: app: shutdown timed out with requests still in flight`; the client saw the connection closed | PASS |
| 25 | `REDIS_HOST=127.0.0.1 REDIS_PORT=56999` (closed port), fake `REDIS_PASSWORD` | exit 1, message names Redis, no DSN or password in the log | exit 1 after 1.80 s; log `OpenRedis; ping redis: connection refused` and `service exited with error: open redis: ping redis: connection refused`; the fake password appears 0 times in the log; no listener opened | PASS |
| 26 | No Redis variables: start time | no 2 s pause (it was 2-3 s before) | healthcheck 200 after 0.10 s without migrations, 1.71 s on an empty database including all migrations (0.56 s in the previous run; the Docker host was slower to answer this time), 0.11 s on the legacy database | PASS |
| 27 | Body limit: 11 MB declared `Content-Length` to `POST /api/user/login` | 413 | 413 `request body too large` | PASS |
| 28 | `docker build` | image built | built (50 s, base layers cached); `migrations/` contains only 000005 and 000006 | PASS |
| 29 | `docker run --rm <image> -h`, no environment | binary runs, configuration error | exit code 1; `service exited with error: load environment: load .env (and APP_ENV is not set): open .env: no such file or directory` | PASS |
| 30 | `docker run --rm -e APP_ENV=development <image> -h` | usage printed | exit code 0; prints `Usage of api:` with `-appname`, `-migrate` (default true), `-migrate-only`, `-port`. The check image was removed afterwards | PASS |
| 31 | The README "Adding a module" recipe (extra) | compiles, migrates, enforces permissions | in a scratch copy of the repository (`git archive` of this commit, never this one) with the recipe's files and its config change added: builds and vets; migration 000007 applied (`schema_migrations` 7 / f); 5 `projects` permissions and 10 role grants (admin, superadmin) created; `GET /api/projects` 401 without token, 403 for a viewer; after granting the viewer role the five permissions, 200 with an empty list, `POST` 201, `?search=first` lists it; audit row `projects / create / success`; the down migration runs (`DELETE 5`, `DELETE 1`, `DROP TABLE`) | PASS |

## Results: checks added by the fix wave

| # | Check | Expected | Actual | Result |
|---|---|---|---|---|
| 32 | First start on an empty database logs no warning or error about missing tables | no `does not exist` / `failed to mark interrupted location sync jobs` line | 0 matching lines in the logs of the first start on `fresh` (1a), on `urlpath` (1b) and in the `-migrate-only` run on `fresh2` (18). The only `WARN`/`ERROR` lines are the expected ones listed under Observations | PASS |
| 33 | A second SIGTERM during a held shutdown ends the process at once | exits immediately, not after `HTTP_SHUTDOWN_TIMEOUT` | half-written request held the shutdown open; after the first SIGTERM the process was still alive 1.5 s later; 0.01 s after the second SIGTERM it was gone, exit status 143 (killed by SIGTERM; the log shows `Shutdown started` and nothing else) | PASS |
| 34 | A second SIGINT (Ctrl-C) during a held shutdown | same | first signal SIGINT, process alive 1.5 s later, gone 0.00 s after the second SIGINT, `Popen` return code -2 (killed by SIGINT). See the note on the first attempt below | PASS |
| 35 | Database errors name the kind of problem, never a credential | operator can tell config errors from network ones; no password in the log | wrong `DB_PASS=wrongpw-SECRET-xyz`: exit 1, `open database: connect to database: authentication failed`; `DB_NAME=does_not_exist`: exit 1, `connect to database: server rejected the connection parameters`; closed `DB_PORT`: exit 1, `connect to database: connection refused`. The wrong password appears 0 times in the log | PASS |

Note on check 34: the first attempt started the service from a non-interactive shell as a background
job and the second SIGINT did not end it. That is not a defect of the service: such shells start
background jobs with SIGINT ignored, and Go correctly returns to "ignored" when signal handling is
restored, so the signal stays ignored by design. Started with default signal dispositions (a
foreground process, as with a real Ctrl-C, or `Popen` with `SIGINT` reset), the second SIGINT ends it
immediately. SIGTERM (check 33) is not affected by this.

### What the shutdown checks show, and what they do not

- Shown: the process exits 0 within milliseconds to a fraction of a second when idle or when only an
  idle keep-alive connection is open (checks 22 and 23). When a request is still being received after
  SIGTERM, the service keeps waiting for it for the full `HTTP_SHUTDOWN_TIMEOUT`, then cuts it off and
  exits 1 with `ErrShutdownTimeout` (check 24); a second signal ends it immediately (checks 33, 34).
  The half-written request was able to hold the shutdown open because `HTTP_READ_TIMEOUT` (30 s) is
  longer than `HTTP_SHUTDOWN_TIMEOUT` (15 s).
- Not shown: a request that is being processed at SIGTERM and still completes normally with its
  response delivered. No route of this service is slow enough to observe that without changing the
  code, so it was not demonstrated here; it is covered by the unit tests in `internal/app`.

## Resolved: `DB_*` connection failed against a real PostgreSQL

Check 1a failed in the previous run: with `DB_HOST`, `DB_PORT`, `DB_USERNAME`, `DB_PASS`, `DB_NAME`,
`DB_SSLMODE` set, every start failed with `connect to database: unavailable`, and only the PostgreSQL
log showed the cause (`FATAL: invalid value for parameter "TimeZone": "'Asia/Jakarta'"`).

- Cause: `config.Database.DSN` single-quotes every value (so awkward passwords cannot break the
  string), and `gorm.io/driver/postgres` v1.6.3 extracts `TimeZone=...` from the raw DSN text with its
  own regular expression and passes the match, quotes included, to the server as a session parameter.
  pgx itself parses the quoted form correctly.
- Fix: `database.Open` parses the connection string with pgx, sets the session time zone on the
  parsed configuration (`RuntimeParams`), and hands gorm an existing pool (`stdlib.OpenDB`), so the
  driver's regular expression never sees the DSN. A time zone written in `DATABASE_URL` still wins.
  The error classifier now distinguishes `authentication failed`, `server rejected the connection
  parameters`, `connection refused`, `timed out`, `unreachable` and `invalid configuration`, without
  any driver text.
- Why it was not caught: no automated test connected to a PostgreSQL. There is now an integration
  test (skipped unless `STARTER_KIT_TEST_DATABASE_URL` is set) and this document's check 1a.

## Observations

- Startup time without Redis: 0.10 s to a working `/healthcheck` (no migration), 1.71 s on an empty
  database including all migrations in this run. There are no `redis:` lines at all when Redis is not
  configured.
- Log lines seen during a clean shutdown (idle or with an idle keep-alive connection):
  `Shutdown started`, `Shutdown complete`, and nothing else. When the time limit runs out:
  `Shutdown started`, then `ERROR service exited with error: app: shutdown timed out with requests still in flight`.
  The wording is neutral because the same exit path serves startup, serving, and shutdown errors; the
  cause in the text says which.
- With Redis configured but unreachable the service takes about 1.8 s to give up and exits 1. The log
  has the service's own lines (`ping redis: connection refused`, no URL or password) and four lines
  from the Redis client library's own logger (`redis: connection pool: failed to dial after 5
  attempts: dial tcp 127.0.0.1:56999: connect: connection refused`). Those name the address but carry
  no credential.
- Log line `Loading config: config - development.env ... Not Found in [.../config]` (ERROR level)
  still appears because `APP_ENV=development` makes `config.LoadRemote` look for an optional config
  file that does not exist. The service continues normally.
- authkit logs two `WARN` lines in this setup: `AppEnv is a development value ...` (password reset
  tokens are returned in the API response) and `Redis is not configured: login rate limiting, register
  rate limiting, sessions, OTP and email password reset are inactive`. These, and the config-file
  line above, are the only `WARN`/`ERROR` lines on a first start against an empty database.
- The routes are now built after the migrations. The location service marks sync jobs interrupted by
  a previous run when it is constructed, which queries `location_sync_jobs`; the old order logged a
  `WARN ... relation "location_sync_jobs" does not exist` on a first start. `-migrate-only` now builds
  no routes at all (the previous order built them before migrating).
- In the earlier smoke test, a first registration attempt with `SmokePass123` got 400
  `password must contain at least 1 symbol (!@#$%^&*...)`; that is the authkit password rule, not a
  defect. `SmokePass123!` succeeds.
- Migration order works for the legacy database: authkit migrations ran against tables created by the
  old starter-kit migrations without altering seeded counts. The old `main` migration files
  000001-000004 no longer exist in this branch (only 000005 and 000006); on the fresh database
  `schema_migrations` still reaches 6 because golang-migrate numbers by file prefix.
- `docker run <image> -h` without `APP_ENV` stops at the missing `.env` file before it prints usage
  (exit 1), because `.env` is loaded before the flags are parsed. That is the documented behavior
  (`.env` is optional only when `APP_ENV` is set).
