# Adoption smoke test

Smoke test of starter-kit (branch `feat/adopt-shared-modules`, commit 802d51a) against a real,
throwaway PostgreSQL, after auth/users/RBAC were replaced by the `logus`, `gokit` and `authkit`
modules. Run on 2026-11-17. Two paths: an empty database (`fresh`) and a "legacy" database
created by the service's old six migrations (`legacy`).

Overall result: all checks PASS on both paths.

## How to reproduce

All values are fake. Nothing here uses a `.env` file; configuration comes from exported variables.

```sh
# 1. Throwaway database
docker run --rm -d --name starter-kit-adopt-test -e POSTGRES_PASSWORD=test \
  -p 127.0.0.1:55433:5432 postgres:latest
docker exec starter-kit-adopt-test psql -U postgres -c "CREATE DATABASE fresh" -c "CREATE DATABASE legacy"

# 2. Build outside the repo and set the environment
go build -o "$SCRATCH/starter-kit-smoke" .
export APP_NAME=starter-kit-smoke APP_ENV=development GIN_MODE=release
export DB_HOST=127.0.0.1 DB_PORT=55433 DB_USERNAME=postgres DB_PASS=test DB_SSLMODE=disable
export JWT_KEY=fake-smoke-test-jwt-key-0123456789abcdef
export MEDIA_ENABLED=false PATH_MIGRATE=file://migrations
# no REDIS_* and no SMTP_* variables

# 3. Fresh path (run from the repo root so file://migrations resolves)
DB_NAME=fresh "$SCRATCH/starter-kit-smoke" -port 18080 -migrate &

# 4. Cross-application token check: second instance, other APP_NAME, same JWT_KEY and database
DB_NAME=fresh APP_NAME=other-app "$SCRATCH/starter-kit-smoke" -port 18081 -migrate=false &

# 5. Legacy path: old migrations from main, then golang-migrate bookkeeping
for f in 000001_create_users_table 000002_create_rbac_tables 000003_create_audit_trails_table \
         000004_create_app_configs_table 000005_create_locations_tables 000006_create_media_table; do
  git show main:migrations/$f.up.sql | docker exec -i starter-kit-adopt-test \
    psql -U postgres -d legacy -v ON_ERROR_STOP=1 -q
done
docker exec -i starter-kit-adopt-test psql -U postgres -d legacy -c \
 "CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL); INSERT INTO schema_migrations VALUES (6, false);"
# remove one admin role_permissions row (via ctid), record counts, then:
DB_NAME=legacy "$SCRATCH/starter-kit-smoke" -port 18080 -migrate &

# 6. Cleanup
kill <pids>; docker stop starter-kit-adopt-test   # --rm removes the container
```

HTTP checks used `curl` against `127.0.0.1` only. Registration body (fields from authkit
`dto.UserRegister`):

```sh
curl -X POST http://127.0.0.1:18080/api/user/register -H 'Content-Type: application/json' \
  -d '{"name":"Smoke User","email":"smoke@example.test","phone":"081234567890","password":"SmokePass123!"}'
curl -X POST http://127.0.0.1:18080/api/user/login -H 'Content-Type: application/json' \
  -d '{"email":"smoke@example.test","password":"SmokePass123!"}'
```

## Results: empty database (`fresh`)

| # | Check | Expected | Actual | Result |
|---|---|---|---|---|
| 1 | Start with `-migrate` | starts without error | healthcheck answered about 3 s after launch; log shows `Migration Success` and `All routes registered successfully` | PASS |
| 2 | `authkit_schema_migrations` | version 4, not dirty | `4 / f` | PASS |
| 3 | `schema_migrations` | version 6, not dirty | `6 / f` | PASS |
| 4 | `GET /healthcheck` | 200 | 200 `{"message":"OK!!"}` | PASS |
| 5 | `GET /api/user/register/status` | 200 | 200 `{"enabled":true,"otp_cooldown":60,"otp_enabled":false}` | PASS |
| 6 | `GET /api/users` without token | 401 | 401 `Invalid or expired token. Please login again.` | PASS |
| 7 | `POST /api/user/register` (fake user) | success | 201, `role":"viewer"`, phone normalised to `6281234567890` | PASS |
| 8 | `POST /api/user/login` | 200 with `access_token` | 200, `access_token` present (408 chars); token claims `iss`/`aud` = `starter-kit-smoke` | PASS |
| 9 | `GET /api/user` with token | 200, role `viewer` | 200, `"role":"viewer"`, permissions `view_dashboard, list_menus, view_menu, view_profile` | PASS |
| 10 | `GET /api/users` with viewer token | 403 | 403 `Access denied. You do not have the required permissions.` | PASS |
| 11 | `GET /api/location/province` | not 401/403 | 200, list of provinces (Aceh, Bali, ...) | PASS |
| 12 | Same token on instance 2 (`APP_NAME=other-app`, same `JWT_KEY`, same DB) | 401 | 401 `Invalid or expired token. Please login again.` (the same token still gave 200 on instance 1) | PASS |

## Results: legacy database (`legacy`)

Legacy state: old migrations 000001-000006 from `main`, `schema_migrations` = 6 (not dirty).
Before the run, one `role_permissions` row of role `admin` was deleted (admin 34 -> 33).

| # | Check | Expected | Actual | Result |
|---|---|---|---|---|
| 13 | Start with `-migrate` | starts without error | healthcheck answered about 2 s after launch; `Migration Success`, `All routes registered successfully` | PASS |
| 14 | `authkit_schema_migrations` | version 4 | `4 / f` | PASS |
| 15 | `schema_migrations` | stays 6 | `6 / f` | PASS |
| 16 | Row counts unchanged | `role_permissions`, `permissions`, `roles`, `menu_items` same as before | before and after: 77 / 34 / 4 / 7; the deleted admin row was not re-added (admin still 33) | PASS |
| 17 | `GET /api/user/register/status` | 200 | 200 `{"enabled":true,"otp_cooldown":60,"otp_enabled":false}` | PASS |

## Observations

- Log noise at startup, expected here and harmless: with no `REDIS_*` set the service still tries
  `localhost:6379`, so several `redis: ... connection refused` lines (about 2 s of retries) and one
  `Failed to connect to Redis` error appear before it continues without Redis. This accounts for
  most of the 2-3 s startup.
- Log line `Loading config: config - development.env ... Not Found in [.../config]` (ERROR level) appears
  because `APP_ENV=development` makes `GetAppConf` look for an optional config file that does not exist.
  The service continues normally.
- My first registration attempt used `SmokePass123` and got 400
  `password must contain at least 1 symbol (!@#$%^&*...)`; login with it then gave 400
  `Invalid Credentials`. This is the authkit password rule, not a defect. `SmokePass123!` succeeded.
- Migration order works for the legacy database: authkit migrations ran against tables created by the old
  starter-kit migrations without altering seeded counts.
- The old `main` migration files 000001-000004 no longer exist in this branch (only 000005 and 000006);
  on the fresh database `schema_migrations` still reaches 6 because golang-migrate numbers by file prefix.
