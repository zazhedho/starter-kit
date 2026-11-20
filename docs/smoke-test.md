# Smoke test

The procedure to check a fresh checkout of this project against a real, throwaway PostgreSQL: empty database,
migrations, boot, endpoints, readiness, signals, the Redis failure mode and the Docker image. Run it after
changing startup, configuration, migrations or the Dockerfile; every check must match the expected result below.

Everything is fake and disposable. No `.env` file is used: the service accepts a missing `.env` when `APP_ENV`
is set, so all configuration is exported in the shell. Scratch files (binary, logs) live outside the repository.
Run the commands from the repository root so `file://migrations` resolves. Docker (or OrbStack) must be running.

## Procedure

```sh
SCRATCH=$(mktemp -d)

# 1. Throwaway database on localhost only, then an empty database for the run
docker run --rm -d --name starter-kit-smoke -e POSTGRES_PASSWORD=test -p 127.0.0.1:55439:5432 postgres:latest
# wait until it accepts connections (the image restarts once while initialising), then:
docker exec starter-kit-smoke psql -U postgres -c 'CREATE DATABASE smoke'

# 2. Build outside the repository and set a fake environment
go build -o "$SCRATCH/starter-kit-smoke" ./cmd/api
export APP_NAME=starter-kit-smoke APP_ENV=development GIN_MODE=release PORT=18080
export JWT_KEY=fake-smoke-test-jwt-key-0123456789abcdef JWT_EXP_MINUTES=15
export PATH_MIGRATE=file://migrations MEDIA_ENABLED=false
export DB_HOST=127.0.0.1 DB_PORT=55439 DB_USERNAME=postgres DB_PASS=test DB_NAME=smoke DB_SSLMODE=disable
# no REDIS_*, SMTP_* or DATABASE_URL unless a check says so

# 3. Migrate only (check 1)
"$SCRATCH/starter-kit-smoke" -migrate-only; echo "exit $?"
docker exec starter-kit-smoke psql -U postgres -d smoke -tAc \
  "select table_name from information_schema.tables where table_name like '%schema_migrations'"
curl -s -m 2 localhost:18080/healthcheck || echo "no port opened"

# 4. Boot with migrations, probes, a fake user (checks 2-11)
"$SCRATCH/starter-kit-smoke" -migrate &  APP=$!
curl -i localhost:18080/healthcheck
curl -i localhost:18080/readyz
docker pause starter-kit-smoke;   curl -i -m 8 localhost:18080/readyz     # 503
docker unpause starter-kit-smoke; curl -i localhost:18080/readyz          # 200 again
curl -i -X POST localhost:18080/api/user/register -H 'Content-Type: application/json' \
  -d '{"name":"Smoke User","email":"smoke.user@example.com","phone":"081200000001","password":"Password1!"}'
curl -s -X POST localhost:18080/api/user/login -H 'Content-Type: application/json' \
  -d '{"identifier":"smoke.user@example.com","password":"Password1!"}'      # note data.access_token
TOKEN=<access_token from the login response>
curl -i localhost:18080/api/user  -H "Authorization: Bearer $TOKEN"        # 200
curl -i localhost:18080/api/users                                          # 401
curl -i localhost:18080/api/users -H "Authorization: Bearer $TOKEN"        # 403 (viewer)
curl -i localhost:18080/api/location/province                              # see the note under the table

# 5. Graceful shutdown (check 12)
kill -TERM $APP; wait $APP; echo "exit $?"                                 # 0

# 6. A second signal ends a held shutdown at once (check 13)
HTTP_SHUTDOWN_TIMEOUT=30s HTTP_READ_TIMEOUT=60s HTTP_READ_HEADER_TIMEOUT=60s \
  "$SCRATCH/starter-kit-smoke" -migrate=false &  APP=$!
exec 3<>/dev/tcp/127.0.0.1/18080       # an unfinished request keeps the shutdown waiting
printf 'POST /api/user/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{"identifier":' >&3
kill -TERM $APP; sleep 3; kill -0 $APP && echo "still shutting down"
kill -TERM $APP; wait $APP; echo "exit $?"                                 # 143 at once
exec 3>&-

# 7. Redis configured but unreachable (check 14)
REDIS_HOST=127.0.0.1 REDIS_PORT=1 REDIS_PASSWORD=fake-redis-password-xyz \
  "$SCRATCH/starter-kit-smoke" -migrate=false; echo "exit $?"              # 1, no password in the log

# 8. Docker image (check 15); host.docker.internal reaches the database published on the host
docker build -t starter-kit-smoke-image .
docker run --rm -d --name starter-kit-smoke-app -p 127.0.0.1:18081:8080 \
  -e APP_NAME=starter-kit-smoke -e APP_ENV=development -e GIN_MODE=release \
  -e JWT_KEY=fake-smoke-test-jwt-key-0123456789abcdef -e JWT_EXP_MINUTES=15 -e PORT=8080 -e RUN_MIGRATION=true \
  -e DB_HOST=host.docker.internal -e DB_PORT=55439 -e DB_USERNAME=postgres -e DB_PASS=test \
  -e DB_NAME=smoke -e DB_SSLMODE=disable -e MEDIA_ENABLED=false starter-kit-smoke-image
curl -i localhost:18081/healthcheck
docker stop starter-kit-smoke-app

# 9. Clean up (only what this procedure created)
docker rm -f starter-kit-smoke-app starter-kit-smoke; docker rmi starter-kit-smoke-image
rm -rf "$SCRATCH"
```

## Expected results

| # | Check | Expected |
|---|---|---|
| 1 | `-migrate-only` on an empty database | exit 0, both version tables, no port opened |
| 2 | boot with `-migrate`, `GET /healthcheck` | 200 |
| 3 | `GET /readyz` | 200 |
| 4 | `GET /readyz` while the database container is paused | 503 |
| 5 | `GET /readyz` after unpause | 200 |
| 6 | register a fake user | 201 |
| 7 | log in | 200 with a token |
| 8 | `GET /api/user` as viewer | 200 |
| 9 | `GET /api/users` without a token | 401 |
| 10 | `GET /api/users` as viewer | 403 |
| 11 | `GET /api/location/province` | reported |
| 12 | SIGTERM | exit 0, `Shutdown started` and `Shutdown complete` logged |
| 13 | second SIGTERM during a held shutdown | process ends at once |
| 14 | Redis configured but unreachable | exit 1, no credentials in the log |
| 15 | `docker build .` and run the image | build succeeds, the binary starts |

Notes:
- Check 11 depends on an external service. With empty location tables the first `GET /api/location/province`
  fetches the list from the Location Service (`LOCATION_SERVICE_BASE_URL`) and stores it (the read fallback in
  `internal/services/location`), so a `5xx` there means the service was unreachable, not that the project is
  broken. Later calls read PostgreSQL.
- Check 13 holds the shutdown with an open, unfinished request because the drain waits for running requests; the
  first signal restores default signal handling, which is why the second one ends the process.
- To exercise the modules that are off by default, set `MEDIA_ENABLED=true` together with the `STORAGE_*`
  variables of [`docs/modules/media.md`](modules/media.md).
