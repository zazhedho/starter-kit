# Location module

Provinces, cities, districts and villages, stored in PostgreSQL and filled by an asynchronous sync job
(or, on a first read of an empty table, by a fallback fetch) from a shared Location Service.

- Code: `internal/{domain,dto,services,repositories}/location`, `internal/handlers/http/location`,
  `internal/infrastructure/cache/location`, `internal/router/location` (`wire.go`, `register.go`),
  `internal/config/location.go`.
- Always mounted (there is no on/off switch).
- PostgreSQL is the source of truth. Redis is only a runtime cache and is optional. The Location Service is
  called by the sync job and by one fallback in the read routes: when a read finds no rows (empty tables, or
  nothing under that parent code), the service fetches that level from the Location Service, upserts it and
  returns it, so a first read of an unsynced database needs the Location Service to be reachable (an error
  there is returned to the caller). City, district and village fallbacks also need the parent row to exist
  locally (the district fallback reads the city, the village fallback the city and district), so bootstrap
  with a sync before relying on it.

## Routes

Mounted under `/api`. The route list in `internal/router/location/routes_test.go` is the source of truth.

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/location/province` | public | all provinces |
| GET | `/api/location/city?province_code=11` | public | `province_code` required, else `400` |
| GET | `/api/location/district?city_code=1101` | public | `city_code` required, else `400` |
| GET | `/api/location/village?district_code=110101` | public | `district_code` required, else `400` |
| POST | `/api/location/sync` | token and permission `locations:sync` | starts a sync job, `202`; `409` when one is already queued or running; `400` for an invalid request |
| GET | `/api/location/sync/:id` | token and permission `locations:sync` | job state; `404` when the id is unknown |

The migration seeds the permission `sync_locations` (resource `locations`, action `sync`) and grants it to the
`admin` and `superadmin` roles. Grant it to other roles through the role-permission API.

### Sync request

`POST /api/location/sync` takes a JSON body; every field is optional.

| Field | Meaning |
|---|---|
| `level` | `all` (default), `province`, `city`, `district` or `village` |
| `province_code` | required for `city`, `district` and `village` |
| `city_code` | required for `district` and `village` |
| `district_code` | required for `village` |

Use scoped syncs for regular updates. `level=all` imports the whole hierarchy and is meant for the initial
bootstrap.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `LOCATION_SERVICE_BASE_URL` | `https://location-service-y7si.onrender.com` | base URL of the Location Service (a trailing `/` is removed) |
| `LOCATION_SERVICE_TIMEOUT_SECONDS` | `20` | per-request timeout in whole seconds; zero or less means the default |
| `LOCATION_CACHE_TTL` | `4320h` (180 days) | cache lifetime; a Go duration, plain seconds or `eod`; zero or less means the default |

### Location Service contract

The module is a client of an HTTP service you point it at with `LOCATION_SERVICE_BASE_URL`. It sends `GET`
requests (no authentication) to `/api/locations/provinces`, `/api/locations/regencies`,
`/api/locations/districts` and `/api/locations/villages`, passing `province_code`, `regency_code` or
`district_code` plus `code_format=short` as the level needs, and expects status `200` with either a JSON object
`{"<code>": "<name>"}` or an array of `{"code", "name"}`, optionally wrapped in `{"data": ...}`. Any other status
fails the job or read. Swap the client in `internal/services/location/remote.go` if your source differs.

The `.env.example` values are examples, not defaults; the table lists what the code uses when a variable is
unset.

## Tables

Created by `migrations/20260101000000_location_create_tables.up.sql`:

| Table | Holds |
|---|---|
| `provinces` | `code` (unique), `name` |
| `cities` | `code` (unique), `province_code`, `name` |
| `districts` | `code` (unique), `city_code`, `name` |
| `villages` | `code` (unique), `district_code`, `name` |
| `location_sync_jobs` | one row per sync: `status` (`queued`, `running`, `completed`, `failed`), `level`, the scope codes, `requested_by_user_id`, `message`, `error_message`, the four counts, `started_at`, `finished_at` |

## Operational notes

### Cache

With Redis, read results are cached under `location:province`, `location:city:<province_code>`,
`location:district:<city_code>` and `location:village:<district_code>`. A sync deletes the keys it touched
(everything under `location:` after `level=all`). Without Redis nothing is cached and every read goes to
PostgreSQL.

### Sync lifecycle

1. `POST /api/location/sync` validates the request and rejects it with `409` when a job is queued or running,
   then stores a `queued` job and answers `202` with it; the work continues in the background.
2. The job moves to `running`, updates its `message` and counts as it goes, then ends `completed` or `failed`
   (`error_message` holds the reason).
3. Poll `GET /api/location/sync/:id` until `status` is `completed` or `failed`.
4. Only one sync runs per service instance at a time.

### Shutdown and recovery

- On SIGINT or SIGTERM the running job is canceled and the service waits for it inside the one
  `HTTP_SHUTDOWN_TIMEOUT` budget. The job is recorded as `failed` with the message `Location sync interrupted`
  when its final write fits in that budget. If the budget is already spent the write is skipped and the
  next startup repairs the row.
- At startup, before the routes are mounted, every job still `queued` or `running` is marked `failed` with the
  message `Location sync interrupted` (the process that owned it is gone). This takes at most 10 seconds; if it
  fails or times out, registration fails and the service does not start.
- A failed or interrupted sync is simply started again; imports are upserts, so repeating one is safe.
- Run a single instance of the sync, or deploy accordingly: the recovery step of a new instance marks the jobs
  of instances that are still running as interrupted.
- With `RUN_MIGRATION=false` the schema must already exist, or startup stops at the recovery step because
  `location_sync_jobs` is missing.
