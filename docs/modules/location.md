# Location module

Provinces, cities, districts and villages, stored in PostgreSQL and filled by an asynchronous sync job
(or, on a first read of an empty table, by a fallback fetch) from a shared Location Service.

- Code: `internal/{domain,dto,services,repositories}/location`, `internal/handlers/http/location`,
  `internal/infrastructure/cache/location`, `internal/router/location` (`wire.go`, `register.go`),
  `internal/config/location.go`.
- Always mounted (there is no on/off switch).
- PostgreSQL is the source of truth. Redis is only a runtime cache and is optional. The Location Service is
  called by the sync job and by one fallback in the read routes: when a read finds no rows under a parent that
  exists locally, the service fetches that level from the Location Service, stores it and returns it. The parent
  must already be in the tables (the city fallback reads the province, the district fallback the city, the
  village fallback the district and its city); an unknown parent answers `404` without any outbound call, so
  bootstrap with a sync before relying on the fallback. An error from the Location Service is answered with `502`.
- Concurrent reads of the same empty level share one outbound call. An empty answer is remembered in the
  process for one minute and a failed call for 8 seconds (the same level answers `502` during that time), so a
  public read cannot make the service call the Location Service on every request, even while it is down.

## Routes

Mounted under `/api`. The route list in `internal/router/location/routes_test.go` is the source of truth.

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/location/province` | public, rate limited | all provinces |
| GET | `/api/location/city?province_code=11` | public, rate limited | `province_code` required and 1 to 20 digits, else `400`; `404` for an unknown province |
| GET | `/api/location/district?city_code=1101` | public, rate limited | `city_code` required and 1 to 20 digits, else `400`; `404` for an unknown city |
| GET | `/api/location/village?district_code=110101` | public, rate limited | `district_code` required and 1 to 20 digits, else `400`; `404` for an unknown district |
| POST | `/api/location/sync` | token and permission `locations:sync` | starts a sync job, `202`; `409` when one is already queued or running on any instance; `400` for an invalid request or a code that is not 1 to 20 digits; `503` once shutdown has started |
| GET | `/api/location/sync/:id` | token and permission `locations:sync` | job state; `400` when `:id` is not a UUID; `404` when the id is unknown |

Errors use one mapping: a malformed or missing code, `400`; an unknown parent or job, `404`; an unreachable or
misbehaving Location Service, `502`; anything unexpected, `500` with only a log ID. Client errors are logged at
`WARN`, server errors at `ERROR`.

Public reads are limited per client IP to `LOCATION_RATE_LIMIT` requests per `LOCATION_RATE_WINDOW_SECONDS`
(`429` over it). The limit needs Redis; without Redis it is off and a warning is logged at startup. When Redis
fails while it is configured, the reads are let through unless `LIMITER_FAIL_CLOSED=true`, which answers `503`.
Behind a load balancer or CDN list it in `TRUSTED_PROXIES`, or every client shares one limit.

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

Every code that is given must be 1 to 20 digits.

Use scoped syncs for regular updates. `level=all` imports the whole hierarchy and is meant for the initial
bootstrap.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `LOCATION_SERVICE_BASE_URL` | `https://location-service-y7si.onrender.com` (the maintained default service) | base URL of the Location Service (a trailing `/` is removed); must be an `http` or `https` URL with a host, and `https` unless `APP_ENV` is `development`, `dev`, `local` or `test` |
| `LOCATION_SERVICE_TIMEOUT_SECONDS` | `20` | per-request timeout in whole seconds; zero or less means the default |
| `LOCATION_SERVICE_MAX_RESPONSE_MB` | `4` | largest accepted Location Service response body, 1 to 64 MB; a larger one fails the call |
| `LOCATION_RATE_LIMIT` | `60` | public reads per client IP and window; must be above zero |
| `LOCATION_RATE_WINDOW_SECONDS` | `60` | window of that limit in seconds; must be above zero |
| `LOCATION_CACHE_TTL` | `4320h` (180 days) | cache lifetime; a Go duration, plain seconds or `eod`; zero or less means the default |

### Location Service contract

The module is a client of an HTTP service you point it at with `LOCATION_SERVICE_BASE_URL`. It sends `GET`
requests (no authentication) to `/api/locations/provinces`, `/api/locations/regencies`,
`/api/locations/districts` and `/api/locations/villages`, passing `province_code`, `regency_code` or
`district_code` plus `code_format=short` as the level needs, and expects status `200` (a redirect is an error, never followed) with either a JSON object
`{"<code>": "<name>"}` or an array of `{"code", "name"}`, optionally wrapped in `{"data": ...}`. Any other status
fails the job or read. Whichever shape arrives, every item is read the same way: the code must be 1 to 20 digits and the name 1 to 255 characters, otherwise the item is dropped. A code relative to its parent (`71` under province `31`) is stored as `3171`; a code longer than the parent's that does not start with it belongs to another parent and is dropped, so nothing outside the requested parent is ever stored. Swap the client in `internal/services/location/remote.go` if your source differs.

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
| `location_sync_jobs` | one row per sync: `status` (`queued`, `running`, `completed`, `failed`), `level`, the scope codes, `requested_by_user_id`, `message`, `error_message`, the four counts, `started_at`, `finished_at`, `owner_instance_id` and `heartbeat_at` (which instance runs the job, and when it last reported in) |

The unique partial index `ux_location_sync_jobs_one_active` allows one row with status `queued` or `running`, so
only one sync is active across all instances.

## Operational notes

### Cache

With Redis, read results are cached under `location:province`, `location:city:<province_code>`,
`location:district:<city_code>` and `location:village:<district_code>`. A sync deletes the keys it touched
(everything under `location:` after `level=all`). Without Redis nothing is cached and every read goes to
PostgreSQL.

### Sync lifecycle

1. `POST /api/location/sync` validates the request, fails jobs whose instance stopped reporting, then stores a
   `queued` job owned by this instance and answers `202`; the work continues in the background. When another job
   is queued or running, on this or any other instance, the unique index refuses the row and the answer is `409`
   with that job.
2. The job moves to `running`, reports a heartbeat every 15 seconds and writes its `message` and counts as it
   goes, at most once every 2 seconds, then ends `completed` or `failed` (`error_message` holds the reason). Every
   write names its columns and the owning instance, so an instance never overwrites a job it no longer owns.
3. Poll `GET /api/location/sync/:id` until `status` is `completed` or `failed`.
4. A sync is an upsert: it adds locations and updates names, and removes nothing. A location the Location
   Service stopped listing stays in the tables, so repeating a sync is always safe.

### Shutdown and recovery

- A job whose heartbeat is older than 2 minutes belongs to an instance that died. It is failed with the message
  `Location sync interrupted` when any instance starts, and before any new job is created, so a crashed instance
  never blocks syncs for longer than that. A job of an instance that is still alive is never touched, which
  makes rolling deploys safe. The heartbeat and the staleness check use the database clock, so the clocks of the
  instances do not matter.
- A job that finds it was taken over, on a heartbeat or a progress write, stops at once and writes nothing more.
- Startup recovery runs before the routes are mounted and takes at most 10 seconds; if it fails or times out,
  registration fails and the service does not start.
- On SIGINT or SIGTERM the running job is canceled at the start of the shutdown, before the HTTP requests drain,
  so it records `failed` with the message `Location sync interrupted` while they finish. New syncs answer `503`
  from then on. If the shutdown budget is already spent the write is skipped and the job is failed by the
  stale-heartbeat rule.
- With `RUN_MIGRATION=false` the schema must already exist, or startup stops at the recovery step because
  `location_sync_jobs` is missing.
