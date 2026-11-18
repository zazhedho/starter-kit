# Media list and `_any` permissions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:**
- Give the template one real, tested list endpoint built on the gokit list standard.
- Replace the hard-coded superadmin rule in media with RBAC permissions.

**Architecture:**
- authkit gains `Kit.LoadPermissions()`. It is a middleware that loads the user's permissions into the request scope without rejecting anyone, so a handler can branch on `authkit.ScopeFrom(ctx).Has(resource, action)`.
- starter-kit media uses it:
  - `GET /api/media` lists the caller's own files, or everyone's with `media:list_any`;
  - `DELETE /api/media/:id` deletes the caller's own file, or anyone's with `media:delete_any`.

**Tech Stack:** Go, gin, GORM/Postgres, authkit, gokit (`GetBaseParams`, `Repository.GetAll`, `QueryOptions`, `PaginationResponse`).

**Spec:** owner decisions in conversation (2026-11-18): option B with permissions, done in authkit (option 1), `_any` suffix naming.

## Global Constraints
- **Ownership convention:** an action on your own data needs no permission. Acting on other users' data needs `<resource>:<action>_any`. Superadmin passes every `Has` check, as `Can` already does.
- **Permissions:** `media:list_any` and `media:delete_any`, seeded to roles `admin` and `superadmin`.
- **Not found and forbidden look the same:** a file that does not exist and a file owned by someone else both answer 404, as Delete already does.
- **authkit release:** v0.3.0, a new public API. The owner approved the push and tag.
- **Style:** comments of at most 3 lines that explain why. Conventional Commits, no attribution lines. Stage explicitly by path. Never read `.env`.

## Review Focus
- **Plain user filtering by owner:** a user without `list_any` who sends `filters[owner_user_id]=<other>` must still see only their own files. The owner filter is ignored or overridden, never honored.
- **Disallowed sort column:** `order_by` on a column outside the allow list (e.g. `object_key` or an SQL fragment) falls back to the default order.
- **Bad paging values:** `limit=-1` or a huge `limit` behaves per `GetBaseParams`, and `page=abc` returns 400.
- **Permission lookup fails:** `LoadPermissions` with a DB error answers 500. With a deleted user it answers 403. It never answers 200 with an empty scope.
- **Unauthorized delete leaks nothing:** deleting another user's file without `delete_any` answers 404, and storage is untouched.

---

### Task 1: authkit `Kit.LoadPermissions()` (repo /Users/zaqiakhana/Code/Project/authkit)

**Files:**
- `internal/middlewares/auth.go`: extract the permission-loading part of `PermissionMiddleware` into a shared helper, and add `(m *Middleware) LoadPermissionsMiddleware() gin.HandlerFunc`.
- `authkit.go`: add `func (k *Kit) LoadPermissions() gin.HandlerFunc`, with a doc comment saying to use it after Auth and that it never rejects a user who holds no permission.
- Tests next to the existing `TestCanAllowsAndDenies` and the middleware tests.
- README section on permissions, and the CHANGELOG if one exists.

**Interfaces:**
- **Produces:** `(*authkit.Kit).LoadPermissions() gin.HandlerFunc`. After it runs, `authkit.ScopeFrom(ctx.Request.Context()).Has(r, a)` reflects the user's real permissions.

**Steps:**
- [ ] Write failing tests:
  - `TestLoadPermissionsFillsScope`: a user with `media:list_any` gets `Has=true`, and `Has("x","y")` is false.
  - `TestLoadPermissionsDoesNotReject`: a user with no permissions reaches the handler with status 200.
  - `TestLoadPermissionsSuperadmin`: `Has` is true for any pair.
  - `TestLoadPermissionsUserNotFound`: 403.
  - `TestLoadPermissionsRepoError`: 500.
  - `TestLoadPermissionsWithoutAuth`: 403, the same as `Can`.
- [ ] Run them and see them fail.
- [ ] Implement by sharing the loader with `PermissionMiddleware`. The behavior of `Can` stays byte-identical, and its existing tests stay green.
- [ ] Run the gate:
  - `go build ./... && go vet ./... && go test -race -count=1 ./...`;
  - the repo's lint target if any.
- [ ] Commit `feat: add Kit.LoadPermissions for in-handler permission checks`.
- [ ] Release: done by the coordinator after verification. Tag `v0.3.0` and push main and the tag.

### Task 2: starter-kit media list and `_any` permissions (repo /Users/zaqiakhana/Code/Project/starter-kit, new branch `feat/media-list`)

**Files:**
- `go.mod`: `github.com/zazhedho/authkit v0.3.0`.
- `migrations/20260101000100_media_create_table.{up,down}.sql`, edited in place because the template starts from zero:
  - add index `idx_media_owner_created_at ON media(owner_user_id, created_at DESC)`;
  - seed `list_any_media` / `delete_any_media` (resource `media`, actions `list_any` / `delete_any`) and grant them to `admin` and `superadmin`, in the same style as the location migration;
  - the down migration removes the grants and the permissions.
- `internal/domain/media/actor.go`: `Actor{UserID string; CanListAny bool; CanDeleteAny bool}`. Remove `IsSuperAdmin`.
- `internal/dto/media`: add the package.
  - `ListRequest{Search, OwnerUserID, ContentType, OrderBy, OrderDirection string; Page, Limit, Offset int}`.
  - The dto keeps the gokit type out of the service.
- `internal/services/media`:
  - `ports.go`: `Repository` gains `List(ctx, dtomedia.ListRequest) ([]domainmedia.Media, int64, error)`.
  - service: `List(ctx, actor domainmedia.Actor, req dtomedia.ListRequest) ([]domainmedia.Media, int64, error)`. Without `CanListAny`, it forces `req.OwnerUserID = actor.UserID`.
  - `Delete` uses `actor.CanDeleteAny`.
- `internal/repositories/media/repository.go`: `List` via `gokit.Repository.GetAll` with these `gokit.QueryOptions`:
  - `Search: BuildSearchFunc("original_name")`;
  - `AllowedFilters: owner_user_id, content_type`;
  - `AllowedOrderColumns: created_at, size, original_name`;
  - `DefaultOrders: created_at DESC`.
- `internal/handlers/http/media`:
  - `ports.go`: `Service` gains `List`.
  - handler `List`:
    - parse the query with `gokit.GetBaseParams(query, "created_at", "desc", 20)`, and answer 400 on a parse error;
    - whitelist the filters `owner_user_id` and `content_type`;
    - answer 400 when `owner_user_id` is not a UUID;
    - respond with `PaginationResponse`.
  - `actorFrom` fills `CanListAny` / `CanDeleteAny` from `authkit.ScopeFrom(ctx).Has("media", ...)`.
- `internal/router/media/register.go`: `GET ""` and `DELETE "/:id"` get `d.Kit.LoadPermissions()` after `Auth()`. Upload is unchanged.
- `internal/router/media/routes_test.go`: update the route set.
- **Docs:**
  - `docs/modules/media.md`: routes, permissions, query params;
  - `docs/adding-a-module.md`: the ownership/`_any` convention and `LoadPermissions`, in one short section;
  - the Postman collection: add a "List media" request in the media folder, with the query params;
  - the README route mention, if one exists.

**Steps:**
- [ ] Write failing tests:
  - service: `TestListOwnOnlyWithoutListAny` (an owner filter for another user is overridden); `TestListAnyHonorsOwnerFilter`; `TestDeleteOtherWithoutDeleteAnyIsForbidden` (storage untouched); `TestDeleteOtherWithDeleteAny`.
  - repository: a sqlmock test of the generated SQL for search, filter and order, and that a disallowed `order_by` falls back to the default.
  - handler: 400 for `page=abc`; 400 for a bad `owner_user_id`; 200 with the pagination shape; `actorFrom` maps `Has`.
  - router: the route set includes `GET /api/media`, with middleware `Auth`, then `LoadPermissions`, then the handler.
- [ ] Run them and see them fail.
- [ ] Implement.
- [ ] Run the gate:
  - `go build ./... && go vet ./... && go test -race -count=1 ./... && make lint` (0 issues);
  - `gofmt -l .` empty;
  - apply the migrations to a throwaway Postgres and check that both permissions exist and are granted to admin and superadmin.
- [ ] Make small Conventional Commits, including this plan file.
