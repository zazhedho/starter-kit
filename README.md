# Starter Kit

Backend starter template for Go services with:
- Gin HTTP router
- PostgreSQL via GORM
- JWT authentication
- permission-first RBAC
- runtime application configurations from database
- optional Redis-based session management and rate limiting

This repository is intended to be the foundation for future projects. The current structure is generic on purpose and should be extended by adding new business modules on top of the existing patterns.

## Core Principles

### Permission-First RBAC

RBAC in this starter kit is designed with these rules:
- `permission` is the runtime source of truth for access control
- `role` is a label and a grouping mechanism for permissions
- `superadmin` is the only exception and bypasses permission checks
- menu visibility is derived from permissions, not from manual menu assignment

Practical implications:
- endpoint access is checked by `PermissionMiddleware(resource, action)`
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

## Current Modules

System modules currently included:
- Authentication and user profile
- Users
- Roles
- Permissions
- Menus
- Configurations
- Locations
- Sessions when Redis is enabled

## Project Structure

Main backend layout:

```text
starter-kit/
├── infrastructure/
├── internal/
│   ├── domain/
│   ├── dto/
│   ├── handlers/http/
│   ├── interfaces/
│   ├── repositories/
│   ├── router/
│   └── services/
├── middlewares/
├── migrations/
├── pkg/
├── utils/
└── main.go
```

Pattern for each module:

```text
route -> handler -> service -> repository -> database
```

Repository layer convention:
- use the generic repository in `internal/repositories/generic` for common CRUD and list query behavior
- keep module repository files focused on custom query cases only, such as joins, aggregates, or transactional assignment logic

## Environment

Copy `.env.example` to `.env` and adjust the values as needed.

Minimum required variables:
- `APP_NAME`
- `APP_ENV`
- `PORT`
- `DB_HOST`
- `DB_PORT`
- `DB_USERNAME`
- `DB_PASS`
- `DB_NAME`
- `DB_SSLMODE`
- `JWT_KEY`
- `JWT_EXP`
- `PATH_MIGRATE`

Optional but recommended:
- Redis settings for sessions and rate limiting
- storage settings for file upload use cases
- `GOOGLE_CLIENT_ID` or `GOOGLE_CLIENT_IDS` for Google login
- SMTP settings for register OTP and password reset email flows

## Run Locally

Install dependencies and prepare `.env`, then:

```bash
go run . -migrate
```

Or run migration and server separately:

```bash
go run . -migrate
go run .
```

Default health check:

```text
GET /healthcheck
```

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
- `GET /api/location/city`
- `GET /api/location/district`
- `GET /api/location/village`

Additional session routes are registered only when Redis is available.

## Module Seed Helper

To avoid writing menu and permission seed SQL manually for every new module, the starter kit includes a helper command:

```bash
go run ./cmd/module-seed \
  --name projects \
  --display-name "Projects" \
  --path /projects \
  --icon bi-folder \
  --order-index 905
```

The command prints SQL for:
- one `menu_items` row
- matching `permissions` rows for the same resource
- optional default `role_permissions` grants

This helps prevent mismatch bugs such as:
- `menu_items.name = projects`
- `permissions.resource = project`

Optional flags:
- `--parent-name education`
- `--resource reports`
- `--actions list,view,export`
- `--grant-roles admin,superadmin`

For nested menus, `--parent-name` generates a `parent_id` subquery so the migration stays declarative and consistent.

## How To Add A New Module

When adding a new module, keep it aligned with the permission-first design.

### 1. Add the backend layers

Create these parts:
- `internal/domain/<module>`
- `internal/dto`
- `internal/interfaces/<module>`
- `internal/repositories/<module>`
- `internal/services/<module>`
- `internal/handlers/http/<module>`
- route registration in `internal/router/router.go`

For repository implementation:
- reuse `internal/repositories/generic.GenericRepository[T]` for `Store`, `GetByID`, `GetAll`, `Update`, and `Delete`
- embed `interfacegeneric.GenericRepository[T]` in module repository interfaces for the common contract
- configure searchable columns, allowed filters, and sortable columns through `repositorygeneric.QueryOptions`
- add custom methods in the module repo only when the query is business-specific

### 2. Add migration

For a new business module, create:
- the business table(s)
- one `menu_items` row for the module
- the required `permissions` rows for the same resource name
- optional default `role_permissions` seed if needed

Important:
- use the same resource name across menu and permissions
- example:
  - menu name: `projects`
  - permission resource: `projects`

This is what allows menus to be derived automatically from permissions.

Tip:
- use `go run ./cmd/module-seed ...` to generate the menu and permission seed block before pasting it into the migration

### 3. Protect routes with permissions

Use:

```go
mdw.PermissionMiddleware("projects", "list")
mdw.PermissionMiddleware("projects", "view")
mdw.PermissionMiddleware("projects", "create")
mdw.PermissionMiddleware("projects", "update")
mdw.PermissionMiddleware("projects", "delete")
```

Avoid using role-name checks for module access unless the case is explicitly special like `superadmin`.

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
