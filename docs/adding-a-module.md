# Adding a module

A module is a business feature (`location`, `media`, `projects`) built from the same layers and
mounted with one line. Almost everything you write lives in folders named after the module, so two
people adding two modules do not touch the same files.

Read the [dependency rule and naming conventions](../README.md#dependency-rule) first; the
architecture guard (`internal/architecture`) fails `go test` when a layer imports what it must not,
when an import alias is wrong or when a package name differs from its directory.

## Checklist

Inside the module's own folders (new files, no conflicts):

| Folder | What goes there |
|---|---|
| `internal/domain/<m>/` | entities and domain errors |
| `internal/dto/<m>/` | request shapes the handler and service share (only when they share something) |
| `internal/services/<m>/` | business rules; `ports.go` declares the `Repository` (and `Cache`, `Storage`) interfaces it needs |
| `internal/repositories/<m>/` | GORM adapter that satisfies the service's `Repository` by method set |
| `internal/handlers/http/<m>/` | gin handlers; `ports.go` declares the `Service` interface they call |
| `internal/router/<m>/` | `wire.go` (builds repository, service, handler; side effects; lifecycle hooks), `register.go` (routes only), `routes_test.go` (pins the routes) |
| `internal/infrastructure/cache/<m>/` | optional: Redis implementation of the service's `Cache` port |
| `internal/config/<m>.go`, `<m>_test.go` | optional: the module's settings, their parsing and validation |
| `docs/modules/<m>.md` | optional: routes, permissions, env variables, operational notes |

The few shared files:

| Step | File | Edit |
|---|---|---|
| 1 | `migrations/<UTC timestamp>_<m>_create_table.up.sql` and `.down.sql` | the table plus the `module-seed` output (menu and permissions) |
| 2 | `internal/router/modules.go` | one import line and one entry in `modules`, alphabetical |
| 3 (only with settings) | `internal/config/config.go`, `load.go`, `validate.go` | one field in `Config`, one line in `FromEnv`, one call in `Validate` |
| 4 (only with env variables) | `.env.example` | its own `# --- <m> ---` block |

No edit to the README, the route-table test, the architecture guard, lint, CI, the Makefile or the
Dockerfile. `TestRouteTable` in `internal/router` derives its expectation from `modules.go`, so the new
module is covered the moment it is listed.

Order of work: migration, domain, dto, service (with a fake-based test), repository, handler,
`router/<m>` (wire, register, route test), the `modules.go` line, config if needed, then

```bash
go build ./... && go vet ./... && go test -race -count=1 ./... && make lint
```

## Worked example: a `projects` module

A user with `projects:list` can list projects and a user with `projects:create` can create one. The
module name `projects` is the menu name, the permission resource, the table and the audit resource;
keep them identical, because menus are derived from permissions by that name. Every package of the
module is named `projects` and imported under the alias `<layer>projects` (`domainprojects`,
`serviceprojects`, `httpprojects`, `routerprojects`, ...).

The code below was built in a scratch copy of this repository, outside the repository, with
`go build ./... && go vet ./... && go test -race -count=1 ./... && make lint` all green, including
`internal/architecture` (guard and migration-format test) and `TestRouteTable`. It is a recipe to copy and
adapt; it is not part of this repository.

### 1. Migration: table, menu and permissions

Generate the timestamp when you create the file (`date -u +%Y%m%d%H%M%S`); the name is
`<timestamp>_projects_create_table`. See [`migrations/README.md`](../migrations/README.md) for the rules.
Create the `.up.sql` with the table, then append the menu and permission seed that authkit generates:

```bash
go run github.com/zazhedho/authkit/cmd/module-seed \
  --name projects \
  --display-name "Projects" \
  --path /projects \
  --icon bi-folder \
  --order-index 905 \
  >> migrations/<timestamp>_projects_create_table.up.sql
```

It prints SQL for one `menu_items` row, the `permissions` rows for the resource (`list`, `view`,
`create`, `update`, `delete` unless `--actions` says otherwise) and default `role_permissions` grants
(`admin` and `superadmin` unless `--grant-roles` says otherwise). Other flags: `--parent-name` for a
nested menu, `--resource` when the permission resource differs from the name.

`migrations/<timestamp>_projects_create_table.up.sql`, before the generated seed:

```sql
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id UUID NOT NULL,
    name VARCHAR(200) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_projects_owner FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE RESTRICT
);

```

`migrations/<timestamp>_projects_create_table.down.sql`:

```sql
DELETE FROM permissions WHERE resource = 'projects';
DELETE FROM menu_items WHERE name = 'projects';
DROP TABLE IF EXISTS projects;
```

The migration runs on the next start, or with `-migrate-only`.

### 2. Domain

`internal/domain/projects/entity.go`:

```go
package projects

import "time"

func (Project) TableName() string { return "projects" }

type Project struct {
	ID          string    `json:"id" gorm:"column:id;primaryKey"`
	OwnerUserID string    `json:"owner_user_id" gorm:"column:owner_user_id"`
	Name        string    `json:"name" gorm:"column:name"`
	CreatedAt   time.Time `json:"created_at" gorm:"column:created_at"`
}
```

`internal/domain/projects/errors.go` holds the errors callers match with `errors.Is`. A repository that looks a row up returns a domain `ErrNotFound` instead of the ORM error (see `internal/domain/media`):

```go
package projects

import "errors"

// ErrNameRequired is returned when a project is created without a name.
var ErrNameRequired = errors.New("project name is required")
```

### 3. DTO

`internal/dto/projects/projects.go`. Add it only when handler and service share a shape; it must not import gin or gorm:

```go
// Package projects holds the request shapes the projects handler and service
// share. It must not import gin or gorm.
package projects

// ListRequest is a parsed list query: the handler fills it from the URL, the
// repository applies it.
type ListRequest struct {
	Search         string
	OrderBy        string
	OrderDirection string
	Page           int
	Limit          int
	Offset         int
}
```

### 4. Service

The service declares the ports it needs in `ports.go` and holds the business rules. From this project it
imports only `domain` and `dto`, and no framework: the ID generator is injected and the caller's identity
is a plain argument.

`internal/services/projects/ports.go`:

```go
package projects

import (
	"context"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// Repository is the persistence the service needs. The GORM adapter in
// internal/repositories/projects satisfies it by method set.
type Repository interface {
	Store(ctx context.Context, p domainprojects.Project) error
	List(ctx context.Context, req dtoprojects.ListRequest) ([]domainprojects.Project, int64, error)
}
```

`internal/services/projects/service.go`:

```go
package projects

import (
	"context"
	"strings"
	"time"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// Service holds the projects business rules. It imports no framework: ids are
// injected, and the caller's identity arrives as a plain argument.
type Service struct {
	repo  Repository
	newID func() string
}

// NewService builds the service. newID returns a new row id; the router passes
// gokit.CreateUUID.
func NewService(repo Repository, newID func() string) *Service {
	return &Service{repo: repo, newID: newID}
}

func (s *Service) Create(ctx context.Context, ownerUserID, name string) (domainprojects.Project, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return domainprojects.Project{}, domainprojects.ErrNameRequired
	}
	p := domainprojects.Project{ID: s.newID(), OwnerUserID: ownerUserID, Name: name, CreatedAt: time.Now()}
	if err := s.repo.Store(ctx, p); err != nil {
		return domainprojects.Project{}, err
	}
	return p, nil
}

func (s *Service) List(ctx context.Context, req dtoprojects.ListRequest) ([]domainprojects.Project, int64, error) {
	return s.repo.List(ctx, req)
}
```

Test the service against a fake of its port, no database (`internal/services/projects/service_test.go`):

```go
package projects

import (
	"context"
	"errors"
	"testing"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// fakeRepository satisfies Repository; services are tested without a database.
type fakeRepository struct {
	stored domainprojects.Project
	err    error
}

func (f *fakeRepository) Store(_ context.Context, p domainprojects.Project) error {
	f.stored = p
	return f.err
}

func (f *fakeRepository) List(context.Context, dtoprojects.ListRequest) ([]domainprojects.Project, int64, error) {
	return nil, 0, f.err
}

func TestCreateTrimsTheNameAndUsesTheInjectedID(t *testing.T) {
	repo := &fakeRepository{}
	svc := NewService(repo, func() string { return "p-1" })

	p, err := svc.Create(context.Background(), "u-1", "  First  ")
	if err != nil {
		t.Fatalf("Create = %v", err)
	}
	if p.ID != "p-1" || p.Name != "First" || repo.stored.OwnerUserID != "u-1" {
		t.Fatalf("unexpected project %+v, stored %+v", p, repo.stored)
	}
}

func TestCreateRejectsABlankName(t *testing.T) {
	svc := NewService(&fakeRepository{}, func() string { return "p-1" })
	if _, err := svc.Create(context.Background(), "u-1", "   "); !errors.Is(err, domainprojects.ErrNameRequired) {
		t.Fatalf("Create = %v, want ErrNameRequired", err)
	}
}
```

### 5. Repository

The adapter satisfies the service's `Repository` port by method set and returns a concrete `*Repository`;
nothing declares an interface for it here. It embeds the generic `gokit.Repository` for `Store`, `GetByID`,
`Update` and `Delete`, and adds only the list query. Test it with sqlmock like
`internal/repositories/media/repository_test.go`.

`internal/repositories/projects/repository.go`:

```go
package projects

import (
	"context"

	"github.com/zazhedho/gokit"
	"gorm.io/gorm"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// Repository is the GORM adapter for the projects table. It embeds the generic
// gokit repository for Store, GetByID, Update and Delete, and adds only the
// list query. Translate gorm.ErrRecordNotFound into a domain ErrNotFound for
// any lookup the service exposes, as repositories/media does.
type Repository struct {
	*gokit.Repository[domainprojects.Project]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainprojects.Project](db)}
}

func (r *Repository) List(ctx context.Context, req dtoprojects.ListRequest) ([]domainprojects.Project, int64, error) {
	params := gokit.BaseParams{
		Search:         req.Search,
		OrderBy:        req.OrderBy,
		OrderDirection: req.OrderDirection,
		Page:           req.Page,
		Limit:          req.Limit,
		Offset:         req.Offset,
	}
	return r.GetAll(ctx, params, gokit.QueryOptions{
		Search:              gokit.BuildSearchFunc("name"),
		AllowedOrderColumns: []string{"name", "created_at"},
		DefaultOrders:       []string{"created_at DESC"},
	})
}
```

Searchable columns, allowed filters and sortable columns are set through `gokit.QueryOptions`; add custom
repository methods only for business-specific queries.

### 6. Handler

The handler declares the `Service` interface it calls, so it never imports the service package.

`internal/handlers/http/projects/ports.go`:

```go
package projects

import (
	"context"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// Service is what the handlers call. The concrete service is in
// internal/services/projects; the router wires it in.
type Service interface {
	Create(ctx context.Context, ownerUserID, name string) (domainprojects.Project, error)
	List(ctx context.Context, req dtoprojects.ListRequest) ([]domainprojects.Project, int64, error)
}
```

`internal/handlers/http/projects/handler.go` embeds `authkit.AuditWriter` and audits the success and
failure of every mutation. The caller comes from `authkit.ScopeFrom`, which `d.Kit.Auth()` fills in, and is
handed to the service as a plain value. Domain errors become status codes here. Test it with a fake
`Service` and `httptest`, as `internal/handlers/http/media/handler_test.go` does.

```go
package projects

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zazhedho/authkit"
	"github.com/zazhedho/gokit"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// Handler embeds authkit.AuditWriter to record every mutation.
type Handler struct {
	service  Service
	pageSize int
	authkit.AuditWriter
}

func New(svc Service, audit authkit.AuditService, pageSize int) *Handler {
	return &Handler{
		service:     svc,
		pageSize:    pageSize,
		AuditWriter: authkit.NewAuditWriter(audit, "ProjectsHandler"),
	}
}

type createRequest struct {
	Name string `json:"name" binding:"required"`
}

func (h *Handler) List(ctx *gin.Context) {
	logID := gokit.GenerateLogId(ctx)
	params, err := gokit.GetBaseParams(ctx.Request.URL.Query(), "created_at", "desc", h.pageSize)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, err.Error()))
		return
	}
	items, total, err := h.service.List(ctx.Request.Context(), dtoprojects.ListRequest{
		Search:         params.Search,
		OrderBy:        params.OrderBy,
		OrderDirection: params.OrderDirection,
		Page:           params.Page,
		Limit:          params.Limit,
		Offset:         params.Offset,
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gokit.InternalServerError(logID))
		return
	}
	ctx.JSON(http.StatusOK, gokit.PaginationResponse(http.StatusOK, int(total), params.Page, params.Limit, logID, items))
}

func (h *Handler) Create(ctx *gin.Context) {
	logID := gokit.GenerateLogId(ctx)
	var req createRequest
	if !gokit.BindJSON(ctx, logID, "[ProjectsHandler][Create]", &req) {
		return
	}

	// The handler turns the authenticated scope into the plain input the
	// service needs; services never import authkit.
	scope := authkit.ScopeFrom(ctx.Request.Context())
	p, err := h.service.Create(ctx.Request.Context(), scope.UserID, req.Name)
	if err != nil {
		h.WriteAudit(ctx, authkit.AuditEvent{
			Action: authkit.ActionCreate, Resource: "projects",
			Status: authkit.StatusFailed, Message: "Failed to create project", ErrorMessage: err.Error(),
		})
		if errors.Is(err, domainprojects.ErrNameRequired) {
			ctx.JSON(http.StatusBadRequest, gokit.ErrorResponse(http.StatusBadRequest, gokit.MsgInvalidRequest, logID, err.Error()))
			return
		}
		ctx.JSON(http.StatusInternalServerError, gokit.InternalServerError(logID))
		return
	}

	h.WriteAudit(ctx, authkit.AuditEvent{
		Action: authkit.ActionCreate, Resource: "projects", ResourceID: p.ID,
		Status: authkit.StatusSuccess, Message: "Created project", AfterData: p,
	})
	ctx.JSON(http.StatusCreated, gokit.Response(http.StatusCreated, "Project created successfully", logID, p))
}
```

### 7. Router package

`internal/router/projects/` has three files, imported elsewhere as `routerprojects`.

- `wire.go`: `func wire(d module.Deps) (*wired, error)` builds repository, service and handler from
  `module.Deps` (`Config`, `DB`, `SQLDB`, `Redis` which is nil when unused, `Kit`, `Storage` which is nil
  when media is disabled, `Lifecycle`). It is the one place that passes `gokit.CreateUUID` as the ID
  generator, runs any startup recovery and registers shutdown hooks. It opens no connection.
- `register.go`: `func Register(r gin.IRouter, d module.Deps) error` calls `wire`, mounts routes relative to
  the `/api` group it receives and returns an error instead of panicking or exiting. Protect routes with
  `d.Kit.Auth()` first, then `d.Kit.Can(resource, action)`.
- `routes_test.go`: pins the exact routes and checks which are protected, using
  `internal/testutil/routertest` (`NewDeps`, `Mount`, `RouteSet`, `SortedKeys`, `Serve`).

`internal/router/projects/wire.go`:

```go
package projects

import (
	"github.com/zazhedho/gokit"

	httpprojects "starter-kit/internal/handlers/http/projects"
	repositoryprojects "starter-kit/internal/repositories/projects"
	"starter-kit/internal/router/module"
	serviceprojects "starter-kit/internal/services/projects"
)

type wired struct{ handler *httpprojects.Handler }

func wire(d module.Deps) (*wired, error) {
	repo := repositoryprojects.NewRepository(d.DB)
	svc := serviceprojects.NewService(repo, gokit.CreateUUID)
	return &wired{handler: httpprojects.New(svc, d.Kit.Audit(), d.Config.Projects.PageSize)}, nil
}
```

`internal/router/projects/register.go`:

```go
// Package projects mounts the projects module: wire.go builds it from
// module.Deps, register.go mounts its routes. Alias routerprojects.
package projects

import (
	"github.com/gin-gonic/gin"

	"starter-kit/internal/router/module"
)

// Register wires the module and mounts its routes under r.
func Register(r gin.IRouter, d module.Deps) error {
	w, err := wire(d)
	if err != nil {
		return err
	}
	h := w.handler

	projects := r.Group("/projects").Use(d.Kit.Auth())
	{
		projects.GET("", d.Kit.Can("projects", "list"), h.List)
		projects.POST("", d.Kit.Can("projects", "create"), h.Create)
	}
	return nil
}
```

`internal/router/projects/routes_test.go`:

```go
package projects

import (
	"net/http"
	"strings"
	"testing"

	"starter-kit/internal/testutil/routertest"
)

// projectsRoutes is every route the module mounts, pinned on purpose: a new
// route must be added here and, if it is protected, to TestProjectsRoutesProtection.
var projectsRoutes = []string{
	"GET /api/projects",
	"POST /api/projects",
}

func TestProjectsMountsExactlyItsRoutes(t *testing.T) {
	engine := routertest.Mount(t, Register, routertest.NewDeps(t, nil))
	got := routertest.SortedKeys(routertest.RouteSet(engine))
	if strings.Join(got, "\n") != strings.Join(projectsRoutes, "\n") {
		t.Fatalf("routes are\n  %v\nwant\n  %v", got, projectsRoutes)
	}
}

func TestProjectsRoutesProtection(t *testing.T) {
	engine := routertest.Mount(t, Register, routertest.NewDeps(t, nil))
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/projects"},
		{http.MethodPost, "/api/projects"},
	} {
		if got := routertest.Serve(engine, c.method, c.path); got != http.StatusUnauthorized {
			t.Fatalf("%s %s without token: expected 401, got %d", c.method, c.path, got)
		}
	}
}
```

If the module starts background work, register its stop function in `wire` with
`d.Lifecycle.OnClose("projects job", svc.Close)` (the function takes a `context.Context` and must return
when it ends) and run any startup recovery there, as `internal/router/location/wire.go` does with
`RecoverInterruptedJobs`; never do either in a constructor. If the module is switched on by a setting, check
it at the top of `Register` and return `nil` when it is off, as `internal/router/media/register.go` does.
Avoid role-name checks for module access (`d.Kit.Role(...)`) unless the case is special, like `superadmin`.

### 8. Mount it in `modules.go`

Add the import and one entry to `internal/router/modules.go`, in alphabetical order. Everything in the list
is mounted under `/api` after authkit's own routes; the probes live in `router.go`. A registration error
stops startup with `register projects routes: ...`.

```go
import (
	routerlocation "starter-kit/internal/router/location"
	routermedia "starter-kit/internal/router/media"
	"starter-kit/internal/router/module"
	routerprojects "starter-kit/internal/router/projects"
)

var modules = []module.Entry{
	{Name: "location", Register: routerlocation.Register},
	{Name: "media", Register: routermedia.Register},
	{Name: "projects", Register: routerprojects.Register},
}
```

`TestModulesAreAlphabeticalAndUnique` enforces the order.

### 9. Optional: configuration

Settings go through `internal/config`; a module never reads the environment itself. The module's own file
holds its type, how it is read and how it is validated, and the three shared files get one line each.

`internal/config/projects.go`:

```go
package config

// Projects is the projects module's setting.
type Projects struct{ PageSize int }

func projectsFromEnv(l *loader) Projects {
	return Projects{PageSize: l.integer("PROJECTS_PAGE_SIZE", 20)}
}

// validateProjects names the variable and never its value.
func (c Config) validateProjects() []string {
	if n := c.Projects.PageSize; n < 1 || n > 100 {
		return []string{"PROJECTS_PAGE_SIZE must be between 1 and 100"}
	}
	return nil
}
```

`internal/config/projects_test.go`:

```go
package config

import "testing"

func TestProjectsPageSizeIsValidated(t *testing.T) {
	c := Config{Projects: Projects{PageSize: 0}}
	if got := c.validateProjects(); len(got) != 1 {
		t.Fatalf("validateProjects = %v, want one problem", got)
	}
	c.Projects.PageSize = 20
	if got := c.validateProjects(); len(got) != 0 {
		t.Fatalf("validateProjects = %v, want none", got)
	}
}
```

The shared edits:

```go
// internal/config/config.go, in type Config
Projects Projects

// internal/config/load.go, in FromEnv, next to the other sections
Projects: projectsFromEnv(&l),

// internal/config/validate.go, in Validate
problems = append(problems, c.validateProjects()...)
```

`l.str`, `l.integer`, `l.duration` and `l.megabytes` record an unparsable value for `Validate` and fall
back to the default; validation messages name the variable and never print its value. Config's `String`
method lists sections one by one: add the new one to its format string if it should appear in the logged
configuration. Skip this step when the module has no settings (and have `wire` pass a constant instead of
`d.Config.Projects.PageSize`).

Document the variable in `.env.example` under its own block:

```bash
# --- projects ---
# Default page size of GET /api/projects, 1-100 (default 20).
# PROJECTS_PAGE_SIZE=20
```

### 10. Check it

```bash
go build ./... && go vet ./... && go test -race -count=1 ./... && make lint
go run ./cmd/api -migrate-only   # applies the new migration
go run ./cmd/api
```

With the seed above, `admin` and `superadmin` hold the `projects` permissions. A new user has the
`viewer` role, so `GET /api/projects` answers `401` without a token and `403` with a viewer token until a
role is granted `projects:list`. `POST /api/projects` with `{"name":"First project"}` answers `201` for a
user with `projects:create`, and `GET /api/projects?search=first` lists the project. The audit trail gets a
`projects` / `create` entry.

When the module is done, add `docs/modules/projects.md` (see [`docs/modules/`](modules/)) and, if you keep
the Postman collection, a `Projects` folder in
[`docs/postman/starter-kit.postman_collection.json`](postman/starter-kit.postman_collection.json).
