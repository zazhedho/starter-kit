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
| `internal/domain/<m>/` | `entity.go` (entities) and `errors.go` (domain errors) |
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
| 3 (only with settings) | `internal/config/config.go`, `load.go`, `validate.go` | one field in `Config` and its section in the `Config.String` format, one line in `FromEnv`, one call in `Validate` |
| 4 (only with env variables) | `.env.example` | its own `# --- <m> ---` block |

Apart from the composition-root edit under "Extension points" below (needed only for a new shared
client), no edit to the README, the route-table test, the architecture guard, lint, CI, the Makefile or the
Dockerfile. `TestRouteTable` in `internal/router` derives its expectation from `modules.go`, so the new
module is covered the moment it is listed. `TestEveryRouterDirectoryIsMounted` fails if `internal/router/<m>`
exists but is not in `modules`, and the entry's `Name` must equal the directory name.

### Shared helpers: the reserved `shared` directory

Modules must not import each other's services, handlers, repositories or routers (they may reference another
module's `domain` and `dto` from those layers, never from `domain` or `dto`), so a helper two modules need (pagination, response helpers, a common
DTO) has one home: `<tree>/shared`, for example `internal/handlers/http/shared` or `internal/dto/shared`.
Use it only when a second module needs the code; until then keep it in the module. Rules:

- any module of that tree may import it; it must not import any business module, in any tree;
- the layer rules of its tree still apply (`dto/shared` is standard library plus domain only);
- the import alias is the prefix plus `shared` (`dtoshared`, `httpshared`);
- a business module must not be named `shared`, and `internal/router/shared` is never mounted.

### Ownership and the `_any` permissions

For data a user owns, acting on your own rows needs no permission. Acting on other users' rows needs
`<resource>:<action>_any` (`media:list_any`, `media:delete_any`), seeded in the migration to the roles that
should have it. The handler decides: mount the route with `Auth()` then `LoadPermissions()`, read
`authkit.ScopeFrom(ctx).Has("<resource>", "<action>_any")`, and pass the answer to the service inside a plain
`Actor` (`CanListAny`, `CanDeleteAny`). The service applies it, for example by forcing the owner filter to the
caller, and returns a forbidden error (`ErrMediaForbidden`) for a row the actor may not touch; the handler
maps it to `404`, the same as a missing row, so a caller cannot probe which ids exist. `superadmin` passes every `Has` check.
`LoadPermissions()` never rejects a user who holds no permission. The reference is the media module:
[`docs/modules/media.md`](modules/media.md), `internal/router/media/register.go` and
`internal/handlers/http/media/handler.go`. Use `Can(resource, action)` instead when the whole route needs a
permission.

### Extension points: the composition root

A module that needs a new shared infrastructure client (a mailer, a queue, a search client) makes one
expected edit outside its own folders: add a field to `module.Deps` (`internal/router/module/module.go`),
open and close the client in `internal/app`, and set the field in `App.ModuleDeps()`. `internal/app` is the
composition root, the only place that opens connections. Note that storage is opened only when media is
enabled (the `if cfg.Media.Enabled` block of `newApp` in `internal/app/app.go`): another module that uses `d.Storage`
must widen that condition, or `Storage` is nil for it.

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

Added to this repository as written, the code below passes
`go build ./... && go vet ./... && go test -race -count=1 ./... && make lint`, including `internal/architecture`
(the layer guards, the comment guards and the migration-format test) and `TestRouteTable`. It is a recipe to copy
and adapt; it is not part of this repository.

### 1. Migration: table, menu and permissions

Generate the timestamp when you create the file (`date -u +%Y%m%d%H%M%S`); the name is
`<timestamp>_projects_create_table`. See [`migrations/README.md`](../migrations/README.md) for the rules.
Create the `.up.sql` with the table, then append the menu and permission seed that authkit generates. (The two
reference modules, `location` and `media`, are API-only and seed permissions without a menu; a module with a UI
seeds both, as below.)

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

`internal/domain/projects/errors.go` holds the errors callers match with `errors.Is`. A repository that looks a row up returns a domain `ErrNotFound` instead of the ORM error (see `internal/domain/media`). Both reference modules use the same file set: `entity.go` and `errors.go`.

```go
package projects

import "errors"

// ErrNameRequired is returned when a project is created without a name.
var ErrNameRequired = errors.New("project name is required")
```

### 3. DTO

`internal/dto/projects/projects.go`. Add it only when handler, service and repository share a shape; it must not import gin or gorm. `ListResult.Limit` carries the page size the repository applied, so the handler reports the real one:

```go
// Package projects holds the request and result shapes the projects handler,
// service and repository share. It must not import gin or gorm.
package projects

import domainprojects "starter-kit/internal/domain/projects"

// ListRequest is a parsed list query: the handler fills it from the URL, the
// repository applies it.
type ListRequest struct {
	Search         string
	OrderBy        string
	OrderDirection string
	Page           int
	Limit          int
}

// ListResult is one page of projects. Limit is the page size the repository
// applied, which can differ from the requested one; use it for the pagination
// metadata.
type ListResult struct {
	Items []domainprojects.Project
	Total int64
	Limit int
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
	Store(ctx context.Context, p *domainprojects.Project) error
	List(ctx context.Context, req dtoprojects.ListRequest) (dtoprojects.ListResult, error)
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
	if err := s.repo.Store(ctx, &p); err != nil {
		return domainprojects.Project{}, err
	}
	return p, nil
}

func (s *Service) List(ctx context.Context, req dtoprojects.ListRequest) (dtoprojects.ListResult, error) {
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

func (f *fakeRepository) Store(_ context.Context, p *domainprojects.Project) error {
	f.stored = *p
	return f.err
}

func (f *fakeRepository) List(context.Context, dtoprojects.ListRequest) (dtoprojects.ListResult, error) {
	return dtoprojects.ListResult{}, f.err
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
nothing declares an interface for it here. Test it with sqlmock like
`internal/repositories/media/repository_test.go`.

`internal/repositories/projects/repository.go`:

```go
package projects

import (
	"context"
	"slices"
	"strings"

	"github.com/zazhedho/gokit"
	"gorm.io/gorm"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// maxListLimit is the one cap on the page size of a project list.
const maxListLimit = 100

var listOrderColumns = []string{"name", "created_at"}

// Repository embeds the generic gokit repository for Store, GetByID, Update and
// Delete, and adds only the list query. Translate gokit.ErrNotFound into a domain
// ErrNotFound for a lookup the service exposes, as repositories/media does.
type Repository struct {
	*gokit.Repository[domainprojects.Project]
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{Repository: gokit.NewRepository[domainprojects.Project](db)}
}

// List returns one page of projects and the total. A sort column or direction
// outside the allow list falls back to created_at DESC instead of failing, and
// id is the last sort key, so pages never skip or repeat rows.
func (r *Repository) List(ctx context.Context, req dtoprojects.ListRequest) (dtoprojects.ListResult, error) {
	orderBy, direction := req.OrderBy, strings.ToUpper(req.OrderDirection)
	if !slices.Contains(listOrderColumns, orderBy) || (direction != "ASC" && direction != "DESC") {
		orderBy, direction = "created_at", "DESC"
	}

	// gokit appends DefaultOrders only when the params carry no explicit
	// order, so the chosen order goes through DefaultOrders to get the
	// tie-breaker after it.
	params := gokit.BaseParams{Search: req.Search, Page: req.Page, Limit: req.Limit}
	opts := gokit.QueryOptions{
		Search:        gokit.BuildSearchFunc("name"),
		DefaultOrders: []string{orderBy + " " + direction, "id " + direction},
		MaxLimit:      maxListLimit,
	}
	items, total, err := r.GetAll(ctx, params, opts)
	if err != nil {
		return dtoprojects.ListResult{}, err
	}
	return dtoprojects.ListResult{Items: items, Total: total, Limit: opts.PageSize(params)}, nil
}
```

The page-size cap lives here, in `QueryOptions.MaxLimit`, and `PageSize` reports the limit `GetAll` applied: a
missing or non-positive limit becomes the handler's default, and `limit=-1` or a value above the cap becomes
`MaxLimit`, because `AllowAll` is off. The handler therefore passes the request's limit through and neither clamps
it nor recomputes the offset. Searchable columns, allowed filters and sortable columns are also set through
`gokit.QueryOptions`; add custom repository methods only for business-specific queries. The repository is the
single authority for the sort columns, the default order and (when the list has filters) `AllowedFilters`; the
handler keeps no copy of the order defaults (it passes empty ones to `GetBaseParams`). The one list the handler
does keep is the `filters[...]` keys it reads into typed fields of the dto (see `internal/handlers/http/media`): it
only turns values into strings, and the repository's `AllowedFilters` still decides what reaches SQL.

#### When to embed `gokit.Repository`

Embed it when the module is plain CRUD on one table: `Store`, `GetByID`, `Update`, `Delete`, `SoftDelete` and
`GetAll` come for free, and the module adds only what is special (`internal/repositories/media` embeds it and overrides
`GetByID` and `Delete` to translate `gokit.ErrNotFound` into the domain error). Do not embed it when the module has
no such CRUD surface: `internal/repositories/location` has no embedded repository because it works on four tables
with upserts, a sync job state machine with owner-scoped column updates and a unique-index conflict, none of which
the generic repository models. Exposing the generic `Update` or `Delete` there would add untested ways to write.

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
	List(ctx context.Context, req dtoprojects.ListRequest) (dtoprojects.ListResult, error)
}
```

`internal/handlers/http/projects/handler.go` embeds `authkit.AuditWriter` and audits the success and
failure of every mutation. The caller comes from `authkit.ScopeFrom`, which `d.Kit.Auth()` fills in, and is
handed to the service as a plain value. Errors follow the one pattern of both reference modules:
`projectsErrorResponse` is the single place a domain error becomes a status and a caller-facing detail, and `fail`
logs it through `httpshared.Log` (`WARN` for a 4xx, `ERROR` for a 5xx) and answers through `httpshared.Write`. A
`500` never carries the error's text. Log lines use the `[ProjectsHandler][Method]` prefix, as `[MediaHandler]` and
`[LocationHandler]` do.

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
	httpshared "starter-kit/internal/handlers/http/shared"
)

// defaultListLimit is the page size when the request names none; the repository
// owns the maximum.
const defaultListLimit = 20

// Handler embeds authkit.AuditWriter to record every mutation.
type Handler struct {
	service Service
	authkit.AuditWriter
}

func New(svc Service, audit authkit.AuditService) *Handler {
	return &Handler{
		service:     svc,
		AuditWriter: authkit.NewAuditWriter(audit, "ProjectsHandler"),
	}
}

type createRequest struct {
	Name string `json:"name" binding:"required"`
}

func (h *Handler) List(ctx *gin.Context) {
	params, err := gokit.GetBaseParams(ctx.Request.URL.Query(), "", "", defaultListLimit)
	if err != nil {
		httpshared.Log(ctx, http.StatusBadRequest, "[ProjectsHandler][List]", "GetBaseParams", err)
		httpshared.Write(ctx, http.StatusBadRequest, "invalid query parameters")
		return
	}
	result, err := h.service.List(ctx.Request.Context(), dtoprojects.ListRequest{
		Search:         params.Search,
		OrderBy:        params.OrderBy,
		OrderDirection: params.OrderDirection,
		Page:           params.Page,
		Limit:          params.Limit,
	})
	if err != nil {
		fail(ctx, "List", err)
		return
	}
	// The repository caps the limit and reports the one it applied.
	ctx.JSON(http.StatusOK, gokit.PaginationResponse(http.StatusOK, result.Total, params.Page, result.Limit, gokit.RequestID(ctx), result.Items))
}

func (h *Handler) Create(ctx *gin.Context) {
	logID := gokit.RequestID(ctx)
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
		fail(ctx, "Create", err)
		return
	}

	h.WriteAudit(ctx, authkit.AuditEvent{
		Action: authkit.ActionCreate, Resource: "projects", ResourceID: p.ID,
		Status: authkit.StatusSuccess, Message: "Created project", AfterData: p,
	})
	ctx.JSON(http.StatusCreated, gokit.Response(http.StatusCreated, "Project created successfully", logID, p))
}

// fail logs and answers a service error with the status projectsErrorResponse
// maps it to: WARN for a 4xx, ERROR for a 5xx.
func fail(ctx *gin.Context, method string, err error) {
	status, detail := projectsErrorResponse(err)
	httpshared.Log(ctx, status, "[ProjectsHandler]["+method+"]", "Service."+method, err)
	httpshared.Write(ctx, status, detail)
}

// projectsErrorResponse is the one place service errors become HTTP statuses.
// The detail is written for the caller; an unexpected error gets the standard
// 500 body instead of its text.
func projectsErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, domainprojects.ErrNameRequired):
		return http.StatusBadRequest, err.Error()
	default:
		return http.StatusInternalServerError, gokit.MsgSomethingWrong
	}
}
```

Test the mapper and the handler with a fake `Service` and `httptest`, as
`internal/handlers/http/media/handler_test.go` does (`internal/handlers/http/projects/handler_test.go`):

```go
package projects

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	domainprojects "starter-kit/internal/domain/projects"
	dtoprojects "starter-kit/internal/dto/projects"
)

// serviceDouble records what the handler passes to the service.
type serviceDouble struct {
	listReq dtoprojects.ListRequest
	result  dtoprojects.ListResult
	err     error
}

func (d *serviceDouble) Create(context.Context, string, string) (domainprojects.Project, error) {
	return domainprojects.Project{}, d.err
}

func (d *serviceDouble) List(_ context.Context, req dtoprojects.ListRequest) (dtoprojects.ListResult, error) {
	d.listReq = req
	return d.result, d.err
}

func TestProjectsErrorResponseMapsDomainErrors(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		status int
	}{
		"name required":         {domainprojects.ErrNameRequired, http.StatusBadRequest},
		"wrapped name required": {fmt.Errorf("create: %w", domainprojects.ErrNameRequired), http.StatusBadRequest},
		"unexpected":            {errors.New("database down"), http.StatusInternalServerError},
	} {
		if status, _ := projectsErrorResponse(c.err); status != c.status {
			t.Errorf("%s: status = %d, want %d", name, status, c.status)
		}
	}
}

// The handler passes the limit as asked; capping it is the repository's job,
// and the response reports the limit the repository applied.
func TestListReportsTheLimitTheRepositoryApplied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &serviceDouble{result: dtoprojects.ListResult{Total: 3, Limit: 100}}
	engine := gin.New()
	engine.GET("/projects", New(svc, nil).List)

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/projects?limit=5000", nil))

	if rec.Code != http.StatusOK || svc.listReq.Limit != 5000 {
		t.Fatalf("status %d, service got limit %d", rec.Code, svc.listReq.Limit)
	}
	if !strings.Contains(rec.Body.String(), `"limit":100`) {
		t.Fatalf("response lacks the applied limit: %s", rec.Body.String())
	}
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
	return &wired{handler: httpprojects.New(svc, d.Kit.Audit())}, nil
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

import "github.com/zazhedho/gokit"

// Projects is the projects module's setting.
type Projects struct{ PageSize int }

func projectsFromEnv() Projects {
	return Projects{PageSize: gokit.GetEnv("PROJECTS_PAGE_SIZE", 20)}
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
Projects: projectsFromEnv(),

// internal/config/validate.go, in Validate
problems = append(problems, c.validateProjects()...)
```

Read every value with `gokit.GetEnv(key, default)`: unset or blank gives the default, and an unparsable
value gives the default and is reported by `gokit.EnvErrors()`, which `Validate` already includes
(`PROJECTS_PAGE_SIZE must be a valid int`). Durations accept `60` (seconds), `30s`, `1m` and `1h`. Keep only
business rules (ranges, required fields) in `validateProjects`; messages name the variable and never print
its value. Config's `String`
method lists sections one by one: add the new one to its format string if it should appear in the logged
configuration. Skip this step when the module has no settings. The handler above uses the `defaultListLimit`
constant; to make that default configurable, give `New` a `pageSize int`, use it in place of
`defaultListLimit` in `List`, and pass `d.Config.Projects.PageSize` from `wire`.

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
