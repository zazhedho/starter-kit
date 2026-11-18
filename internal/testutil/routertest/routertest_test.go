package routertest

import (
	"database/sql/driver"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"

	"starter-kit/internal/router/module"
)

func TestNewDepsIsCompleteAndMediaIsOff(t *testing.T) {
	d := NewDeps(t, nil)
	if d.DB == nil || d.SQLDB == nil || d.Kit == nil || d.Lifecycle == nil {
		t.Fatalf("incomplete Deps: %+v", d)
	}
	if d.Config.Media.Enabled || d.Storage != nil || d.Redis != nil {
		t.Fatal("media, storage and redis must be off by default")
	}
}

func TestRouteSetServeAndAuthkitRoutes(t *testing.T) {
	engine := gin.New()
	engine.GET("/a", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	engine.POST("/b/:id", func(c *gin.Context) { c.Status(http.StatusAccepted) })

	if got := SortedKeys(RouteSet(engine)); len(got) != 2 || got[0] != "GET /a" || got[1] != "POST /b/:id" {
		t.Fatalf("RouteSet = %v", got)
	}
	if got := Serve(engine, http.MethodGet, "/a"); got != http.StatusNoContent {
		t.Fatalf("Serve = %d", got)
	}
	if got := Serve(engine, http.MethodGet, "/missing"); got != http.StatusNotFound {
		t.Fatalf("Serve = %d", got)
	}
	if len(AuthkitRoutes(t, NewDeps(t, nil))) == 0 {
		t.Fatal("authkit mounted no routes")
	}
}

func TestNewExecDBSendsStatementsToTheMock(t *testing.T) {
	db, mock := NewExecDB(t)
	mock.ExpectExec("UPDATE").WillReturnResult(sqlmockResult())
	if err := db.Exec("UPDATE t SET a = 1").Error; err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func sqlmockResult() driver.Result { return sqlmock.NewResult(0, 1) }

func TestMountRegistersOnlyUnderAPI(t *testing.T) {
	reg := func(r gin.IRouter, _ module.Deps) error {
		r.GET("/thing", func(c *gin.Context) { c.Status(http.StatusNoContent) })
		return nil
	}
	engine := Mount(t, reg, NewDeps(t, nil))
	if got := SortedKeys(RouteSet(engine)); len(got) != 1 || got[0] != "GET /api/thing" {
		t.Fatalf("routes = %v", got)
	}
	if got := Serve(engine, http.MethodGet, "/api/thing"); got != http.StatusNoContent {
		t.Fatalf("Serve = %d", got)
	}
}
