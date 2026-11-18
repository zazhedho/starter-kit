package media

import (
	"testing"

	"github.com/gin-gonic/gin"

	"starter-kit/internal/config"
	"starter-kit/internal/testutil/routertest"
)

func TestWireRequiresStorageWhenEnabled(t *testing.T) {
	d := routertest.NewDeps(t, func(c *config.Config) { c.Media.Enabled = true })
	d.Storage = nil

	if w, err := wire(d); err == nil || w != nil {
		t.Fatalf("wire = %v, %v; want an error and nothing wired", w, err)
	}
	if err := Register(gin.New(), d); err == nil {
		t.Fatal("Register accepted enabled media without storage")
	}
}

func TestWireBuildsTheHandler(t *testing.T) {
	d := routertest.NewDeps(t, func(c *config.Config) { c.Media.Enabled = true })
	d.Storage = routertest.FakeStorage{}
	w, err := wire(d)
	if err != nil || w == nil || w.handler == nil {
		t.Fatalf("wire = %v, %v", w, err)
	}
}

func TestRegisterDisabledNeedsNoStorage(t *testing.T) {
	d := routertest.NewDeps(t, func(c *config.Config) { c.Media.Enabled = false })
	d.Storage = nil
	if err := Register(gin.New(), d); err != nil {
		t.Fatalf("Register = %v, want nil when media is disabled", err)
	}
}
