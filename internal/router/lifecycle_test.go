package router

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLifecycleClosesInReverseOrderAndJoinsErrors(t *testing.T) {
	var l Lifecycle
	var order []string
	boom := errors.New("boom")
	l.OnClose("first", func(context.Context) error { order = append(order, "first"); return nil })
	l.OnClose("second", func(context.Context) error { order = append(order, "second"); return boom })
	l.OnClose("third", func(context.Context) error { order = append(order, "third"); return nil })

	err := l.Close(context.Background())
	if !reflect.DeepEqual(order, []string{"third", "second", "first"}) {
		t.Fatalf("hooks ran in order %v", order)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("Close = %v, want it to wrap boom", err)
	}
}

func TestLifecycleCloseRunsHooksOnce(t *testing.T) {
	var l Lifecycle
	calls := 0
	l.OnClose("once", func(context.Context) error { calls++; return nil })
	_ = l.Close(context.Background())
	_ = l.Close(context.Background())
	if calls != 1 {
		t.Fatalf("hook ran %d times, want 1", calls)
	}
}

func TestLifecycleCloseHandsTheContextToHooks(t *testing.T) {
	var l Lifecycle
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l.OnClose("waits", func(ctx context.Context) error { return ctx.Err() })
	if err := l.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close = %v, want context.Canceled", err)
	}
}

func TestRegisterLocationRegistersAShutdownHook(t *testing.T) {
	d := newTestDeps(t, nil)
	if err := registerLocation(gin.New(), d); err != nil {
		t.Fatalf("registerLocation: %v", err)
	}
	if len(d.Lifecycle.hooks) != 1 {
		t.Fatalf("registerLocation registered %d shutdown hooks, want 1", len(d.Lifecycle.hooks))
	}
	if err := d.Lifecycle.Close(context.Background()); err != nil {
		t.Fatalf("Lifecycle.Close = %v", err)
	}
}
