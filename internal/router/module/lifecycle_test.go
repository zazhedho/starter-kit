package module

import (
	"context"
	"errors"
	"reflect"
	"testing"
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

func TestLifecycleLenCountsHooks(t *testing.T) {
	var l Lifecycle
	if l.Len() != 0 {
		t.Fatalf("Len = %d on a new Lifecycle", l.Len())
	}
	l.OnClose("a", func(context.Context) error { return nil })
	l.OnClose("b", func(context.Context) error { return nil })
	if l.Len() != 2 {
		t.Fatalf("Len = %d, want 2", l.Len())
	}
	_ = l.Close(context.Background())
	if l.Len() != 0 {
		t.Fatalf("Len = %d after Close, want 0", l.Len())
	}
}
