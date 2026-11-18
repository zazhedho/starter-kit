package router

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Lifecycle collects shutdown hooks for work that outlives a request. Close
// runs once, after the HTTP server drains and before the database and Redis close.
type Lifecycle struct {
	mu    sync.Mutex
	hooks []hook
}

type hook struct {
	name string
	fn   func(context.Context) error
}

// OnClose registers fn to run at shutdown. fn must return when ctx ends.
func (l *Lifecycle) OnClose(name string, fn func(context.Context) error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hooks = append(l.hooks, hook{name: name, fn: fn})
}

// Close runs the hooks in reverse order of registration with ctx, and returns
// every error joined. Hooks run once: a second Close does nothing.
func (l *Lifecycle) Close(ctx context.Context) error {
	l.mu.Lock()
	hooks := l.hooks
	l.hooks = nil
	l.mu.Unlock()

	var errs []error
	for i := len(hooks) - 1; i >= 0; i-- {
		if err := hooks[i].fn(ctx); err != nil {
			errs = append(errs, fmt.Errorf("close %s: %w", hooks[i].name, err))
		}
	}
	return errors.Join(errs...)
}
