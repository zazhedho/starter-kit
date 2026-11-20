// Package module holds what every router/<module> package shares: the Deps a
// module is wired from, the Lifecycle it registers shutdown hooks with, and the
// Entry that mounts it. It imports no feature module.
package module

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
)

// Lifecycle collects the shutdown hooks of work that outlives a request.
// Shutdown has two steps. Drain runs first, when the signal arrives and before the
// HTTP server drains: it tells background work to stop. Close runs after the
// server has drained and before the database and Redis close: it waits for that work.
type Lifecycle struct {
	mu       sync.Mutex
	hooks    []hook
	drains   []func()
	draining bool
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

// OnDrain registers fn to run when shutdown starts, before requests drain. fn
// must not block: it only signals the work to stop, and OnClose waits for it.
func (l *Lifecycle) OnDrain(fn func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.drains = append(l.drains, fn)
}

// Drain marks the service as shutting down and runs the OnDrain functions in
// reverse order of registration. Only the first call acts.
func (l *Lifecycle) Drain() {
	l.mu.Lock()
	if l.draining {
		l.mu.Unlock()
		return
	}
	l.draining = true
	drains := l.drains
	l.mu.Unlock()

	for _, fn := range slices.Backward(drains) {
		fn()
	}
}

// Draining reports whether shutdown has started; /readyz answers 503 from then on.
func (l *Lifecycle) Draining() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.draining
}

// Close runs the hooks in reverse order of registration with ctx, and returns
// every error joined. Hooks run once: a second Close does nothing.
func (l *Lifecycle) Close(ctx context.Context) error {
	l.mu.Lock()
	hooks := l.hooks
	l.hooks = nil
	l.mu.Unlock()

	var errs []error
	for _, hook := range slices.Backward(hooks) {
		if err := hook.fn(ctx); err != nil {
			errs = append(errs, fmt.Errorf("close %s: %w", hook.name, err))
		}
	}
	return errors.Join(errs...)
}
