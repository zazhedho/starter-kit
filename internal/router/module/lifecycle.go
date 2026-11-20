package module

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
)

// Lifecycle runs Drain hooks before the HTTP drain, and they only signal; Close hooks run after the
// drain, before the database closes, and wait.
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

// OnClose registers fn, which must return when ctx ends.
func (l *Lifecycle) OnClose(name string, fn func(context.Context) error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hooks = append(l.hooks, hook{name: name, fn: fn})
}

// OnDrain registers fn, which must not block: it only signals the work to stop, and OnClose waits for it.
func (l *Lifecycle) OnDrain(fn func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.drains = append(l.drains, fn)
}

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

func (l *Lifecycle) Draining() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.draining
}

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
