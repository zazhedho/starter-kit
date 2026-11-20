package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/zazhedho/logus"
)

var ErrShutdownTimeout = errors.New("app: shutdown timed out with requests still in flight")

func (a *App) Serve(ctx context.Context) error {
	if err := a.buildRoutes(); err != nil {
		return a.closeAfter(err)
	}
	ln := a.listener
	if ln == nil {
		var lc net.ListenConfig
		var err error
		if ln, err = lc.Listen(ctx, "tcp", a.server.Addr); err != nil {
			return a.closeAfter(fmt.Errorf("listen: %w", err))
		}
	}
	logus.Log(logus.LevelInfo, "Listening on", ln.Addr())

	serveErr := make(chan error, 1)
	go func() { serveErr <- a.server.Serve(ln) }()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return a.closeAfter(nil)
		}
		return a.closeAfter(fmt.Errorf("serve: %w", err))
	case <-ctx.Done():
	}

	logus.Log(logus.LevelInfo, "Shutdown started")
	// Before the drain: /readyz turns 503 and background work is told to stop, so it can record its final state.
	if a.lifecycle != nil {
		a.lifecycle.Drain()
	}
	// One deadline covers the HTTP drain, the lifecycle hooks and the jobs' final writes; the caller's ctx is already canceled.
	deadline := time.Now().Add(a.cfg.HTTP.ShutdownTimeout)
	shutdownCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer cancel()

	// The listener stays open for the delay so a load balancer sees /readyz turn 503 before connections are refused.
	if delay := a.cfg.HTTP.ShutdownDelay; delay > 0 {
		select {
		case <-time.After(delay):
		case <-shutdownCtx.Done():
		}
	}
	err := a.server.Shutdown(shutdownCtx)
	if err != nil {
		_ = a.server.Close()
		if errors.Is(err, context.DeadlineExceeded) {
			err = ErrShutdownTimeout
		} else {
			err = fmt.Errorf("shutdown: %w", err)
		}
	}
	<-serveErr

	if closeErr := a.closeBy(deadline); closeErr != nil {
		err = errors.Join(err, closeErr)
	}
	if err == nil {
		logus.Log(logus.LevelInfo, "Shutdown complete")
	}
	return err
}

func (a *App) closeAfter(err error) error {
	if closeErr := a.Close(); closeErr != nil {
		return errors.Join(err, closeErr)
	}
	return err
}
